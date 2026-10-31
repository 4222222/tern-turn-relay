//! Cloudflare management-key custody. Secret values never enter public results.
use crate::common::{self, Error, Options, Result};
use futures_util::StreamExt;
use serde_json::{json, Value};
#[cfg(unix)]
use sha2::{Digest, Sha256};
use std::future::Future;
use std::io::IsTerminal;
#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

fn invalid() -> Error {
    Error::with_exit(
        "credential-error",
        "Invalid Cloudflare TURN key; use the TURN-key token, not an account token.",
        4,
    )
}
fn remote_error() -> Error {
    Error::with_exit("credential-error", "Cloudflare TURN credential issuance failed; verify connectivity, TLS trust and TURN-key authorization.", 5)
}
fn cancelled() -> Error {
    Error::with_exit("cancelled", "Local credential change cancelled.", 6)
}
fn validate(value: Value) -> Result<Value> {
    let key = value
        .get("turn_key_id")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    let token = value
        .get("api_token")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    if value.get("provider").and_then(Value::as_str) != Some("cloudflare")
        || key.is_empty()
        || key.len() > 128
        || !key
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        || token.is_empty()
        || token.len() > 8192
        || !token.bytes().all(|c| (33..=126).contains(&c))
    {
        return Err(invalid());
    }
    Ok(json!({"provider":"cloudflare","turn_key_id":key,"api_token":token}))
}
fn load(path: &Path) -> Result<Value> {
    if crate::install::snapshot(path, 65536)?.is_none() {
        return Err(Error::with_exit(
            "credential-absent",
            "No local management key is configured.",
            3,
        ));
    }
    let stored = common::read_json(path, true)?;
    #[cfg(windows)]
    {
        if stored.get("storage").and_then(Value::as_str) != Some("windows-dpapi-user")
            || stored.get("schema").and_then(Value::as_u64) != Some(1)
        {
            return Err(Error::with_exit("credential-reconfigure-required", "Windows 凭据必须使用用户级加密存储；请显式重新配置，原文件已保留。", 4));
        }
        let ciphertext = hex::decode(stored.get("ciphertext").and_then(Value::as_str).ok_or_else(invalid)?).map_err(|_| invalid())?;
        let mut plaintext = crate::windows_credentials::unprotect_storage(&ciphertext)?;
        let parsed = serde_json::from_slice(&plaintext).map_err(|_| invalid());
        for byte in &mut plaintext { unsafe { std::ptr::write_volatile(byte, 0); } }
        return validate(parsed?);
    }
    #[cfg(unix)]
    validate(stored)
}
pub fn configured(path: &Path) -> Result<bool> {
    if crate::install::snapshot(path, 65536)?.is_none() {
        return Ok(false);
    }
    load(path)?;
    Ok(true)
}
pub fn default_path() -> Result<PathBuf> {
    #[cfg(windows)]
    {
        return Ok(crate::windows_security::state_dir()?.join("plugin-data/tern-turn-relay/credentials/cloudflare.json"));
    }
    #[cfg(unix)]
    Ok(crate::install::home()?.join(
        "Library/Application Support/Tern/plugin-data/tern-turn-relay/credentials/cloudflare.json",
    ))
}

fn usable_turn(entries: &[Value]) -> bool {
    entries.iter().any(|entry| {
        if entry
            .get("username")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
            || entry
                .get("credential")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            || entry
                .get("credentialType")
                .is_some_and(|v| v.as_str() != Some("password"))
        {
            return false;
        }
        let urls: Vec<&str> = match entry.get("urls") {
            Some(Value::String(s)) => vec![s],
            Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).collect(),
            _ => return false,
        };
        urls.into_iter().any(|url| {
            let Some((scheme, rest)) = url.split_once(':') else {
                return false;
            };
            if !matches!(scheme, "turn" | "turns") || rest.starts_with("//") {
                return false;
            }
            let Ok(parsed) = reqwest::Url::parse(&format!("{scheme}://{rest}")) else {
                return false;
            };
            if parsed.host_str().is_none()
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || !parsed.path().is_empty()
                || parsed.fragment().is_some()
                || parsed.port() == Some(0)
            {
                return false;
            }
            let pairs: Vec<_> = parsed.query_pairs().collect();
            pairs.is_empty()
                || (pairs.len() == 1
                    && pairs[0].0 == "transport"
                    && (pairs[0].1 == "tcp" || (scheme == "turn" && pairs[0].1 == "udp")))
        })
    })
}
async fn issue_key(key: &Value, ttl: u64) -> Result<Value> {
    if !(1..=86400).contains(&ttl) {
        return Err(invalid());
    }
    // Both secret path component and Authorization come only from validated memory.
    let client = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(12))
        .build()
        .map_err(|_| remote_error())?;
    let url = format!(
        "https://rtc.live.cloudflare.com/v1/turn/keys/{}/credentials/generate-ice-servers",
        key["turn_key_id"].as_str().ok_or_else(invalid)?
    );
    let issued = common::unix_time();
    let response = client
        .post(url)
        .bearer_auth(key["api_token"].as_str().ok_or_else(invalid)?)
        .header("Accept", "application/json")
        .header("User-Agent", "tern-turn-relay/0.4.0")
        .json(&json!({"ttl":ttl}))
        .send()
        .await
        .map_err(|_| remote_error())?;
    if !response.status().is_success() || response.content_length().is_some_and(|n| n > 131072) {
        return Err(remote_error());
    }
    let mut stream = response.bytes_stream();
    let mut raw = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| remote_error())?;
        if raw.len() + chunk.len() > 131072 {
            return Err(remote_error());
        }
        raw.extend_from_slice(&chunk);
    }
    let mut document = common::parse_json(&raw).map_err(|_| remote_error())?;
    let entries = match document.get_mut("iceServers").map(Value::take) {
        Some(Value::Array(entries)) => entries,
        Some(entry @ Value::Object(_)) => vec![entry],
        _ => return Err(remote_error()),
    };
    if !usable_turn(&entries) {
        return Err(remote_error());
    }
    Ok(json!({"entries":entries,"expires_unix":issued + ttl as f64}))
}
/// Internal transport-only result; never serialize this result at a CLI boundary.
pub async fn issue(path: &Path, ttl: u64) -> Result<Value> {
    issue_key(&load(path)?, ttl).await
}

#[cfg(unix)]
const DIALOG: &str = r#"try
    set keyID to text returned of (display dialog "Cloudflare TURN key ID" default answer "" with hidden answer buttons {"Cancel", "Continue"} default button "Continue" cancel button "Cancel" with title "Tern TURN setup")
    set apiToken to text returned of (display dialog "Cloudflare TURN-key API token (not an account token). Continue validates it with Cloudflare and saves it privately on this Mac." default answer "" with hidden answer buttons {"Cancel", "Validate and Save"} default button "Validate and Save" cancel button "Cancel" with title "Tern TURN setup")
    if (length of keyID) > 128 or (length of apiToken) > 8192 then return "__INVALID__"
    return keyID & linefeed & apiToken
on error number -128
    return "__CANCELLED__"
end try"#;

fn parse_native(raw: &[u8]) -> Result<Value> {
    if raw.len() > 16384 {
        return Err(invalid());
    }
    let text = std::str::from_utf8(raw).map_err(|_| invalid())?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    if text == "__CANCELLED__" {
        return Err(cancelled());
    }
    let (key, token) = text.split_once('\n').ok_or_else(invalid)?;
    validate(json!({"provider":"cloudflare","turn_key_id":key,"api_token":token}))
}

#[cfg(unix)]
struct TerminalMode<'a> {
    terminal: &'a std::fs::File,
    original: libc::termios,
}
#[cfg(unix)]
impl Drop for TerminalMode<'_> {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(self.terminal.as_raw_fd(), libc::TCSAFLUSH, &self.original);
        }
    }
}
#[cfg(unix)]
fn hidden_line(terminal: &mut std::fs::File, prompt: &[u8], limit: usize) -> Result<String> {
    let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();
    if unsafe { libc::tcgetattr(terminal.as_raw_fd(), original.as_mut_ptr()) } != 0 {
        return Err(invalid());
    }
    let original = unsafe { original.assume_init() };
    let mut mode = original;
    mode.c_lflag &= !(libc::ECHO | libc::ICANON | libc::ISIG);
    mode.c_cc[libc::VMIN] = 1;
    mode.c_cc[libc::VTIME] = 0;
    if unsafe { libc::tcsetattr(terminal.as_raw_fd(), libc::TCSAFLUSH, &mode) } != 0 {
        return Err(invalid());
    }
    let guard = TerminalMode { terminal, original };
    let mut io = &*guard.terminal;
    io.write_all(prompt).map_err(|_| invalid())?;
    io.flush().map_err(|_| invalid())?;
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0];
        if io.read(&mut byte).map_err(|_| cancelled())? != 1 {
            return Err(cancelled());
        }
        match byte[0] {
            b'\n' | b'\r' => break,
            3 => {
                return Err(Error::with_exit(
                    "cancelled",
                    "Credential operation interrupted.",
                    130,
                ))
            }
            4 | 27 => return Err(cancelled()),
            8 | 127 => {
                bytes.pop();
            }
            value if (32..=126).contains(&value) && bytes.len() < limit => bytes.push(value),
            _ => return Err(invalid()),
        }
    }
    io.write_all(b"\n").map_err(|_| invalid())?;
    String::from_utf8(bytes).map_err(|_| invalid())
}
#[cfg(windows)]
fn terminal_key() -> Result<Value> {
    let (id, token) = crate::windows_credentials::terminal_key()?;
    validate(json!({"provider":"cloudflare","turn_key_id":id,"api_token":token}))
}

#[cfg(unix)]
fn terminal_key() -> Result<Value> {
    let mut terminal = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| invalid())?;
    let id = hidden_line(&mut terminal, b"Cloudflare TURN key ID (hidden): ", 128)?;
    let token = hidden_line(
        &mut terminal,
        b"Cloudflare TURN-key API token (hidden): ",
        8192,
    )?;
    validate(json!({"provider":"cloudflare","turn_key_id":id,"api_token":token}))
}
#[cfg(windows)]
async fn native_key() -> Result<Value> {
    parse_native(&crate::windows_credentials::native_input().await?)
}

#[cfg(unix)]
async fn native_key() -> Result<Value> {
    if cfg!(target_os = "macos") {
        let output = common::run(
            "/usr/bin/osascript",
            &["-e".into(), DIALOG.into()],
            None,
            Duration::from_secs(300),
        )
        .await
        .map_err(|_| {
            Error::with_exit(
                "credential-error",
                "Native hidden credential input failed or timed out.",
                4,
            )
        })?;
        if !output.status.success() {
            return Err(invalid());
        }
        parse_native(&output.stdout)
    } else {
        terminal_key()
    }
}
fn confirm(authorized: bool, prompt: &[u8]) -> Result<()> {
    if std::io::stdin().is_terminal() {
        #[cfg(unix)]
        let answer = {
            let mut terminal = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/tty")
                .map_err(|_| invalid())?;
            hidden_line(&mut terminal, prompt, 16)?
        };
        #[cfg(windows)]
        let answer = crate::windows_credentials::hidden_line(prompt, 16)?;
        if answer != "yes" {
            return Err(cancelled());
        }
    } else if !authorized {
        return Err(Error::with_exit(
            "confirmation-required",
            "Explicit replacement or removal consent is required.",
            6,
        ));
    }
    Ok(())
}
fn storage_kind() -> &'static str {
    if cfg!(windows) { "windows-dpapi-user" } else { "private-file" }
}

fn storage_bytes(key: &Value) -> Result<Vec<u8>> {
    let mut raw = serde_json::to_vec(key).map_err(|_| invalid())?;
    #[cfg(windows)]
    {
        let protected = crate::windows_credentials::protect_storage(&raw);
        for byte in &mut raw { unsafe { std::ptr::write_volatile(byte, 0); } }
        return serde_json::to_vec(&json!({"schema":1,"storage":storage_kind(),"ciphertext":hex::encode(protected?)})).map_err(|_| invalid());
    }
    #[cfg(unix)]
    {
        raw.push(b'\n');
        Ok(raw)
    }
}

async fn save(path: &Path, before: &Option<crate::install::Snapshot>, key: Value) -> Result<Value> {
    issue_key(&key, 60).await?;
    let raw = storage_bytes(&key)?;
    crate::install::replace(path, before.as_ref(), Some(&raw), 0o600)?;
    Ok(
        json!({"configured":true,"validated":true,"replaced":before.is_some(),"provider":"cloudflare","storage":storage_kind()}),
    )
}
#[cfg(windows)]
fn mutation_lock_path(path: &Path) -> Result<PathBuf> {
    const LOCK_NAME: &str = ".tern-credential-mutation.lock";
    let filename = path.file_name().and_then(|name| name.to_str()).ok_or_else(invalid)?;
    if filename.eq_ignore_ascii_case(LOCK_NAME) { return Err(invalid()); }
    // Serialize the private credential directory so case aliases cannot bypass the lock.
    Ok(path.parent().ok_or_else(invalid)?.join(LOCK_NAME))
}

#[cfg(unix)]
fn mutation_lock_path(path: &Path) -> Result<PathBuf> {
    let filename = path.file_name().ok_or_else(invalid)?;
    let mut name = format!(
        ".tern-credential-{}.lock",
        hex::encode(Sha256::digest(filename.as_encoded_bytes()))
    );
    // Include the complete filename, not only its stem. Even a target deliberately
    // named like a generated lock must never become its own mutation lock.
    if path.with_file_name(&name) == path {
        name.push_str(".guard");
    }
    Ok(path.with_file_name(name))
}
fn mutation_lock(path: &Path) -> Result<std::fs::File> {
    common::lock(&mutation_lock_path(path)?, true)
}
async fn configure_native_input(
    path: &Path,
    replace_existing: bool,
    input: impl Future<Output = Result<Value>>,
) -> Result<Value> {
    common::private_dir(path.parent().ok_or_else(invalid)?, true)?;
    let _lock = mutation_lock(path)?;
    let before = crate::install::snapshot(path, 65536)?;
    if let Some(existing) = &before {
        existing.require_private()?;
        if !replace_existing {
            return Err(Error::with_exit(
                "replacement-consent-required",
                "Replacing an existing credential requires explicit consent.",
                6,
            ));
        }
    }
    save(path, &before, input.await?).await
}
pub async fn configure_native(path: &Path, replace_existing: bool) -> Result<Value> {
    configure_native_input(path, replace_existing, native_key()).await
}
pub async fn run(args: &[String]) -> Result<Value> {
    let opts = Options::parse(
        args,
        &["--file", "--input-file"],
        &["--stdin", "--replace", "--yes"],
    )?;
    if opts.positionals.len() != 1 {
        return Err(invalid());
    }
    let action = opts.positionals[0].as_str();
    if !matches!(action, "configure" | "check" | "status" | "remove-local")
        || (action != "configure"
            && (opts.flag("--stdin")
                || opts.flag("--replace")
                || opts.get("--input-file").is_some()))
        || (action != "remove-local" && opts.flag("--yes"))
    {
        return Err(Error::with_exit(
            "invalid-request",
            "Invalid credential command or options; argument values withheld.",
            2,
        ));
    }
    let path = opts
        .get("--file")
        .map(PathBuf::from)
        .map(Ok)
        .unwrap_or_else(default_path)?;
    common::safe_local_absolute(path.to_str().ok_or_else(invalid)?)?;
    let mut result = match action {
        "status" | "check" => {
            let key = load(&path)?;
            if action == "check" {
                issue_key(&key, 60).await?;
            }
            let mut summary = json!({"configured":true,"storage":storage_kind(),"network_checked":action == "check"});
            if action == "check" {
                summary["validated"] = json!(true);
                summary["probe_ttl_seconds"] = json!(60);
            }
            summary
        }
        "configure" => {
            if opts.flag("--stdin") && opts.get("--input-file").is_some() {
                return Err(invalid());
            }
            common::private_dir(path.parent().ok_or_else(invalid)?, true)?;
            let _lock = mutation_lock(&path)?;
            let before = crate::install::snapshot(&path, 65536)?;
            if let Some(existing) = &before {
                existing.require_private()?;
                confirm(
                    opts.flag("--replace"),
                    b"Replace the local TURN key after validation? Type yes: ",
                )?;
            }
            let key = if let Some(source) = opts.get("--input-file") {
                validate(common::read_json(Path::new(source), true)?)?
            } else if opts.flag("--stdin") {
                if std::io::stdin().is_terminal() {
                    return Err(invalid());
                }
                validate(common::read_json_stdin(65536)?)?
            } else {
                if !std::io::stdin().is_terminal() {
                    return Err(Error::with_exit(
                        "invalid-request",
                        "Use --stdin or --input-file for noninteractive configuration.",
                        2,
                    ));
                }
                terminal_key()?
            };
            save(&path, &before, key).await?
        }
        "remove-local" => {
            if crate::install::snapshot(&path, 65536)?.is_none() {
                return Err(Error::with_exit(
                    "credential-absent",
                    "No local management key is configured.",
                    3,
                ));
            }
            common::private_dir(path.parent().ok_or_else(invalid)?, false)?;
            let _lock = mutation_lock(&path)?;
            let before = crate::install::snapshot(&path, 65536)?;
            before
                .as_ref()
                .ok_or_else(|| {
                    Error::with_exit(
                        "credential-absent",
                        "No local management key is configured.",
                        3,
                    )
                })?
                .require_private()?;
            confirm(
                opts.flag("--yes"),
                b"Remove only this local key (no Cloudflare revocation)? Type yes: ",
            )?;
            crate::install::replace(&path, before.as_ref(), None, 0o600)?;
            json!({"configured":false,"removed":true,"remote_revoked":false})
        }
        _ => {
            return Err(Error::with_exit(
                "invalid-request",
                "Unknown credential action.",
                2,
            ))
        }
    };
    result["ok"] = json!(true);
    result["command"] = json!(action);
    result["credential_file"] = json!(path);
    result["provider"] = json!("cloudflare");
    result["exit_code"] = json!(0);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_only_supported_secret_fields() {
        let input = json!({"provider":"cloudflare","turn_key_id":"a_B-9","api_token":"opaque","ignored":"never retained"});
        let result = validate(input).unwrap();
        assert_eq!(result.as_object().unwrap().len(), 3);
        for token in ["", "line\nbreak", "space here", "\u{7f}", "秘密"] {
            assert!(validate(
                json!({"provider":"cloudflare","turn_key_id":"id","api_token":token})
            )
            .is_err());
        }
        assert!(validate(
            json!({"provider":"cloudflare","turn_key_id":"../id","api_token":"secret"})
        )
        .is_err());
    }
    #[test]
    fn native_cancellation_and_malformed_output_are_redacted() {
        assert_eq!(
            parse_native(b"__CANCELLED__\n").unwrap_err().code,
            "cancelled"
        );
        assert!(parse_native(b"id\nsecret\nextra\n").is_err());
        assert_eq!(parse_native(b"id\nsecret\n").unwrap()["turn_key_id"], "id");
        assert!(!parse_native(b"id\nbad token\n")
            .unwrap_err()
            .to_string()
            .contains("bad token"));
    }
    #[test]
    fn accepts_only_usable_turn_servers() {
        let entry = |url: &str| json!({"urls":url,"username":"u","credential":"p"});
        assert!(usable_turn(&[entry(
            "turns:turn.cloudflare.com:5349?transport=tcp"
        )]));
        assert!(usable_turn(&[entry(
            "turn:turn.cloudflare.com:3478?transport=udp"
        )]));
        for url in [
            "https://example.com",
            "turn://host",
            "turn:user@host",
            "turn:host/path",
            "turns:host?transport=udp",
            "turn:host?transport=udp&transport=tcp",
            "turn:host:0",
            "turn:host#frag",
        ] {
            assert!(!usable_turn(&[entry(url)]), "{url}");
        }
    }
    fn temporary_credentials() -> PathBuf {
        let root = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        #[cfg(windows)]
        let root = crate::windows_security::normalize_system_path(&root).unwrap();
        let root = root.join(format!("tern-credential-lock-test-{:032x}", rand::random::<u128>()));
        common::private_dir(&root, true).unwrap();
        root
    }
    #[tokio::test]
    async fn cancelled_and_invalid_native_input_never_create_lock_named_target() {
        let root = temporary_credentials();
        let target = root.join("cancelled.lock");
        let error = configure_native_input(&target, false, std::future::ready(Err(cancelled())))
            .await
            .unwrap_err();
        assert_eq!(error.code, "cancelled");
        assert!(!target.exists());
        // Separate input scenarios must not depend on immediate reacquisition of
        // a lock briefly inherited by another test's concurrent fork before exec.
        let invalid_target = root.join("invalid.lock");
        let error = configure_native_input(
            &invalid_target,
            false,
            std::future::ready(parse_native(b"invalid output\n")),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, "credential-error");
        assert!(!invalid_target.exists());
        assert!(!target.exists());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[tokio::test]
    async fn invalid_cli_input_never_creates_lock_named_target() {
        let root = temporary_credentials();
        let target = root.join("credentials.lock");
        let input = root.join("input.json");
        common::atomic_json(&input, &json!({"provider":"invalid"})).unwrap();
        let error = run(&[
            "configure".into(),
            "--file".into(),
            target.to_str().unwrap().into(),
            "--input-file".into(),
            input.to_str().unwrap().into(),
        ])
        .await
        .unwrap_err();
        assert_eq!(error.code, "credential-error");
        assert!(!target.exists());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn credential_mutation_lock_survives_atomic_target_replacement() {
        use std::{os::fd::AsRawFd, os::unix::fs::MetadataExt};
        let root = temporary_credentials();
        let target = root.join("credentials.lock");
        common::atomic_json(&target, &json!({"value":"old"})).unwrap();
        let held = mutation_lock(&target).unwrap();
        let lock_inode = held.metadata().unwrap().ino();
        let before = crate::install::snapshot(&target, 65536).unwrap();
        crate::install::replace(
            &target,
            before.as_ref(),
            Some(b"{\"value\":\"new\"}"),
            0o600,
        )
        .unwrap();
        assert_eq!(mutation_lock(&target).unwrap_err().code, "lock-busy");
        assert_eq!(
            configure_native_input(&target, false, std::future::ready(Err(cancelled())))
                .await
                .unwrap_err()
                .code,
            "lock-busy"
        );
        assert_eq!(
            run(&[
                "remove-local".into(),
                "--file".into(),
                target.to_str().unwrap().into(),
                "--yes".into()
            ])
            .await
            .unwrap_err()
            .code,
            "lock-busy"
        );
        assert_eq!(
            std::fs::metadata(mutation_lock_path(&target).unwrap())
                .unwrap()
                .ino(),
            lock_inode
        );
        assert_eq!(common::read_json(&target, true).unwrap()["value"], "new");
        // Parallel subprocess tests can briefly inherit this CLOEXEC descriptor.
        // Release the fixture's shared open-file-description lock explicitly;
        // this test checks stable lock identity across credential replacement.
        assert_eq!(unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_UN) }, 0);
        drop(held);
        assert_eq!(
            mutation_lock(&target).unwrap().metadata().unwrap().ino(),
            lock_inode
        );
        std::fs::remove_dir_all(root).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn lock_names_include_the_complete_filename_and_are_distinct_from_targets() {
        let first = Path::new("/private/credentials.json");
        let second = Path::new("/private/credentials.lock");
        assert_ne!(
            mutation_lock_path(first).unwrap(),
            mutation_lock_path(second).unwrap()
        );
        for target in [
            first.to_path_buf(),
            second.to_path_buf(),
            PathBuf::from("/private").join("x".repeat(250)),
        ] {
            let lock = mutation_lock_path(&target).unwrap();
            assert_ne!(lock, target);
            assert_eq!(lock.parent(), target.parent());
            assert_ne!(mutation_lock_path(&lock).unwrap(), lock);
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_case_aliases_cannot_bypass_credential_mutation_lock() {
        let root = temporary_credentials();
        let target = root.join("cloudflare.json");
        let alias = root.join("CLOUDFLARE.JSON");
        let held = mutation_lock(&target).unwrap();
        assert_eq!(mutation_lock(&alias).unwrap_err().code, "lock-busy");
        assert!(mutation_lock_path(&root.join(".tern-credential-mutation.lock")).is_err());
        drop(held);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_storage_encrypts_and_rejects_tampering_and_plaintext() {
        let root = temporary_credentials();
        let path = root.join("cloudflare.json");
        let key = json!({"provider":"cloudflare","turn_key_id":"test-key","api_token":"test-secret-not-for-production"});
        let bytes = storage_bytes(&key).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("test-secret-not-for-production"));
        crate::install::replace(&path, None, Some(&bytes), 0o600).unwrap();
        assert_eq!(load(&path).unwrap(), key);
        let mut stored: Value = serde_json::from_slice(&bytes).unwrap();
        let mut ciphertext = hex::decode(stored["ciphertext"].as_str().unwrap()).unwrap();
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 1;
        stored["ciphertext"] = json!(hex::encode(ciphertext));
        common::atomic_json(&path, &stored).unwrap();
        assert!(load(&path).is_err());
        common::atomic_json(&path, &key).unwrap();
        assert_eq!(load(&path).unwrap_err().code, "credential-reconfigure-required");
        assert_eq!(common::read_json(&path, true).unwrap(), key);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn cancelled_windows_replacement_preserves_existing_credentials() {
        let root = temporary_credentials();
        let target = root.join("cloudflare.json");
        let previous = json!({"provider":"cloudflare","turn_key_id":"test-key","api_token":"test-token"});
        common::atomic_json(&target, &previous).unwrap();
        let error = configure_native_input(&target, true, std::future::ready(Err(cancelled())))
            .await.unwrap_err();
        assert_eq!(error.code, "cancelled");
        assert_eq!(common::read_json(&target, true).unwrap(), previous);
        std::fs::remove_dir_all(root).unwrap();
    }
}
