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
/// Only positively classified transient issuance failures may be retried.
pub(crate) fn retryable(error: &Error) -> bool {
    matches!(
        error.code,
        "credential-network" | "credential-rate-limited" | "credential-unavailable"
    )
}

enum TransportEvidence {
    Transient,
    Terminal,
    Unknown,
}

fn transport_evidence(error: &(dyn std::error::Error + 'static)) -> TransportEvidence {
    // A TLS failure can be wrapped in an io::Error and still be a connect error.
    // Inspect typed causes only; error text may contain the secret request URL.
    if error.is::<rustls::Error>() {
        return TransportEvidence::Terminal;
    }
    let io = error.downcast_ref::<std::io::Error>();
    let own = match io.map(std::io::Error::kind) {
        Some(
            std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::NetworkUnreachable
            | std::io::ErrorKind::HostUnreachable,
        ) => TransportEvidence::Transient,
        Some(
            std::io::ErrorKind::InvalidData
            | std::io::ErrorKind::InvalidInput
            | std::io::ErrorKind::PermissionDenied,
        ) => TransportEvidence::Terminal,
        _ => TransportEvidence::Unknown,
    };
    // io::Error::source may skip the wrapped error itself; inspect get_ref first.
    let source = match io.and_then(std::io::Error::get_ref) {
        Some(inner) => Some(inner as &(dyn std::error::Error + 'static)),
        None => error.source(),
    };
    let nested = source.map_or(TransportEvidence::Unknown, transport_evidence);
    match (own, nested) {
        (TransportEvidence::Terminal, _) | (_, TransportEvidence::Terminal) => TransportEvidence::Terminal,
        (TransportEvidence::Transient, _) | (_, TransportEvidence::Transient) => TransportEvidence::Transient,
        _ => TransportEvidence::Unknown,
    }
}

fn request_error(error: reqwest::Error) -> Error {
    let retry = match transport_evidence(&error) {
        TransportEvidence::Terminal => false,
        TransportEvidence::Transient => true,
        TransportEvidence::Unknown => error.is_timeout(),
    };
    if retry && !error.is_builder() && !error.is_redirect() && !error.is_decode() {
        Error::with_exit(
            "credential-network",
            "Cloudflare TURN credential issuance encountered a transient network failure.",
            5,
        )
    } else {
        remote_error()
    }
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
        .await;
    issue_response(response, issued, ttl).await
}

async fn issue_response(
    response: reqwest::Result<reqwest::Response>,
    issued: f64,
    ttl: u64,
) -> Result<Value> {
    let response = response.map_err(request_error)?;
    if response.content_length().is_some_and(|n| n > 131072) {
        return Err(remote_error());
    }
    let transient = if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
        Some(Error::with_exit(
            "credential-rate-limited",
            "Cloudflare TURN credential issuance is temporarily rate limited.",
            5,
        ))
    } else if response.status().is_server_error() {
        Some(Error::with_exit(
            "credential-unavailable",
            "Cloudflare TURN credential issuance is temporarily unavailable.",
            5,
        ))
    } else if response.status().is_success() {
        None
    } else {
        return Err(remote_error());
    };
    let mut stream = response.bytes_stream();
    let mut raw = Vec::new();
    let mut received = 0usize;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(request_error)?;
        if chunk.len() > 131072 - received {
            return Err(remote_error());
        }
        received += chunk.len();
        if transient.is_none() {
            raw.extend_from_slice(&chunk);
        }
    }
    // Even error responses must satisfy the streaming bound, not just a claimed
    // Content-Length. Discard their bodies without retaining potentially secret data.
    if let Some(error) = transient {
        return Err(error);
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

#[cfg(target_os = "macos")]
const DIALOG: &str = r#"try
    set keyID to text returned of (display dialog "Cloudflare TURN key ID" default answer "" with hidden answer buttons {"Cancel", "Continue"} default button "Continue" cancel button "Cancel" with title "Tern TURN setup")
    set apiToken to text returned of (display dialog "Cloudflare TURN-key API token (not an account token). Continue validates it with Cloudflare and saves it privately on this Mac." default answer "" with hidden answer buttons {"Cancel", "Validate and Save"} default button "Validate and Save" cancel button "Cancel" with title "Tern TURN setup")
    if (length of keyID) > 128 or (length of apiToken) > 8192 then return "__INVALID__"
    return keyID & linefeed & apiToken
on error number -128
    return "__CANCELLED__"
end try"#;

#[cfg(any(windows, target_os = "macos", test))]
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

#[cfg(target_os = "macos")]
async fn native_key() -> Result<Value> {
    let output = common::run(
        "/usr/bin/osascript",
        &["-e".into(), DIALOG.into()],
        None,
        Duration::from_secs(300),
    )
    .await
    .map_err(|_| native_failed())?;
    if !output.status.success() {
        return Err(invalid());
    }
    parse_native(&output.stdout)
}
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn native_failed() -> Error {
    Error::with_exit(
        "credential-error",
        "Native hidden credential input failed or timed out.",
        4,
    )
}
/// Desktop hidden-entry dialogs at fixed system paths; PATH is never searched.
#[cfg(target_os = "linux")]
const LINUX_DIALOGS: &[&str] = &["/usr/bin/zenity", "/usr/bin/kdialog"];
#[cfg(target_os = "linux")]
async fn hidden_dialog(program: &str, prompt: &str, limit: usize) -> Result<String> {
    let args: Vec<String> = if program.ends_with("/zenity") {
        ["--entry", "--hide-text", "--title", "Tern TURN setup", "--text", prompt]
            .map(str::to_owned)
            .to_vec()
    } else {
        ["--title", "Tern TURN setup", "--password", prompt].map(str::to_owned).to_vec()
    };
    let output = common::run(program, &args, None, Duration::from_secs(150))
        .await
        .map_err(|_| native_failed())?;
    // Both dialogs exit 1 when the user cancels or closes the window.
    if output.status.code() == Some(1) {
        return Err(cancelled());
    }
    if !output.status.success() {
        return Err(native_failed());
    }
    let text = std::str::from_utf8(&output.stdout).map_err(|_| invalid())?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    if text.len() > limit || text.contains('\n') {
        return Err(invalid());
    }
    Ok(text.to_owned())
}
#[cfg(target_os = "linux")]
async fn native_key() -> Result<Value> {
    let graphical = ["DISPLAY", "WAYLAND_DISPLAY"]
        .iter()
        .any(|name| std::env::var_os(name).is_some_and(|value| !value.is_empty()));
    let dialog = LINUX_DIALOGS.iter().copied().find(|path| {
        std::fs::metadata(path).is_ok_and(|m| m.is_file())
    });
    let Some(program) = dialog.filter(|_| graphical) else {
        return terminal_key().map_err(|_| Error::with_exit(
            "credential-error",
            "Hidden credential input needs a desktop session with zenity or kdialog in /usr/bin, or a terminal.",
            4,
        ));
    };
    let id = hidden_dialog(program, "Cloudflare TURN key ID", 128).await?;
    let token = hidden_dialog(
        program,
        "Cloudflare TURN-key API token (not an account token). Continuing validates it with Cloudflare and saves it privately on this computer.",
        8192,
    )
    .await?;
    validate(json!({"provider":"cloudflare","turn_key_id":id,"api_token":token}))
}
#[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
async fn native_key() -> Result<Value> {
    terminal_key()
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
    // Exercise the production issuance-result boundary with real reqwest HTTP,
    // timeout and TLS errors. No production endpoint or TLS policy is overridden.
    async fn issuance_fixture(reply: Option<String>, tls: bool) -> reqwest::Result<reqwest::Response> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4096];
            stream.read(&mut request).await.unwrap();
            if let Some(reply) = reply {
                let _ = stream.write_all(reply.as_bytes()).await;
            } else {
                std::future::pending::<()>().await;
            }
        });
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_millis(250))
            .build()
            .unwrap();
        let scheme = if tls { "https" } else { "http" };
        let result = client
            .get(format!("{scheme}://{address}/private-key-fixture"))
            .send()
            .await;
        server.abort();
        result
    }

    async fn http_issuance(status: u16, body: &str) -> Result<Value> {
        let reply = format!(
            "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        issue_response(issuance_fixture(Some(reply), false).await, 1000.0, 86400).await
    }

    #[tokio::test]
    async fn rate_limited_issuance_can_retry() {
        assert!(retryable(&http_issuance(429, "private-response-fixture").await.unwrap_err()));
    }

    #[tokio::test]
    async fn unavailable_issuance_can_retry() {
        assert!(retryable(&http_issuance(503, "private-response-fixture").await.unwrap_err()));
    }

    #[tokio::test]
    async fn timed_out_issuance_can_retry_without_exposing_request_url() {
        let result = issuance_fixture(None, false).await;
        assert!(result.as_ref().unwrap_err().is_timeout());
        let error = issue_response(result, 1000.0, 86400).await.unwrap_err();
        assert!(!error.to_string().contains("private-key-fixture"));
        assert!(retryable(&error));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn reset_issuance_connection_can_retry() {
        use tokio::io::AsyncReadExt;

        // Own a listening endpoint and reset an established request explicitly;
        // a bound non-listening port does not portably produce connection refusal.
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4096];
            assert!(stream.read(&mut request).await.unwrap() > 0);
            let linger = libc::linger { l_onoff: 1, l_linger: 0 };
            assert_eq!(unsafe {
                libc::setsockopt(
                    stream.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_LINGER,
                    (&linger as *const libc::linger).cast(),
                    std::mem::size_of::<libc::linger>() as libc::socklen_t,
                )
            }, 0);
            drop(stream);
        });
        let result = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap()
            .get(format!("http://{address}/private-key-fixture"))
            .send()
            .await;
        server.await.unwrap();
        let request_error = result.as_ref().unwrap_err();
        assert!(!request_error.is_timeout());
        let mut cause: Option<&(dyn std::error::Error + 'static)> = Some(request_error);
        let mut reset = false;
        while let Some(error) = cause {
            if error.downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::ConnectionReset)
            {
                reset = true;
                break;
            }
            cause = error.source();
        }
        assert!(reset, "fixture must produce a concrete TCP reset, not an unrelated failure");
        let error = issue_response(result, 1000.0, 86400).await.unwrap_err();
        assert!(retryable(&error));
        assert!(!error.to_string().contains("private-key-fixture"));
    }

    #[tokio::test]
    async fn malformed_http_issuance_remains_terminal() {
        let result = issuance_fixture(Some("not-an-http-response\r\n\r\n".into()), false).await;
        assert!(result.is_err());
        assert!(!retryable(&issue_response(result, 1000.0, 86400).await.unwrap_err()));
    }

    #[tokio::test]
    async fn chunked_transient_issuance_requires_a_bounded_response() {
        for status in [429, 503] {
            for size in [16, 131073] {
                let reply = format!(
                    "HTTP/1.1 {status} Fixture\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{size:x}\r\n{}\r\n0\r\n\r\n",
                    "x".repeat(size)
                );
                let response = issuance_fixture(Some(reply), false).await;
                assert!(response.as_ref().unwrap().content_length().is_none());
                let error = issue_response(response, 1000.0, 86400).await.unwrap_err();
                assert_eq!(retryable(&error), size == 16, "status {status}, size {size}");
            }
        }
    }

    #[tokio::test]
    async fn issuance_security_and_protocol_failures_remain_terminal() {
        for status in [301, 302, 307, 308, 400, 401, 403] {
            let error = http_issuance(status, "private-response-fixture").await.unwrap_err();
            assert!(!retryable(&error), "status {status}");
            assert!(!error.to_string().contains("private-response-fixture"));
        }
        for body in ["not-json", "{}", "{\"iceServers\":[]}"] {
            assert!(!retryable(&http_issuance(200, body).await.unwrap_err()));
        }
        for status in [200, 429, 503] {
            assert!(!retryable(&http_issuance(status, &"x".repeat(131073)).await.unwrap_err()));
        }

        // A connect error can be a TLS failure, not a transient network outage.
        let result = issuance_fixture(
            Some("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".into()),
            true,
        ).await;
        assert!(result.as_ref().unwrap_err().is_connect());
        let error = issue_response(result, 1000.0, 86400).await.unwrap_err();
        assert!(!retryable(&error));
        assert!(!error.to_string().contains("private-key-fixture"));
        assert!(!retryable(&validate(json!({"provider":"invalid"})).unwrap_err()));
    }

    #[tokio::test]
    async fn untrusted_certificate_issuance_remains_terminal() {
        use base64::Engine;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

        // Isolated self-signed localhost fixture, never trusted by the client.
        let certificate = base64::engine::general_purpose::STANDARD.decode("MIIBNTCB3aADAgECAgkA1l/bYXWB8ZQwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MTEwMzAxMTAwM1oXDTM2MTAzMTAxMTAwM1owFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOvdQQhnbWhcKjctPQfumvwqDfGIGMBYoL9Ay40VVyNFeXlR0lpBR0Er0p+6inwgEjrttOTezBn79C2/uH/4seqMYMBYwFAYDVR0RBA0wC4IJbG9jYWxob3N0MAoGCCqGSM49BAMCA0cAMEQCHykeh7xfi47nH1ZhL59EA+stUtKLLx3s7igXQ0WTgqYCIQCUD61QQvDNf3Q6n/cg6dJAUT1MQmSGw6Vk6kEppdotOA==").unwrap();
        let key = base64::engine::general_purpose::STANDARD.decode("MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgJc9d23Vo1Le7KaqvzrsanFIZBncpx2gHIvtJAw4X/BahRANCAAQ691BCGdtaFwqNy09B+6a/CoN8YgYwFigv0DLjRVXI0V5eVHSWkFHQSvSn7qKfCASOu205N7MGfv0Lb+4f/ix6").unwrap();
        let config = rustls::ServerConfig::builder_with_provider(
            std::sync::Arc::new(rustls::crypto::ring::default_provider()),
        )
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(certificate)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
        )
        .unwrap();
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config));
            let _ = acceptor.accept(stream).await;
        });
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .resolve("localhost", address)
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        let result = client
            .get(format!("https://localhost:{}/private-key-fixture", address.port()))
            .send()
            .await;
        server.abort();

        fn certificate_rejected(error: &(dyn std::error::Error + 'static)) -> bool {
            if matches!(error.downcast_ref::<rustls::Error>(), Some(rustls::Error::InvalidCertificate(_))) {
                return true;
            }
            if let Some(inner) = error.downcast_ref::<std::io::Error>().and_then(std::io::Error::get_ref) {
                if certificate_rejected(inner) {
                    return true;
                }
            }
            error.source().is_some_and(certificate_rejected)
        }
        let request_error = result.as_ref().unwrap_err();
        assert!(request_error.is_connect());
        assert!(certificate_rejected(request_error));
        let error = issue_response(result, 1000.0, 86400).await.unwrap_err();
        assert!(!retryable(&error));
        assert!(!error.to_string().contains("private-key-fixture"));
    }

    #[tokio::test]
    async fn successful_issuance_preserves_validated_payload_and_expiry() {
        let entries = json!([{
            "urls":"turns:turn.cloudflare.com:5349?transport=tcp",
            "username":"fixture-user",
            "credential":"fixture-password"
        }]);
        let result = http_issuance(200, &json!({"iceServers":entries}).to_string())
            .await
            .unwrap();
        assert_eq!(result["entries"], entries);
        assert_eq!(result["expires_unix"], json!(87400.0));
        for ttl in [0, 86401] {
            let error = issue_key(&json!({}), ttl).await.unwrap_err();
            assert!(!retryable(&error));
        }
    }

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
