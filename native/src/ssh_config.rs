//! Exact loopback/user/port SSH compatibility. Unrelated rules are byte-preserved.
use crate::common::{self, Error, Result};
use crate::install::{self, Snapshot};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const BEGIN: &str = "# BEGIN tern-turn-relay SSH compatibility\n";
pub const END: &str = "# END tern-turn-relay SSH compatibility\n";
fn error() -> Error {
    Error::new("ssh-config-changed", "SSH compatibility rule is unsafe, changed or does not match the verified target; existing content was preserved.")
}
pub fn without_block(text: &str) -> Result<&str> {
    if !text.contains(BEGIN) && !text.contains(END) {
        return Ok(text);
    }
    if !text.starts_with(BEGIN)
        || text.matches(BEGIN).count() != 1
        || text.matches(END).count() != 1
    {
        return Err(error());
    }
    let (_, remainder) = text.split_once(END).ok_or_else(error)?;
    Ok(remainder)
}
pub fn block_digest(text: &str) -> Result<Option<String>> {
    let rest = without_block(text)?;
    if rest.len() == text.len() {
        Ok(None)
    } else {
        Ok(Some(hex::encode(Sha256::digest(
            &text.as_bytes()[..text.len() - rest.len()],
        ))))
    }
}
fn quoted(value: &str) -> Result<String> {
    if value.chars().any(char::is_control) {
        return Err(error());
    }
    Ok(format!(
        "\"{}\"",
        value.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}
fn parse_options(bytes: &[u8]) -> Result<BTreeMap<String, Vec<String>>> {
    let text = std::str::from_utf8(bytes).map_err(|_| error())?;
    let mut result = BTreeMap::<String, Vec<String>>::new();
    for line in text.lines() {
        if let Some((key, value)) = line.split_once(' ') {
            if value.chars().any(char::is_control) {
                return Err(error());
            }
            result
                .entry(key.to_ascii_lowercase())
                .or_default()
                .push(value.to_owned());
        }
    }
    Ok(result)
}
fn first<'a>(options: &'a BTreeMap<String, Vec<String>>, name: &str) -> Result<&'a str> {
    options
        .get(name)
        .and_then(|v| v.first())
        .map(String::as_str)
        .ok_or_else(error)
}

const TRUST_KEYS: [&str; 2] = ["userknownhostsfile", "globalknownhostsfile"];
type TrustFiles = BTreeMap<String, Vec<String>>;
struct ResolvedOptions {
    options: BTreeMap<String, Vec<String>>,
    trust: TrustFiles,
}
fn trust_error() -> Error {
    Error::new("ssh-trust-ambiguous", "无法从稳定的 OpenSSH 配置来源无歧义恢复 known-hosts 文件集合；原 SSH 配置已保留。")
}

// This lexer handles only the two file-list directives, not Host, Match or
// Include selection. Native OpenSSH remains the sole configuration evaluator.
fn trust_words(value: &str) -> Result<Vec<String>> {
    let mut chars = value.chars().peekable();
    let mut result = Vec::new();
    while chars.peek().is_some() {
        while chars.peek().is_some_and(|c| c.is_ascii_whitespace()) { chars.next(); }
        if chars.peek().is_none_or(|c| *c == '#') { break; }
        let mut word = String::new();
        let mut quote = None;
        while let Some(c) = chars.next() {
            if c == '\\' && chars.peek().is_some_and(|next| matches!(*next, '\\' | '\'' | '"' | ' ' | '\t')) {
                word.push(chars.next().ok_or_else(trust_error)?);
            } else if quote == Some(c) {
                quote = None;
            } else if quote.is_none() && matches!(c, '\'' | '"') {
                quote = Some(c);
            } else if quote.is_none() && c.is_ascii_whitespace() {
                break;
            } else {
                word.push(c);
            }
        }
        if quote.is_some() || word.is_empty() || word.chars().any(char::is_control) || result.len() >= 16 {
            return Err(trust_error());
        }
        result.push(word);
    }
    if result.is_empty() { return Err(trust_error()); }
    Ok(result)
}
fn trust_directives(bytes: &[u8]) -> Result<Vec<(String, Vec<String>)>> {
    let text = std::str::from_utf8(bytes).map_err(|_| trust_error())?;
    let mut result = Vec::new();
    for line in text.lines() {
        let line = line.trim_start();
        if line.is_empty() || line.starts_with('#') { continue; }
        // Refuse alternate keyword spellings/continuations instead of losing a
        // possible directive from the exhaustive candidate inventory.
        if line.starts_with(['\'', '"']) || line.ends_with('\\') { return Err(trust_error()); }
        let end = line.find(|c: char| c.is_ascii_whitespace() || c == '=').unwrap_or(line.len());
        let key = line[..end].to_ascii_lowercase();
        if !TRUST_KEYS.contains(&key.as_str()) { continue; }
        let rest = line[end..].trim_start();
        let rest = rest.strip_prefix('=').unwrap_or(rest).trim_start();
        result.push((key, trust_words(rest)?));
        if result.len() > 32 { return Err(trust_error()); }
    }
    Ok(result)
}
fn source_paths(stderr: &[u8]) -> Result<BTreeSet<PathBuf>> {
    let mut paths = BTreeSet::new();
    for line in stderr.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(bytes) = line.strip_prefix(b"debug1: Reading configuration data ") else {
            if line.windows(b"Reading configuration data".len()).any(|part| part == b"Reading configuration data") { return Err(trust_error()); }
            continue;
        };
        // macOS OpenSSH 可混合原始 UTF-8 字节与八进制转义；必须先恢复字节，
        // 再验证完整路径的 UTF-8，不能对整段诊断提前解码或有损替换。
        let mut decoded = Vec::with_capacity(bytes.len());
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] != b'\\' {
                decoded.push(bytes[index]);
                index += 1;
            } else if bytes.get(index + 1) == Some(&b'\\') {
                decoded.push(b'\\');
                index += 2;
            } else {
                let digits = bytes.get(index + 1..index + 4).ok_or_else(trust_error)?;
                if !digits.iter().all(|b| matches!(*b, b'0'..=b'7')) { return Err(trust_error()); }
                let value = u16::from(digits[0] - b'0') * 64
                    + u16::from(digits[1] - b'0') * 8 + u16::from(digits[2] - b'0');
                decoded.push(u8::try_from(value).map_err(|_| trust_error())?);
                index += 4;
            }
        }
        let path = String::from_utf8(decoded).map_err(|_| trust_error())?;
        common::safe_local_absolute(&path).map_err(|_| trust_error())?;
        paths.insert(PathBuf::from(path));
        if paths.len() > 16 { return Err(trust_error()); }
    }
    Ok(paths)
}

#[cfg(windows)]
type SourceHandle = crate::windows_security::Opened;
#[cfg(unix)]
type SourceHandle = std::fs::File;
#[cfg(windows)]
type SourceStamp = (crate::windows_security::Identity, Vec<u8>);
#[cfg(unix)]
type SourceStamp = (u64, u64, u64, i64, i64, u32, u32, u32);
struct ConfigSource {
    path: PathBuf,
    bytes: Vec<u8>,
    stamp: SourceStamp,
    _held: SourceHandle,
}
fn config_stamp(file: &std::fs::File) -> Result<SourceStamp> {
    #[cfg(windows)]
    {
        let id = crate::windows_security::identity(file, false)?;
        if id.size > 65536 { return Err(trust_error()); }
        Ok((id, crate::windows_security::check_acl(file, false, false, false)?))
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let m = file.metadata().map_err(|_| trust_error())?;
        if !m.is_file() || m.nlink() != 1 || m.len() > 65536 || common::foreign_writable(m.mode(), m.gid())
            || (m.uid() != 0 && m.uid() != unsafe { libc::getuid() }) { return Err(trust_error()); }
        Ok((m.dev(), m.ino(), m.len(), m.mtime(), m.mtime_nsec(), m.uid(), m.gid(), m.mode()))
    }
}
fn config_source(path: &Path) -> Result<ConfigSource> {
    common::safe_local_absolute(path.to_str().ok_or_else(trust_error)?)?;
    #[cfg(windows)]
    let mut held = {
        // The trusted-owner read policy also permits SYSTEM-owned ssh_config;
        // never apply the system executable hard-link exception to a source.
        if path.extension().is_some_and(|s| s.eq_ignore_ascii_case("exe") || s.eq_ignore_ascii_case("com")) {
            return Err(trust_error());
        }
        crate::windows_security::open(path, false, true)?.ok_or_else(trust_error)?
    };
    #[cfg(unix)]
    let mut held = {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let canonical = path.canonicalize().map_err(|_| trust_error())?;
        for parent in canonical.ancestors().skip(1) {
            let m = std::fs::symlink_metadata(parent).map_err(|_| trust_error())?;
            if !m.is_dir() || (m.uid() != 0 && m.uid() != unsafe { libc::getuid() })
                || (common::foreign_writable(m.mode(), m.gid()) && !(m.uid() == 0 && m.mode() & 0o1000 != 0)) {
                return Err(trust_error());
            }
        }
        std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(canonical).map_err(|_| trust_error())?
    };
    #[cfg(windows)]
    let file = &mut held.file;
    #[cfg(unix)]
    let file = &mut held;
    let stamp = config_stamp(file)?;
    let mut bytes = Vec::new();
    (&mut *file).take(65537).read_to_end(&mut bytes).map_err(|_| trust_error())?;
    if bytes.len() > 65536 || config_stamp(file)? != stamp { return Err(trust_error()); }
    Ok(ConfigSource { path: path.to_owned(), bytes, stamp, _held: held })
}
fn verify_sources(sources: &[ConfigSource]) -> Result<()> {
    for source in sources {
        let fresh = config_source(&source.path)?;
        if fresh.stamp != source.stamp || fresh.bytes != source.bytes { return Err(trust_error()); }
    }
    Ok(())
}
async fn native_dump(executable: &str, invocation: &[String], extra: &[String], trace: bool) -> Result<std::process::Output> {
    let mut args = Vec::with_capacity(invocation.len() + extra.len() + 2);
    args.push("-G".into());
    if trace { args.push("-vvv".into()); }
    args.extend_from_slice(extra);
    args.extend_from_slice(invocation);
    let output = common::run(executable, &args, None, Duration::from_secs(5)).await?;
    if !output.status.success() || output.stdout.len() > 65536 || output.stderr.len() > 262144 {
        return Err(trust_error());
    }
    Ok(output)
}
async fn expand_trust_item(executable: &str, invocation: &[String], key: &str, item: &str,
    cache: &mut BTreeMap<(String, String), String>) -> Result<String> {
    let cache_key = (key.to_owned(), item.to_owned());
    if let Some(value) = cache.get(&cache_key) { return Ok(value.clone()); }
    if cache.len() >= 16 { return Err(trust_error()); }
    let output = native_dump(executable, invocation, &["-o".into(), format!("{key} {}", quoted(item)?)], false).await?;
    let options = parse_options(&output.stdout)?;
    let value = first(&options, key)?.to_owned();
    cache.insert(cache_key, value.clone());
    Ok(value)
}
fn validate_trust_vector(key: &str, values: &[String], native_default: bool) -> Result<()> {
    if values.is_empty() || values.len() > 16 { return Err(trust_error()); }
    if values.len() == 1 && values[0] == "none" { return Ok(()); }
    for value in values {
        #[cfg(windows)]
        if native_default && key == "globalknownhostsfile" && matches!(value.as_str(),
            "__PROGRAMDATA__\\ssh/ssh_known_hosts" | "__PROGRAMDATA__\\ssh/ssh_known_hosts2") { continue; }
        let _ = (key, native_default);
        common::safe_local_absolute(value).map_err(|_| trust_error())?;
    }
    Ok(())
}
async fn resolve_native_options(executable: &str, invocation: &[String]) -> Result<ResolvedOptions> {
    let observed = native_dump(executable, invocation, &[], true).await?;
    let options = parse_options(&observed.stdout)?;
    let paths = source_paths(&observed.stderr)?;
    let mut sources = Vec::with_capacity(paths.len());
    let mut directives = Vec::new();
    for path in &paths {
        let source = config_source(path)?;
        directives.extend(trust_directives(&source.bytes)?);
        if directives.len() > 32 { return Err(trust_error()); }
        sources.push(source);
    }
    // Default provenance is a separate native invocation with *no* user or
    // system config. A custom flattened value is never treated as that proof.
    let defaults = native_dump(executable, &[
        "-F".into(), "none".into(), "-l".into(), first(&options, "user")?.into(),
        "-p".into(), first(&options, "port")?.into(),
        "-o".into(), format!("HostName={}", first(&options, "hostname")?),
        invocation.last().ok_or_else(trust_error)?.clone(),
    ], &[], false).await?;
    let defaults = parse_options(&defaults.stdout)?;
    let mut cache = BTreeMap::new();
    let mut trust = BTreeMap::new();
    for key in TRUST_KEYS {
        let expected = first(&options, key)?;
        if options.get(key).is_none_or(|v| v.len() != 1) { return Err(trust_error()); }
        let default = if key == "userknownhostsfile" {
            let mut values = Vec::with_capacity(2);
            for raw in ["~/.ssh/known_hosts", "~/.ssh/known_hosts2"] {
                values.push(expand_trust_item(executable, invocation, key, raw, &mut cache).await?);
            }
            values
        } else {
            // The isolated compiled system defaults are the documented two
            // names; unknown native layouts fail instead of splitting custom
            // output (in particular, a quoted path with spaces) heuristically.
            let values: Vec<String> = first(&defaults, key)?.split_ascii_whitespace().map(str::to_owned).collect();
            if values.len() != 2 || !values[0].ends_with("/ssh_known_hosts")
                || !values[1].ends_with("/ssh_known_hosts2") { return Err(trust_error()); }
            values
        };
        if default.join(" ") != first(&defaults, key)? { return Err(trust_error()); }
        let mut selected = if default.join(" ") == expected { Some((default.clone(), true)) } else { None };
        for (candidate_key, raw) in &directives {
            if candidate_key != key { continue; }
            let mut candidate = Vec::with_capacity(raw.len());
            for item in raw {
                candidate.push(expand_trust_item(executable, invocation, key, item, &mut cache).await?);
            }
            if candidate.join(" ") != expected { continue; }
            // Compare every matching vector BEFORE validating paths. Dropping
            // an invalid/relative candidate here could widen the trusted set.
            if selected.as_ref().is_some_and(|(prior, _)| prior != &candidate) { return Err(trust_error()); }
            if selected.is_none() { selected = Some((candidate, false)); }
        }
        let (values, is_default) = selected.ok_or_else(trust_error)?;
        validate_trust_vector(key, &values, is_default)?;
        trust.insert(key.to_owned(), values);
    }
    verify_sources(&sources)?;
    let confirmed = native_dump(executable, invocation, &[], true).await?;
    if source_paths(&confirmed.stderr)? != paths || parse_options(&confirmed.stdout)? != options { return Err(trust_error()); }
    verify_sources(&sources)?;
    Ok(ResolvedOptions { options, trust })
}
fn expand(value: &str, host: &str, alias: &str, port: &str, user: &str, home: &str) -> String {
    let mut result = String::new();
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            result.push(c);
            continue;
        }
        match chars.next() {
            Some('h') => result.push_str(host),
            Some('n') => result.push_str(alias),
            Some('p') => result.push_str(port),
            Some('r') => result.push_str(user),
            Some('d') => result.push_str(home),
            Some('%') => result.push('%'),
            Some(other) => {
                result.push('%');
                result.push(other);
            }
            None => result.push('%'),
        }
    }
    result
}
fn render(
    config: &Value,
    options: &BTreeMap<String, Vec<String>>,
    home: &str,
    trust: &TrustFiles,
) -> Result<(String, String)> {
    let host = first(options, "hostname")?;
    let user = first(options, "user")?;
    let port = first(options, "port")?;
    let alias = config["ssh_destination"].as_str().ok_or_else(error)?;
    if Some(host) != config["target"]["host"].as_str()
        || Some(user) != config["target"]["user"].as_str()
        || port.parse::<u16>().ok().is_none_or(|p| p == 0)
    {
        return Err(error());
    }
    common::safe_alias(user)?;
    if user.len() > 64 {
        return Err(error());
    }
    let default_pin = if port == "22" {
        host.to_owned()
    } else {
        format!("[{host}]:{port}")
    };
    let pin = options
        .get("hostkeyalias")
        .and_then(|v| v.first())
        .filter(|s| s.as_str() != "none")
        .cloned()
        .unwrap_or(default_pin);
    let listen = config["listen_port"]
        .as_u64()
        .filter(|n| (1024..=65535).contains(n))
        .ok_or_else(error)?;
    #[cfg(unix)]
    let port_match = format!("test %p = {listen}");
    #[cfg(windows)]
    let port_match = {
        let command = crate::windows_process::system_program("cmd.exe")?;
        // Match exec has its own double-quote delimiter; nesting quoted argv
        // here is not portable to Win32 OpenSSH. Only a literal shell-safe
        // system pathname may enter this command (never PATH or COMSPEC).
        if !command.bytes().all(|c| c.is_ascii_alphanumeric() || b":\\._-".contains(&c)) {
            return Err(Error::new("ssh-match-shell", "系统 cmd.exe 路径无法安全写入 OpenSSH Match exec；未修改 SSH 规则。"));
        }
        format!("{command} /d /c if %p=={listen} (exit /b 0) else (exit /b 1)")
    };
    let mut lines = vec![
        BEGIN.trim_end().to_owned(),
        format!("Match originalhost 127.0.0.1 user {user} exec {}", quoted(&port_match)?),
        format!("    HostKeyAlias {}", quoted(&pin)?),
        "    StrictHostKeyChecking yes".into(),
        "    CheckHostIP no".into(),
        "    PasswordAuthentication no".into(),
        "    KbdInteractiveAuthentication no".into(),
        "    PreferredAuthentications publickey".into(),
        "    PubkeyAuthentication yes".into(),
        "    ForwardAgent no".into(),
        "    ProxyCommand none".into(),
        "    ProxyJump none".into(),
        "    CanonicalizeHostname no".into(),
    ];
    for key in [
        "identityfile",
        "certificatefile",
        "identityagent",
        "identitiesonly",
        "hostkeyalgorithms",
    ] {
        if let Some(values) = options.get(key) {
            for value in values {
                lines.push(format!(
                    "    {key} {}",
                    quoted(&expand(value, host, alias, port, user, home))?
                ));
            }
        }
    }
    for key in TRUST_KEYS {
        if let Some(values) = trust.get(key) {
            let mut line = format!("    {key}");
            for value in values {
                // UserKnownHostsFile has already been expanded by native -G.
                // Escape literal percent signs for its second parse only.
                let quoted_value = if key == "userknownhostsfile" {
                    quoted(&value.replace('%', "%%"))?
                } else { quoted(value)? };
                line.push(' ');
                line.push_str(&quoted_value);
            }
            lines.push(line);
        }
    }
    lines.push("Match all".into());
    lines.push(END.trim_end().into());
    Ok((lines.join("\n") + "\n", pin))
}
pub struct Prepared {
    pub before: Option<Snapshot>,
    pub bytes: Vec<u8>,
    pub digest: String,
}
fn combine_rule(old: &str, block: &str, expected: Option<&str>) -> Result<Vec<u8>> {
    if block_digest(old)?.as_deref() != expected {
        return Err(error());
    }
    let remainder = without_block(old)?;
    if block.len() + remainder.len() > 65536 {
        return Err(error());
    }
    let mut result = String::with_capacity(block.len() + remainder.len());
    result.push_str(block);
    result.push_str(remainder);
    Ok(result.into_bytes())
}
pub async fn prepare(config: &Value, path: &Path, expected: Option<&str>) -> Result<Prepared> {
    let alias = config["ssh_destination"].as_str().ok_or_else(error)?;
    common::safe_alias(alias)?;
    let executable = common::ssh_executable()?;
    let resolved = resolve_native_options(&executable, &[alias.into()]).await?;
    let home = install::home()?;
    let (block, pin) = render(config, &resolved.options, home.to_str().ok_or_else(error)?, &resolved.trust)?;
    let before = install::snapshot(path, 65536)?;
    let old = std::str::from_utf8(before.as_ref().map(|s| s.bytes.as_slice()).unwrap_or(b""))
        .map_err(|_| error())?;
    let bytes = combine_rule(old, &block, expected)?;
    let staged = path.with_file_name(format!(".tern-ssh-{:032x}", rand::random::<u128>()));
    install::replace(&staged, None, Some(&bytes), 0o600)?;
    let validation = resolve_native_options(&executable, &[
        "-F".into(), staged.to_str().ok_or_else(error)?.into(),
        "-p".into(), config["listen_port"].to_string(),
        format!("{}@127.0.0.1", config["target"]["user"].as_str().ok_or_else(error)?),
    ]).await;
    let staged_snapshot = install::snapshot(&staged, 65536)?;
    install::replace(&staged, staged_snapshot.as_ref(), None, 0o600)?;
    let effective = validation?;
    if first(&effective.options, "hostkeyalias")? != pin || first(&effective.options, "hostname")? != "127.0.0.1" {
        return Err(error());
    }
    if effective.trust != resolved.trust {
        return Err(Error::new("ssh-trust-changed", "生成的 SSH 入口未保留原 known-hosts 信任集合；SSH 规则未修改。"));
    }
    let digest =
        block_digest(std::str::from_utf8(&bytes).map_err(|_| error())?)?.ok_or_else(error)?;
    Ok(Prepared {
        before,
        bytes,
        digest,
    })
}
pub fn removal(path: &Path, expected: &str) -> Result<Option<Prepared>> {
    let before = install::snapshot(path, 65536)?;
    let Some(snapshot) = &before else {
        return Ok(None);
    };
    let text = std::str::from_utf8(&snapshot.bytes).map_err(|_| error())?;
    let Some(digest) = block_digest(text)? else {
        return Ok(None);
    };
    if digest != expected {
        return Err(error());
    }
    let bytes = without_block(text)?.as_bytes().to_vec();
    Ok(Some(Prepared {
        before,
        bytes,
        digest,
    }))
}
fn words(line: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut escaped = false;
    for c in line.chars() {
        if escaped {
            word.push(c);
            escaped = false;
            continue;
        }
        if c == '\\' && quote != Some('\'') {
            escaped = true;
            continue;
        }
        if let Some(delimiter) = quote {
            if c == delimiter {
                quote = None;
            } else {
                word.push(c);
            }
        } else if c == '#' {
            break;
        } else if c == '"' || c == '\'' {
            quote = Some(c);
        } else if c.is_whitespace() {
            if !word.is_empty() {
                words.push(std::mem::take(&mut word));
            }
        } else {
            word.push(c);
        }
    }
    if quote.is_some() || escaped {
        return None;
    }
    if !word.is_empty() {
        words.push(word);
    }
    Some(words)
}
/// Inventory literal Host entries only; no Include traversal, SSH or Match execution.
pub fn aliases(path: &Path) -> Result<Value> {
    let mut aliases = std::collections::BTreeSet::new();
    if let Some(file) = install::snapshot(path, 65536)? {
        let text = std::str::from_utf8(&file.bytes).map_err(|_| error())?;
        for line in text.lines() {
            let Some(words) = words(line) else {
                continue;
            };
            let mut words = words.into_iter();
            if !words.next().is_some_and(|w| w.eq_ignore_ascii_case("host")) {
                continue;
            }
            for alias in words {
                if common::safe_alias(&alias).is_ok() {
                    aliases.insert(alias);
                }
                if aliases.len() >= 64 {
                    break;
                }
            }
            if aliases.len() >= 64 {
                break;
            }
        }
    }
    Ok(Value::Array(
        aliases
            .into_iter()
            .map(|s| serde_json::json!({"label":s,"value":s}))
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_paths_decode_mixed_native_bytes_before_utf8_validation() {
        let prefix = if cfg!(windows) { "C:/fixture/" } else { "/fixture/" };
        let mut diagnostic = b"debug3: unrelated \xff\n debug note\n".to_vec();
        diagnostic.extend_from_slice(b"debug1: Reading configuration data ");
        diagnostic.extend_from_slice(prefix.as_bytes());
        diagnostic.extend_from_slice(b"\xe4\\270\xad config\r\n");
        assert!(std::str::from_utf8(&diagnostic).is_err());
        assert_eq!(source_paths(&diagnostic).unwrap(), BTreeSet::from([PathBuf::from(format!("{prefix}中 config"))]));
        let invalid = format!("debug1: Reading configuration data {prefix}\\377\n");
        assert!(source_paths(invalid.as_bytes()).is_err());
    }

    #[test]
    fn alias_tokenizer_preserves_quoting_without_executing_config() {
        assert_eq!(
            words("Host one \"two words\" 'three' # ignored").unwrap(),
            vec!["Host", "one", "two words", "three"]
        );
        assert!(words("Host \"unterminated").is_none());
        assert_eq!(words("Host a\\ b").unwrap(), vec!["Host", "a b"]);
    }
    #[test]
    fn removes_only_one_unmodified_prefix() {
        let original = "Host mine\n    HostName 203.0.113.7\n";
        let managed = format!("{BEGIN}Match all\n{END}{original}");
        assert_eq!(without_block(&managed).unwrap(), original);
        assert!(block_digest(&managed).unwrap().is_some());
        assert!(without_block(&(original.to_owned() + &managed)).is_err());
        assert!(without_block(&(managed.clone() + &managed)).is_err());
        assert!(without_block(BEGIN).is_err());
    }
    #[test]
    fn rule_is_scoped_and_inherits_original_endpoint_tokens() {
        let options = parse_options(b"hostname 8.8.8.8\nuser alice\nport 2222\nidentityfile %d/.ssh/%h-%r-%p\nuserknownhostsfile /home/alice/.ssh/known_hosts\n").unwrap();
        let config = serde_json::json!({"ssh_destination":"server","target":{"host":"8.8.8.8","user":"alice"},"listen_port":18377});
        let trust = BTreeMap::from([("userknownhostsfile".into(), vec!["/home/alice/.ssh/known_hosts".into()])]);
        let (block, pin) = render(&config, &options, "/home/alice", &trust).unwrap();
        assert_eq!(pin, "[8.8.8.8]:2222");
        assert!(block.contains("/home/alice/.ssh/8.8.8.8-alice-2222"));
        assert!(block.contains("StrictHostKeyChecking yes"));
        let mut changed = config;
        changed["target"]["host"] = serde_json::json!("1.1.1.1");
        assert!(render(&changed, &options, "/home/alice", &trust).is_err());
    }
    #[test]
    fn rejects_control_character_injection() {
        assert!(quoted("ok\nProxyCommand bad").is_err());
        assert_eq!(quoted("a\\b\"c").unwrap(), "\"a\\\\b\\\"c\"");
        assert_eq!(
            expand("%%-%h-%x", "host", "alias", "22", "user", "/home"),
            "%-host-%x"
        );
    }
    #[test]
    fn retired_rule_can_be_recreated_but_never_adopts_an_unowned_block() {
        let block = format!("{BEGIN}Match all\n{END}");
        let user = "Host unrelated\n";
        assert_eq!(
            combine_rule(user, &block, None).unwrap(),
            format!("{block}{user}").as_bytes()
        );
        let edited = format!("{BEGIN}Host edited\n{END}{user}");
        assert!(combine_rule(&edited, &block, None).is_err());
        let old_digest = block_digest(&block).unwrap().unwrap();
        assert!(combine_rule(user, &block, Some(&old_digest)).is_err());
    }

    #[tokio::test]
    async fn native_ssh_applies_the_rule_only_to_its_exact_loopback_user_and_port() {
        let base = std::env::temp_dir().canonicalize().unwrap();
        #[cfg(windows)]
        let base = crate::windows_security::normalize_system_path(&base).unwrap();
        let directory = base.join(format!("tern-ssh-scope-{:032x}", rand::random::<u128>()));
        common::private_dir(&directory, true).unwrap();
        let options = parse_options(b"hostname 8.8.8.8\nuser alice\nport 2222\n").unwrap();
        let config = serde_json::json!({"ssh_destination":"server","target":{"host":"8.8.8.8","user":"alice"},"listen_port":18377});
        let (block, expected_pin) = render(&config, &options, directory.to_str().unwrap(), &BTreeMap::new()).unwrap();
        let contents = format!("{block}Host *\n    HostKeyAlias baseline\n");
        let file = directory.join("ssh-config");
        install::replace(&file, None, Some(contents.as_bytes()), 0o600).unwrap();
        let executable = common::ssh_executable().unwrap();
        for (host, user, port, expected) in [
            ("127.0.0.1", "alice", "18377", expected_pin.as_str()),
            ("127.0.0.1", "alice", "18378", "baseline"),
            ("127.0.0.1", "bob", "18377", "baseline"),
            ("127.0.0.2", "alice", "18377", "baseline"),
        ] {
            let args = vec!["-G".into(), "-F".into(), file.to_str().unwrap().into(),
                "-l".into(), user.into(), "-p".into(), port.into(), host.into()];
            let output = common::run(&executable, &args, None, Duration::from_secs(10)).await.unwrap();
            assert!(output.status.success(), "native SSH rejected the generated rule");
            let effective = parse_options(&output.stdout).unwrap();
            assert_eq!(first(&effective, "hostkeyalias").unwrap(), expected);
        }
        std::fs::remove_dir_all(directory).unwrap();
    }
    async fn dump_fixture(path: &Path, destination: &str, port: &str) -> BTreeMap<String, Vec<String>> {
        let executable = common::ssh_executable().unwrap();
        let output = common::run(&executable, &[
            "-G".into(), "-F".into(), path.to_str().unwrap().into(),
            "-l".into(), "alice".into(), "-p".into(), port.into(), destination.into(),
        ], None, Duration::from_secs(10)).await.unwrap();
        assert!(output.status.success(), "native SSH rejected a private diagnostic fixture");
        parse_options(&output.stdout).unwrap()
    }

    async fn resolve_fixture(path: &Path, destination: &str, port: &str) -> Result<ResolvedOptions> {
        let executable = common::ssh_executable()?;
        resolve_native_options(&executable, &[
            "-F".into(), path.to_str().ok_or_else(error)?.into(),
            "-l".into(), "alice".into(), "-p".into(), port.into(), destination.into(),
        ]).await
    }

    async fn assert_trust_roundtrip(directory: &Path, original: &Path) -> ResolvedOptions {
        let resolved = resolve_fixture(original, "server", "2222").await.unwrap();
        let config = serde_json::json!({"ssh_destination":"server","target":{"host":"8.8.8.8","user":"alice"},"listen_port":18377});
        let (block, pin) = render(&config, &resolved.options, directory.to_str().unwrap(), &resolved.trust).unwrap();
        let generated = directory.join(format!("generated-{:032x}", rand::random::<u128>()));
        install::replace(&generated, None, Some(block.as_bytes()), 0o600).unwrap();
        let effective = resolve_fixture(&generated, "127.0.0.1", "18377").await.unwrap();
        assert_eq!(first(&effective.options, "hostkeyalias").unwrap(), pin);
        assert_eq!(effective.trust, resolved.trust, "generated entry changed file boundaries or the trust set");
        resolved
    }

    fn trust_fixture_directory() -> std::path::PathBuf {
        let base = std::env::temp_dir().canonicalize().unwrap();
        #[cfg(windows)]
        let base = crate::windows_security::normalize_system_path(&base).unwrap();
        let directory = base.join(format!("tern-ssh-trust-{:032x}", rand::random::<u128>()));
        common::private_dir(&directory, true).unwrap();
        directory
    }

    #[tokio::test]
    async fn native_known_hosts_dump_cannot_disambiguate_quoted_file_boundaries() {
        let directory = trust_fixture_directory();
        let stem = directory.join("信任").to_str().unwrap().replace('\\', "/");
        // Every individual pathname is legal, including the relative names.
        // OpenSSH emits the same flattened value for one file and three files.
        let single = quoted(&format!("{stem} 文件/known hosts")).unwrap();
        let multiple = format!("{} {} {}", quoted(&stem).unwrap(), quoted("文件/known").unwrap(), quoted("hosts").unwrap());
        let mut observations = Vec::new();
        for (name, value) in [("one", single), ("many", multiple)] {
            let path = directory.join(name);
            let contents = format!("Host server\n HostName 8.8.8.8\n User alice\n Port 2222\n UserKnownHostsFile {value}\n GlobalKnownHostsFile {value}\n");
            install::replace(&path, None, Some(contents.as_bytes()), 0o600).unwrap();
            observations.push(dump_fixture(&path, "server", "2222").await);
        }
        for key in ["userknownhostsfile", "globalknownhostsfile"] {
            assert_eq!(observations[0].get(key), observations[1].get(key),
                "the native dump format changed; reassess whether boundaries can be recovered");
            assert_eq!(first(&observations[0], key).unwrap(), format!("{stem} 文件/known hosts"));
        }
        let one = resolve_fixture(&directory.join("one"), "server", "2222").await.unwrap();
        assert_eq!(one.trust["userknownhostsfile"], vec![format!("{stem} 文件/known hosts")]);
        assert!(resolve_fixture(&directory.join("many"), "server", "2222").await.is_err(),
            "relative-path camouflage must not be accepted as one absolute file");
        let collision = directory.join("collision");
        let contents = format!("Host server\n HostName 8.8.8.8\n UserKnownHostsFile {}\n GlobalKnownHostsFile none\nHost never-selected\n UserKnownHostsFile {} {} {}\n",
            quoted(&format!("{stem} 文件/known hosts")).unwrap(), quoted(&stem).unwrap(), quoted("文件/known").unwrap(), quoted("hosts").unwrap());
        install::replace(&collision, None, Some(contents.as_bytes()), 0o600).unwrap();
        assert!(resolve_fixture(&collision, "server", "2222").await.is_err(),
            "two source vectors with identical native dumps must remain ambiguous");
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn native_known_hosts_roundtrip_preserves_unicode_and_literal_percent() {
        let directory = trust_fixture_directory();
        let original = directory.join("original");
        let stem = directory.to_str().unwrap().replace('\\', "/");
        let source = format!("Host server\n HostName 8.8.8.8\n User alice\n Port 2222\n UserKnownHostsFile {}\n GlobalKnownHostsFile {}\n",
            quoted(&format!("{stem}/信任-%%h")).unwrap(), quoted(&format!("{stem}/全局-%d")).unwrap());
        install::replace(&original, None, Some(source.as_bytes()), 0o600).unwrap();
        let resolved = assert_trust_roundtrip(&directory, &original).await;
        assert_eq!(resolved.trust["userknownhostsfile"], vec![format!("{stem}/信任-%h")]);
        assert_eq!(resolved.trust["globalknownhostsfile"], vec![format!("{stem}/全局-%d")]);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn native_default_known_hosts_lists_roundtrip() {
        let directory = trust_fixture_directory();
        let original = directory.join("default-source");
        let contents = "Host server\n HostName 8.8.8.8\n User alice\n Port 2222\n";
        install::replace(&original, None, Some(contents.as_bytes()), 0o600).unwrap();
        let resolved = assert_trust_roundtrip(&directory, &original).await;
        for key in TRUST_KEYS {
            assert_eq!(resolved.trust[key].len(), 2,
                "native default file-list boundaries were not preserved");
            assert_eq!(resolved.trust[key].join(" "), first(&resolved.options, key).unwrap());
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn native_single_and_multiple_space_unicode_paths_keep_each_boundary() {
        let directory = trust_fixture_directory();
        let paths = vec![
            directory.join("用户 信任/文件 一").to_str().unwrap().replace('\\', "/"),
            directory.join("其他 信任/文件 二").to_str().unwrap().replace('\\', "/"),
        ];
        for count in [1, 2] {
            let original = directory.join(format!("来源 中文 {count}"));
            let arguments = paths[..count].iter().map(|path| quoted(path).unwrap()).collect::<Vec<_>>().join(" ");
            let source = format!("Host server\n HostName 8.8.8.8\n User alice\n Port 2222\n UserKnownHostsFile {arguments}\n GlobalKnownHostsFile {arguments}\n");
            install::replace(&original, None, Some(source.as_bytes()), 0o600).unwrap();
            let resolved = assert_trust_roundtrip(&directory, &original).await;
            for key in TRUST_KEYS {
                assert_eq!(resolved.trust[key], paths[..count],
                    "quoted native source boundaries changed during generation");
            }
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn native_home_expansion_with_spaces_is_not_split_again() {
        let directory = trust_fixture_directory();
        let original = directory.join("home-token");
        let source = "Host server\n HostName 8.8.8.8\n User alice\n Port 2222\n UserKnownHostsFile \"%d/信任 文件\"\n GlobalKnownHostsFile none\n";
        install::replace(&original, None, Some(source.as_bytes()), 0o600).unwrap();
        let resolved = assert_trust_roundtrip(&directory, &original).await;
        assert_eq!(resolved.trust["userknownhostsfile"].len(), 1);
        let path = &resolved.trust["userknownhostsfile"][0];
        assert!(path.ends_with("/信任 文件"));
        common::safe_local_absolute(path).unwrap();
        assert_eq!(resolved.trust["globalknownhostsfile"], vec!["none"]);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn native_default_collision_is_rejected_before_invalid_candidate_filtering() {
        let directory = trust_fixture_directory();
        let baseline = directory.join("baseline");
        let source = "Host server\n HostName 8.8.8.8\n User alice\n Port 2222\n";
        install::replace(&baseline, None, Some(source.as_bytes()), 0o600).unwrap();
        let defaults = dump_fixture(&baseline, "server", "2222").await;
        let flattened = first(&defaults, "userknownhostsfile").unwrap();
        let collision = directory.join("default-collision");
        let contents = format!("{source} UserKnownHostsFile {}\n GlobalKnownHostsFile none\n", quoted(flattened).unwrap());
        install::replace(&collision, None, Some(contents.as_bytes()), 0o600).unwrap();
        let observed = dump_fixture(&collision, "server", "2222").await;
        assert_eq!(first(&observed, "userknownhostsfile").unwrap(), flattened);
        assert!(resolve_fixture(&collision, "server", "2222").await.is_err(),
            "one quoted filename must not silently become the default two-file trust set");
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn native_include_and_match_supply_sources_without_reimplementing_selection() {
        let directory = trust_fixture_directory();
        let original = directory.join("original");
        let included = directory.join("包含 中文 配置");
        let trust_path = directory.join("信任 文件").to_str().unwrap().replace('\\', "/");
        let source = format!("Host server\n HostName 8.8.8.8\n User alice\n Port 2222\n Include {}\n",
            quoted(&included.to_str().unwrap().replace('\\', "/")).unwrap());
        let child = format!("Match originalhost server\n UserKnownHostsFile {}\n GlobalKnownHostsFile none\n", quoted(&trust_path).unwrap());
        install::replace(&included, None, Some(child.as_bytes()), 0o600).unwrap();
        install::replace(&original, None, Some(source.as_bytes()), 0o600).unwrap();
        let resolved = assert_trust_roundtrip(&directory, &original).await;
        assert_eq!(resolved.trust["userknownhostsfile"], vec![trust_path]);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn native_windows_unsafe_trust_paths_are_not_reinterpreted_as_absolute_lists() {
        let directory = trust_fixture_directory();
        for (index, path) in ["relative/known", "C:/known:stream", "//server/share/known", "//?/C:/known"].iter().enumerate() {
            let original = directory.join(format!("unsafe-{index}"));
            let source = format!("Host server\n HostName 8.8.8.8\n User alice\n Port 2222\n UserKnownHostsFile {}\n GlobalKnownHostsFile none\n", quoted(path).unwrap());
            install::replace(&original, None, Some(source.as_bytes()), 0o600).unwrap();
            assert!(resolve_fixture(&original, "server", "2222").await.is_err(),
                "unsafe trust pathname must fail closed rather than change its meaning");
        }
        std::fs::remove_dir_all(directory).unwrap();
    }
}
