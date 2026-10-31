//! Exact loopback/user/port SSH compatibility. Unrelated rules are byte-preserved.
use crate::common::{self, Error, Result};
use crate::install::{self, Snapshot};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;
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
    let mut lines = vec![
        BEGIN.trim_end().to_owned(),
        format!("Match originalhost 127.0.0.1 user {user} exec \"test %p = {listen}\""),
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
    for key in ["userknownhostsfile", "globalknownhostsfile"] {
        if let Some(value) = options.get(key).and_then(|v| v.first()) {
            let value = expand(value, host, alias, port, user, home);
            if value.chars().any(char::is_control) {
                return Err(error());
            }
            lines.push(format!("    {key} {value}"));
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
    let output = common::run(
        "/usr/bin/ssh",
        &["-G".into(), alias.into()],
        None,
        Duration::from_secs(10),
    )
    .await?;
    if !output.status.success() {
        return Err(error());
    }
    let options = parse_options(&output.stdout)?;
    let home = install::home()?;
    let (block, pin) = render(config, &options, home.to_str().ok_or_else(error)?)?;
    let before = install::snapshot(path, 65536)?;
    let old = std::str::from_utf8(before.as_ref().map(|s| s.bytes.as_slice()).unwrap_or(b""))
        .map_err(|_| error())?;
    let bytes = combine_rule(old, &block, expected)?;
    let staged = path.with_file_name(format!(".tern-ssh-{:032x}", rand::random::<u128>()));
    install::replace(&staged, None, Some(&bytes), 0o600)?;
    let validation = common::run(
        "/usr/bin/ssh",
        &[
            "-G".into(),
            "-F".into(),
            staged.to_str().ok_or_else(error)?.into(),
            "-p".into(),
            config["listen_port"].to_string(),
            format!(
                "{}@127.0.0.1",
                config["target"]["user"].as_str().ok_or_else(error)?
            ),
        ],
        None,
        Duration::from_secs(10),
    )
    .await;
    let staged_snapshot = install::snapshot(&staged, 65536)?;
    install::replace(&staged, staged_snapshot.as_ref(), None, 0o600)?;
    let output = validation?;
    if !output.status.success() {
        return Err(error());
    }
    let effective = parse_options(&output.stdout)?;
    if first(&effective, "hostkeyalias")? != pin || first(&effective, "hostname")? != "127.0.0.1" {
        return Err(error());
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
        let (block, pin) = render(&config, &options, "/home/alice").unwrap();
        assert_eq!(pin, "[8.8.8.8]:2222");
        assert!(block.contains("Match originalhost 127.0.0.1 user alice exec \"test %p = 18377\""));
        assert!(block.contains("/home/alice/.ssh/8.8.8.8-alice-2222"));
        assert!(block.contains("StrictHostKeyChecking yes"));
        let mut changed = config;
        changed["target"]["host"] = serde_json::json!("1.1.1.1");
        assert!(render(&changed, &options, "/home/alice").is_err());
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
}
