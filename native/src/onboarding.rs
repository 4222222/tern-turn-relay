//! Bounded JSON onboarding boundary. Inspection is local, read-only and secret-free.
use crate::common::{self, Error, Options, Result};
use crate::install::{self, Paths};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

fn request_error() -> Error {
    Error::with_exit(
        "invalid-request",
        "Onboarding input contains missing, invalid or unsupported fields.",
        2,
    )
}
fn discovery_error() -> Error {
    Error::new(
        "discovery-failed",
        "Remote discovery did not return a complete, verified existing service selection.",
    )
}
fn fields(request: &Value, allowed: &[&str], required: &[&str]) -> Result<()> {
    let object = request.as_object().ok_or_else(request_error)?;
    if object.keys().any(|key| !allowed.contains(&key.as_str()))
        || required.iter().any(|key| !object.contains_key(*key))
    {
        return Err(request_error());
    }
    Ok(())
}
fn boolean(request: &Value, key: &str) -> Result<bool> {
    request
        .get(key)
        .map(|value| value.as_bool().ok_or_else(request_error))
        .unwrap_or(Ok(false))
}
fn confirm(request: &Value) -> Result<()> {
    fields(request, &["confirm"], &["confirm"])?;
    if !boolean(request, "confirm")? {
        return Err(Error::with_exit(
            "confirmation-required",
            "Explicit confirmation is required for migration, update or removal.",
            6,
        ));
    }
    Ok(())
}
fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(discovery_error)
}
fn remote_path<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    let value = text(value, field)?;
    if value.len() > 4096 || value == "/" {
        return Err(discovery_error());
    }
    common::safe_absolute(value)?;
    Ok(value)
}
fn candidate(value: &str) -> bool {
    value.len() == 24
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
#[cfg(windows)]
fn machine_name() -> Result<String> {
    let mut name = [0u16; 256];
    let mut length = name.len() as u32;
    if unsafe { windows_sys::Win32::System::WindowsProgramming::GetComputerNameW(name.as_mut_ptr(), &mut length) } == 0 {
        return Err(request_error());
    }
    String::from_utf16(&name[..length as usize]).map_err(|_| request_error())
}

#[cfg(unix)]
fn machine_name() -> Result<String> {
    let mut raw = [0u8; 256];
    if unsafe { libc::gethostname(raw.as_mut_ptr().cast(), raw.len()) } != 0 {
        return Err(request_error());
    }
    let length = raw.iter().position(|b| *b == 0).ok_or_else(request_error)?;
    String::from_utf8(raw[..length].to_vec()).map_err(|_| request_error())
}
fn migration_required(paths: &Paths) -> Result<bool> {
    let config_old = if install::snapshot(&paths.config(), 65536)?.is_some() {
        common::read_json(&paths.config(), true)?["schema"] == 3
    } else {
        false
    };
    Ok(config_old || install::manifest(paths)?.is_some_and(|record| record["schema"] == 1))
}
fn require_native(paths: &Paths) -> Result<()> {
    if migration_required(paths)? {
        return Err(Error::with_exit("migration-required", "Explicitly migrate the stopped v0.3 installation before replacing its configuration or updating the plugin.", 6));
    }
    Ok(())
}
fn inspect(paths: &Paths) -> Result<Value> {
    let config = install::current(paths)?;
    let credential = config
        .as_ref()
        .and_then(|v| v["credential_file"].as_str())
        .map(Path::new)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| paths.credential());
    let credential_present = install::snapshot(&credential, 65536)?.is_some();
    let (credential_ready, credential_reconfigure_required) = match crate::credentials::configured(&credential) {
        Ok(ready) => (ready, false),
        Err(error) if cfg!(windows) && matches!(error.code, "credential-reconfigure-required" | "credential-protection") => (false, true),
        Err(error) => return Err(error),
    };
    let runtime_ready = install::runtime_ready();
    let migration = migration_required(paths)?;
    let registration = install::registration(&paths.plugins())?
        .map(|r| r.kind)
        .unwrap_or("unregistered");
    Ok(
        json!({"credential_configured":credential_ready,"credential_present":credential_present,"credential_reconfigure_required":credential_reconfigure_required,"configured":config.is_some(),
        "running":common::is_locked(&paths.runtime().join("service.lock"))?,
        "ssh_aliases":crate::ssh_config::aliases(&paths.aliases)?,"current_target":config.as_ref().map(|c| &c["target"]),
        "paths":paths.json(),"registration":registration,"migration_required":migration,
        "readiness":{"credentials":credential_ready,"configuration":config.is_some(),"runtime":runtime_ready,
            "ready":credential_ready && config.is_some() && runtime_ready && !migration,"runtime_kind":"rust","migration_required":migration}}),
    )
}
fn inventory(remote: &Value) -> Result<Value> {
    let candidates = remote["candidates"]
        .as_array()
        .filter(|c| c.len() <= 64)
        .ok_or_else(discovery_error)?;
    let mut public = Vec::with_capacity(candidates.len());
    for entry in candidates {
        let id = text(entry, "id")?;
        let pid = entry["pid"]
            .as_u64()
            .filter(|p| *p > 0)
            .ok_or_else(discovery_error)?;
        let port = entry["port"]
            .as_u64()
            .filter(|p| (1..=65535).contains(p))
            .ok_or_else(discovery_error)?;
        if !candidate(id) {
            return Err(discovery_error());
        }
        let state = remote_path(entry, "state")?;
        let daemon = remote_path(entry, "daemon_socket")?;
        public.push(json!({"id":id,"label":format!("Tern service PID {pid} · UDP {port}"),"detail":format!("{state} → {daemon}")}));
    }
    Ok(json!({"code":"choose","candidates":public}))
}
fn configuration(
    paths: &Paths,
    previous: Option<&Value>,
    alias: &str,
    listen_port: u64,
    remote: &Value,
    machine: &str,
) -> Result<(Value, bool)> {
    let home = remote_path(remote, "home")?;
    let original = remote_path(remote, "original_state_dir")?;
    let daemon = remote_path(remote, "daemon_socket")?;
    let host = text(remote, "host")?;
    let user = text(remote, "user")?;
    let fingerprint = text(remote, "fingerprint")?;
    common::fingerprint(fingerprint)?;
    let target_port = remote["target_port"]
        .as_u64()
        .filter(|p| (1..=65535).contains(p))
        .ok_or_else(discovery_error)?;
    let same_workspace = previous.is_some_and(|old| {
        old["target"]["host"] == host
            && old["target"]["user"] == user
            && old["target"]["fingerprint"] == fingerprint
            && old["target"]["port"] == target_port
            && old["gateway"]["daemon_socket"] == daemon
    });
    let name = if let Some(old) = previous.filter(|old| old["ssh_destination"] == alias) {
        old["target"]["name"]
            .as_str()
            .ok_or_else(discovery_error)?
            .to_owned()
    } else if alias.len() <= 64 {
        alias.to_owned()
    } else {
        format!(
            "server-{}",
            &hex::encode(Sha256::digest(alias.as_bytes()))[..16]
        )
    };
    let gateway_state = if same_workspace {
        previous
            .and_then(|p| p["gateway"]["state_dir"].as_str())
            .ok_or_else(discovery_error)?
            .to_owned()
    } else {
        let binding = json!([
            machine,
            paths.data,
            host,
            user,
            daemon,
            original,
            fingerprint,
            target_port
        ]);
        let bytes = serde_json::to_vec(&binding).map_err(|_| discovery_error())?;
        format!(
            "{home}/.local/state/tern-turn-relay/workspaces/{}",
            &hex::encode(Sha256::digest(bytes))[..24]
        )
    };
    if Path::new(&gateway_state).starts_with(original)
        || Path::new(original).starts_with(&gateway_state)
    {
        return Err(discovery_error());
    }
    let credential = previous
        .and_then(|p| p["credential_file"].as_str())
        .map(Path::new)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| paths.credential());
    let mut config = json!({"schema":4,"ssh_destination":alias,
        "target":{"name":name,"host":host,"user":user,"port":target_port,"fingerprint":fingerprint},
        "listen_port":listen_port,"gateway":{"state_dir":gateway_state,"daemon_socket":daemon},"credential_file":credential});
    if same_workspace {
        config["gateway"]["fingerprint"] =
            previous.ok_or_else(discovery_error)?["gateway"]["fingerprint"].clone();
    }
    Ok((common::validate_config(config, true)?, same_workspace))
}
async fn discover(paths: &Paths, request: &Value) -> Result<Value> {
    fields(
        request,
        &["ssh_destination", "candidate_id", "listen_port"],
        &["ssh_destination"],
    )?;
    let alias = request["ssh_destination"]
        .as_str()
        .ok_or_else(request_error)?;
    common::safe_alias(alias)?;
    let selected = match request.get("candidate_id") {
        None | Some(Value::Null) => None,
        Some(value) => Some(
            value
                .as_str()
                .filter(|id| candidate(id))
                .ok_or_else(request_error)?,
        ),
    };
    let previous = install::current(paths)?;
    let listen_port = request
        .get("listen_port")
        .map(|v| v.as_u64().ok_or_else(request_error))
        .unwrap_or_else(|| {
            Ok(previous
                .as_ref()
                .and_then(|p| p["listen_port"].as_u64())
                .unwrap_or(18377))
        })?;
    if !(1024..=65535).contains(&listen_port) {
        return Err(request_error());
    }
    let excluded = previous
        .as_ref()
        .and_then(|p| p["gateway"]["state_dir"].as_str())
        .map(|s| vec![format!("{s}/native")])
        .unwrap_or_default();
    let remote = crate::discovery::discover(alias, selected, &excluded).await?;
    if remote.get("candidates").is_some() {
        return inventory(&remote);
    }
    let id = text(&remote, "candidate_id")?;
    if !candidate(id) {
        return Err(discovery_error());
    }
    let (config, same_workspace) = configuration(
        paths,
        previous.as_ref(),
        alias,
        listen_port,
        &remote,
        &machine_name()?,
    )?;
    if selected.is_some_and(|selected| selected != id) {
        return Err(discovery_error());
    }
    install::owned_path(
        Path::new(
            config["credential_file"]
                .as_str()
                .ok_or_else(discovery_error)?,
        ),
        false,
    )?;
    let registered = install::registration(&paths.plugins())?;
    let kind = registered
        .as_ref()
        .map(|r| r.kind)
        .unwrap_or("unregistered");
    let mut public_paths = paths.json();
    public_paths["credential_file"] = config["credential_file"].clone();
    let mut changes = vec![
        json!("Use the verified native Rust runtime; no Python runtime or local dependency installation."),
        json!("Discovery deploys a verified native helper into the private remote cache without starting the original service."),
        json!("Provision the dedicated TURN gateway in the reviewed remote gateway state directory."),
        json!("Write private plugin configuration and the exact-address managed SSH compatibility block."),
        json!("Preserve the original Tern identity and existing session daemon; do not start a connection.")];
    if previous.is_some() && !same_workspace {
        changes.push(json!(format!(
            "Preserve the previous gateway state and daemon pin without modification: {}",
            previous
                .as_ref()
                .and_then(|p| p["gateway"]["state_dir"].as_str())
                .ok_or_else(discovery_error)?
        )));
    }
    if kind == "linked" {
        changes.push(json!("Migrate the owned legacy registration to an allowlisted native plugin copy; retain the old durable package for recovery."));
    }
    let review = json!({"schema":1,"ssh_destination":alias,"candidate_id":id,"listen_port":listen_port,
        "configuration":config,"original_state_dir":remote_path(&remote,"original_state_dir")?,"paths":public_paths,
        "previous_config_sha256":install::digest(&paths.config())?,"installation_sha256":install::digest(&paths.manifest())?,
        "ssh_config_sha256":install::digest(&paths.ssh)?,"registration":kind,"migrate_native":kind == "linked",
        "package_sha256":install::package_digest(&paths.package)?,
        "registered_package":registered.as_ref().map(|r| &r.source),"changes":changes});
    Ok(json!({"code":"review","review":review,"candidates":[],
        "summary":format!("{} · {}:{} · existing daemon {}", alias, text(&remote,"host")?, remote["target_port"], remote_path(&remote,"daemon_socket")?)}))
}
async fn execute(action: &str, paths: &Paths, request: &Value) -> Result<Value> {
    match action {
        "inspect" => {
            fields(request, &[], &[])?;
            inspect(paths)
        }
        "discover" | "review" => discover(paths, request).await,
        "apply" => {
            fields(request, &["review", "authorize_replace"], &["review"])?;
            let replace = boolean(request, "authorize_replace")?;
            let review = request["review"].as_object().ok_or_else(request_error)?;
            let _locks = install::lifecycle(paths)?;
            require_native(paths)?;
            if install::current(paths)?.is_some() && !replace {
                return Err(Error::with_exit(
                    "replacement-consent-required",
                    "Replacing installed configuration requires explicit consent.",
                    6,
                ));
            }
            let fresh = discover(paths, &json!({"ssh_destination":review.get("ssh_destination"),"candidate_id":review.get("candidate_id"),"listen_port":review.get("listen_port")})).await?;
            if fresh["code"] != "review" || fresh["review"] != request["review"] {
                return Err(Error::with_exit(
                    "review-changed",
                    "Target, ownership or configuration changed; discover and review again.",
                    6,
                ));
            }
            install::apply(paths, &fresh["review"]).await
        }
        "configure-credentials" => {
            fields(request, &["replace"], &[])?;
            let replace = boolean(request, "replace")?;
            let _locks = install::lifecycle(paths)?;
            let current = install::current(paths)?;
            let key = current
                .as_ref()
                .and_then(|c| c["credential_file"].as_str())
                .map(Path::new)
                .map(Path::to_path_buf)
                .unwrap_or_else(|| paths.credential());
            let mut result = crate::credentials::configure_native(&key, replace).await?;
            result["credential_configured"] = json!(true);
            Ok(result)
        }
        "migrate" => {
            confirm(request)?;
            install::migrate(paths).await
        }
        "update" | "uninstall" => {
            confirm(request)?;
            install::manage(paths, action).await
        }
        _ => Err(request_error()),
    }
}
pub async fn run(args: &[String]) -> Result<Value> {
    let options = Options::parse(
        args,
        &[
            "--data-dir",
            "--package-dir",
            "--config-dir",
            "--ssh-config",
            "--tern",
        ],
        &[],
    )?;
    if options.positionals.len() != 1 {
        return Err(request_error());
    }
    let action = options.positionals[0].as_str();
    let request = common::read_json_stdin(65536)?;
    let paths = install::context(&options)?;
    let mut result = execute(action, &paths, &request).await?;
    result["ok"] = json!(true);
    result["action"] = json!(action);
    result["exit_code"] = json!(0);
    if result.get("code").is_none() {
        result["code"] = json!("ok");
    }
    if serde_json::to_vec(&result)
        .map_err(|_| request_error())?
        .len()
        > 65536
    {
        return Err(Error::with_exit(
            "response-limit",
            "Onboarding response exceeded its bounded output limit.",
            7,
        ));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inspection_of_absent_profile_creates_nothing() {
        let base = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        #[cfg(windows)]
        let base = crate::windows_security::normalize_system_path(&base).unwrap();
        let root = base.join(format!("tern-inspect-test-{:032x}", rand::random::<u128>()));
        let paths = Paths {
            data: root.join("plugin-data").join(install::PLUGIN),
            package: root.join("plugins").join(install::PLUGIN),
            profile: root.clone(),
            ssh: root.join("ssh-config"),
            aliases: root.join("aliases"),
            tern: None,
        };
        let result = inspect(&paths).unwrap();
        assert_eq!(result["configured"], false);
        assert_eq!(result["credential_configured"], false);
        assert_eq!(result["running"], false);
        assert_eq!(result["migration_required"], false);
        assert!(!root.exists());
    }
    fn paths() -> Paths {
        #[cfg(windows)]
        let home = std::path::PathBuf::from(r"C:\Users\example");
        #[cfg(unix)]
        let home = std::path::PathBuf::from("/home/example");
        let profile = home.join("profile");
        let data = profile.join("plugin-data").join(install::PLUGIN);
        Paths {
            ssh: data.join("ssh-config"),
            data,
            package: profile.join("plugins").join(install::PLUGIN),
            profile,
            aliases: home.join(".ssh/config"),
            tern: None,
        }
    }
    fn remote() -> Value {
        json!({"home":"/home/example","original_state_dir":"/home/example/original","daemon_socket":"/home/example/daemon.sock",
            "host":"8.8.8.8","user":"example","fingerprint":"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","target_port":8377})
    }
    #[test]
    fn consent_never_accepts_truthy_values() {
        for value in [
            json!({}),
            json!({"confirm":false}),
            json!({"confirm":"true"}),
            json!({"confirm":1}),
            json!({"confirm":true,"url":"untrusted"}),
        ] {
            assert!(confirm(&value).is_err());
        }
        assert!(confirm(&json!({"confirm":true})).is_ok());
        assert!(boolean(&json!({"replace":null}), "replace").is_err());
    }
    #[test]
    fn inventory_exposes_only_verified_public_fields() {
        let remote = json!({"candidates":[{"id":"abcdef0123456789abcdef01","pid":17,"port":8377,"state":"/home/a/state","daemon_socket":"/home/a/daemon.sock","secret":"not returned"}]});
        let result = inventory(&remote).unwrap();
        assert_eq!(result["code"], "choose");
        assert!(!result.to_string().contains("secret"));
        let mut invalid = remote;
        invalid["candidates"][0]["state"] = json!("/home/a/../private");
        assert!(inventory(&invalid).is_err());
    }
    #[test]
    fn workspace_namespace_is_stable_and_profile_bound() {
        let first = configuration(&paths(), None, "server", 18377, &remote(), "machine")
            .unwrap()
            .0;
        let again = configuration(&paths(), None, "server", 18377, &remote(), "machine")
            .unwrap()
            .0;
        assert_eq!(first, again);
        assert_eq!(first["schema"], 4);
        assert!(first.get("dependency_dir").is_none());
        let mut other = paths();
        other.data = other.profile.join("other-plugin-data").join(install::PLUGIN);
        let distinct = configuration(&other, None, "server", 18377, &remote(), "machine")
            .unwrap()
            .0;
        assert_ne!(
            first["gateway"]["state_dir"],
            distinct["gateway"]["state_dir"]
        );
        let mut pinned = first;
        pinned["gateway"]["fingerprint"] =
            json!("SHA256:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE");
        let (updated, same) = configuration(
            &paths(),
            Some(&pinned),
            "server",
            18378,
            &remote(),
            "machine",
        )
        .unwrap();
        assert!(same);
        assert_eq!(updated["gateway"], pinned["gateway"]);
        assert_eq!(updated["credential_file"], pinned["credential_file"]);
        assert_eq!(updated["listen_port"], 18378);
    }
}
