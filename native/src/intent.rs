//! Durable, exact-configuration-bound resume selection. Stop revokes before IPC.
use crate::common::{self, Error, Result};
use serde_json::{json, Value};
use std::{fs, io, path::Path};

const INVALID: &str = "Saved relay selection is invalid or unsafe; use an explicit start or stop before automatic recovery.";

fn selection(config: &Value, mode: &str) -> Value {
    json!({"target": config["target"], "gateway": config["gateway"],
        "listen_port": config["listen_port"], "ssh_destination": config["ssh_destination"], "mode": mode})
}

fn validate(config: &Value, value: &Value) -> Result<String> {
    let mode = value["mode"]
        .as_str()
        .filter(|mode| matches!(*mode, "tls" | "udp"))
        .ok_or_else(|| Error::new("invalid_intent", INVALID))?;
    if !value.as_object().is_some_and(|object| object.len() == 5)
        || !value["listen_port"].is_u64()
        || !value["target"]["port"].is_u64()
        || !value["target"].is_object()
        || !value["gateway"].is_object()
    {
        return Err(Error::new("invalid_intent", INVALID));
    }
    if *value != selection(config, mode) {
        return Err(Error::new("intent_mismatch", "Saved relay selection does not match the configured target, gateway, port or SSH destination; use an explicit start or stop before automatic recovery."));
    }
    Ok(mode.to_owned())
}

pub fn load(config: &Value, directory: &Path) -> Result<Option<String>> {
    let path = directory.join("intent.json");
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(Error::new("invalid_intent", INVALID)),
        Ok(_) => {}
    }
    let value =
        common::read_json(&path, true).map_err(|_| Error::new("invalid_intent", INVALID))?;
    validate(config, &value).map(Some)
}

pub fn save(config: &Value, directory: &Path, mode: &str) -> Result<()> {
    if !matches!(mode, "tls" | "udp") {
        return Err(Error::new("invalid_intent", INVALID));
    }
    common::atomic_json(&directory.join("intent.json"), &selection(config, mode))
        .map_err(|_| Error::new("intent_write", "Relay is ready, but saving its backend selection failed. Retry an explicit start or stop; automatic recovery was not confirmed."))
}

pub fn clear(directory: &Path) -> Result<()> {
    // Unlink the entry even if its JSON is invalid or it is a symlink. Never follow it.
    match fs::remove_file(directory.join("intent.json")) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(Error::new("intent_revoke", "Cannot clear saved relay selection; the backend was not stopped. Fix intent.json permissions and retry stop.")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Value {
        json!({"target":{"host":"1.1.1.1","user":"alice","port":1234},
            "gateway":{"fingerprint":"pinned","daemon_socket":"/run/user/123/daemon.sock"},
            "listen_port":18377,"ssh_destination":"server"})
    }

    #[test]
    fn resume_is_bound_to_every_connection_identity_field() {
        let original = config();
        let saved = selection(&original, "tls");
        assert_eq!(validate(&original, &saved).unwrap(), "tls");
        for field in ["target", "gateway", "listen_port", "ssh_destination"] {
            let mut changed = original.clone();
            changed[field] = Value::Null;
            assert!(validate(&changed, &saved).is_err());
        }
        let mut extra = saved.clone();
        extra["schema"] = json!(1);
        assert!(validate(&original, &extra).is_err());
        let mut bad = saved.clone();
        bad["mode"] = json!("direct");
        assert!(validate(&original, &bad).is_err());
        bad = saved;
        bad["listen_port"] = json!(18377.0);
        assert!(validate(&original, &bad).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn stop_revokes_invalid_symlink_intent_without_touching_target() {
        use std::os::unix::fs::PermissionsExt;
        let directory = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "ttr-intent-{}",
            hex::encode(rand::random::<[u8; 16]>())
        ));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let target = directory.join("preserved");
        fs::write(&target, b"not-owned-by-intent").unwrap();
        std::os::unix::fs::symlink(&target, directory.join("intent.json")).unwrap();
        assert!(load(&config(), &directory).is_err());
        clear(&directory).unwrap();
        assert!(load(&config(), &directory).unwrap().is_none());
        assert_eq!(fs::read(&target).unwrap(), b"not-owned-by-intent");
        save(&config(), &directory, "udp").unwrap();
        assert_eq!(load(&config(), &directory).unwrap().as_deref(), Some("udp"));
        clear(&directory).unwrap();
        clear(&directory).unwrap();
        fs::remove_file(target).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn stop_revokes_invalid_json_before_a_new_resume_selection() {
        let base = std::env::temp_dir().canonicalize().unwrap();
        #[cfg(windows)]
        let base = crate::windows_security::normalize_system_path(&base).unwrap();
        let directory = base.join(format!("ttr-intent-{:032x}", rand::random::<u128>()));
        common::private_dir(&directory, true).unwrap();
        common::atomic_json(&directory.join("intent.json"), &json!({"invalid":true})).unwrap();
        assert!(load(&config(), &directory).is_err());
        clear(&directory).unwrap();
        assert!(load(&config(), &directory).unwrap().is_none());
        save(&config(), &directory, "tls").unwrap();
        assert_eq!(load(&config(), &directory).unwrap().as_deref(), Some("tls"));
        clear(&directory).unwrap();
        clear(&directory).unwrap();
        fs::remove_dir_all(directory).unwrap();
    }
}
