//! Read-only inventory of original Tern services over an already-trusted SSH alias.
use crate::{
    common::{self, Result},
    gateway::failure,
};
use serde_json::{json, Value};
use std::{collections::BTreeMap, net::Ipv4Addr, time::Duration};

pub(crate) fn public_ipv4(text: &str) -> Result<Ipv4Addr> {
    let ip: Ipv4Addr = text.parse().map_err(|_| failure("identity_mismatch"))?;
    let [a, b, c, d] = ip.octets();
    let private = a == 0
        || a == 10
        || a == 127
        || a >= 224
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 192 && b == 0 && (c == 2 || (c == 0 && d != 9 && d != 10)))
        || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
        || (a == 203 && b == 0 && c == 113);
    if private || ip.to_string() != text {
        Err(failure("identity_mismatch"))
    } else {
        Ok(ip)
    }
}

fn parse_resolution(bytes: &[u8]) -> Result<Value> {
    let text = std::str::from_utf8(bytes).map_err(|_| failure("security_error"))?;
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(' ') else {
            continue;
        };
        if ["hostname", "user", "port", "proxyjump", "proxycommand"].contains(&key)
            && fields.insert(key, value.trim()).is_some()
        {
            return Err(failure("security_error"));
        }
    }
    for proxy in ["proxyjump", "proxycommand"] {
        if fields
            .get(proxy)
            .is_some_and(|v| !v.eq_ignore_ascii_case("none"))
        {
            return Err(failure("security_error"));
        }
    }
    let host = *fields
        .get("hostname")
        .ok_or_else(|| failure("security_error"))?;
    public_ipv4(host)?;
    let user = *fields
        .get("user")
        .ok_or_else(|| failure("security_error"))?;
    common::safe_alias(user).map_err(|_| failure("security_error"))?;
    if user.len() > 64 {
        return Err(failure("security_error"));
    }
    let port = fields
        .get("port")
        .and_then(|v| v.parse::<u16>().ok())
        .filter(|v| *v != 0)
        .ok_or_else(|| failure("security_error"))?;
    Ok(json!({"host":host,"user":user,"ssh_port":port}))
}

pub async fn resolve(alias: &str) -> Result<Value> {
    common::safe_alias(alias).map_err(|_| failure("security_error"))?;
    let mut args = common::ssh_args(alias, "");
    args.pop();
    args.insert(0, "-G".into());
    let output = common::run(&common::ssh_executable()?, &args, None, Duration::from_secs(15))
        .await
        .map_err(|_| failure("security_error"))?;
    if !output.status.success() {
        return Err(failure("security_error"));
    }
    parse_resolution(&output.stdout)
}

fn candidate_id(text: &str) -> bool {
    text.len() == 24
        && text
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
}
fn validate_remote(value: &Value, endpoint: &Value) -> Result<()> {
    if value["ok"] != true || value["user"] != endpoint["user"] || value["uid"].as_u64().is_none() {
        return Err(failure("identity_mismatch"));
    }
    common::safe_absolute(value["home"].as_str().unwrap_or(""))
        .map_err(|_| failure("identity_mismatch"))?;
    let object = value.as_object().ok_or_else(|| failure("protocol_error"))?;
    let expected = if value.get("candidates").is_some() {
        let values = value["candidates"]
            .as_array()
            .ok_or_else(|| failure("protocol_error"))?;
        if values.len() > 64 {
            return Err(failure("protocol_error"));
        }
        for item in values {
            if item.as_object().map(|v| v.len()) != Some(5)
                || !candidate_id(item["id"].as_str().unwrap_or(""))
                || item["pid"].as_u64().unwrap_or(0) <= 1
                || !item["port"]
                    .as_u64()
                    .is_some_and(|p| (1..=65535).contains(&p))
            {
                return Err(failure("protocol_error"));
            }
            for field in ["state", "daemon_socket"] {
                common::safe_absolute(item[field].as_str().unwrap_or(""))
                    .map_err(|_| failure("identity_mismatch"))?;
            }
        }
        vec!["ok", "home", "uid", "user", "candidates"]
    } else {
        for field in ["original_state_dir", "daemon_socket"] {
            common::safe_absolute(value[field].as_str().unwrap_or(""))
                .map_err(|_| failure("identity_mismatch"))?;
        }
        common::fingerprint(value["fingerprint"].as_str().unwrap_or(""))
            .map_err(|_| failure("identity_mismatch"))?;
        if !candidate_id(value["candidate_id"].as_str().unwrap_or(""))
            || !value["target_port"]
                .as_u64()
                .is_some_and(|p| (1..=65535).contains(&p))
        {
            return Err(failure("protocol_error"));
        }
        vec![
            "ok",
            "home",
            "uid",
            "user",
            "original_state_dir",
            "daemon_socket",
            "target_port",
            "fingerprint",
            "candidate_id",
        ]
    };
    if object.len() != expected.len() || expected.iter().any(|name| !object.contains_key(*name)) {
        return Err(failure("protocol_error"));
    }
    Ok(())
}

pub async fn discover(
    alias: &str,
    selected: Option<&str>,
    excluded_state_dirs: &[String],
) -> Result<Value> {
    if selected.is_some_and(|id| !candidate_id(id)) || excluded_state_dirs.len() > 64 {
        return Err(failure("protocol_error"));
    }
    for path in excluded_state_dirs {
        common::safe_absolute(path).map_err(|_| failure("security_error"))?;
    }
    let endpoint = resolve(alias).await?;
    let helper = crate::gateway::deploy(alias, &endpoint).await?;
    let request = json!({"target_host":endpoint["host"],"candidate_id":selected,"excluded_state_dirs":excluded_state_dirs,"inventory":true});
    let input = serde_json::to_vec(&request).map_err(|_| failure("protocol_error"))?;
    let command = format!("{} remote discover", common::shell_quote(&helper));
    let output = common::run(
        &common::ssh_executable()?,
        &common::ssh_args(alias, &command),
        Some(&input),
        Duration::from_secs(40),
    )
    .await
    .map_err(|_| failure("connectivity_uncertain"))?;
    if output.stdout.len() > 65536 {
        return Err(failure("protocol_error"));
    }
    let mut remote = crate::remote::parse_json(&output.stdout)?;
    if remote["ok"] == false {
        return Err(failure(remote["reason"].as_str().unwrap_or("unknown")));
    }
    if !output.status.success() {
        return Err(failure("connectivity_uncertain"));
    }
    validate_remote(&remote, &endpoint)?;
    if selected.is_some_and(|id| remote["candidate_id"] != id) {
        return Err(failure("identity_mismatch"));
    }
    remote["host"] = endpoint["host"].clone();
    remote["ssh_port"] = endpoint["ssh_port"].clone();
    Ok(remote)
}

#[cfg(target_os = "linux")]
pub(crate) mod linux {
    use super::*;
    use crate::remote::linux::{self as secure, DaemonPin};
    use sha2::{Digest, Sha256};
    use std::{
        collections::BTreeSet,
        fs,
        net::{Ipv6Addr, SocketAddr},
        os::unix::fs::MetadataExt,
        path::{Path, PathBuf},
    };

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct Listener {
        pub(crate) port: u16,
        pub(crate) address: String,
        pub(crate) inode: String,
    }
    fn table_listener(
        line: &str,
        owned: &BTreeSet<String>,
        ipv6: bool,
    ) -> Result<Option<Listener>> {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 10
            || !owned.contains(fields[9])
            || fields[7].parse::<u32>().ok() != Some(secure::uid())
            || fields[3] != "07"
        {
            return Ok(None);
        }
        if !fields[2].bytes().all(|b| b == b'0' || b == b':') {
            return Ok(None);
        }
        let (address, port) = fields[1]
            .split_once(':')
            .ok_or_else(|| failure("protocol_error"))?;
        let port = u16::from_str_radix(port, 16).map_err(|_| failure("protocol_error"))?;
        if port == 0 {
            return Ok(None);
        }
        let address = if ipv6 {
            if address.len() != 32 || !address.is_ascii() {
                return Err(failure("protocol_error"));
            }
            let mut bytes = [0u8; 16];
            for i in 0..4 {
                bytes[i * 4..i * 4 + 4].copy_from_slice(
                    &u32::from_str_radix(&address[i * 8..i * 8 + 8], 16)
                        .map_err(|_| failure("protocol_error"))?
                        .to_ne_bytes(),
                );
            }
            Ipv6Addr::from(bytes).to_string()
        } else {
            if address.len() != 8 {
                return Err(failure("protocol_error"));
            }
            Ipv4Addr::from(
                u32::from_str_radix(address, 16)
                    .map_err(|_| failure("protocol_error"))?
                    .to_ne_bytes(),
            )
            .to_string()
        };
        Ok(Some(Listener {
            port,
            address,
            inode: fields[9].to_owned(),
        }))
    }
    pub(crate) fn udp_listeners(pid: u32) -> Result<Vec<Listener>> {
        let root = PathBuf::from(format!("/proc/{pid}"));
        let mut owned = BTreeSet::new();
        for (index, entry) in fs::read_dir(root.join("fd"))
            .map_err(|_| failure("identity_mismatch"))?
            .enumerate()
        {
            if index >= 65536 {
                return Err(failure("security_error"));
            }
            let Ok(entry) = entry else {
                continue;
            };
            let Ok(target) = fs::read_link(entry.path()) else {
                continue;
            };
            if let Some(inode) = target
                .to_str()
                .and_then(|s| s.strip_prefix("socket:["))
                .and_then(|s| s.strip_suffix(']'))
            {
                if !inode.is_empty() && inode.bytes().all(|v| v.is_ascii_digit()) {
                    owned.insert(inode.to_owned());
                }
            }
        }
        let mut result = Vec::new();
        for (name, ipv6) in [("udp", false), ("udp6", true)] {
            let table = root.join("net").join(name);
            if !table
                .try_exists()
                .map_err(|_| failure("identity_mismatch"))?
            {
                continue;
            }
            let raw = secure::bounded(&table, 4 * 1024 * 1024)?;
            let text = std::str::from_utf8(&raw).map_err(|_| failure("protocol_error"))?;
            for (index, line) in text.lines().skip(1).enumerate() {
                if index >= 16384 {
                    return Err(failure("security_error"));
                }
                if let Some(listener) = table_listener(line, &owned, ipv6)? {
                    result.push(listener);
                }
            }
        }
        result.sort_by(|a, b| a.port.cmp(&b.port).then(a.inode.cmp(&b.inode)));
        Ok(result)
    }
    fn option(argv: &[String], name: &str) -> Result<Option<String>> {
        let prefix = format!("{name}=");
        let mut result = None;
        for (index, arg) in argv.iter().enumerate() {
            let value = if arg == name {
                Some(
                    argv.get(index + 1)
                        .filter(|v| !v.starts_with("--"))
                        .ok_or_else(|| failure("protocol_error"))?
                        .clone(),
                )
            } else {
                arg.strip_prefix(&prefix).map(str::to_owned)
            };
            if let Some(value) = value {
                if value.is_empty() || result.replace(value).is_some() {
                    return Err(failure("protocol_error"));
                }
            }
        }
        Ok(result)
    }
    fn native_listeners(listen: Option<&str>, listeners: &[Listener], host: &str) -> Vec<Listener> {
        let allowed = ["0.0.0.0", "127.0.0.1", "::", "::1", host];
        let (address, port) = if let Some(listen) = listen {
            let Ok(endpoint) = listen.parse::<SocketAddr>() else {
                return Vec::new();
            };
            let address = endpoint.ip().to_string();
            if endpoint.port() == 0 || !allowed.contains(&address.as_str()) {
                return Vec::new();
            }
            (Some(address), endpoint.port())
        } else {
            (None, 8376)
        };
        listeners
            .iter()
            .filter(|v| {
                v.port == port
                    && allowed.contains(&v.address.as_str())
                    && address.as_ref().is_none_or(|a| a == &v.address)
            })
            .cloned()
            .collect()
    }
    fn dedicated(state: &Path, home: &Path, excluded: &BTreeSet<PathBuf>) -> bool {
        if excluded.contains(state) || state == home.join(".local/state/tern-turn-relay/native") {
            return true;
        }
        if state.file_name().is_some_and(|name| name == "native") {
            if let Some(parent) = state.parent() {
                // Any marker, including an unsafe symlink, reserves this state.
                match fs::symlink_metadata(parent.join("daemon-identity.json")) {
                    Ok(_) => return true,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                    Err(_) => return true,
                }
            }
        }
        false
    }
    struct Service {
        pid: u32,
        start: String,
        state: PathBuf,
        listen: Option<String>,
        daemon: Option<String>,
        argv: Vec<String>,
        binary: PathBuf,
        listeners: Vec<Listener>,
    }
    struct Daemon {
        pid: u32,
        start: String,
        ppid: u32,
        socket: String,
    }
    struct Candidate {
        identifier: String,
        service: usize,
        daemon: usize,
        listener: Listener,
    }
    fn service_daemon(pid: u32) -> Result<Option<String>> {
        let raw = secure::bounded(&PathBuf::from(format!("/proc/{pid}/environ")), 1024 * 1024)?;
        let mut daemon = None;
        let mut pane = None;
        for entry in raw.split(|b| *b == 0) {
            for (name, value) in [
                (b"TERN_DAEMON_SOCKET=".as_slice(), &mut daemon),
                (b"TERN_PANE_SOCKET=".as_slice(), &mut pane),
            ] {
                if let Some(bytes) = entry.strip_prefix(name) {
                    if value.is_some() {
                        return Err(failure("security_error"));
                    }
                    if !bytes.is_empty() {
                        *value = Some(
                            std::str::from_utf8(bytes)
                                .map_err(|_| failure("security_error"))?
                                .to_owned(),
                        );
                    }
                }
            }
        }
        Ok(daemon.or(pane))
    }
    fn original_files(state: &Path) -> Result<[(u64, u64, u64); 2]> {
        secure::ancestors(state)?;
        let mut result = [(0, 0, 0); 2];
        for (index, name) in ["host_key", "host_cert.der"].iter().enumerate() {
            let file = secure::regular(&state.join(name), false)?;
            let info = file.metadata().map_err(|_| failure("security_error"))?;
            if info.len() == 0 {
                return Err(failure("identity_mismatch"));
            }
            result[index] = (info.dev(), info.ino(), info.len());
        }
        Ok(result)
    }
    pub(crate) fn discover(request: &Value) -> Result<Value> {
        let object = request
            .as_object()
            .ok_or_else(|| failure("protocol_error"))?;
        let allowed = [
            "target_host",
            "candidate_id",
            "excluded_state_dirs",
            "inventory",
            "original_state_dir",
            "daemon_socket",
            "target_port",
        ];
        if object.keys().any(|name| !allowed.contains(&name.as_str())) {
            return Err(failure("protocol_error"));
        }
        let host = request["target_host"]
            .as_str()
            .ok_or_else(|| failure("protocol_error"))?;
        public_ipv4(host)?;
        let selected = match request.get("candidate_id") {
            None | Some(Value::Null) => None,
            Some(Value::String(id)) if candidate_id(id) => Some(id.as_str()),
            _ => return Err(failure("protocol_error")),
        };
        let inventory = request.get("inventory").map_or(Ok(false), |v| {
            v.as_bool().ok_or_else(|| failure("protocol_error"))
        })?;
        let mut excluded = BTreeSet::new();
        if let Some(values) = request.get("excluded_state_dirs") {
            let values = values.as_array().ok_or_else(|| failure("protocol_error"))?;
            if values.len() > 64 {
                return Err(failure("protocol_error"));
            }
            for value in values {
                excluded.insert(secure::path(
                    value.as_str().ok_or_else(|| failure("protocol_error"))?,
                )?);
            }
        }
        for field in ["original_state_dir", "daemon_socket"] {
            if let Some(value) = request.get(field).filter(|v| !v.is_null()) {
                secure::path(value.as_str().ok_or_else(|| failure("protocol_error"))?)?;
            }
        }
        if let Some(port) = request.get("target_port").filter(|v| !v.is_null()) {
            if !port.as_u64().is_some_and(|p| (1..=65535).contains(&p)) {
                return Err(failure("protocol_error"));
            }
        }
        let (user, home) = secure::account()?;
        let mut services = Vec::new();
        let mut daemons = Vec::new();
        for (index, entry) in fs::read_dir("/proc")
            .map_err(|_| failure("security_error"))?
            .enumerate()
        {
            if index >= 131072 {
                return Err(failure("security_error"));
            }
            let Ok(entry) = entry else {
                continue;
            };
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|v| v.parse::<u32>().ok())
            else {
                continue;
            };
            if entry
                .metadata()
                .map(|v| v.uid() != secure::uid())
                .unwrap_or(true)
            {
                continue;
            }
            let Ok(argv) = secure::command_line(pid) else {
                continue;
            };
            if argv
                .first()
                .and_then(|v| Path::new(v).file_name())
                .is_none_or(|v| v != "tern")
            {
                continue;
            }
            let Ok((start, ppid)) = secure::process_stat(pid) else {
                continue;
            };
            if argv.iter().any(|v| v == "daemon") {
                if let Some(socket) = option(&argv, "--socket")? {
                    daemons.push(Daemon {
                        pid,
                        start: start.clone(),
                        ppid,
                        socket,
                    });
                }
            }
            if argv.get(1).map(String::as_str) != Some("remote")
                || argv.get(2).map(String::as_str) != Some("serve")
            {
                continue;
            }
            let Some(state) = option(&argv, "--state-dir")? else {
                continue;
            };
            let state = secure::path(&state)?;
            if dedicated(&state, &home, &excluded) {
                continue;
            }
            let Ok(binary) = secure::executable(pid) else {
                continue;
            };
            let Ok(daemon) = service_daemon(pid) else {
                continue;
            };
            let Ok(listeners) = udp_listeners(pid) else {
                continue;
            };
            services.push(Service {
                pid,
                start,
                state,
                listen: option(&argv, "--listen")?,
                daemon,
                argv,
                binary,
                listeners,
            });
        }
        let mut candidates = Vec::new();
        for (si, service) in services.iter().enumerate() {
            if request
                .get("original_state_dir")
                .filter(|v| !v.is_null())
                .is_some_and(|v| v.as_str() != service.state.to_str())
            {
                continue;
            }
            if original_files(&service.state).is_err() {
                continue;
            }
            for (di, daemon) in daemons.iter().enumerate() {
                let related = if let Some(wanted) = &service.daemon {
                    daemon.socket == *wanted
                } else {
                    daemon.ppid == service.pid
                        && daemon.start.parse::<u64>().unwrap_or(0)
                            >= service.start.parse::<u64>().unwrap_or(u64::MAX)
                };
                if !related
                    || request
                        .get("daemon_socket")
                        .filter(|v| !v.is_null())
                        .is_some_and(|v| v != &daemon.socket)
                {
                    continue;
                }
                let Ok(pin) = DaemonPin::new(&daemon.socket) else {
                    continue;
                };
                if pin.pid != daemon.pid || pin.identity["start_time"] != daemon.start {
                    continue;
                }
                for listener in
                    native_listeners(service.listen.as_deref(), &service.listeners, host)
                {
                    if request
                        .get("target_port")
                        .filter(|v| !v.is_null())
                        .is_some_and(|v| v.as_u64() != Some(listener.port as u64))
                    {
                        continue;
                    }
                    let binding = json!([
                        service.pid,
                        service.start,
                        service.state,
                        daemon.pid,
                        daemon.start,
                        daemon.socket,
                        listener.inode,
                        listener.port
                    ]);
                    let encoded =
                        serde_json::to_vec(&binding).map_err(|_| failure("protocol_error"))?;
                    let identifier = hex::encode(Sha256::digest(encoded))[..24].to_owned();
                    candidates.push(Candidate {
                        identifier,
                        service: si,
                        daemon: di,
                        listener,
                    });
                    if candidates.len() > 64 {
                        return Err(failure("security_error"));
                    }
                }
            }
        }
        if selected.is_none() && inventory && candidates.len() != 1 {
            let values:Vec<_>=candidates.iter().map(|c|json!({"id":c.identifier,"pid":services[c.service].pid,"state":services[c.service].state,"daemon_socket":daemons[c.daemon].socket,"port":c.listener.port})).collect();
            return Ok(
                json!({"ok":true,"home":home,"uid":secure::uid(),"user":user,"candidates":values}),
            );
        }
        let selected: Vec<_> = candidates
            .iter()
            .filter(|c| selected.is_none_or(|id| c.identifier == id))
            .collect();
        if selected.len() != 1 {
            return Err(failure("identity_mismatch"));
        }
        let chosen = selected[0];
        let service = &services[chosen.service];
        let daemon = &daemons[chosen.daemon];
        let pin = DaemonPin::new(&daemon.socket)?;
        if pin.pid != daemon.pid || pin.identity["start_time"] != daemon.start {
            return Err(failure("identity_mismatch"));
        }
        let files = original_files(&service.state)?;
        let identity = pin.capture(
            &[
                "remote".into(),
                "host-key".into(),
                "--state-dir".into(),
                service
                    .state
                    .to_str()
                    .ok_or_else(|| failure("security_error"))?
                    .into(),
            ],
            None,
            65536,
        )?;
        let fingerprint = identity["fingerprint"]
            .as_str()
            .ok_or_else(|| failure("protocol_error"))?;
        common::fingerprint(fingerprint).map_err(|_| failure("identity_mismatch"))?;
        if original_files(&service.state)? != files
            || secure::process_stat(service.pid)?.0 != service.start
            || secure::command_line(service.pid)? != service.argv
            || secure::executable(service.pid)? != service.binary
            || !udp_listeners(service.pid)?.contains(&chosen.listener)
        {
            return Err(failure("identity_mismatch"));
        }
        if service.daemon.is_none() && secure::process_stat(daemon.pid)?.1 != service.pid {
            return Err(failure("identity_mismatch"));
        }
        if fs::metadata(format!("/proc/{}", service.pid))
            .map_err(|_| failure("identity_mismatch"))?
            .uid()
            != secure::uid()
            || service_daemon(service.pid)? != service.daemon
        {
            return Err(failure("identity_mismatch"));
        }
        pin.check(true)?;
        Ok(
            json!({"ok":true,"home":home,"uid":secure::uid(),"user":user,"original_state_dir":service.state,"daemon_socket":daemon.socket,"target_port":chosen.listener.port,"fingerprint":fingerprint,"candidate_id":chosen.identifier}),
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn native_listener_never_guesses_iroh_or_missing_default() {
            let listeners = vec![Listener {
                port: 45000,
                address: "0.0.0.0".into(),
                inode: "1".into(),
            }];
            assert!(native_listeners(None, &listeners, "1.1.1.1").is_empty());
            assert_eq!(
                native_listeners(Some("0.0.0.0:45000"), &listeners, "1.1.1.1"),
                listeners
            );
            assert!(native_listeners(Some("10.0.0.1:45000"), &listeners, "1.1.1.1").is_empty());
        }
        #[test]
        fn kernel_udp_rows_require_owned_unconnected_inode() {
            let owned = ["42".to_owned()].into_iter().collect();
            let row = format!(
                "0: 0100007F:20B8 00000000:0000 07 00000000:00000000 00:00000000 00000000 {} 0 42",
                secure::uid()
            );
            let listener = table_listener(&row, &owned, false).unwrap().unwrap();
            assert_eq!(listener.address, "127.0.0.1");
            assert_eq!(listener.port, 8376);
            assert!(table_listener(&row, &BTreeSet::new(), false)
                .unwrap()
                .is_none());
            assert!(table_listener(
                &row.replace("00000000:0000 07", "0100007F:1111 01"),
                &owned,
                false
            )
            .unwrap()
            .is_none());
        }
        #[test]
        fn duplicate_options_and_reserved_gateway_are_ineligible() {
            assert!(option(
                &[
                    "--listen".into(),
                    "0.0.0.0:8376".into(),
                    "--listen=0.0.0.0:45000".into()
                ],
                "--listen"
            )
            .is_err());
            assert!(dedicated(
                Path::new("/home/test/.local/state/tern-turn-relay/native"),
                Path::new("/home/test"),
                &BTreeSet::new()
            ));
            let excluded = [PathBuf::from("/home/test/custom/native")]
                .into_iter()
                .collect();
            assert!(dedicated(
                Path::new("/home/test/custom/native"),
                Path::new("/home/test"),
                &excluded
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ssh_resolution_rejects_proxy_ambiguity_and_private_addresses() {
        assert_eq!(
            parse_resolution(b"hostname 1.1.1.1\nuser tester\nport 22\n").unwrap()["ssh_port"],
            22
        );
        for text in [
            "hostname 127.0.0.1\nuser tester\nport 22\n",
            "hostname 1.1.1.1\nhostname 8.8.8.8\nuser tester\nport 22\n",
            "hostname 1.1.1.1\nuser tester\nport 22\nproxycommand secret command\n",
        ] {
            let error = parse_resolution(text.as_bytes()).unwrap_err();
            assert!(!error.message.contains("secret"));
        }
        for ip in [
            "100.64.0.1",
            "169.254.1.1",
            "198.18.1.1",
            "192.0.2.1",
            "224.1.1.1",
            "1.01.1.1",
        ] {
            assert!(public_ipv4(ip).is_err());
        }
    }
    #[test]
    fn inventory_response_has_no_unvalidated_public_fields() {
        let endpoint = json!({"host":"1.1.1.1","user":"tester","ssh_port":22});
        let mut value = json!({"ok":true,"home":"/home/tester","uid":1000,"user":"tester","candidates":[{"id":"0123456789abcdef01234567","pid":42,"state":"/home/tester/original","daemon_socket":"/run/user/1000/daemon.sock","port":8376}]});
        assert!(validate_remote(&value, &endpoint).is_ok());
        value["private_environment"] = json!("secret");
        assert!(validate_remote(&value, &endpoint).is_err());
        value.as_object_mut().unwrap().remove("private_environment");
        value["user"] = json!("other");
        assert!(validate_remote(&value, &endpoint).is_err());
    }
}
