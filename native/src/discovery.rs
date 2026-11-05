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
    daemon_socket: Option<&str>,
) -> Result<Value> {
    if selected.is_some_and(|id| !candidate_id(id)) || excluded_state_dirs.len() > 64 {
        return Err(failure("protocol_error"));
    }
    for path in excluded_state_dirs {
        common::safe_absolute(path).map_err(|_| failure("security_error"))?;
    }
    if let Some(socket) = daemon_socket {
        common::safe_absolute(socket).map_err(|_| failure("security_error"))?;
    }
    let endpoint = resolve(alias).await?;
    let helper = crate::gateway::deploy(alias, &endpoint).await?;
    let request = json!({"target_host":endpoint["host"],"candidate_id":selected,"excluded_state_dirs":excluded_state_dirs,"inventory":true,"daemon_socket":daemon_socket});
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
    fn related(service: &Service, daemon: &Daemon, requested_socket: Option<&str>) -> bool {
        if requested_socket.is_some_and(|socket| socket != daemon.socket) {
            return false;
        }
        if let Some(socket) = &service.daemon {
            // A saved socket must never override the service's explicit environment.
            return *socket == daemon.socket;
        }
        // No upstream default-path contract is available here. Only an explicitly
        // supplied, saved socket may associate an independent --user daemon.
        // Unknown/non-user modes retain the original parent/start-time rule.
        (requested_socket.is_some()
            && service.argv.iter().take_while(|arg| arg.as_str() != "--").any(|arg| arg == "--user"))
            || (daemon.ppid == service.pid
                && daemon.start.parse::<u64>().unwrap_or(0)
                    >= service.start.parse::<u64>().unwrap_or(u64::MAX))
    }
    fn matching_daemons<'a>(
        service: &'a Service,
        daemons: &'a [Daemon],
        requested_socket: Option<&'a str>,
        mut verified: impl FnMut(&Daemon) -> bool + 'a,
    ) -> impl Iterator<Item = (usize, &'a Daemon)> + 'a {
        daemons.iter().enumerate().filter(move |(_, daemon)| {
            related(service, daemon, requested_socket) && verified(daemon)
        })
    }
    fn verified_daemon(daemon: &Daemon) -> bool {
        // This includes socket ownership, SO_PEERCRED UID, executable and argv
        // checks; a path match alone is never sufficient evidence.
        DaemonPin::new(&daemon.socket).is_ok_and(|pin| {
            pin.pid == daemon.pid && pin.identity["start_time"] == daemon.start
        })
    }
    fn choose_candidate<'a>(
        candidates: &'a [Candidate],
        selected: Option<&str>,
    ) -> Result<&'a Candidate> {
        let mut matching = candidates
            .iter()
            .filter(|candidate| selected.is_none_or(|id| candidate.identifier == id));
        let chosen = matching.next().ok_or_else(|| failure("identity_mismatch"))?;
        if matching.next().is_some() {
            return Err(failure("identity_mismatch"));
        }
        Ok(chosen)
    }
    fn service_daemon(pid: u32) -> Result<Option<String>> {
        let raw = secure::bounded(&PathBuf::from(format!("/proc/{pid}/environ")), 1024 * 1024)?;
        daemon_environment(&raw)
    }
    fn daemon_environment(raw: &[u8]) -> Result<Option<String>> {
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
            for (di, daemon) in matching_daemons(
                service,
                &daemons,
                request["daemon_socket"].as_str(),
                verified_daemon,
            ) {
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
        let chosen = choose_candidate(&candidates, selected)?;
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
        let current_daemon = Daemon {
            pid: daemon.pid,
            start: pin.identity["start_time"]
                .as_str()
                .ok_or_else(|| failure("identity_mismatch"))?
                .to_owned(),
            ppid: secure::process_stat(daemon.pid)?.1,
            socket: daemon.socket.clone(),
        };
        if !related(service, &current_daemon, request["daemon_socket"].as_str()) {
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
        fn service() -> Service {
            Service {
                pid: 100,
                start: "1000".into(),
                state: "/home/test/original".into(),
                listen: None,
                daemon: None,
                argv: vec!["tern".into(), "remote".into(), "serve".into(), "--user".into()],
                binary: "/home/test/bin/tern".into(),
                listeners: vec![Listener {
                    port: 8376,
                    address: "0.0.0.0".into(),
                    inode: "42".into(),
                }],
            }
        }
        fn daemon(pid: u32, ppid: u32, socket: &str) -> Daemon {
            Daemon {
                pid,
                ppid,
                start: "2000".into(),
                socket: socket.into(),
            }
        }
        fn candidates(
            service: &Service,
            daemons: &[Daemon],
            requested_socket: Option<&str>,
            verified: impl FnMut(&Daemon) -> bool,
        ) -> Vec<Candidate> {
            // Exercise the same association + mandatory verification iterator
            // and uniqueness selector used by discovery, not just path parsing.
            matching_daemons(service, daemons, requested_socket, verified)
                .map(|(index, daemon)| Candidate {
                    identifier: format!("{:024x}", daemon.pid),
                    service: 0,
                    daemon: index,
                    listener: service.listeners[0].clone(),
                })
                .collect()
        }
        #[test]
        fn independent_user_daemon_requires_exact_saved_socket_and_verification() {
            let service = service();
            let daemons = [
                daemon(201, 1, "/home/test/test.sock"),
                daemon(202, 1, "/run/user/1000/tern/daemon.sock"),
                daemon(203, 1, "/run/user/1001/tern/daemon.sock"),
            ];
            let mut verified = Vec::new();
            let found = candidates(
                &service,
                &daemons,
                Some("/run/user/1000/tern/daemon.sock"),
                |daemon| {
                    verified.push(daemon.pid);
                    true
                },
            );
            assert_eq!(verified, [202]);
            assert_eq!(choose_candidate(&found, None).unwrap().daemon, 1);
            assert!(candidates(&service, &daemons, None, |_| true).is_empty());
            assert!(candidates(&service, &daemons, Some("/missing.sock"), |_| true).is_empty());
            // A failed DaemonPin check (including another UID's SO_PEERCRED)
            // cannot be bypassed even when the saved path matches exactly.
            let refused = candidates(
                &service,
                &daemons,
                Some("/run/user/1000/tern/daemon.sock"),
                |_| false,
            );
            assert!(choose_candidate(&refused, None).is_err());
        }
        #[test]
        fn explicit_daemon_environment_wins_over_saved_socket_and_parent() {
            let mut service = service();
            service.daemon = daemon_environment(
                b"TERN_PANE_SOCKET=/pane.sock\0TERN_DAEMON_SOCKET=/explicit.sock\0",
            ).unwrap();
            assert_eq!(service.daemon.as_deref(), Some("/explicit.sock"));
            let daemons = [
                daemon(201, service.pid, "/saved.sock"),
                daemon(202, 1, "/explicit.sock"),
                daemon(203, 1, "/pane.sock"),
            ];
            let found = candidates(&service, &daemons, None, |_| true);
            assert_eq!(choose_candidate(&found, None).unwrap().daemon, 1);
            assert!(candidates(&service, &daemons, Some("/saved.sock"), |_| true).is_empty());
            let found = candidates(&service, &daemons, Some("/explicit.sock"), |_| true);
            assert_eq!(choose_candidate(&found, None).unwrap().daemon, 1);
            service.daemon = daemon_environment(b"TERN_PANE_SOCKET=/pane.sock\0").unwrap();
            let found = candidates(&service, &daemons, None, |_| true);
            assert_eq!(choose_candidate(&found, None).unwrap().daemon, 2);
        }
        #[test]
        fn unknown_mode_retains_parent_and_start_time_requirements() {
            let mut service = service();
            service.argv.pop();
            let mut daemons = [daemon(201, 1, "/saved.sock")];
            assert!(candidates(&service, &daemons, Some("/saved.sock"), |_| true).is_empty());
            daemons[0].ppid = service.pid;
            let found = candidates(&service, &daemons, Some("/saved.sock"), |_| true);
            assert_eq!(choose_candidate(&found, None).unwrap().daemon, 0);
            daemons[0].start = "999".into();
            assert!(candidates(&service, &daemons, Some("/saved.sock"), |_| true).is_empty());
            service.argv.extend(["--".into(), "--user".into()]);
            daemons[0].ppid = 1;
            assert!(candidates(&service, &daemons, Some("/saved.sock"), |_| true).is_empty());
        }
        #[test]
        fn ambiguous_daemons_are_not_reduced_to_first_match() {
            let service = service();
            let daemons = [
                daemon(201, service.pid, "/first.sock"),
                daemon(202, service.pid, "/second.sock"),
            ];
            let found = candidates(&service, &daemons, None, |_| true);
            assert_eq!(found.len(), 2);
            assert!(choose_candidate(&found, None).is_err());
            assert_eq!(choose_candidate(&found, Some(&found[1].identifier)).unwrap().daemon, 1);
            let unknown = [daemon(201, 1, "/first.sock"), daemon(202, 1, "/second.sock")];
            assert!(candidates(&service, &unknown, None, |_| true).is_empty());
        }
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
