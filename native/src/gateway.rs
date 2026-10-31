//! SSH-only deployment and control of a single dedicated gateway generation.
use crate::common::{self, Error, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::RngCore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::OpenOptions,
    io::Read,
    net::SocketAddr,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    process::{Child, Command},
    sync::{oneshot, watch},
    task::JoinHandle,
    time::{timeout, Instant},
};
use tokio_util::sync::CancellationToken;

const MAX_LINE: usize = 65536;
const MAX_BINARY: u64 = 64 * 1024 * 1024;

pub(crate) fn failure(code: &str) -> Error {
    let (code, message) = match code {
        "protocol_error" => (
            "protocol_error",
            "Dedicated gateway returned an invalid control response.",
        ),
        "identity_mismatch" => (
            "identity_mismatch",
            "Gateway identity, existing daemon or endpoint verification failed.",
        ),
        "security_error" => (
            "security_error",
            "Dedicated gateway failed a security check.",
        ),
        "authorization_denied" => (
            "authorization_denied",
            "Dedicated gateway authorization was denied.",
        ),
        "control_eof" => ("control_eof", "Dedicated gateway control channel closed."),
        "heartbeat_timeout" => (
            "heartbeat_timeout",
            "Dedicated gateway control heartbeat expired.",
        ),
        "send_timeout" => ("send_timeout", "Dedicated gateway control send timed out."),
        "frontend_exit" => ("frontend_exit", "Dedicated gateway owned frontend exited."),
        "state_lock_busy" => (
            "state_lock_busy",
            "Dedicated gateway state is controlled by another SSH session.",
        ),
        "connectivity_uncertain" => (
            "connectivity_uncertain",
            "Dedicated gateway startup connectivity could not be established.",
        ),
        _ => (
            "unknown",
            "Dedicated gateway failed an unspecified control check.",
        ),
    };
    Error::new(code, message)
}

pub(crate) fn recoverable(code: &str) -> bool {
    matches!(
        code,
        "control_eof"
            | "heartbeat_timeout"
            | "send_timeout"
            | "frontend_exit"
            | "state_lock_busy"
            | "connectivity_uncertain"
    )
}

fn settings(config: &Value, pinned: bool) -> Result<(&str, &str, &str, &str)> {
    let alias = config["ssh_destination"]
        .as_str()
        .ok_or_else(|| failure("security_error"))?;
    common::safe_alias(alias).map_err(|_| failure("security_error"))?;
    let host = config["target"]["host"]
        .as_str()
        .ok_or_else(|| failure("identity_mismatch"))?;
    crate::discovery::public_ipv4(host)?;
    let state = config["gateway"]["state_dir"]
        .as_str()
        .ok_or_else(|| failure("security_error"))?;
    let socket = config["gateway"]["daemon_socket"]
        .as_str()
        .ok_or_else(|| failure("security_error"))?;
    common::safe_absolute(state).map_err(|_| failure("security_error"))?;
    common::safe_absolute(socket).map_err(|_| failure("security_error"))?;
    common::fingerprint(config["target"]["fingerprint"].as_str().unwrap_or(""))
        .map_err(|_| failure("identity_mismatch"))?;
    match config["gateway"].get("fingerprint") {
        Some(pin) => common::fingerprint(pin.as_str().unwrap_or(""))
            .map_err(|_| failure("identity_mismatch"))?,
        None if pinned => return Err(failure("identity_mismatch")),
        None => (),
    }
    Ok((alias, host, state, socket))
}

fn descriptor(config: &Value, value: Value, serving: bool) -> Result<Value> {
    let (_, host, _, socket) = settings(config, serving)?;
    let object = value
        .as_object()
        .ok_or_else(|| failure("identity_mismatch"))?;
    let mut fields: BTreeSet<&str> = [
        "ok",
        "fingerprint",
        "daemon_socket",
        "daemon_pid",
        "session_ids",
        "tab_ids",
        "pane_ids",
    ]
    .into_iter()
    .collect();
    if serving {
        fields.extend(["host", "port"]);
        if object.contains_key("native_frontend_pid") {
            fields.insert("native_frontend_pid");
        }
    }
    if object.keys().map(String::as_str).collect::<BTreeSet<_>>() != fields
        || value["ok"] != true
        || value["daemon_socket"] != socket
        || value["daemon_pid"].as_u64().unwrap_or(0) == 0
    {
        return Err(failure("identity_mismatch"));
    }
    common::fingerprint(value["fingerprint"].as_str().unwrap_or(""))
        .map_err(|_| failure("identity_mismatch"))?;
    if value["fingerprint"] == config["target"]["fingerprint"]
        || config["gateway"]
            .get("fingerprint")
            .is_some_and(|pin| pin != &value["fingerprint"])
    {
        return Err(failure("identity_mismatch"));
    }
    for field in ["session_ids", "tab_ids", "pane_ids"] {
        let items = value[field]
            .as_array()
            .ok_or_else(|| failure("identity_mismatch"))?;
        if items.is_empty()
            || items.len() > 4096
            || items.iter().any(|item| {
                item.as_u64().is_none()
                    && !item.as_str().is_some_and(|id| {
                        !id.is_empty() && id.len() <= 256 && !id.chars().any(|c| c.is_control())
                    })
            })
        {
            return Err(failure("identity_mismatch"));
        }
    }
    if serving
        && (value["host"] != host
            || !value["port"]
                .as_u64()
                .is_some_and(|p| (1024..=65535).contains(&p))
            || object
                .get("native_frontend_pid")
                .is_some_and(|p| p.as_u64().unwrap_or(0) == 0 || p == &value["daemon_pid"]))
    {
        return Err(failure("identity_mismatch"));
    }
    Ok(value)
}

pub(crate) struct SecretBytes(pub(crate) Vec<u8>);
impl Drop for SecretBytes {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

pub(crate) async fn send<W: AsyncWrite + Unpin>(writer: &mut W, value: &Value) -> Result<()> {
    let mut bytes = SecretBytes(serde_json::to_vec(value).map_err(|_| failure("protocol_error"))?);
    bytes.0.push(b'\n');
    timeout(Duration::from_secs(5), writer.write_all(&bytes.0))
        .await
        .map_err(|_| failure("send_timeout"))?
        .map_err(|_| failure("control_eof"))
}

pub(crate) async fn receive<R: AsyncBufRead + Unpin>(reader: &mut R) -> Result<Value> {
    // read_until itself is unbounded; consume only a bounded prefix on each poll.
    let mut bytes = Vec::with_capacity(1024);
    loop {
        let available = reader
            .fill_buf()
            .await
            .map_err(|_| failure("control_eof"))?;
        if available.is_empty() {
            return Err(failure(if bytes.is_empty() {
                "control_eof"
            } else {
                "protocol_error"
            }));
        }
        let end = available.iter().position(|b| *b == b'\n').map(|n| n + 1);
        let count = end.unwrap_or(available.len());
        if bytes.len() + count > MAX_LINE {
            return Err(failure("protocol_error"));
        }
        bytes.extend_from_slice(&available[..count]);
        reader.consume(count);
        if end.is_some() {
            break;
        }
    }
    let value = crate::remote::parse_json(&bytes)?;
    if value["ok"] == false {
        return Err(failure(value["reason"].as_str().unwrap_or("unknown")));
    }
    if value["ok"] != true {
        return Err(failure("protocol_error"));
    }
    Ok(value)
}

// Fixed bootstrap code; the only variable arguments are a canonical cache path,
// a SHA-256 digest and a bounded size. Executable bytes arrive over SSH stdin.
// Releases are immutable so deployment never rewrites an executing helper.
const INSTALLER: &str = r#"
set -efu
PATH=/usr/bin:/bin
export PATH
umask 077
root=$1; digest=$2; size=$3
uid=$(id -u)
check_dir() {
    [ ! -L "$1" ] && [ -d "$1" ] || exit 41
    owner=$(stat -c %u -- "$1"); mode=$(stat -c %a -- "$1")
    [ "$owner" = 0 ] || [ "$owner" = "$uid" ] || exit 41
    [ $((0$mode & 0022)) -eq 0 ] || exit 41
}
walk() {
    rest=${1#/}; current=
    while [ -n "$rest" ]; do
        part=${rest%%/*}; current=$current/$part
        if [ "$rest" = "$part" ]; then rest=; else rest=${rest#*/}; fi
        [ -n "$part" ] && [ "$part" != . ] && [ "$part" != .. ] || exit 41
        if [ ! -e "$current" ] && [ ! -L "$current" ]; then mkdir -m 700 -- "$current" || exit 41; fi
        check_dir "$current"
    done
}
walk "$root"
[ "$(stat -c %u -- "$root")" = "$uid" ] && [ "$(stat -c %a -- "$root")" = 700 ] || exit 41
release=$root/$digest
if [ ! -e "$release" ] && [ ! -L "$release" ]; then mkdir -m 700 -- "$release" || exit 41; fi
check_dir "$release"
[ "$(stat -c %u -- "$release")" = "$uid" ] && [ "$(stat -c %a -- "$release")" = 700 ] || exit 41
binary=$release/tern-turn-relay
valid() {
    [ ! -L "$binary" ] && [ -f "$binary" ] || return 1
    [ "$(stat -c %u -- "$binary")" = "$uid" ] && [ "$(stat -c %a -- "$binary")" = 700 ] &&
    [ "$(stat -c %h -- "$binary")" = 1 ] && [ "$(stat -c %s -- "$binary")" = "$size" ] || return 1
    actual=$(sha256sum -- "$binary"); [ "${actual%% *}" = "$digest" ]
}
temporary=$(mktemp "$release/.upload.XXXXXXXXXXXX")
trap 'rm -f -- "$temporary"' EXIT HUP INT TERM
# Local input is bounded before SSH starts; also cap remote disk consumption.
dd iflag=fullblock bs=65536 count=1025 of="$temporary" 2>/dev/null
[ "$(stat -c %s -- "$temporary")" = "$size" ] || exit 41
actual=$(sha256sum -- "$temporary"); [ "${actual%% *}" = "$digest" ] || exit 41
chmod 700 -- "$temporary"
if [ -e "$binary" ] || [ -L "$binary" ]; then valid || exit 41;
else ln -- "$temporary" "$binary" || exit 41; fi
rm -f -- "$temporary"
valid || exit 41
printf '{"ok":true,"digest":"%s"}\n' "$digest"
"#;

pub(crate) async fn deploy(alias: &str, endpoint: &Value) -> Result<String> {
    let probe = common::run(
        "/usr/bin/ssh",
        &common::ssh_args(
            alias,
            "PATH=/usr/bin:/bin; export PATH; printf '%s\\n' \"$(uname -m)\" \"$HOME\"",
        ),
        None,
        Duration::from_secs(15),
    )
    .await
    .map_err(|_| failure("connectivity_uncertain"))?;
    if !probe.status.success() {
        return Err(failure("connectivity_uncertain"));
    }
    let text = std::str::from_utf8(&probe.stdout).map_err(|_| failure("protocol_error"))?;
    let lines: Vec<&str> = text.lines().collect();
    if lines.len() != 2 {
        return Err(failure("protocol_error"));
    }
    let arch = match lines[0] {
        "x86_64" => "x86_64",
        "aarch64" | "arm64" => "aarch64",
        _ => return Err(failure("security_error")),
    };
    common::safe_absolute(lines[1]).map_err(|_| failure("security_error"))?;
    if endpoint["user"].as_str().is_none() {
        return Err(failure("security_error"));
    }
    let source = crate::assets::ensure_remote(arch).await?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(source)
        .map_err(|_| failure("security_error"))?;
    let info = file.metadata().map_err(|_| failure("security_error"))?;
    if !info.is_file()
        || info.uid() != unsafe { libc::geteuid() }
        || info.mode() & 0o022 != 0
        || info.nlink() != 1
        || info.len() == 0
        || info.len() > MAX_BINARY
    {
        return Err(failure("security_error"));
    }
    let mut bytes = Vec::with_capacity(info.len() as usize);
    file.take(MAX_BINARY + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| failure("security_error"))?;
    if bytes.len() as u64 != info.len() {
        return Err(failure("security_error"));
    }
    let digest = hex::encode(Sha256::digest(&bytes));
    let root = format!("{}/.cache/tern-turn-relay-native", lines[1]);
    let command = format!(
        "/bin/sh -c {} sh {} {} {}",
        common::shell_quote(INSTALLER),
        common::shell_quote(&root),
        digest,
        bytes.len()
    );
    let output = common::run(
        "/usr/bin/ssh",
        &common::ssh_args(alias, &command),
        Some(&bytes),
        Duration::from_secs(40),
    )
    .await
    .map_err(|_| failure("connectivity_uncertain"))?;
    if !output.status.success() {
        return Err(failure("security_error"));
    }
    let response = crate::remote::parse_json(&output.stdout)?;
    if response != json!({"ok":true,"digest":digest}) {
        return Err(failure("identity_mismatch"));
    }
    Ok(format!("{root}/{digest}/tern-turn-relay"))
}

async fn prepare(config: &Value, pinned: bool) -> Result<String> {
    let (alias, host, _, _) = settings(config, pinned)?;
    let endpoint = crate::discovery::resolve(alias).await?;
    if endpoint["host"] != host
        || config["target"]
            .get("user")
            .is_some_and(|u| u != &endpoint["user"])
        || config["target"]
            .get("ssh_port")
            .is_some_and(|p| p != &endpoint["ssh_port"])
    {
        return Err(failure("identity_mismatch"));
    }
    deploy(alias, &endpoint).await
}

fn initial_request(config: &Value, host: &str, socket: &str) -> Value {
    let mut request = json!({"daemon_socket":socket,"bind_host":host,
        "original_fingerprint":config["target"]["fingerprint"]});
    if let Some(pin) = config["gateway"].get("fingerprint") {
        request["gateway_fingerprint"] = pin.clone();
    }
    request
}

pub async fn provision(config: &Value) -> Result<Value> {
    timeout(Duration::from_secs(50), async {
        let helper = prepare(config, false).await?;
        let (alias, host, state, socket) = settings(config, false)?;
        let command = format!(
            "{} remote provision --state-dir {}",
            common::shell_quote(&helper),
            common::shell_quote(state)
        );
        let mut input = serde_json::to_vec(&initial_request(config, host, socket))
            .map_err(|_| failure("protocol_error"))?;
        input.push(b'\n');
        let output = common::run(
            "/usr/bin/ssh",
            &common::ssh_args(alias, &command),
            Some(&input),
            Duration::from_secs(30),
        )
        .await
        .map_err(|_| failure("connectivity_uncertain"))?;
        let mut reader = BufReader::new(output.stdout.as_slice());
        let response = receive(&mut reader).await?;
        if !output.status.success() {
            return Err(failure("security_error"));
        }
        descriptor(config, response, false)
    })
    .await
    .map_err(|_| failure("connectivity_uncertain"))?
}

pub struct Gateway {
    pub peer: SocketAddr,
    pub key: [u8; 32],
    pub descriptor: Value,
    cancel: CancellationToken,
    failed: watch::Receiver<Option<&'static str>>,
    task: Option<JoinHandle<()>>,
}

impl Drop for Gateway {
    fn drop(&mut self) {
        self.cancel.cancel();
        wipe(&mut self.key);
        // The detached supervisor owns and reaps the SSH process even when an
        // opening/closing future is cancelled. Never abort it from Drop.
    }
}

pub(crate) fn wipe(bytes: &mut [u8]) {
    for byte in bytes {
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

impl Gateway {
    pub async fn open(config: &Value) -> Result<Self> {
        timeout(Duration::from_secs(50), Self::open_inner(config))
            .await
            .map_err(|_| failure("connectivity_uncertain"))?
            .map_err(|e| {
                if e.code == "control_eof" {
                    failure("connectivity_uncertain")
                } else {
                    e
                }
            })
    }

    async fn open_inner(config: &Value) -> Result<Self> {
        let helper = prepare(config, true).await?;
        let (alias, host, state, socket) = settings(config, true)?;
        let command = format!(
            "{} remote serve --state-dir {}",
            common::shell_quote(&helper),
            common::shell_quote(state)
        );
        let mut child = Command::new("/usr/bin/ssh")
            .args(common::ssh_args(alias, &command))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| failure("connectivity_uncertain"))?;
        let input = child.stdin.take().ok_or_else(|| failure("unknown"))?;
        let output = child.stdout.take().ok_or_else(|| failure("unknown"))?;
        let cancel = CancellationToken::new();
        let (failure_tx, failed) = watch::channel(None);
        let (ready_tx, ready_rx) = oneshot::channel();
        let mut result = Self {
            peer: "0.0.0.0:0".parse().unwrap(),
            key: [0; 32],
            descriptor: Value::Null,
            cancel: cancel.clone(),
            failed,
            task: None,
        };
        rand::rngs::OsRng.fill_bytes(&mut result.key);
        let mut request = initial_request(config, host, socket);
        request["session_key"] = Value::String(STANDARD.encode(&result.key));
        let mut request_bytes =
            SecretBytes(serde_json::to_vec(&request).map_err(|_| failure("protocol_error"))?);
        request_bytes.0.push(b'\n');
        if let Some(Value::String(encoded)) = request
            .as_object_mut()
            .and_then(|v| v.remove("session_key"))
        {
            wipe(&mut encoded.into_bytes());
        }
        let config = config.clone();
        result.task = Some(tokio::spawn(async move {
            let mut input = input;
            let mut output = BufReader::new(output);
            let work = async {
                let sent = timeout(Duration::from_secs(5), input.write_all(&request_bytes.0)).await;
                wipe(&mut request_bytes.0);
                sent.map_err(|_| failure("send_timeout"))?
                    .map_err(|_| failure("control_eof"))?;
                let value = descriptor(&config, receive(&mut output).await?, true)?;
                if child
                    .try_wait()
                    .map_err(|_| failure("control_eof"))?
                    .is_some()
                {
                    return Err(failure("control_eof"));
                }
                ready_tx.send(value).map_err(|_| failure("control_eof"))?;
                supervise(&mut input, &mut output).await
            };
            let outcome: Result<()> = tokio::select! {
                biased;
                _ = cancel.cancelled() => Ok(()),
                result = work => result,
            };
            if let Err(error) = outcome {
                let _ = failure_tx.send(Some(error.code));
            }
            drop(input); // EOF revokes the remote generation before local reap.
            let drain = tokio::spawn(async move {
                let _ = tokio::io::copy(&mut output, &mut tokio::io::sink()).await;
            });
            reap(&mut child).await;
            drain.abort();
            let _ = drain.await;
        }));
        tokio::select! {
            biased;
            changed = result.failed.changed() => {
                let _ = changed;
                let code = (*result.failed.borrow()).unwrap_or("control_eof");
                Err(failure(code))
            }
            ready = ready_rx => {
                let value = ready.map_err(|_| failure((*result.failed.borrow()).unwrap_or("control_eof")))?;
                result.peer = SocketAddr::new(host.parse().map_err(|_| failure("identity_mismatch"))?,
                    value["port"].as_u64().ok_or_else(|| failure("identity_mismatch"))? as u16);
                result.descriptor = value;
                Ok(result)
            }
        }
    }

    pub async fn failure(&mut self) -> Result<()> {
        loop {
            let reason = *self.failed.borrow();
            if let Some(code) = reason {
                wipe(&mut self.key);
                return Err(failure(code));
            }
            if self.failed.changed().await.is_err() {
                wipe(&mut self.key);
                return Err(failure("control_eof"));
            }
        }
    }

    pub async fn close(&mut self) -> Result<()> {
        self.cancel.cancel();
        wipe(&mut self.key);
        if let Some(task) = self.task.as_mut() {
            timeout(Duration::from_secs(8), task)
                .await
                .map_err(|_| failure("send_timeout"))?
                .map_err(|_| failure("unknown"))?;
            self.task = None;
        }
        Ok(())
    }
}

async fn supervise<W: AsyncWrite + Unpin, R: AsyncBufRead + Unpin>(
    input: &mut W,
    output: &mut R,
) -> Result<()> {
    let heartbeat = async {
        let mut ping = tokio::time::interval_at(
            Instant::now() + Duration::from_secs(15),
            Duration::from_secs(15),
        );
        ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ping.tick().await;
            send(input, &json!({"op":"ping"})).await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), Error>(())
    };
    let observe = async {
        loop {
            let value = timeout(Duration::from_secs(35), receive(output))
                .await
                .map_err(|_| failure("heartbeat_timeout"))??;
            if value != json!({"ok":true,"op":"pong"}) {
                return Err(failure("protocol_error"));
            }
        }
    };
    // A ready protocol/security rejection wins over a simultaneous send failure.
    // Neither partial receive nor partial send is cancelled by a heartbeat tick.
    tokio::select! { biased; result = observe => result, result = heartbeat => result }
}

async fn reap(child: &mut Child) {
    if timeout(Duration::from_secs(5), child.wait()).await.is_err() {
        let _ = child.start_kill();
        let _ = timeout(Duration::from_secs(2), child.wait()).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> Value {
        json!({"ssh_destination":"server","target":{"host":"1.1.1.1","fingerprint":format!("SHA256:{}",STANDARD.encode([1u8;32]).trim_end_matches('='))},"gateway":{"state_dir":"/home/test/gateway","daemon_socket":"/run/user/1000/daemon.sock","fingerprint":format!("SHA256:{}",STANDARD.encode([2u8;32]).trim_end_matches('='))}})
    }
    fn value() -> Value {
        let c = config();
        json!({"ok":true,"fingerprint":c["gateway"]["fingerprint"],"daemon_socket":c["gateway"]["daemon_socket"],"daemon_pid":42,"native_frontend_pid":43,"session_ids":["s"],"tab_ids":["t"],"pane_ids":["p"],"host":"1.1.1.1","port":45000})
    }
    #[test]
    fn descriptor_never_exposes_secret_or_original_identity() {
        assert!(descriptor(&config(), value(), true).is_ok());
        for (field, bad) in [
            ("session_key", json!("secret")),
            ("daemon_pid", json!(true)),
            ("port", json!(22)),
            ("native_frontend_pid", json!(42)),
            ("pane_ids", json!(["\u{0}"])),
        ] {
            let mut v = value();
            v[field] = bad;
            assert_eq!(
                descriptor(&config(), v, true).unwrap_err().code,
                "identity_mismatch"
            );
        }
        let mut v = value();
        v["fingerprint"] = config()["target"]["fingerprint"].clone();
        assert!(descriptor(&config(), v, true).is_err());
    }
    #[tokio::test]
    async fn receive_limits_frames_and_sanitizes_errors() {
        for (raw, code) in [
            (b"".as_slice(), "control_eof"),
            (b"{", "protocol_error"),
            (b"[]\n", "protocol_error"),
            (
                b"{\"ok\":false,\"reason\":\"secret\",\"recoverable\":true}\n",
                "unknown",
            ),
        ] {
            let e = receive(&mut BufReader::new(raw)).await.unwrap_err();
            assert_eq!(e.code, code);
            assert!(!e.message.contains("secret"));
        }
        let large = vec![b'x'; MAX_LINE + 1];
        assert_eq!(
            receive(&mut BufReader::new(large.as_slice()))
                .await
                .unwrap_err()
                .code,
            "protocol_error"
        );
        assert!(!recoverable("authorization_denied"));
        assert!(recoverable("frontend_exit"));
    }
    #[tokio::test]
    async fn fragmented_control_line_preserves_boundaries() {
        let (mut writer, reader) = tokio::io::duplex(8);
        let task = tokio::spawn(async move {
            writer.write_all(b"{\"ok\":true,").await.unwrap();
            writer.write_all(b"\"op\":\"pong\"}\n").await.unwrap();
        });
        assert_eq!(
            receive(&mut BufReader::new(reader)).await.unwrap(),
            json!({"ok":true,"op":"pong"})
        );
        task.await.unwrap();
    }
    #[tokio::test]
    async fn failed_control_erases_generation_key_and_close_is_idempotent() {
        let (sender, failed) = watch::channel(None);
        let cancel = CancellationToken::new();
        let owned = cancel.clone();
        let task = tokio::spawn(async move {
            owned.cancelled().await;
        });
        let mut gateway = Gateway {
            peer: "127.0.0.1:45000".parse().unwrap(),
            key: [7; 32],
            descriptor: Value::Null,
            cancel,
            failed,
            task: Some(task),
        };
        sender.send(Some("identity_mismatch")).unwrap();
        assert_eq!(
            gateway.failure().await.unwrap_err().code,
            "identity_mismatch"
        );
        assert_eq!(gateway.key, [0; 32]);
        gateway.close().await.unwrap();
        gateway.close().await.unwrap();
        assert!(gateway.task.is_none());
    }
    #[tokio::test]
    async fn supervisor_rejects_non_pong_and_control_eof() {
        for (raw, reason) in [
            (
                b"{\"ok\":true,\"op\":\"other\"}\n".as_slice(),
                "protocol_error",
            ),
            (b"".as_slice(), "control_eof"),
        ] {
            assert_eq!(
                supervise(&mut tokio::io::sink(), &mut BufReader::new(raw))
                    .await
                    .unwrap_err()
                    .code,
                reason
            );
        }
    }
}
