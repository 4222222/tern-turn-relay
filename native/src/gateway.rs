//! SSH-only deployment and control of a single dedicated gateway generation.
use crate::common::{self, Error, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::RngCore;
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    io::Read,
    net::SocketAddr,
    process::{Output, Stdio},
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

// Both phases use the same fixed validation rules. Probe never creates or
// changes paths; only a missing, otherwise trusted cache permits an upload.
const INSTALLER: &str = r#"
set -efu
PATH=/usr/bin:/bin
export PATH
umask 077
root=$1; digest=$2; size=$3; operation=$4
case "$operation" in probe|install) ;; *) exit 41 ;; esac
uid=$(id -u)
missing() {
    if [ "$operation" = probe ]; then
        printf '{"ok":true,"digest":"%s","cached":false}\n' "$digest"
        exit 0
    fi
}
check_dir() {
    [ ! -L "$1" ] && [ -d "$1" ] || exit 41
    owner=$(stat -c %u -- "$1"); mode=$(stat -c %a -- "$1")
    [ "$owner" = 0 ] || [ "$owner" = "$uid" ] || exit 41
    [ $((0$mode & 0022)) -eq 0 ] || exit 41
}
walk() {
    check_dir /
    rest=${1#/}; current=
    while [ -n "$rest" ]; do
        part=${rest%%/*}; current=$current/$part
        if [ "$rest" = "$part" ]; then rest=; else rest=${rest#*/}; fi
        [ -n "$part" ] && [ "$part" != . ] && [ "$part" != .. ] || exit 41
        if [ ! -e "$current" ] && [ ! -L "$current" ]; then
            missing
            mkdir -m 700 -- "$current" || exit 41
        fi
        check_dir "$current"
    done
}
walk "$root"
[ "$(stat -c %u -- "$root")" = "$uid" ] && [ "$(stat -c %a -- "$root")" = 700 ] || exit 41
release=$root/$digest
if [ ! -e "$release" ] && [ ! -L "$release" ]; then
    missing
    mkdir -m 700 -- "$release" || exit 41
fi
check_dir "$release"
[ "$(stat -c %u -- "$release")" = "$uid" ] && [ "$(stat -c %a -- "$release")" = 700 ] || exit 41
binary=$release/tern-turn-relay
valid() {
    [ ! -L "$binary" ] && [ -f "$binary" ] || return 1
    [ "$(stat -c %u -- "$binary")" = "$uid" ] && [ "$(stat -c %a -- "$binary")" = 700 ] &&
    [ "$(stat -c %h -- "$binary")" = 1 ] && [ "$(stat -c %s -- "$binary")" = "$size" ] || return 1
    actual=$(sha256sum -- "$binary"); [ "${actual%% *}" = "$digest" ]
}
if [ "$operation" = probe ]; then
    if [ ! -e "$binary" ] && [ ! -L "$binary" ]; then missing; fi
    valid || exit 41
    printf '{"ok":true,"digest":"%s","cached":true}\n' "$digest"
    exit 0
fi
temporary=$(mktemp "$release/.upload.XXXXXXXXXXXX")
trap 'rm -f -- "$temporary"' EXIT HUP INT TERM
# The expected hash remains the manifest digest, not a hash supplied by stdin.
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

#[derive(Clone, Copy)]
enum PreparationStage {
    Architecture,
    CacheProbe,
    CacheInstall,
}

impl PreparationStage {
    fn annotate(self, mut error: Error) -> Error {
        error.message = match self {
            Self::Architecture => "Dedicated gateway architecture probe failed.",
            Self::CacheProbe => "Dedicated gateway cache probe failed.",
            Self::CacheInstall => "Dedicated gateway cache install failed.",
        };
        error
    }

    fn failure(self, code: &str) -> Error {
        self.annotate(failure(code))
    }

    fn process_error(self, error: Error) -> Error {
        // Without a completed Output, only an explicit deadline is evidence
        // of a transient failure. Spawn, I/O and output-limit errors fail closed.
        self.failure(if error.code == "process-timeout" {
            "connectivity_uncertain"
        } else {
            "unknown"
        })
    }
}

fn network_diagnostic(line: &str) -> bool {
    let reason = if let Some(rest) = line.strip_prefix("ssh: connect to host ") {
        rest.rsplit_once(": ").map(|(_, reason)| reason)
    } else if let Some(rest) = line.strip_prefix("Read from remote host ") {
        rest.rsplit_once(": ").map(|(_, reason)| reason)
    } else {
        line.strip_prefix("kex_exchange_identification: read: ")
            .or_else(|| line.strip_prefix("client_loop: send disconnect: "))
    };
    if reason.is_some_and(|reason| {
        matches!(reason, "Connection timed out" | "Operation timed out"
            | "Connection reset by peer" | "Connection refused"
            | "No route to host" | "Network is unreachable" | "Broken pipe")
    }) || line == "Connection timed out during banner exchange" {
        return true;
    }
    let peer = line.strip_prefix("Connection reset by ").or_else(|| {
        line.strip_prefix("Connection to ")?.strip_suffix(" timed out")
    });
    peer.and_then(|peer| peer.rsplit_once(" port "))
        .is_some_and(|(host, port)| {
            !host.is_empty()
                && !host.chars().any(char::is_whitespace)
                && port.parse::<u16>().is_ok_and(|port| port != 0)
        })
}

fn preparation_status(output: &Output, stage: PreparationStage) -> Result<()> {
    if output.status.success() {
        return Ok(());
    }
    // Keep the exit status and stderr together until classification. In
    // particular, the installer's validation refusal outranks network text.
    let code = if output.status.code() == Some(41) {
        "security_error"
    } else if let Ok(stderr) = std::str::from_utf8(&output.stderr) {
        let contains = |needle: &str| {
            stderr.as_bytes().windows(needle.len())
                .any(|part| part.eq_ignore_ascii_case(needle.as_bytes()))
        };
        if ["host key", "hostkey", "remote host identification has changed"]
            .iter().any(|needle| contains(needle)) {
            "security_error"
        } else if ["permission denied", "access denied", "authentication",
            "load key", "sign_and_send_pubkey"]
            .iter().any(|needle| contains(needle)) {
            "authorization_denied"
        } else if output.status.code() == Some(255)
            && !stderr.trim().is_empty()
            && stderr.lines().map(str::trim).filter(|line| !line.is_empty())
                .all(network_diagnostic)
        {
            // Only known OpenSSH network diagnostics qualify. Unknown lines,
            // including localized diagnostics, remain terminal rather than
            // guessing from exit 255 or network words in arbitrary text.
            "connectivity_uncertain"
        } else {
            "unknown"
        }
    } else {
        "unknown"
    };
    Err(stage.failure(code))
}

fn architecture_response(output: &Output) -> Result<(&str, &str)> {
    let stage = PreparationStage::Architecture;
    preparation_status(output, stage)?;
    let text = std::str::from_utf8(&output.stdout)
        .map_err(|_| stage.failure("protocol_error"))?;
    let mut lines = text.lines();
    let (Some(arch), Some(home), None) = (lines.next(), lines.next(), lines.next()) else {
        return Err(stage.failure("protocol_error"));
    };
    let arch = match arch {
        "x86_64" => "x86_64",
        "aarch64" | "arm64" => "aarch64",
        _ => return Err(stage.failure("security_error")),
    };
    common::safe_absolute(home).map_err(|_| stage.failure("security_error"))?;
    Ok((arch, home))
}

fn cache_response(output: &Output, digest: &str) -> Result<bool> {
    let stage = PreparationStage::CacheProbe;
    preparation_status(output, stage)?;
    let response = crate::remote::parse_json(&output.stdout).map_err(|e| stage.annotate(e))?;
    let cached = response["cached"]
        .as_bool()
        .ok_or_else(|| stage.failure("protocol_error"))?;
    if response != json!({"ok":true,"digest":digest,"cached":cached}) {
        return Err(stage.failure("identity_mismatch"));
    }
    Ok(cached)
}

fn install_response(output: &Output, digest: &str) -> Result<()> {
    let stage = PreparationStage::CacheInstall;
    preparation_status(output, stage)?;
    let response = crate::remote::parse_json(&output.stdout).map_err(|e| stage.annotate(e))?;
    if response != json!({"ok":true,"digest":digest}) {
        return Err(stage.failure("identity_mismatch"));
    }
    Ok(())
}

fn upload_payload<R: Read>(cached: bool, source: &mut R, size: u64) -> Result<Option<Vec<u8>>> {
    if cached {
        return Ok(None);
    }
    if size == 0 || size > MAX_BINARY {
        return Err(failure("security_error"));
    }
    let mut bytes = Vec::with_capacity(size as usize);
    source
        .take(size + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| failure("security_error"))?;
    if bytes.len() as u64 != size {
        return Err(failure("security_error"));
    }
    Ok(Some(bytes))
}

fn cache_command(root: &str, digest: &str, size: u64, operation: &str) -> String {
    format!(
        "/bin/sh -c {} sh {} {} {} {}",
        common::shell_quote(INSTALLER),
        common::shell_quote(root),
        common::shell_quote(digest),
        size,
        common::shell_quote(operation)
    )
}

pub(crate) async fn deploy(alias: &str, endpoint: &Value) -> Result<String> {
    timeout(Duration::from_secs(180), deploy_inner(alias, endpoint))
        .await
        .map_err(|_| failure("connectivity_uncertain"))?
}

async fn deploy_inner(alias: &str, endpoint: &Value) -> Result<String> {
    let probe = common::run(
        &common::ssh_executable()?,
        &common::ssh_args(
            alias,
            "PATH=/usr/bin:/bin; export PATH; printf '%s\\n' \"$(uname -m)\" \"$HOME\"",
        ),
        None,
        Duration::from_secs(15),
    )
    .await
    .map_err(|e| PreparationStage::Architecture.process_error(e))?;
    let (arch, home) = architecture_response(&probe)?;
    if endpoint["user"].as_str().is_none() {
        return Err(failure("security_error"));
    }
    // The verified inode remains open across the remote probe. A cache hit
    // neither reads this file nor allocates/copies/hashes the executable body.
    let mut asset = crate::assets::ensure_remote(arch).await?;
    if asset.size == 0
        || asset.size > MAX_BINARY
        || asset.digest.len() != 64
        || !asset
            .digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(failure("security_error"));
    }
    let root = format!("{home}/.cache/tern-turn-relay-native");
    let helper = format!("{root}/{}/tern-turn-relay", asset.digest);
    let command = cache_command(&root, &asset.digest, asset.size, "probe");
    let probe = common::run(
        &common::ssh_executable()?,
        &common::ssh_args(alias, &command),
        None,
        Duration::from_secs(15),
    )
    .await
    .map_err(|e| PreparationStage::CacheProbe.process_error(e))?;
    let cached = cache_response(&probe, &asset.digest)?;
    let Some(bytes) = upload_payload(cached, &mut asset.file, asset.size)? else {
        return Ok(helper);
    };
    let command = cache_command(&root, &asset.digest, asset.size, "install");
    let output = common::run(
        &common::ssh_executable()?,
        &common::ssh_args(alias, &command),
        Some(&bytes),
        Duration::from_secs(150),
    )
    .await
    .map_err(|e| PreparationStage::CacheInstall.process_error(e))?;
    install_response(&output, &asset.digest)?;
    Ok(helper)
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
    timeout(Duration::from_secs(180), async {
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
            &common::ssh_executable()?,
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
        let mut ssh_command = Command::new(common::ssh_executable()?);
        ssh_command
            .args(common::ssh_args(alias, &command))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        #[cfg(unix)]
        let mut child = ssh_command.spawn().map_err(|_| failure("connectivity_uncertain"))?;
        #[cfg(windows)]
        let (mut child, owned_job) = crate::windows_process::spawn(&mut ssh_command, false)?;
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
            #[cfg(windows)]
            let _owned_job = owned_job;
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
    fn ssh_output(code: i32, stdout: &[u8], stderr: &[u8]) -> std::process::Output {
        #[cfg(unix)]
        let status = {
            use std::os::unix::process::ExitStatusExt;
            std::process::ExitStatus::from_raw(code << 8)
        };
        #[cfg(windows)]
        let status = {
            use std::os::windows::process::ExitStatusExt;
            std::process::ExitStatus::from_raw(code as u32)
        };
        std::process::Output {
            status,
            stdout: stdout.to_vec(),
            stderr: stderr.to_vec(),
        }
    }

    #[test]
    fn preparation_output_classifies_network_and_refuses_untrusted_failures() {
        for (code, stderr, expected) in [
            (255, "ssh: connect to host example port 22: Connection timed out\n", "connectivity_uncertain"),
            (255, "kex_exchange_identification: read: Connection reset by peer\n", "connectivity_uncertain"),
            (255, "Connection reset by 192.0.2.1 port 22\n", "connectivity_uncertain"),
            (255, "Connection to 192.0.2.1 port 22 timed out\n", "connectivity_uncertain"),
            (255, "client_loop: send disconnect: Broken pipe\n", "connectivity_uncertain"),
            (41, "ssh: connect to host example port 22: Connection timed out\n", "security_error"),
            (255, "user@example: Permission denied (publickey).\n", "authorization_denied"),
            (255, "Host key verification failed.\n", "security_error"),
            (255, "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!\n", "security_error"),
            (255, "ssh: connect to host example port 22: Connection timed out\nuser@example: Permission denied (publickey).\n", "authorization_denied"),
            (255, "Host key verification failed.\nConnection reset by 192.0.2.1 port 22\n", "security_error"),
            (255, "Too many authentication failures\nConnection reset by 192.0.2.1 port 22\n", "authorization_denied"),
            (255, "Load key \"/private/secret-key\": invalid format\nConnection reset by 192.0.2.1 port 22\n", "authorization_denied"),
            (255, "unexpected failure\nConnection reset by 192.0.2.1 port 22\n", "unknown"),
            (255, "remote command failed\n", "unknown"),
            (255, "unknown error mentioning Connection timed out\n", "unknown"),
            (255, "Connexion réinitialisée par le correspondant\n", "unknown"),
            (255, "", "unknown"),
            (1, "Connection reset by 192.0.2.1 port 22\n", "unknown"),
        ] {
            let output = ssh_output(code, b"untrusted response", stderr.as_bytes());
            let errors = [
                architecture_response(&output).unwrap_err(),
                cache_response(&output, "digest").unwrap_err(),
                install_response(&output, "digest").unwrap_err(),
            ];
            for (error, message) in errors.into_iter().zip([
                "Dedicated gateway architecture probe failed.",
                "Dedicated gateway cache probe failed.",
                "Dedicated gateway cache install failed.",
            ]) {
                assert_eq!(error.code, expected, "{code}: {stderr}");
                assert_eq!(recoverable(error.code), expected == "connectivity_uncertain");
                assert_eq!(error.message, message);
            }
        }
    }

    #[test]
    fn incomplete_process_evidence_fails_closed() {
        let outputs = vec![ssh_output(255, b"", b"\xffConnection reset by 192.0.2.1 port 22\n")];
        #[cfg(unix)]
        let outputs = {
            let mut outputs = outputs;
            use std::os::unix::process::ExitStatusExt;
            let mut signaled = ssh_output(255, b"", b"Connection reset by 192.0.2.1 port 22\n");
            signaled.status = std::process::ExitStatus::from_raw(9);
            outputs.push(signaled);
            outputs
        };
        for output in outputs {
            for error in [
                architecture_response(&output).unwrap_err(),
                cache_response(&output, "digest").unwrap_err(),
                install_response(&output, "digest").unwrap_err(),
            ] {
                assert_eq!(error.code, "unknown");
                assert!(!recoverable(error.code));
            }
        }
        for stage in [PreparationStage::Architecture, PreparationStage::CacheProbe, PreparationStage::CacheInstall] {
            for code in ["process-start", "process-io", "process-wait", "response-limit"] {
                let error = stage.process_error(Error::new(code, "private process detail"));
                assert_eq!(error.code, "unknown");
                assert!(!recoverable(error.code));
                assert!(!error.message.contains("private"));
            }
            let error = stage.process_error(Error::new("process-timeout", "private process detail"));
            assert_eq!(error.code, "connectivity_uncertain");
            assert!(recoverable(error.code));
            assert!(!error.message.contains("private"));
        }
    }

    #[test]
    fn successful_preparation_still_requires_exact_identity_and_schema() {
        let digest = "a".repeat(64);
        let architecture = ssh_output(0, b"arm64\n/home/test\n", b"");
        assert_eq!(architecture_response(&architecture).unwrap(), ("aarch64", "/home/test"));
        let installed = ssh_output(0, &serde_json::to_vec(&json!({"ok":true,"digest":digest})).unwrap(), b"");
        install_response(&installed, &digest).unwrap();
        for response in [
            json!({"ok":true,"digest":"wrong","cached":true}),
            json!({"ok":true,"digest":digest,"cached":true,"extra":true}),
        ] {
            let output = ssh_output(0, &serde_json::to_vec(&response).unwrap(), b"");
            let error = cache_response(&output, &digest).unwrap_err();
            assert_eq!(error.code, "identity_mismatch");
            assert!(!recoverable(error.code));
            assert_eq!(error.message, "Dedicated gateway cache probe failed.");
        }
        let output = ssh_output(0, b"{\"ok\":true,\"digest\":\"wrong\"}", b"");
        let error = install_response(&output, &digest).unwrap_err();
        assert_eq!(error.code, "identity_mismatch");
        assert!(!recoverable(error.code));
        assert_eq!(error.message, "Dedicated gateway cache install failed.");
        let error = architecture_response(&ssh_output(0, b"unexpected\n/home/test\n", b""))
            .unwrap_err();
        assert_eq!(error.code, "security_error");
        assert!(!recoverable(error.code));
        assert_eq!(error.message, "Dedicated gateway architecture probe failed.");
        let malformed = ssh_output(0, b"not a response", b"");
        for error in [
            architecture_response(&malformed).unwrap_err(),
            cache_response(&malformed, &digest).unwrap_err(),
            install_response(&malformed, &digest).unwrap_err(),
        ] {
            assert!(!recoverable(error.code));
        }
    }

    #[test]
    fn cached_hit_never_reads_or_allocates_an_upload_body() {
        struct Unreadable;
        impl Read for Unreadable {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                panic!("verified cache hit must not read executable bytes");
            }
        }
        let digest = "a".repeat(64);
        let response =
            serde_json::to_vec(&json!({"ok":true,"digest":digest,"cached":true})).unwrap();
        let cached = cache_response(&ssh_output(0, &response, b""), &digest).unwrap();
        assert!(upload_payload(cached, &mut Unreadable, MAX_BINARY)
            .unwrap()
            .is_none());
        assert_eq!(
            cache_response(&ssh_output(41, &response, b""), &digest).unwrap_err().code,
            "security_error"
        );
        assert!(cache_response(&ssh_output(0, b"{\"ok\":true,\"cached\":false}", b""), &digest).is_err());
        let extra =
            serde_json::to_vec(&json!({"ok":true,"digest":digest,"cached":true,"extra":true}))
                .unwrap();
        assert!(cache_response(&ssh_output(0, &extra, b""), &digest).is_err());
    }

    #[test]
    fn missing_cache_requires_exact_bounded_payload() {
        let digest = "a".repeat(64);
        let response =
            serde_json::to_vec(&json!({"ok":true,"digest":digest,"cached":false})).unwrap();
        let cached = cache_response(&ssh_output(0, &response, b""), &digest).unwrap();
        let mut source = std::io::Cursor::new(b"verified".as_slice());
        assert_eq!(
            upload_payload(cached, &mut source, 8).unwrap(),
            Some(b"verified".to_vec())
        );
        assert_eq!(source.position(), 8);
        assert!(upload_payload(false, &mut b"short".as_slice(), 8).is_err());
        assert!(upload_payload(false, &mut b"too long".as_slice(), 3).is_err());
        assert!(upload_payload(false, &mut b"".as_slice(), MAX_BINARY + 1).is_err());
    }

    #[cfg(target_os = "linux")]
    mod cache_installation {
        use super::*;
        use sha2::{Digest, Sha256};
        use std::{
            fs,
            os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
            path::PathBuf,
        };

        const BODY: &[u8] = b"verified native helper fixture";

        struct Fixture {
            base: PathBuf,
            root: PathBuf,
            digest: String,
        }
        impl Fixture {
            fn new() -> Self {
                // /tmp is deliberately not trusted by the production validator.
                // Use a new owned directory below the account's trusted home.
                let home = crate::remote::linux::account().unwrap().1;
                let base = home.join(format!(
                    ".tern-gateway-cache-test-{:032x}",
                    rand::random::<u128>()
                ));
                fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
                Self {
                    root: base.join("cache"),
                    base,
                    digest: hex::encode(Sha256::digest(BODY)),
                }
            }
            fn binary(&self) -> PathBuf {
                self.root.join(&self.digest).join("tern-turn-relay")
            }
            async fn invoke(&self, operation: &str, input: Option<&[u8]>) -> std::process::Output {
                let args = vec![
                    "-c".into(),
                    INSTALLER.into(),
                    "sh".into(),
                    self.root.to_str().unwrap().into(),
                    self.digest.clone(),
                    BODY.len().to_string(),
                    operation.into(),
                ];
                common::run("/bin/sh", &args, input, Duration::from_secs(10))
                    .await
                    .unwrap()
            }
            async fn install(&self) {
                let output = self.invoke("install", Some(BODY)).await;
                install_response(&output, &self.digest).unwrap();
            }
        }
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.base);
            }
        }

        #[tokio::test]
        async fn readonly_miss_then_atomic_upload_then_readonly_hit() {
            let fixture = Fixture::new();
            let probe = fixture.invoke("probe", None).await;
            assert!(
                !cache_response(&probe, &fixture.digest).unwrap()
            );
            assert!(!fixture.root.exists());
            assert_eq!(fs::read_dir(&fixture.base).unwrap().count(), 0);
            fixture.install().await;
            let binary = fixture.binary();
            let before = fs::metadata(&binary).unwrap();
            assert_eq!(before.mode() & 0o777, 0o700);
            assert_eq!(before.nlink(), 1);
            assert_eq!(fs::read(&binary).unwrap(), BODY);
            let probe = fixture.invoke("probe", None).await;
            assert!(
                cache_response(&probe, &fixture.digest).unwrap()
            );
            assert_eq!(fs::metadata(&binary).unwrap().ino(), before.ino());
            assert_eq!(fs::read_dir(binary.parent().unwrap()).unwrap().count(), 1);
        }

        #[tokio::test]
        async fn unsafe_cache_is_fatal_not_a_miss_and_is_never_replaced() {
            for kind in [
                "writable",
                "symlink",
                "hardlink",
                "wrong-digest",
                "unsafe-parent",
            ] {
                let fixture = Fixture::new();
                fixture.install().await;
                let binary = fixture.binary();
                match kind {
                    "writable" => {
                        fs::set_permissions(&binary, fs::Permissions::from_mode(0o777)).unwrap()
                    }
                    "symlink" => {
                        let victim = fixture.base.join("keep");
                        fs::write(&victim, b"unrelated fixture bytes").unwrap();
                        fs::remove_file(&binary).unwrap();
                        std::os::unix::fs::symlink(&victim, &binary).unwrap();
                    }
                    "hardlink" => fs::hard_link(&binary, fixture.base.join("keep")).unwrap(),
                    "wrong-digest" => fs::write(&binary, vec![b'x'; BODY.len()]).unwrap(),
                    "unsafe-parent" => fs::set_permissions(
                        binary.parent().unwrap(),
                        fs::Permissions::from_mode(0o770),
                    )
                    .unwrap(),
                    _ => unreachable!(),
                }
                let before = fs::read(&binary).unwrap();
                let probe = fixture.invoke("probe", None).await;
                assert_eq!(
                    cache_response(&probe, &fixture.digest)
                        .unwrap_err()
                        .code,
                    "security_error"
                );
                assert_eq!(fs::read(&binary).unwrap(), before);
                assert_eq!(fs::read_dir(binary.parent().unwrap()).unwrap().count(), 1);
            }
            let fixture = Fixture::new();
            fs::set_permissions(&fixture.base, fs::Permissions::from_mode(0o777)).unwrap();
            let probe = fixture.invoke("probe", None).await;
            assert_eq!(
                cache_response(&probe, &fixture.digest)
                    .unwrap_err()
                    .code,
                "security_error"
            );
            assert!(!fixture.root.exists());
        }

        #[tokio::test]
        async fn upload_must_match_manifest_digest_and_preserves_existing_helper() {
            let fixture = Fixture::new();
            let corrupt = vec![b'x'; BODY.len()];
            let failed = fixture.invoke("install", Some(&corrupt)).await;
            assert_eq!(failed.status.code(), Some(41));
            let error = install_response(&failed, &fixture.digest).unwrap_err();
            assert_eq!(error.code, "security_error");
            assert!(!recoverable(error.code));
            assert!(!fixture.binary().exists());
            fixture.install().await;
            let before = fs::metadata(fixture.binary()).unwrap().ino();
            let failed = fixture.invoke("install", Some(&corrupt)).await;
            assert_eq!(failed.status.code(), Some(41));
            let error = install_response(&failed, &fixture.digest).unwrap_err();
            assert_eq!(error.code, "security_error");
            assert!(!recoverable(error.code));
            assert_eq!(fs::metadata(fixture.binary()).unwrap().ino(), before);
            assert_eq!(fs::read(fixture.binary()).unwrap(), BODY);
        }
    }
}
