//! Shared native relay service and public lifecycle CLI.
use crate::{
    common::{self, Error, Options, Result},
    credentials,
    gateway::{Gateway, recoverable as gateway_recoverable},
    intent,
    protocol::{Codec, MAX_FRAME, MAX_PAYLOAD},
    ssh,
    transport::{self, Endpoint, Mode, TransportError, TurnConfig},
};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, VecDeque},
    fs::{self, File},
    io,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex as StdMutex,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
    process::Command,
    sync::{mpsc, Mutex, Notify},
    task::{JoinHandle, JoinSet},
    time::{timeout, Instant},
};
use tokio_util::sync::CancellationToken;
#[cfg(unix)]
use std::os::{fd::{AsRawFd, FromRawFd}, unix::fs::{FileTypeExt, MetadataExt, PermissionsExt}};
#[cfg(unix)]
use tokio::net::{UnixListener as ControlListener, UnixStream as ControlStream};
#[cfg(windows)]
use crate::windows_ipc::{Listener as ControlListener, Stream as ControlStream};

const MAX_FLOWS: usize = 16;
const MAX_PACKETS: usize = 64;
const MAX_BYTES: usize = 256 * 1024;
const ALLOCATION_DELAYS: [u64; 2] = [2, 5];
const GATEWAY_DELAYS: [u64; 5] = [2, 5, 15, 30, 30];
const COOLDOWN: Duration = Duration::from_secs(30);
const FLOW_IDLE: Duration = Duration::from_secs(180);
const SERVICE_IDLE: Duration = Duration::from_secs(120);

fn invalid() -> Error {
    Error::new("invalid_arguments", "Use relay start|resume|status|stop --config PATH --state-dir PATH; start requires --mode tls|udp.")
}
fn runtime_error() -> Error {
    Error::new(
        "unsafe_runtime",
        "Unsafe runtime artifact or private directory; refusing to replace it.",
    )
}
fn gateway_reason(code: &str) -> &'static str {
    match code {
        "control_eof" => "control_eof",
        "heartbeat_timeout" => "heartbeat_timeout",
        "send_timeout" => "send_timeout",
        "frontend_exit" => "frontend_exit",
        "state_lock_busy" => "state_lock_busy",
        "connectivity_uncertain" => "connectivity_uncertain",
        "protocol_error" => "protocol_error",
        "identity_mismatch" => "identity_mismatch",
        "security_error" => "security_error",
        "authorization_denied" => "authorization_denied",
        _ => "unknown",
    }
}
fn same_generation(previous: &Value, current: &Value, config: &Value) -> bool {
    previous["daemon_pid"].as_u64().is_some_and(|pid| pid > 0)
        && previous["daemon_pid"] == current["daemon_pid"]
        && previous["fingerprint"] == current["fingerprint"]
        && current["fingerprint"] == config["gateway"]["fingerprint"]
        && previous["daemon_socket"] == current["daemon_socket"]
        && current["daemon_socket"] == config["gateway"]["daemon_socket"]
}

struct CredentialCache {
    path: PathBuf,
    cached: Option<Value>,
    expires: f64,
    retry_at: Instant,
}
impl CredentialCache {
    async fn get(&mut self, mode: Mode, renew: bool) -> Result<TurnConfig> {
        let now = common::unix_time();
        if self.cached.is_some() && self.expires > now + if renew { 300.0 } else { 60.0 } {
            return transport::select(
                &self.cached.as_ref().unwrap()["entries"],
                mode,
                self.expires,
            );
        }
        if Instant::now() < self.retry_at {
            if self.cached.is_some() && self.expires > now + 60.0 {
                return transport::select(
                    &self.cached.as_ref().unwrap()["entries"],
                    mode,
                    self.expires,
                );
            }
            return Err(Error::new(
                "credentials_cooldown",
                "Credential retry is cooling down; reconnect after one minute.",
            ));
        }
        let issued = timeout(
            Duration::from_secs(14),
            credentials::issue(&self.path, 86400),
        )
        .await
        .map_err(|_| Error::new("credentials_timeout", "Credential API timed out."))
        .and_then(|result| result);
        match issued {
            Ok(value) => {
                let expires = value["expires_unix"]
                    .as_f64()
                    .filter(|value| value.is_finite() && *value > now + 60.0)
                    .ok_or_else(|| {
                        Error::new(
                            "credentials_response",
                            "Credential API returned an invalid expiry.",
                        )
                    })?;
                let config = transport::select(&value["entries"], mode, expires)?;
                self.cached = Some(value);
                self.expires = expires;
                Ok(config)
            }
            Err(error) => {
                self.retry_at = Instant::now() + Duration::from_secs(60);
                Err(error)
            }
        }
    }
}

struct FlowData {
    queue: VecDeque<Vec<u8>>,
    bytes: usize,
    last_activity: Instant,
    demand: u64,
    recovering: bool,
    recovery_error: Option<&'static str>,
    endpoint: Option<Arc<Endpoint>>,
}
struct FlowRecord {
    data: StdMutex<FlowData>,
    changed: Notify,
}
impl FlowRecord {
    fn new(endpoint: Option<Arc<Endpoint>>) -> Self {
        Self {
            data: StdMutex::new(FlowData {
                queue: VecDeque::with_capacity(MAX_PACKETS),
                bytes: 0,
                last_activity: Instant::now(),
                demand: 0,
                recovering: endpoint.is_none(),
                recovery_error: None,
                endpoint,
            }),
            changed: Notify::new(),
        }
    }
    fn enqueue(&self, payload: &[u8]) -> bool {
        let mut data = self.data.lock().unwrap();
        data.last_activity = Instant::now();
        data.demand = data.demand.wrapping_add(1);
        let accepted = data.queue.len() < MAX_PACKETS && data.bytes + payload.len() <= MAX_BYTES;
        if accepted {
            data.bytes += payload.len();
            data.queue.push_back(payload.to_vec());
        }
        drop(data);
        self.changed.notify_one();
        accepted
    }
    async fn next(&self) -> Vec<u8> {
        loop {
            let notified = self.changed.notified();
            {
                let mut data = self.data.lock().unwrap();
                if let Some(packet) = data.queue.pop_front() {
                    data.bytes -= packet.len();
                    return packet;
                }
            }
            notified.await;
        }
    }
    async fn new_demand(&self, previous: u64) {
        loop {
            let notified = self.changed.notified();
            if self.data.lock().unwrap().demand != previous {
                return;
            }
            notified.await;
        }
    }
    async fn wait_after_allocation_failure(&self, error: TransportError) {
        let previous = {
            let mut data = self.data.lock().unwrap();
            data.recovery_error = Some(error.public().message);
            if !data.queue.is_empty() {
                return;
            }
            data.demand
        };
        self.new_demand(previous).await;
    }
}
struct FlowHandle {
    record: Arc<FlowRecord>,
    cancel: CancellationToken,
    task: JoinHandle<()>,
}

struct ServiceState {
    public: Value,
    ssh_endpoint: Option<Value>,
    ssh_count: Arc<AtomicUsize>,
    flows: HashMap<SocketAddr, FlowHandle>,
    warm: Option<Arc<Endpoint>>,
    route_available: bool,
    peer: Option<SocketAddr>,
    key: [u8; 32],
    generation: CancellationToken,
    gateway_recovering: bool,
    gateway_reconnects: u64,
    gateway_failure_reason: Option<&'static str>,
    recovery_error: Option<&'static str>,
    retired_refreshes: u64,
    bytes_up: u64,
    bytes_down: u64,
    dropped_packets: u64,
    dropped_bytes: u64,
    last_drop: Option<Instant>,
    allocation_retry_at: Instant,
    no_clients_since: Instant,
    demand: u64,
    credentials_expires: Option<f64>,
    initialized: bool,
}
struct Shared {
    config: Value,
    mode: Mode,
    state: StdMutex<ServiceState>,
    credentials: Mutex<CredentialCache>,
    stop: CancellationToken,
    fatal: CancellationToken,
    demand: Notify,
}
impl Shared {
    fn fail(&self, error: Error) {
        let mut state = self.state.lock().unwrap();
        if state.public["state"] != "error" {
            state.public["ok"] = json!(false);
            state.public["state"] = json!("error");
            state.public["error"] = json!(error.message);
        }
        state.route_available = false;
        drop(state);
        self.fatal.cancel();
    }
    fn snapshot(&self) -> Value {
        let state = self.state.lock().unwrap();
        let mut result = state.public.clone();
        let mut packets = 0;
        let mut bytes = 0;
        let mut recovering = 0;
        let mut refreshes = state.retired_refreshes;
        let mut usable = false;
        let mut expires = state.credentials_expires;
        let mut recovery_error = state.recovery_error;
        for handle in state.flows.values() {
            let flow = handle.record.data.lock().unwrap();
            packets += flow.queue.len();
            bytes += flow.bytes;
            if flow.recovering {
                recovering += 1;
                recovery_error = flow.recovery_error.or(recovery_error);
            }
            if let Some(endpoint) = &flow.endpoint {
                usable |= endpoint.usable();
                refreshes += endpoint.stats().refreshes;
                expires = Some(expires.map_or(endpoint.expires, |old| old.min(endpoint.expires)));
            }
        }
        if let Some(warm) = &state.warm {
            usable |= warm.usable();
            refreshes += warm.stats().refreshes;
            expires = Some(expires.map_or(warm.expires, |old| old.min(warm.expires)));
        }
        usable &= state.route_available && !self.stop.is_cancelled();
        if result["state"] == "ready" && !usable {
            result["ok"] = json!(false);
            result["state"] = json!("starting");
            result["error"] = Value::Null;
        }
        result["implementation"] = json!("rust");
        result["runtime_version"] = json!(env!("CARGO_PKG_VERSION"));
        result["flows"] = json!(state.flows.len());
        result["ssh_connections"] = json!(state.ssh_count.load(Ordering::SeqCst));
        result["queued_packets"] = json!(packets);
        result["queued_bytes"] = json!(bytes);
        result["queue_dropped_packets"] = json!(state.dropped_packets);
        result["queue_dropped_bytes"] = json!(state.dropped_bytes);
        result["congested"] = json!(state
            .last_drop
            .is_some_and(|at| at.elapsed() < Duration::from_secs(5)));
        result["bytes_up"] = json!(state.bytes_up);
        result["bytes_down"] = json!(state.bytes_down);
        result["allocation_refreshes"] = json!(refreshes);
        result["recovering_flows"] = json!(recovering);
        result["gateway_recovering"] = json!(state.gateway_recovering);
        result["gateway_reconnects"] = json!(state.gateway_reconnects);
        result["gateway_failure_reason"] = json!(state.gateway_failure_reason);
        result["credentials_expires_at"] = json!(expires);
        result["recovery_error"] = if matches!(result["state"].as_str(), Some("error" | "stopped"))
        {
            Value::Null
        } else {
            json!(recovery_error.filter(|_| !usable || recovering != 0))
        };
        result
    }
    fn identity(&self) -> Value {
        let state = self.state.lock().unwrap();
        json!({"service_id":state.public["service_id"], "ssh_endpoint":state.ssh_endpoint,
            "gateway":self.config["gateway"], "implementation":"rust", "runtime_version":env!("CARGO_PKG_VERSION")})
    }
    fn defer(&self) {
        let mut state = self.state.lock().unwrap();
        state.allocation_retry_at = state.allocation_retry_at.max(Instant::now() + COOLDOWN);
    }
    async fn cooldown(&self) {
        let until = self.state.lock().unwrap().allocation_retry_at;
        if until > Instant::now() {
            tokio::time::sleep_until(until).await;
        }
    }
    async fn turn_config(&self, renew: bool) -> Result<TurnConfig> {
        let config = self.credentials.lock().await.get(self.mode, renew).await?;
        self.state.lock().unwrap().credentials_expires = Some(config.expires);
        Ok(config)
    }
    async fn new_demand(&self, previous: u64) {
        loop {
            let notified = self.demand.notified();
            if self.state.lock().unwrap().demand != previous {
                return;
            }
            notified.await;
        }
    }
    fn record_drop(&self, bytes: usize) {
        let mut state = self.state.lock().unwrap();
        state.dropped_packets = state.dropped_packets.saturating_add(1);
        state.dropped_bytes = state.dropped_bytes.saturating_add(bytes as u64);
        state.last_drop = Some(Instant::now());
    }
}

async fn allocate(
    config: TurnConfig,
    peer: SocketAddr,
    retry: bool,
) -> std::result::Result<Arc<Endpoint>, TransportError> {
    for attempt in 0..=if retry { ALLOCATION_DELAYS.len() } else { 0 } {
        match Endpoint::open(config.clone(), peer).await {
            Ok(endpoint) => return Ok(Arc::new(endpoint)),
            Err(error) if retry && error.recoverable() && attempt < ALLOCATION_DELAYS.len() => {
                tokio::time::sleep(Duration::from_secs(ALLOCATION_DELAYS[attempt])).await;
            }
            Err(error) => return Err(error),
        }
    }
    Err(TransportError::Timeout)
}

async fn retire_endpoint(shared: &Shared, record: &FlowRecord) {
    let endpoint = record.data.lock().unwrap().endpoint.take();
    if let Some(endpoint) = endpoint {
        endpoint.close().await;
        shared.state.lock().unwrap().retired_refreshes += endpoint.stats().refreshes;
    }
}

async fn flow_loop(
    shared: Arc<Shared>,
    record: Arc<FlowRecord>,
    socket: Arc<UdpSocket>,
    address: SocketAddr,
    peer: SocketAddr,
    mut codec: Codec,
) -> Result<()> {
    let mut incoming = vec![0; MAX_FRAME];
    let mut outgoing = Vec::with_capacity(MAX_FRAME);
    let mut batch = 0;
    loop {
        let current = record.data.lock().unwrap().endpoint.clone();
        let endpoint = if let Some(endpoint) = current {
            endpoint
        } else {
            record.data.lock().unwrap().recovering = true;
            shared.cooldown().await;
            let config = shared.turn_config(false).await?;
            match allocate(config, peer, true).await {
                Ok(endpoint) => {
                    let mut data = record.data.lock().unwrap();
                    data.endpoint = Some(endpoint.clone());
                    data.recovering = false;
                    data.recovery_error = None;
                    endpoint
                }
                Err(error) if error.recoverable() => {
                    shared.defer();
                    record.wait_after_allocation_failure(error).await;
                    continue;
                }
                Err(error) => return Err(error.public()),
            }
        };
        let outcome: std::result::Result<(), TransportError> = tokio::select! {
            error = endpoint.failure() => Err(error),
            packet = endpoint.recv(&mut incoming) => match packet {
                Ok(length) => {
                    if let Some(payload) = codec.decode(&incoming[..length]) {
                        // The generation is retired before its cancellation is signalled.
                        if shared.state.lock().unwrap().route_available {
                            socket.send_to(payload, address).await.map_err(|_| Error::new("loopback_delivery", "Loopback delivery failed; reconnect to recover."))?;
                            shared.state.lock().unwrap().bytes_down += payload.len() as u64;
                            record.data.lock().unwrap().last_activity = Instant::now();
                        }
                    }
                    Ok(())
                }
                Err(error) => Err(error),
            },
            packet = record.next() => {
                codec.encode(&packet, &mut outgoing)?;
                match endpoint.send(&outgoing).await {
                    Ok(()) => { shared.state.lock().unwrap().bytes_up += packet.len() as u64; Ok(()) },
                    Err(error) => Err(error),
                }
            },
        };
        match outcome {
            Ok(()) => {}
            Err(error) if error.recoverable() => {
                {
                    let mut data = record.data.lock().unwrap();
                    data.recovering = true;
                    data.recovery_error = Some(error.public().message);
                }
                shared.defer();
                drop(endpoint);
                retire_endpoint(&shared, &record).await;
            }
            Err(error) => return Err(error.public()),
        }
        batch += 1;
        if batch == 32 {
            batch = 0;
            tokio::task::yield_now().await;
        }
    }
}

async fn udp_receiver(shared: Arc<Shared>, socket: Arc<UdpSocket>) -> Result<()> {
    let mut buffer = vec![0; 65536];
    loop {
        let (length, address) = tokio::select! {
            biased;
            _ = shared.stop.cancelled() => return Ok(()),
            received = socket.recv_from(&mut buffer) => received.map_err(|_| Error::new("loopback_udp", "Loopback UDP socket failed."))?,
        };
        if address.ip() != std::net::IpAddr::V4(Ipv4Addr::LOCALHOST) {
            continue;
        }
        let handle = {
            let mut state = shared.state.lock().unwrap();
            state.no_clients_since = Instant::now();
            state.demand = state.demand.wrapping_add(1);
            shared.demand.notify_one();
            if !state.route_available || shared.fatal.is_cancelled() {
                continue;
            }
            if length > MAX_PAYLOAD {
                drop(state);
                shared.fail(Error::new(
                    "oversized_udp",
                    "Oversized UDP payload rejected; no TURN packet was sent.",
                ));
                continue;
            }
            if let Some(handle) = state.flows.get(&address) {
                handle.record.clone()
            } else {
                if state.public["state"] != "ready" {
                    continue;
                }
                if state.flows.len() >= MAX_FLOWS {
                    drop(state);
                    shared.record_drop(length);
                    continue;
                }
                let record = Arc::new(FlowRecord::new(state.warm.take()));
                let cancel = state.generation.child_token();
                let stopped = cancel.clone();
                let worker_record = record.clone();
                let worker_shared = shared.clone();
                let worker_socket = socket.clone();
                let peer = state.peer.expect("available route has peer");
                let codec = Codec::new(state.key);
                let task = tokio::spawn(async move {
                    let result = tokio::select! {
                        biased;
                        _ = stopped.cancelled() => Ok(()),
                        _ = worker_shared.stop.cancelled() => Ok(()),
                        _ = worker_shared.fatal.cancelled() => Ok(()),
                        result = flow_loop(worker_shared.clone(), worker_record.clone(), worker_socket, address, peer, codec) => result,
                    };
                    if let Err(error) = result {
                        worker_shared.fail(error);
                    }
                    retire_endpoint(&worker_shared, &worker_record).await;
                    let mut data = worker_record.data.lock().unwrap();
                    data.queue.clear();
                    data.bytes = 0;
                });
                state.flows.insert(
                    address,
                    FlowHandle {
                        record: record.clone(),
                        cancel,
                        task,
                    },
                );
                record
            }
        };
        if !handle.enqueue(&buffer[..length]) {
            shared.record_drop(length);
        }
    }
}

async fn retire_route(shared: &Shared) {
    let (flows, warm) = {
        let mut state = shared.state.lock().unwrap();
        state.route_available = false;
        state.generation.cancel();
        state.key.fill(0);
        let flows = std::mem::take(&mut state.flows);
        (flows, state.warm.take())
    };
    let close_flows = async {
        for flow in flows.values() {
            flow.cancel.cancel();
        }
        for (_, flow) in flows {
            let _ = flow.task.await;
        }
    };
    let close_warm = async {
        if let Some(warm) = warm {
            warm.close().await;
            shared.state.lock().unwrap().retired_refreshes += warm.stats().refreshes;
        }
    };
    tokio::join!(close_flows, close_warm);
    shared.state.lock().unwrap().no_clients_since = Instant::now();
}

async fn warm_gateway(
    shared: Arc<Shared>,
    peer: SocketAddr,
    recovering: bool,
) -> Result<Arc<Endpoint>> {
    loop {
        if recovering {
            shared.cooldown().await;
        }
        let config = shared.turn_config(false).await?;
        match allocate(config, peer, recovering).await {
            Ok(endpoint) => return Ok(endpoint),
            Err(error) if recovering && error.recoverable() => {
                shared.defer();
                let previous = {
                    let mut state = shared.state.lock().unwrap();
                    state.recovery_error = Some(error.public().message);
                    state.gateway_recovering = false;
                    state.demand
                };
                shared.new_demand(previous).await;
                shared.state.lock().unwrap().gateway_recovering = true;
            }
            Err(error) => return Err(error.public()),
        }
    }
}

async fn gateway_manager(shared: Arc<Shared>, ready: mpsc::Sender<()>) -> Result<()> {
    let first = tokio::select! {
        biased;
        _ = shared.stop.cancelled() => return Ok(()),
        _ = shared.fatal.cancelled() => return Ok(()),
        result = Gateway::open(&shared.config) => result,
    }?;
    let original = first.descriptor.clone();
    let mut gateway = Some(first);
    let mut recovering = false;
    let mut attempts = 0;
    loop {
        let current = gateway.as_mut().expect("gateway generation present");
        let peer = current.peer;
        let warmed = tokio::select! {
            biased;
            _ = shared.stop.cancelled() => None,
            _ = shared.fatal.cancelled() => None,
            failed = current.failure() => Some(Err(failed.err().unwrap_or_else(|| Error::new("control_eof", "Dedicated gateway control channel closed.")))),
            warmed = warm_gateway(shared.clone(), peer, recovering) => Some(warmed),
        };
        let failure = match warmed {
            None => {
                retire_route(&shared).await;
                let _ = current.close().await;
                return Ok(());
            }
            Some(Ok(warm)) => {
                {
                    let mut state = shared.state.lock().unwrap();
                    state.generation = CancellationToken::new();
                    state.peer = Some(current.peer);
                    state.key = current.key;
                    state.warm = Some(warm);
                    state.route_available = true;
                    state.gateway_recovering = false;
                    state.recovery_error = None;
                }
                if ready.send(()).await.is_err() {
                    let _ = current.close().await;
                    return Ok(());
                }
                attempts = 0;
                tokio::select! {
                    biased;
                    _ = shared.stop.cancelled() => None,
                    _ = shared.fatal.cancelled() => None,
                    failure = current.failure() => Some(failure.err().unwrap_or_else(|| Error::new("control_eof", "Dedicated gateway control channel closed."))),
                }
            }
            Some(Err(error)) => Some(error),
        };
        {
            let mut state = shared.state.lock().unwrap();
            state.route_available = false;
            state.gateway_recovering = failure
                .as_ref()
                .is_some_and(|error| gateway_recoverable(error.code));
            if let Some(error) = &failure {
                state.gateway_failure_reason = Some(gateway_reason(error.code));
                state.recovery_error = Some(error.message);
                state.public["ok"] = json!(false);
                if state.public["state"] != "error" {
                    state.public["state"] = json!("starting");
                }
            }
        }
        retire_route(&shared).await;
        let _ = current.close().await;
        gateway.take();
        let Some(mut failure) = failure else {
            return Ok(());
        };
        recovering = true;
        loop {
            if !gateway_recoverable(failure.code) {
                return Err(failure);
            }
            if attempts == GATEWAY_DELAYS.len() {
                return Err(Error::new("gateway_recovery_exhausted", "Exclusive gateway recovery exhausted its bounded attempts; no direct fallback was attempted."));
            }
            let delay = GATEWAY_DELAYS[attempts];
            attempts += 1;
            tokio::select! {
                biased;
                _ = shared.stop.cancelled() => return Ok(()),
                _ = shared.fatal.cancelled() => return Ok(()),
                _ = tokio::time::sleep(Duration::from_secs(delay)) => {},
            }
            {
                let mut state = shared.state.lock().unwrap();
                state.gateway_recovering = true;
                state.gateway_reconnects += 1;
            }
            let next = tokio::select! {
                biased;
                _ = shared.stop.cancelled() => return Ok(()),
                _ = shared.fatal.cancelled() => return Ok(()),
                result = Gateway::open(&shared.config) => result,
            };
            match next {
                Ok(mut next) => {
                    if !same_generation(&original, &next.descriptor, &shared.config) {
                        let _ = next.close().await;
                        return Err(Error::new("identity_mismatch", "Gateway identity or original daemon changed; refusing to rebind the workspace."));
                    }
                    gateway = Some(next);
                    break;
                }
                Err(error) => {
                    shared.state.lock().unwrap().gateway_failure_reason =
                        Some(gateway_reason(error.code));
                    shared.state.lock().unwrap().recovery_error = Some(error.message);
                    failure = error;
                }
            }
        }
    }
}

async fn read_line<R: AsyncRead + Unpin>(reader: &mut R, limit: usize) -> Result<Vec<u8>> {
    let mut line = Vec::with_capacity(1024.min(limit));
    let mut buffer = [0u8; 1024];
    loop {
        let count = reader
            .read(&mut buffer)
            .await
            .map_err(|_| Error::new("control_ipc", "Local relay control socket failed."))?;
        if count == 0 {
            return Err(Error::new(
                "control_ipc",
                "Local relay control socket closed without a response.",
            ));
        }
        let used = buffer[..count].iter().position(|byte| *byte == b'\n');
        let size = used.unwrap_or(count);
        if line.len() + size > limit {
            return Err(Error::new(
                "control_ipc",
                "Local relay control response exceeded its limit.",
            ));
        }
        line.extend_from_slice(&buffer[..size]);
        if used.is_some() {
            return Ok(line);
        }
    }
}

async fn control_client(mut stream: ControlStream, shared: Arc<Shared>) -> Result<()> {
    let request = common::parse_json(&read_line(&mut stream, 1024).await?)?;
    let result = match request["command"].as_str() {
        Some("status") => shared.snapshot(),
        Some("identity") => shared.identity(),
        Some("stop") => {
            if request["service_id"] != shared.state.lock().unwrap().public["service_id"] {
                return Err(invalid());
            }
            shared.stop.cancel();
            shared.snapshot()
        }
        _ => return Err(invalid()),
    };
    let mut raw = serde_json::to_vec(&result).map_err(|_| invalid())?;
    raw.push(b'\n');
    stream.write_all(&raw).await.map_err(|_| {
        Error::new(
            "control_ipc",
            "Local control response could not be written.",
        )
    })?;
    stream
        .shutdown()
        .await
        .map_err(|_| Error::new("control_ipc", "Local control socket could not close."))
}

#[allow(unused_mut)]
async fn control_listener(mut listener: ControlListener, shared: Arc<Shared>) -> Result<()> {
    let mut clients = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = shared.stop.cancelled() => break,
            _ = clients.join_next(), if !clients.is_empty() => {},
            accepted = listener.accept() => {
                let (stream, _) = accepted.map_err(|_| Error::new("control_ipc", "Local control listener failed."))?;
                if clients.len() >= 8 { continue; }
                let shared = shared.clone();
                clients.spawn(async move { let _ = timeout(Duration::from_secs(2), control_client(stream, shared)).await; });
            }
        }
    }
    // Let the stop acknowledgement finish; bound uncooperative clients independently.
    let _ = timeout(Duration::from_secs(2), async {
        while clients.join_next().await.is_some() {}
    })
    .await;
    clients.abort_all();
    while clients.join_next().await.is_some() {}
    Ok(())
}

#[cfg(unix)]
fn remove_runtime(path: &Path, socket: bool) -> Result<()> {
    let info = match fs::symlink_metadata(path) {
        Ok(info) => info,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(runtime_error()),
    };
    if info.uid() != unsafe { libc::geteuid() }
        || info.mode() & 0o777 != 0o600
        || if socket {
            !info.file_type().is_socket()
        } else {
            !info.is_file() || info.nlink() != 1
        }
    {
        return Err(runtime_error());
    }
    fs::remove_file(path).map_err(|_| runtime_error())
}

#[cfg(windows)]
fn remove_runtime(path: &Path, socket: bool) -> Result<()> {
    if socket {
        // Named pipes have no disk entry. Never delete an unrelated file with the old socket name.
        return match fs::symlink_metadata(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            _ => Err(runtime_error()),
        };
    }
    let Some(before) = crate::install::snapshot(path, 16384)? else { return Ok(()); };
    before.require_private()?;
    crate::install::replace(path, Some(&before), None, 0o600)
}

#[cfg(windows)]
async fn ipc(directory: &Path, command: &str, identity: Option<&str>) -> Result<Value> {
    timeout(Duration::from_secs(2), async {
        let (mut stream, expected_identity) = crate::windows_ipc::connect(directory).await?;
        let mut request = serde_json::to_vec(&json!({"command":command,"service_id":identity}))
            .map_err(|_| invalid())?;
        request.push(b'\n');
        stream.write_all(&request).await.map_err(|_| runtime_error())?;
        let result = common::parse_json(&read_line(&mut stream, 16384).await?)?;
        if result["service_id"].as_str() != Some(expected_identity.as_str()) {
            return Err(Error::new("control_identity", "The live Windows relay identity does not match its private record."));
        }
        Ok(result)
    }).await.map_err(|_| Error::new("control_timeout", "Local relay control pipe timed out."))?
}

#[cfg(unix)]
async fn ipc(directory: &Path, command: &str, identity: Option<&str>) -> Result<Value> {
    let path = directory.join("control.sock");
    let info = fs::symlink_metadata(&path).map_err(|_| runtime_error())?;
    if !info.file_type().is_socket()
        || info.uid() != unsafe { libc::geteuid() }
        || info.mode() & 0o777 != 0o600
    {
        return Err(runtime_error());
    }
    timeout(Duration::from_secs(2), async {
        let mut stream = ControlStream::connect(path).await.map_err(|_| {
            Error::new("control_ipc", "Cannot reach the live relay control socket.")
        })?;
        let mut request = serde_json::to_vec(&json!({"command":command,"service_id":identity}))
            .map_err(|_| invalid())?;
        request.push(b'\n');
        stream.write_all(&request).await.map_err(|_| {
            Error::new(
                "control_ipc",
                "Cannot write to the live relay control socket.",
            )
        })?;
        let result = common::parse_json(&read_line(&mut stream, 16384).await?)?;
        if !result.is_object() || !result["service_id"].is_string() {
            return Err(Error::new(
                "control_identity",
                "Invalid local relay service identity.",
            ));
        }
        Ok(result)
    })
    .await
    .map_err(|_| Error::new("control_timeout", "Local relay control socket timed out."))?
}

async fn current_status(config: Option<&Value>, directory: &Path) -> Result<Value> {
    if !common::is_locked(&directory.join("service.lock"))? {
        return Ok(common::public_status(config, "stopped", None, None, None));
    }
    Ok(ipc(directory, "status", None).await.unwrap_or_else(|_| common::public_status(config, "error", None, None,
        Some("Relay process holds its lock but control IPC is unavailable; do not kill a PID from a stale file."))))
}

async fn stop(config: Option<&Value>, directory: &Path) -> Result<Value> {
    intent::clear(directory)?;
    if !common::is_locked(&directory.join("service.lock"))? {
        remove_runtime(&directory.join("control.sock"), true)?;
        remove_runtime(&directory.join("pid.json"), false)?;
        return Ok(common::public_status(config, "stopped", None, None, None));
    }
    let before = ipc(directory, "status", None).await?;
    let identity = before["service_id"].as_str().ok_or_else(invalid)?;
    ipc(directory, "stop", Some(identity)).await.map_err(|_| {
        Error::new(
            "control_ipc",
            "Cannot reach the live relay control socket; no process was killed using a saved PID.",
        )
    })?;
    let until = Instant::now() + Duration::from_secs(12);
    while Instant::now() < until {
        if !common::is_locked(&directory.join("service.lock"))? {
            return Ok(common::public_status(config, "stopped", None, None, None));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(Error::new(
        "stop_timeout",
        "Relay shutdown did not finish within 12 seconds; no unrelated process was killed.",
    ))
}

fn same_service(
    config: &Value,
    mode: Mode,
    endpoint: &ssh::Endpoint,
    status: &Value,
    identity: &Value,
) -> bool {
    status["implementation"] == "rust"
        && identity["implementation"] == "rust"
        && status["target"] == config["target"]
        && status["mode"] == mode.name()
        && status["address"]
            == common::public_status(Some(config), "stopped", None, None, None)["address"]
        && status["ssh_destination"] == config["ssh_destination"]
        && status["relay_fingerprint"] == config["gateway"]["fingerprint"]
        && status["daemon_socket"] == config["gateway"]["daemon_socket"]
        && status["route_policy"] == "exclusive"
        && identity["gateway"] == config["gateway"]
        && status["service_id"] == identity["service_id"]
        && identity["ssh_endpoint"] == endpoint.value()
}

async fn terminate_child(child: &mut tokio::process::Child) {
    if matches!(child.try_wait(), Ok(None)) {
        #[cfg(unix)]
        if let Some(pid) = child.id() {
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
            }
        }
        if timeout(Duration::from_secs(5), child.wait()).await.is_err() {
            let _ = child.kill().await;
            let _ = timeout(Duration::from_secs(2), child.wait()).await;
        }
    }
}

async fn start(config: &Value, config_path: &Path, directory: &Path, mode: Mode) -> Result<Value> {
    // Normalization never grants permission to execute a legacy schema3 install.
    if common::read_json(config_path, true)?["schema"] != 4 {
        return Err(Error::new(
            "migration_required",
            "This installation requires an explicit stopped native migration before connecting.",
        ));
    }
    let endpoint = ssh::resolve(config).await?;
    if common::is_locked(&directory.join("service.lock"))? {
        let status = ipc(directory, "status", None).await?;
        let identity = ipc(directory, "identity", None).await?;
        if !same_service(config, mode, &endpoint, &status, &identity) {
            return Err(Error::new("service_mismatch", "Another target, gateway, port, mode, runtime or resolved SSH destination is already running. Disconnect all TURN windows before changing it."));
        }
        if status["state"] != "ready" {
            return Err(Error::new(
                "service_not_ready",
                "Existing relay is not ready. Disconnect before reconnecting.",
            ));
        }
        return Ok(status);
    }
    if !credentials::configured(Path::new(
        config["credential_file"].as_str().ok_or_else(invalid)?,
    ))? {
        return Err(Error::new(
            "credentials_missing",
            "Cloudflare management credentials are not configured.",
        ));
    }
    let lock = common::lock(&directory.join("service.lock"), true)?;
    #[cfg(unix)]
    let fd = lock.as_raw_fd();
    #[cfg(unix)]
    let lock_argument = fd.to_string();
    #[cfg(windows)]
    let lock_argument = "acquire";
    let identity = hex::encode(rand::random::<[u8; 16]>());
    let executable = std::env::current_exe().map_err(|_| {
        Error::new(
            "runtime_executable",
            "Cannot locate the native relay executable.",
        )
    })?;
    #[cfg(windows)]
    let executable = crate::windows_security::normalize_system_path(&executable)?;
    let mut command = Command::new(executable);
    command
        .arg("relay")
        .arg("serve")
        .arg("--config")
        .arg(config_path)
        .arg("--state-dir")
        .arg(directory)
        .arg("--mode")
        .arg(mode.name())
        .arg("--lock-fd")
        .arg(lock_argument)
        .arg("--service-id")
        .arg(&identity)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() < 0 || libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    #[cfg(unix)]
    let mut child = command
        .spawn()
        .map_err(|_| Error::new("relay_spawn", "Unable to start the native relay daemon."))?;
    #[cfg(unix)]
    drop(lock); // Child inherited the same flock open-file description.
    #[cfg(windows)]
    let (mut child, owned_job) = {
        // command.lock serializes lifecycle changes until the child owns service.lock.
        drop(lock);
        crate::windows_process::spawn(&mut command, true)?
    };
    let outcome = async {
        let until = Instant::now() + Duration::from_secs(90);
        while Instant::now() < until {
            if let Ok(status) = ipc(directory, "status", None).await {
                if status["service_id"] == identity {
                    if status["state"] == "ready" {
                        let running_identity = ipc(directory, "identity", None).await?;
                        if !same_service(config, mode, &endpoint, &status, &running_identity) {
                            return Err(Error::new("service_mismatch", "Relay or SSH configuration changed during startup; no relay was retained."));
                        }
                        return Ok(status);
                    }
                    if status["state"] == "error" { return Ok(status); }
                }
            }
            if child.try_wait().map_err(|_| Error::new("relay_wait", "Cannot observe the owned relay process."))?.is_some() {
                if let Ok(saved) = common::read_json(&directory.join("status.json"), true) {
                    if saved["service_id"] == identity && saved["state"] == "error" { return Ok(saved); }
                }
                return Err(Error::new("relay_exited", "Relay daemon exited before the exclusive gateway and TURN allocation became ready."));
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        Err(Error::new("start_timeout", "Exclusive gateway or TURN startup timed out; no direct fallback was attempted."))
    }.await;
    if !outcome
        .as_ref()
        .is_ok_and(|status| status["state"] == "ready")
    {
        #[cfg(windows)]
        let _ = owned_job.terminate();
        terminate_child(&mut child).await;
        if !common::is_locked(&directory.join("service.lock"))? {
            remove_runtime(&directory.join("control.sock"), true)?;
            remove_runtime(&directory.join("pid.json"), false)?;
        }
    }
    #[cfg(windows)]
    if outcome.as_ref().is_ok_and(|value| value["state"] == "ready") {
        owned_job.release()?;
    }
    outcome
}

#[cfg(all(windows, test))]
thread_local! {
    static SERVICE_LOCK_BUSY_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(windows)]
fn acquire_service_lock(directory: &Path, deadline: Instant) -> Result<File> {
    let path = directory.join("service.lock");
    loop {
        match common::lock(&path, true) {
            Ok(lock) => return Ok(lock),
            Err(error) if error.code == "lock-busy" && Instant::now() < deadline => {
                #[cfg(test)]
                SERVICE_LOCK_BUSY_HOOK.with(|slot| {
                    let hook = slot.borrow_mut().take();
                    if let Some(hook) = hook { hook(); }
                });
                // Read-only status probes may briefly acquire this lock during handoff.
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(windows)]
fn inherited_lock(directory: &Path, raw: &str) -> Result<File> {
    if raw != "acquire" { return Err(invalid()); }
    acquire_service_lock(directory, Instant::now() + Duration::from_secs(5))
}

#[cfg(unix)]
fn inherited_lock(directory: &Path, raw: &str) -> Result<File> {
    let fd = raw
        .parse::<i32>()
        .ok()
        .filter(|fd| *fd > 2)
        .ok_or_else(invalid)?;
    let expected =
        fs::symlink_metadata(directory.join("service.lock")).map_err(|_| runtime_error())?;
    if !expected.is_file()
        || expected.nlink() != 1
        || expected.uid() != unsafe { libc::geteuid() }
        || expected.mode() & 0o777 != 0o600
    {
        return Err(runtime_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        return Err(runtime_error());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let actual = file.metadata().map_err(|_| runtime_error())?;
    if expected.dev() != actual.dev()
        || expected.ino() != actual.ino()
        || unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } != 0
    {
        return Err(runtime_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(runtime_error());
    }
    Ok(file)
}

async fn serve(
    config: Value,
    directory: PathBuf,
    mode: Mode,
    identity: String,
    _lock: File,
) -> Result<Value> {
    remove_runtime(&directory.join("control.sock"), true)?;
    remove_runtime(&directory.join("pid.json"), false)?;
    let now = Instant::now();
    let shared = Arc::new(Shared {
        credentials: Mutex::new(CredentialCache {
            path: PathBuf::from(config["credential_file"].as_str().ok_or_else(invalid)?),
            cached: None,
            expires: 0.0,
            retry_at: now,
        }),
        state: StdMutex::new(ServiceState {
            public: common::public_status(
                Some(&config),
                "starting",
                Some(mode.name()),
                Some(&identity),
                None,
            ),
            ssh_endpoint: None,
            ssh_count: Arc::new(AtomicUsize::new(0)),
            flows: HashMap::new(),
            warm: None,
            route_available: false,
            peer: None,
            key: [0; 32],
            generation: CancellationToken::new(),
            gateway_recovering: false,
            gateway_reconnects: 0,
            gateway_failure_reason: None,
            recovery_error: None,
            retired_refreshes: 0,
            bytes_up: 0,
            bytes_down: 0,
            dropped_packets: 0,
            dropped_bytes: 0,
            last_drop: None,
            allocation_retry_at: now,
            no_clients_since: now,
            demand: 0,
            credentials_expires: None,
            initialized: false,
        }),
        config,
        mode,
        stop: CancellationToken::new(),
        fatal: CancellationToken::new(),
        demand: Notify::new(),
    });
    common::atomic_json(
        &directory.join("pid.json"),
        &json!({"pid":std::process::id(),"service_id":identity}),
    )?;
    common::atomic_json(&directory.join("status.json"), &shared.snapshot())?;
    #[cfg(unix)]
    let listener = ControlListener::bind(directory.join("control.sock")).map_err(|_| {
        Error::new(
            "control_bind",
            "Cannot bind the private relay control socket.",
        )
    })?;
    #[cfg(unix)]
    fs::set_permissions(
        directory.join("control.sock"),
        fs::Permissions::from_mode(0o600),
    )
    .map_err(|_| runtime_error())?;
    #[cfg(windows)]
    let listener = ControlListener::bind(&directory)?;
    let control_shared = shared.clone();
    let control = tokio::spawn(async move {
        if let Err(error) = control_listener(listener, control_shared.clone()).await {
            control_shared.fail(error);
            control_shared.stop.cancel();
        }
    });
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| runtime_error())?;
    #[cfg(unix)]
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(|_| runtime_error())?;
    let stop_signal = shared.stop.clone();
    #[cfg(unix)]
    let signal_task = tokio::spawn(async move {
        tokio::select! { _ = terminate.recv() => {}, _ = interrupt.recv() => {}, _ = stop_signal.cancelled() => {} }
        stop_signal.cancel();
    });
    #[cfg(windows)]
    let signal_task = tokio::spawn(async move {
        let interrupt = async {
            if tokio::signal::ctrl_c().await.is_err() {
                std::future::pending::<()>().await;
            }
        };
        tokio::select! { _ = interrupt => {}, _ = stop_signal.cancelled() => {} }
        stop_signal.cancel();
    });
    let (failures, mut failed) = mpsc::channel(32);
    let (ready_tx, mut ready_rx) = mpsc::channel(1);
    let mut forwarder: Option<ssh::Forwarder> = None;
    let mut udp_task = None;
    let mut manager = None;
    let mut renewal: Option<JoinHandle<()>> = None;
    let initialization = async {
        let endpoint = ssh::resolve(&shared.config).await?;
        shared.state.lock().unwrap().ssh_endpoint = Some(endpoint.value());
        let port = shared.config["listen_port"].as_u64().ok_or_else(invalid)? as u16;
        let socket = Arc::new(
            UdpSocket::bind((Ipv4Addr::LOCALHOST, port))
                .await
                .map_err(|_| Error::new("udp_bind", "Cannot bind the loopback UDP relay port."))?,
        );
        let udp_shared = shared.clone();
        udp_task = Some(tokio::spawn(async move {
            if let Err(error) = udp_receiver(udp_shared.clone(), socket).await {
                udp_shared.fail(error);
            }
        }));
        let gateway_shared = shared.clone();
        manager = Some(tokio::spawn(async move {
            let result = gateway_manager(gateway_shared.clone(), ready_tx).await;
            gateway_shared.state.lock().unwrap().gateway_recovering = false;
            if let Err(error) = result {
                gateway_shared.fail(error);
            }
        }));
        Ok::<_, Error>((endpoint, port))
    };
    let initial = tokio::select! {
        biased;
        _ = shared.stop.cancelled() => None,
        result = initialization => Some(result),
    };
    let result = async {
        let (endpoint, port) = match initial { Some(Ok(value)) => value, Some(Err(error)) => return Err(error), None => return Ok(()) };
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                biased;
                _ = shared.stop.cancelled() => break,
                Some(error) = failed.recv() => shared.fail(error),
                Some(()) = ready_rx.recv() => {
                    if shared.fatal.is_cancelled() { continue; }
                    if forwarder.is_none() {
                        let opened = ssh::Forwarder::open(port, endpoint.clone(), failures.clone(), &shared.stop).await?;
                        shared.state.lock().unwrap().ssh_count = opened.count.clone();
                        forwarder = Some(opened);
                    }
                    let mut state = shared.state.lock().unwrap();
                    if state.route_available && !shared.fatal.is_cancelled() {
                        state.public["ok"] = json!(true);
                        state.public["state"] = json!("ready");
                        state.public["error"] = Value::Null;
                        state.initialized = true;
                        state.no_clients_since = Instant::now();
                    }
                    drop(state);
                    common::atomic_json(&directory.join("status.json"), &shared.snapshot())?;
                }
                _ = tick.tick() => {
                    let mut removed = Vec::new();
                    let mut failed_warm = None;
                    let should_renew;
                    {
                        let mut state = shared.state.lock().unwrap();
                        let now = Instant::now();
                        for handle in state.flows.values() {
                            let flow = handle.record.data.lock().unwrap();
                            if now.duration_since(flow.last_activity) >= FLOW_IDLE { handle.cancel.cancel(); }
                        }
                        let finished: Vec<_> = state.flows.iter().filter(|(_, handle)| handle.task.is_finished()).map(|(address, _)| *address).collect();
                        for address in finished { if let Some(flow) = state.flows.remove(&address) { removed.push(flow); } }
                        if !removed.is_empty() && state.flows.is_empty() && state.ssh_count.load(Ordering::SeqCst) == 0 { state.no_clients_since = now; }
                        if state.ssh_count.load(Ordering::SeqCst) != 0 { state.no_clients_since = now; }
                        if state.warm.as_ref().is_some_and(|warm| !warm.usable()) { failed_warm = state.warm.take(); }
                        if (state.initialized || shared.fatal.is_cancelled()) && state.flows.is_empty()
                            && state.ssh_count.load(Ordering::SeqCst) == 0 && !state.gateway_recovering
                            && now.duration_since(state.no_clients_since) >= SERVICE_IDLE { shared.stop.cancel(); }
                        should_renew = !shared.fatal.is_cancelled() && state.public["state"] == "ready"
                            && state.credentials_expires.is_some_and(|expires| common::unix_time() >= expires - 300.0)
                            && renewal.as_ref().is_none_or(JoinHandle::is_finished);
                    }
                    for flow in removed { let _ = flow.task.await; }
                    if let Some(warm) = failed_warm {
                        let error = warm.health().err().unwrap_or(TransportError::Network);
                        if error.recoverable() { shared.defer(); shared.state.lock().unwrap().recovery_error = Some(error.public().message); }
                        else { shared.fail(error.public()); }
                        warm.close().await;
                        shared.state.lock().unwrap().retired_refreshes += warm.stats().refreshes;
                    }
                    if should_renew {
                        let renew_shared = shared.clone();
                        renewal = Some(tokio::spawn(async move {
                            tokio::select! {
                                biased;
                                _ = renew_shared.stop.cancelled() => {},
                                result = renew_shared.turn_config(true) => if let Err(error) = result { renew_shared.fail(error); },
                            }
                        }));
                    }
                    common::atomic_json(&directory.join("status.json"), &shared.snapshot())?;
                }
            }
        }
        Ok::<(), Error>(())
    }.await;
    if let Err(error) = result {
        shared.fail(error);
    }
    shared.stop.cancel();
    if let Some(renewal) = renewal {
        renewal.abort();
        let _ = renewal.await;
    }
    if let Some(udp) = udp_task {
        let _ = udp.await;
    }
    if let Some(mut manager) = manager {
        if timeout(Duration::from_secs(11), &mut manager)
            .await
            .is_err()
        {
            manager.abort();
            let _ = manager.await;
        }
    }
    retire_route(&shared).await;
    if let Some(forwarder) = forwarder {
        forwarder.close().await;
    }
    let _ = control.await;
    let _ = signal_task.await;
    {
        let mut state = shared.state.lock().unwrap();
        state.gateway_recovering = false;
        state.credentials_expires = None;
        if state.public["state"] != "error" {
            state.public["ok"] = json!(true);
            state.public["state"] = json!("stopped");
            state.public["mode"] = Value::Null;
            state.public["error"] = Value::Null;
        }
    }
    let final_status = shared.snapshot();
    common::atomic_json(&directory.join("status.json"), &final_status)?;
    remove_runtime(&directory.join("control.sock"), true)?;
    remove_runtime(&directory.join("pid.json"), false)?;
    Ok(final_status)
}

pub async fn run(args: &[String]) -> Result<Value> {
    let options = Options::parse(
        args,
        &[
            "--config",
            "--state-dir",
            "--mode",
            "--lock-fd",
            "--service-id",
        ],
        &[],
    )?;
    if options.positionals.len() != 1 {
        return Err(invalid());
    }
    let command = options.positionals[0].as_str();
    if !matches!(command, "start" | "resume" | "status" | "stop" | "serve") {
        return Err(invalid());
    }
    let config_path = PathBuf::from(options.required("--config")?);
    let directory = PathBuf::from(options.required("--state-dir")?);
    common::safe_local_absolute(config_path.to_str().ok_or_else(invalid)?)?;
    common::safe_local_absolute(directory.to_str().ok_or_else(invalid)?)?;
    common::private_dir(&directory, true)?;
    let config = match common::load_config(&config_path, false) {
        Ok(config) => Some(config),
        Err(_) if matches!(command, "status" | "stop") => None,
        Err(error) => return Err(error),
    };
    if command != "serve"
        && (options.get("--lock-fd").is_some() || options.get("--service-id").is_some())
    {
        return Err(invalid());
    }
    if !matches!(command, "start" | "serve") && options.get("--mode").is_some() {
        return Err(invalid());
    }
    let outcome = async {
        if command == "serve" {
            let mode = Mode::parse(options.required("--mode")?)?;
            let identity = options.required("--service-id")?;
            if identity.len() != 32 || !identity.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(invalid());
            }
            let lock = inherited_lock(&directory, options.required("--lock-fd")?)?;
            return serve(
                config.clone().ok_or_else(invalid)?,
                directory.clone(),
                mode,
                identity.into(),
                lock,
            )
            .await;
        }
        if command == "status" {
            return current_status(config.as_ref(), &directory).await;
        }
        let _command = common::lock(&directory.join("command.lock"), true).map_err(|_| {
            Error::new(
                "lifecycle_busy",
                "Another relay lifecycle command is in progress; wait and retry.",
            )
        })?;
        if command == "stop" {
            return stop(config.as_ref(), &directory).await;
        }
        let config = config.as_ref().ok_or_else(invalid)?;
        if command == "resume" {
            let Some(mode) = intent::load(config, &directory)? else {
                return current_status(Some(config), &directory).await;
            };
            return start(config, &config_path, &directory, Mode::parse(&mode)?).await;
        }
        let mode = Mode::parse(options.required("--mode")?)?;
        let result = start(config, &config_path, &directory, mode).await?;
        if result["ok"] == true && result["state"] == "ready" {
            intent::save(config, &directory, mode.name())?;
        }
        Ok(result)
    }
    .await;
    let mut result = outcome.unwrap_or_else(|error| {
        common::public_status(
            config.as_ref(),
            "error",
            options.get("--mode"),
            None,
            Some(error.message),
        )
    });
    result["resume_mode"] =
        json!(config
            .as_ref()
            .and_then(|config| intent::load(config, &directory).ok().flatten()));
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recovery_shared() -> Shared {
        let now = Instant::now();
        Shared {
            config: json!({}),
            mode: Mode::Tls,
            state: StdMutex::new(ServiceState {
                public: json!({"state": "ready"}),
                ssh_endpoint: None,
                ssh_count: Arc::new(AtomicUsize::new(0)),
                flows: HashMap::new(),
                warm: None,
                route_available: true,
                peer: None,
                key: [0; 32],
                generation: CancellationToken::new(),
                gateway_recovering: false,
                gateway_reconnects: 0,
                gateway_failure_reason: None,
                recovery_error: None,
                retired_refreshes: 0,
                bytes_up: 0,
                bytes_down: 0,
                dropped_packets: 0,
                dropped_bytes: 0,
                last_drop: None,
                allocation_retry_at: now,
                no_clients_since: now,
                demand: 0,
                credentials_expires: None,
                initialized: true,
            }),
            credentials: Mutex::new(CredentialCache {
                path: PathBuf::new(),
                cached: None,
                expires: 0.0,
                retry_at: now,
            }),
            stop: CancellationToken::new(),
            fatal: CancellationToken::new(),
            demand: Notify::new(),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn recovery_queued_work_retries_after_cooldown_without_new_enqueue() {
        let shared = recovery_shared();
        let record = FlowRecord::new(None);
        assert!(record.enqueue(b"pending handshake"));

        // Exercise flow_loop's production post-exhaustion gate, followed by
        // its existing cooldown, without issuing another local packet.
        shared.defer();
        let previous = record.data.lock().unwrap().demand;
        let retry = async {
            record.wait_after_allocation_failure(TransportError::Timeout).await;
            shared.cooldown().await;
        };
        tokio::pin!(retry);
        assert!(futures_util::poll!(retry.as_mut()).is_pending());
        tokio::time::advance(Duration::from_secs(29)).await;
        assert!(futures_util::poll!(retry.as_mut()).is_pending());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(
            futures_util::poll!(retry.as_mut()).is_ready(),
            "queued work must become retry-eligible when cooldown expires, without another enqueue"
        );
        assert_eq!(record.next().await, b"pending handshake");
        assert_eq!(record.data.lock().unwrap().demand, previous);
    }

    #[tokio::test(start_paused = true)]
    async fn recovery_empty_queue_waits_for_new_demand_after_allocation_failure() {
        let record = FlowRecord::new(None);
        let retry = record.wait_after_allocation_failure(TransportError::Timeout);
        tokio::pin!(retry);
        assert!(futures_util::poll!(retry.as_mut()).is_pending());
        tokio::time::advance(Duration::from_secs(30)).await;
        assert!(futures_util::poll!(retry.as_mut()).is_pending());
        assert!(record.enqueue(b"new handshake"));
        assert!(futures_util::poll!(retry.as_mut()).is_ready());
        assert_eq!(record.next().await, b"new handshake");
    }

    #[tokio::test(start_paused = true)]
    async fn recovery_existing_cooldown_wait_is_not_extended_by_another_flow() {
        let shared = recovery_shared();
        shared.defer();
        let waiting = shared.cooldown();
        tokio::pin!(waiting);
        assert!(futures_util::poll!(waiting.as_mut()).is_pending());

        tokio::time::advance(Duration::from_secs(29)).await;
        shared.defer();
        let newcomer = shared.cooldown();
        tokio::pin!(newcomer);
        assert!(futures_util::poll!(newcomer.as_mut()).is_pending());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(
            futures_util::poll!(waiting.as_mut()).is_ready(),
            "a later independent failure must not extend an already-waiting flow's cooldown"
        );
        assert!(futures_util::poll!(newcomer.as_mut()).is_pending());
        tokio::time::advance(Duration::from_secs(28)).await;
        assert!(futures_util::poll!(newcomer.as_mut()).is_pending());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(
            futures_util::poll!(newcomer.as_mut()).is_ready(),
            "a new waiter must honor the later shared cooldown deadline"
        );
    }

    #[tokio::test]
    async fn flow_loop_delivers_downlink_while_uplink_send_is_pending() {
        let mut fixture = transport::gated_endpoint(Duration::from_secs(120));
        let shared = Arc::new(recovery_shared());
        let record = Arc::new(FlowRecord::new(Some(fixture.endpoint.clone())));
        let socket = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap());
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let key = [7; 32];
        let codec = Codec::new(key);
        let frame = crate::protocol::encode(
            &key,
            crate::protocol::SERVER_TO_CLIENT,
            codec.flow,
            1,
            b"downlink while sending",
        ).unwrap();
        let mut channel = vec![0x40, 0];
        channel.extend_from_slice(&(frame.len() as u16).to_be_bytes());
        channel.extend_from_slice(&frame);
        channel.resize((channel.len() + 3) & !3, 0);
        assert!(record.enqueue(b"blocked uplink"));
        let worker = tokio::spawn(flow_loop(
            shared.clone(),
            record,
            socket.clone(),
            client.local_addr().unwrap(),
            "127.0.0.1:4321".parse().unwrap(),
            codec,
        ));

        // This barrier proves Endpoint::send reached the blocked transport
        // write before any authenticated downlink is made available.
        timeout(Duration::from_secs(2), fixture.entered.recv())
            .await.unwrap().unwrap();
        fixture.incoming.send(Ok(channel)).await.unwrap();
        let mut buffer = [0; 128];
        let received = timeout(Duration::from_secs(1), client.recv_from(&mut buffer)).await;
        let send_still_pending = matches!(
            fixture.written.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        );

        // Never release the write gate: delivery must not depend on uplink
        // completion. Clean up both real loops before reporting a failure.
        worker.abort();
        let _ = worker.await;
        fixture.endpoint.close().await;
        assert!(send_still_pending, "uplink must remain gated during downlink delivery");
        let (length, source) = received
            .expect("flow_loop must receive authenticated downlink while its uplink send is pending")
            .unwrap();
        assert_eq!(&buffer[..length], b"downlink while sending");
        assert_eq!(source, socket.local_addr().unwrap());
        let state = shared.state.lock().unwrap();
        assert_eq!(state.bytes_up, 0);
        assert_eq!(state.bytes_down, b"downlink while sending".len() as u64);
    }

    #[test]
    fn queue_bounds_drop_new_packets_but_preserve_demand_and_accounting() {
        let record = FlowRecord::new(None);
        for _ in 0..MAX_PACKETS {
            assert!(record.enqueue(&[1]));
        }
        assert!(!record.enqueue(&[2]));
        let data = record.data.lock().unwrap();
        assert_eq!(data.queue.len(), MAX_PACKETS);
        assert_eq!(data.bytes, MAX_PACKETS);
        assert_eq!(data.demand, MAX_PACKETS as u64 + 1);
        drop(data);
        let record = FlowRecord::new(None);
        for _ in 0..4 {
            assert!(record.enqueue(&vec![1; 65000]));
        }
        assert!(!record.enqueue(&vec![1; 65000]));
        assert_eq!(record.data.lock().unwrap().bytes, 260000);
    }

    #[test]
    fn recovery_preserves_retry_policy_and_rejects_security_failures() {
        assert_eq!(ALLOCATION_DELAYS, [2, 5]);
        assert_eq!(GATEWAY_DELAYS, [2, 5, 15, 30, 30]);
        assert_eq!(COOLDOWN.as_secs(), 30);
        for reason in [
            "control_eof",
            "heartbeat_timeout",
            "send_timeout",
            "frontend_exit",
            "state_lock_busy",
            "connectivity_uncertain",
        ] {
            assert!(gateway_recoverable(reason));
        }
        for reason in [
            "authorization_denied",
            "identity_mismatch",
            "security_error",
            "protocol_error",
            "unknown",
            "anything",
        ] {
            assert!(!gateway_recoverable(reason));
        }
    }

    #[test]
    fn gateway_recovery_requires_same_daemon_and_pins() {
        let original =
            json!({"daemon_pid":42,"fingerprint":"pin","daemon_socket":"/private/daemon.sock"});
        let config =
            json!({"gateway":{"fingerprint":"pin","daemon_socket":"/private/daemon.sock"}});
        assert!(same_generation(&original, &original, &config));
        for key in ["daemon_pid", "fingerprint", "daemon_socket"] {
            let mut changed = original.clone();
            changed[key] = Value::Null;
            assert!(!same_generation(&original, &changed, &config));
        }
        let zero =
            json!({"daemon_pid":0,"fingerprint":"pin","daemon_socket":"/private/daemon.sock"});
        assert!(!same_generation(&zero, &zero, &config));
    }

    #[tokio::test]
    async fn queue_pop_updates_bytes_and_demand_wait_cannot_lose_enqueue() {
        let record = FlowRecord::new(None);
        let demand = record.data.lock().unwrap().demand;
        record.enqueue(b"abc");
        timeout(Duration::from_millis(50), record.new_demand(demand))
            .await
            .unwrap();
        assert_eq!(record.next().await, b"abc");
        assert_eq!(record.data.lock().unwrap().bytes, 0);
    }

    #[tokio::test]
    async fn bounded_control_read_rejects_missing_newline_and_oversize() {
        let (mut sender, mut receiver) = tokio::io::duplex(128);
        sender
            .write_all(b"{\"command\":\"status\"}\n")
            .await
            .unwrap();
        assert_eq!(
            read_line(&mut receiver, 64).await.unwrap(),
            b"{\"command\":\"status\"}"
        );
        sender.write_all(b"123456789\n").await.unwrap();
        assert!(read_line(&mut receiver, 8).await.is_err());
        drop(sender);
        assert!(read_line(&mut receiver, 8).await.is_err());
    }

    fn private_test_directory(prefix: &str) -> PathBuf {
        let base = std::env::temp_dir().canonicalize().unwrap();
        #[cfg(windows)]
        let base = crate::windows_security::normalize_system_path(&base).unwrap();
        let directory = base.join(format!("{prefix}-{:032x}", rand::random::<u128>()));
        common::private_dir(&directory, true).unwrap();
        directory
    }

    #[tokio::test]
    async fn stale_pid_and_status_are_not_liveness_or_stop_authority() {
        let directory = private_test_directory("ttr-lifecycle");
        common::atomic_json(
            &directory.join("pid.json"),
            &json!({"pid":std::process::id(),"service_id":"stale"}),
        )
        .unwrap();
        common::atomic_json(
            &directory.join("status.json"),
            &json!({"ok":true,"state":"ready","service_id":"stale"}),
        )
        .unwrap();
        assert_eq!(
            current_status(None, &directory).await.unwrap()["state"],
            "stopped"
        );
        assert_eq!(stop(None, &directory).await.unwrap()["state"], "stopped");
        assert!(!directory.join("pid.json").exists());
        assert!(directory.join("status.json").exists());
        fs::remove_file(directory.join("status.json")).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn inherited_lock_must_match_private_service_lock_and_remain_exclusive() {
        use std::os::fd::IntoRawFd;
        let directory = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "ttr-lock-{}",
            hex::encode(rand::random::<[u8; 16]>())
        ));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("service.lock");
        let lock = common::lock(&path, true).unwrap();
        assert!(common::is_locked(&path).unwrap());
        let inherited = inherited_lock(&directory, &lock.into_raw_fd().to_string()).unwrap();
        assert!(common::is_locked(&path).unwrap());
        let unrelated = common::lock(&directory.join("other.lock"), true).unwrap();
        assert!(inherited_lock(&directory, &unrelated.into_raw_fd().to_string()).is_err());
        drop(inherited);
        // Other parallel tests can fork while this CLOEXEC descriptor is open.
        // Their inherited open-file description survives only until exec/exit;
        // require bounded release rather than assuming fork and exec are atomic.
        let release_deadline = Instant::now() + Duration::from_secs(2);
        while common::is_locked(&path).unwrap() && Instant::now() < release_deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(!common::is_locked(&path).unwrap());
        fs::remove_file(path).unwrap();
        fs::remove_file(directory.join("other.lock")).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_service_lock_is_exclusive_and_rejects_foreign_transfer_modes() {
        let directory = private_test_directory("ttr-lock");
        assert!(inherited_lock(&directory, "123").is_err());
        let owned = inherited_lock(&directory, "acquire").unwrap();
        assert!(common::is_locked(&directory.join("service.lock")).unwrap());
        assert!(common::lock(&directory.join("service.lock"), true).is_err());
        drop(owned);
        assert!(!common::is_locked(&directory.join("service.lock")).unwrap());
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_handoff_tolerates_a_read_only_status_probe() {
        let directory = private_test_directory("ttr-lock-handoff");
        let probe = common::lock(&directory.join("service.lock"), true).unwrap();
        let reached = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        let child_directory = directory.clone();
        let child_reached = reached.clone();
        let child_release = release.clone();
        let child = std::thread::spawn(move || {
            SERVICE_LOCK_BUSY_HOOK.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move || {
                    child_reached.wait();
                    child_release.wait();
                }));
            });
            inherited_lock(&child_directory, "acquire")
        });
        reached.wait();
        drop(probe);
        release.wait();
        let owned = child.join().unwrap().unwrap();
        assert!(common::is_locked(&directory.join("service.lock")).unwrap());
        assert_eq!(acquire_service_lock(&directory, Instant::now()).unwrap_err().code, "lock-busy");
        drop(owned);
        assert!(!common::is_locked(&directory.join("service.lock")).unwrap());
        fs::remove_dir_all(directory).unwrap();
    }
}
