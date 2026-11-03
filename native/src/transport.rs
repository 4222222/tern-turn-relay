//! Owned TURN TLS/UDP allocations. No library task outlives its endpoint.
//!
//! STUN attribute parsing/authentication is delegated to the pinned STUN/TURN
//! crates. This owner controls transaction deadlines, nonce retries, leases and
//! shutdown; it never lets a successful late response resurrect an expired lease.
//!
//! The upstream `turn::Client` cannot express the production renewal policy:
//! `RelayConnInternal::refresh_allocation` and its timer are private; the timer
//! uses the initial lifetime forever, retries only stale nonces, and treats
//! other refresh error responses as success (turn 0.17.2 relay_conn.rs).
//! We therefore own scheduling/transactions while keeping attribute encoders,
//! decoders, long-term credential derivation and integrity verification upstream.
use crate::common::{self, Error};
use rustls::pki_types::ServerName;
use serde_json::Value;
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};
use stun::{
    agent::TransactionId, attributes::*, error_code::ErrorCodeAttribute, fingerprint::FINGERPRINT,
    integrity::MessageIntegrity, message::*, textattrs::*,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    net::{TcpStream, UdpSocket},
    sync::{mpsc, oneshot, Mutex},
    task::JoinHandle,
    time::{timeout, timeout_at, Instant},
};
use tokio_rustls::{client::TlsStream, TlsConnector};
use tokio_util::sync::CancellationToken;
use turn::proto::{
    channum::ChannelNumber, data::Data, lifetime::Lifetime, peeraddr::PeerAddress,
    relayaddr::RelayedAddress, reqtrans::RequestedTransport, PROTO_UDP,
};

const OP_TIMEOUT: Duration = Duration::from_secs(18);
const MARGIN: Duration = Duration::from_millis(250);
const CHANNEL: u16 = 0x4000;
const MAX_WIRE: usize = 65535;
const RECEIVE_PACKETS: usize = 64;
const RECEIVE_BYTES: usize = 256 * 1024;
type Result<T, E = TransportError> = std::result::Result<T, E>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Tls,
    Udp,
}
impl Mode {
    pub fn parse(value: &str) -> common::Result<Self> {
        match value {
            "tls" => Ok(Self::Tls),
            "udp" => Ok(Self::Udp),
            _ => Err(Error::new("invalid_mode", "Relay mode must be tls or udp.")),
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Tls => "tls",
            Self::Udp => "udp",
        }
    }
}

#[derive(Clone)]
pub struct TurnConfig {
    pub mode: Mode,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub expires: f64,
}

pub fn select(entries: &Value, mode: Mode, expires: f64) -> common::Result<TurnConfig> {
    let mut selected: Option<TurnConfig> = None;
    for entry in entries.as_array().into_iter().flatten() {
        if entry
            .get("credentialType")
            .is_some_and(|value| value != "password")
        {
            continue;
        }
        let Some(username) = entry["username"].as_str().filter(|value| !value.is_empty()) else {
            continue;
        };
        let Some(password) = entry["credential"]
            .as_str()
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let urls: Vec<&str> = match &entry["urls"] {
            Value::String(url) => vec![url],
            Value::Array(urls) => urls.iter().filter_map(Value::as_str).collect(),
            _ => continue,
        };
        for url in urls {
            let prefix = match mode {
                Mode::Tls => "turns:",
                Mode::Udp => "turn:",
            };
            let Some(rest) = url.strip_prefix(prefix) else {
                continue;
            };
            let (authority, query) = rest.split_once('?').unwrap_or((rest, ""));
            if !query.is_empty()
                && query
                    != match mode {
                        Mode::Tls => "transport=tcp",
                        Mode::Udp => "transport=udp",
                    }
            {
                continue;
            }
            if authority.is_empty()
                || authority
                    .bytes()
                    .any(|b| b <= 32 || b >= 127 || b"/@#[]?".contains(&b))
            {
                continue;
            }
            let (host, port) = if let Some((host, port)) = authority.split_once(':') {
                let Some(port) = port.parse::<u16>().ok().filter(|value| *value != 0) else {
                    continue;
                };
                (host, port)
            } else {
                (authority, if mode == Mode::Tls { 5349 } else { 3478 })
            };
            if host.is_empty()
                || host.len() > 253
                || !host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
            {
                continue;
            }
            let candidate = TurnConfig {
                mode,
                host: host.into(),
                port,
                username: username.into(),
                password: password.into(),
                expires,
            };
            if selected
                .as_ref()
                .is_none_or(|old| old.port != 443 && port == 443)
            {
                selected = Some(candidate);
            }
        }
    }
    selected.ok_or_else(|| {
        Error::new(
            "turn_configuration",
            "Credential API returned no genuine matching TURN URL for the requested mode.",
        )
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportError {
    Configuration,
    TlsAuthentication,
    Authentication,
    Protocol,
    Network,
    Timeout,
    Expired,
    CredentialsExpired,
    Closed,
    Capacity,
}
impl TransportError {
    pub fn recoverable(self) -> bool {
        matches!(self, Self::Network | Self::Timeout | Self::Expired)
    }
    pub fn public(self) -> Error {
        let (code, message) = match self {
            Self::Configuration => (
                "turn_configuration",
                "Invalid TURN transport configuration.",
            ),
            Self::TlsAuthentication => (
                "turn_tls",
                "TURN TLS verification or handshake failed; no direct fallback was attempted.",
            ),
            Self::Authentication => (
                "turn_authorization",
                "TURN authorization was rejected; check provider authorization and quota.",
            ),
            Self::Protocol => (
                "turn_protocol",
                "TURN server returned an invalid control response.",
            ),
            Self::Network => (
                "turn_network",
                "TURN transport was lost; a new allocation is required.",
            ),
            Self::Timeout => (
                "turn_timeout",
                "TURN network operation timed out; no direct fallback was attempted.",
            ),
            Self::Expired => (
                "turn_expired",
                "TURN allocation expired; a new allocation is required.",
            ),
            Self::CredentialsExpired => (
                "turn_credentials_expired",
                "Active TURN credentials are expiring; disconnect and reconnect to recover.",
            ),
            Self::Closed => (
                "turn_closed",
                "TURN endpoint is closed; no packet was sent.",
            ),
            Self::Capacity => ("turn_capacity", "TURN transport capacity exceeded."),
        };
        Error::new(code, message)
    }
}

#[derive(Clone, Copy, Default)]
pub struct Stats {
    pub refreshes: u64,
}
struct State {
    allocation: Option<Instant>,
    permission: Option<Instant>,
    error: Option<TransportError>,
    expires: f64,
    refreshes: u64,
    receive_bytes: usize,
}
struct Shared {
    state: StdMutex<State>,
    cancel: CancellationToken,
}
impl Shared {
    fn check(&self) -> Result<Instant> {
        let state = self.state.lock().unwrap();
        if let Some(error) = state.error {
            return Err(error);
        }
        if self.cancel.is_cancelled() {
            return Err(TransportError::Closed);
        }
        if common::unix_time() >= state.expires - 15.0 {
            return Err(TransportError::CredentialsExpired);
        }
        let deadline = state.allocation.ok_or(TransportError::Protocol)?;
        let deadline = state
            .permission
            .map_or(deadline, |permission| deadline.min(permission));
        if deadline <= Instant::now() {
            return Err(TransportError::Expired);
        }
        Ok(deadline)
    }
    fn fail(&self, error: TransportError) {
        self.state.lock().unwrap().error.get_or_insert(error);
        self.cancel.cancel();
    }
    fn error(&self) -> TransportError {
        self.state
            .lock()
            .unwrap()
            .error
            .unwrap_or(TransportError::Closed)
    }
}

/// Earliest transmission, not response arrival, is the lease authority.
fn lease_end(sent: Instant, lifetime: Duration, now: Instant) -> Result<Instant> {
    let budget = lifetime
        .checked_sub(MARGIN)
        .ok_or(TransportError::Expired)?;
    let end = sent.checked_add(budget).ok_or(TransportError::Protocol)?;
    if end <= now {
        return Err(TransportError::Expired);
    }
    Ok(end)
}

fn parse_stun(raw: &[u8]) -> Result<Message> {
    if raw.len() < 20
        || raw[0] & 0xc0 != 0
        || raw[4..8] != [0x21, 0x12, 0xa4, 0x42]
        || u16::from_be_bytes([raw[2], raw[3]]) as usize + 20 != raw.len()
        || raw.len() % 4 != 0
    {
        return Err(TransportError::Protocol);
    }
    let mut message = Message::new();
    message
        .unmarshal_binary(raw)
        .map_err(|_| TransportError::Protocol)?;
    Ok(message)
}

enum Writer {
    Tls(WriteHalf<TlsStream<TcpStream>>),
    Udp(Arc<UdpSocket>),
    #[cfg(test)]
    Gated(tests::GatedWriter),
}
impl Writer {
    async fn send(&mut self, raw: &[u8]) -> Result<()> {
        match self {
            Self::Tls(writer) => {
                writer
                    .write_all(raw)
                    .await
                    .map_err(|_| TransportError::Network)?;
                writer.flush().await.map_err(|_| TransportError::Network)
            }
            Self::Udp(socket) => {
                if socket
                    .send(raw)
                    .await
                    .map_err(|_| TransportError::Network)?
                    != raw.len()
                {
                    return Err(TransportError::Network);
                }
                Ok(())
            }
            #[cfg(test)]
            Self::Gated(writer) => writer.send(raw).await,
        }
    }
}

async fn read_tls(reader: &mut ReadHalf<TlsStream<TcpStream>>, buffer: &mut [u8]) -> Result<usize> {
    reader
        .read_exact(&mut buffer[..4])
        .await
        .map_err(|_| TransportError::Network)?;
    let length = u16::from_be_bytes([buffer[2], buffer[3]]) as usize;
    let total = match buffer[0] & 0xc0 {
        0 if length % 4 == 0 => 20 + length,
        0x40 => (4 + length + 3) & !3,
        _ => return Err(TransportError::Protocol),
    };
    if total > buffer.len() {
        return Err(TransportError::Capacity);
    }
    reader
        .read_exact(&mut buffer[4..total])
        .await
        .map_err(|_| TransportError::Network)?;
    Ok(total)
}

struct ReaderGuard(JoinHandle<()>);
impl Drop for ReaderGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn tls_handshake_error(error: std::io::Error) -> TransportError {
    // rustls 的证书/协议验证错误始终失败关闭，不能按网络中断恢复。
    if error.get_ref().is_some_and(|source| source.is::<rustls::Error>()) {
        return TransportError::TlsAuthentication;
    }
    match error.kind() {
        std::io::ErrorKind::TimedOut => TransportError::Timeout,
        std::io::ErrorKind::ConnectionReset
        | std::io::ErrorKind::ConnectionAborted
        | std::io::ErrorKind::UnexpectedEof
        | std::io::ErrorKind::BrokenPipe
        | std::io::ErrorKind::NotConnected => TransportError::Network,
        _ => TransportError::TlsAuthentication,
    }
}

async fn wire(
    config: &TurnConfig,
    shared: Arc<Shared>,
) -> Result<(Writer, mpsc::Receiver<Result<Vec<u8>>>, ReaderGuard)> {
    let address = tokio::net::lookup_host((config.host.as_str(), config.port))
        .await
        .map_err(|_| TransportError::Network)?
        .find(SocketAddr::is_ipv4)
        .ok_or(TransportError::Configuration)?;
    let (sender, receiver) = mpsc::channel(64);
    let cancel = shared.cancel.clone();
    if config.mode == Mode::Udp {
        let socket = Arc::new(
            UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
                .await
                .map_err(|_| TransportError::Network)?,
        );
        socket
            .connect(address)
            .await
            .map_err(|_| TransportError::Network)?;
        let read_socket = socket.clone();
        let task = tokio::spawn(async move {
            let mut buffer = vec![0; MAX_WIRE];
            loop {
                let result = tokio::select! {
                    biased;
                    _ = cancel.cancelled() => break,
                    result = read_socket.recv(&mut buffer) => result.map(|n| buffer[..n].to_vec()).map_err(|_| TransportError::Network),
                };
                let failed = result.is_err();
                // UDP congestion is packet loss; never block control behind payloads.
                match sender.try_send(result) {
                    Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
                    Err(mpsc::error::TrySendError::Closed(_)) => break,
                }
                if failed {
                    shared.fail(TransportError::Network);
                    break;
                }
            }
        });
        return Ok((Writer::Udp(socket), receiver, ReaderGuard(task)));
    }
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| TransportError::Configuration)?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let name =
        ServerName::try_from(config.host.clone()).map_err(|_| TransportError::Configuration)?;
    let tcp = TcpStream::connect(address)
        .await
        .map_err(|_| TransportError::Network)?;
    tcp.set_nodelay(true).map_err(|_| TransportError::Network)?;
    let stream = TlsConnector::from(Arc::new(tls))
        .connect(name, tcp)
        .await
        .map_err(tls_handshake_error)?;
    let (mut reader, writer) = tokio::io::split(stream);
    let task = tokio::spawn(async move {
        let mut buffer = vec![0; MAX_WIRE];
        loop {
            let result = tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                result = read_tls(&mut reader, &mut buffer) => result.map(|n| buffer[..n].to_vec()),
            };
            let failed = result.as_ref().err().copied();
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                result = sender.send(result) => if result.is_err() { break; },
            }
            if let Some(error) = failed {
                shared.fail(error);
                break;
            }
        }
    });
    Ok((Writer::Tls(writer), receiver, ReaderGuard(task)))
}

struct SendCommand {
    frame: Vec<u8>,
    reply: oneshot::Sender<Result<()>>,
}
pub struct Endpoint {
    shared: Arc<Shared>,
    commands: mpsc::Sender<SendCommand>,
    packets: Mutex<mpsc::Receiver<Vec<u8>>>,
    owner: Mutex<Option<JoinHandle<()>>>,
    pub expires: f64,
}
impl Endpoint {
    pub async fn open(config: TurnConfig, peer: SocketAddr) -> Result<Self> {
        let shared = Arc::new(Shared {
            state: StdMutex::new(State {
                allocation: None,
                permission: None,
                error: None,
                expires: config.expires,
                refreshes: 0,
                receive_bytes: 0,
            }),
            cancel: CancellationToken::new(),
        });
        let (commands, command_rx) = mpsc::channel(1);
        let (packets_tx, packets) = mpsc::channel(RECEIVE_PACKETS);
        let (ready_tx, ready_rx) = oneshot::channel();
        let owner_shared = shared.clone();
        let expires = config.expires;
        let owner = tokio::spawn(async move {
            let result = owner(
                config,
                peer,
                owner_shared.clone(),
                command_rx,
                packets_tx,
                ready_tx,
            )
            .await;
            owner_shared.fail(result.err().unwrap_or(TransportError::Closed));
        });
        let endpoint = Self {
            shared,
            commands,
            packets: Mutex::new(packets),
            owner: Mutex::new(Some(owner)),
            expires,
        };
        match timeout(OP_TIMEOUT, ready_rx).await {
            Ok(Ok(Ok(()))) => Ok(endpoint),
            result => {
                let error = match result {
                    Ok(Ok(Err(error))) => error,
                    Err(_) => TransportError::Timeout,
                    _ => endpoint.shared.error(),
                };
                endpoint.shared.fail(error);
                endpoint.close().await;
                Err(error)
            }
        }
    }
    pub fn usable(&self) -> bool {
        self.shared.check().is_ok()
    }
    pub fn health(&self) -> Result<()> {
        self.shared.check().map(|_| ())
    }
    pub fn stats(&self) -> Stats {
        let state = self.shared.state.lock().unwrap();
        Stats {
            refreshes: state.refreshes,
        }
    }
    pub async fn failure(&self) -> TransportError {
        self.shared.cancel.cancelled().await;
        self.shared.error()
    }
    pub async fn send(&self, frame: &[u8]) -> Result<()> {
        if frame.len() > crate::protocol::MAX_FRAME {
            return Err(TransportError::Capacity);
        }
        let until = self.shared.check()?.min(Instant::now() + OP_TIMEOUT);
        let (reply, response) = oneshot::channel();
        let operation = async {
            self.commands
                .send(SendCommand {
                    frame: frame.to_vec(),
                    reply,
                })
                .await
                .map_err(|_| self.shared.error())?;
            response.await.map_err(|_| self.shared.error())?
        };
        tokio::select! {
            biased;
            _ = self.shared.cancel.cancelled() => Err(self.shared.error()),
            result = timeout_at(until, operation) => match result { Ok(result) => result, Err(_) => { self.shared.fail(TransportError::Timeout); Err(TransportError::Timeout) } },
        }
    }
    pub async fn recv(&self, buffer: &mut [u8]) -> Result<usize> {
        let operation = async {
            let mut receiver = self.packets.lock().await;
            let packet = receiver.recv().await.ok_or_else(|| self.shared.error())?;
            self.shared.state.lock().unwrap().receive_bytes -= packet.len();
            self.shared.check()?;
            if packet.len() > buffer.len() {
                return Err(TransportError::Capacity);
            }
            buffer[..packet.len()].copy_from_slice(&packet);
            Ok(packet.len())
        };
        tokio::select! {
            biased;
            _ = self.shared.cancel.cancelled() => Err(self.shared.error()),
            result = operation => result,
        }
    }
    pub async fn close(&self) {
        self.shared.cancel.cancel();
        if let Some(mut owner) = self.owner.lock().await.take() {
            if timeout(Duration::from_secs(2), &mut owner).await.is_err() {
                owner.abort();
                let _ = owner.await;
            }
        }
    }
}
impl Drop for Endpoint {
    fn drop(&mut self) {
        self.shared.cancel.cancel();
    }
}

struct Owner {
    // Temporarily owned by write_frame while its single write future is pending.
    writer: Option<Writer>,
    incoming: mpsc::Receiver<Result<Vec<u8>>>,
    _reader: ReaderGuard,
    shared: Arc<Shared>,
    packets: mpsc::Sender<Vec<u8>>,
    commands: mpsc::Receiver<SendCommand>,
    config: TurnConfig,
    peer: SocketAddr,
    realm: Option<Realm>,
    nonce: Option<Nonce>,
    integrity: Option<MessageIntegrity>,
    lifetime: Duration,
    refresh_at: Instant,
    bind_at: Instant,
    bound: bool,
    frame: Vec<u8>,
}
impl Owner {
    fn request(&self, method: Method, deleting: bool) -> Result<Message> {
        let mut attrs: Vec<Box<dyn Setter>> = vec![
            Box::new(TransactionId::new()),
            Box::new(MessageType::new(method, CLASS_REQUEST)),
        ];
        if method == METHOD_ALLOCATE {
            attrs.push(Box::new(RequestedTransport {
                protocol: PROTO_UDP,
            }));
            attrs.push(Box::new(Lifetime(Duration::from_secs(120))));
        } else if method == METHOD_REFRESH {
            attrs.push(Box::new(Lifetime(if deleting {
                Duration::ZERO
            } else {
                self.lifetime
            })));
        } else if method == METHOD_CHANNEL_BIND {
            attrs.push(Box::new(ChannelNumber(CHANNEL)));
            attrs.push(Box::new(PeerAddress {
                ip: self.peer.ip(),
                port: self.peer.port(),
            }));
        }
        if let (Some(realm), Some(nonce), Some(integrity)) =
            (&self.realm, &self.nonce, &self.integrity)
        {
            attrs.push(Box::new(Username::new(
                ATTR_USERNAME,
                self.config.username.clone(),
            )));
            attrs.push(Box::new(realm.clone()));
            attrs.push(Box::new(nonce.clone()));
            attrs.push(Box::new(integrity.clone()));
        }
        attrs.push(Box::new(FINGERPRINT));
        let mut message = Message::new();
        message
            .build(&attrs)
            .map_err(|_| TransportError::Protocol)?;
        Ok(message)
    }
    fn deliver(&mut self, raw: &[u8]) -> Result<bool> {
        if raw.first().is_some_and(|byte| byte & 0xc0 == 0x40) {
            if raw.len() < 4 {
                return Err(TransportError::Protocol);
            }
            let length = u16::from_be_bytes([raw[2], raw[3]]) as usize;
            if raw.len() < length + 4 || raw.len() > ((length + 7) & !3) {
                return Err(TransportError::Protocol);
            }
            if u16::from_be_bytes([raw[0], raw[1]]) != CHANNEL {
                return Ok(true);
            }
            if self.bound {
                self.packet(&raw[4..4 + length])?;
            }
            return Ok(true);
        }
        let message = parse_stun(raw)?;
        if message.typ == MessageType::new(METHOD_DATA, CLASS_INDICATION) {
            let mut peer = PeerAddress::default();
            let mut data = Data::default();
            peer.get_from(&message)
                .map_err(|_| TransportError::Protocol)?;
            data.get_from(&message)
                .map_err(|_| TransportError::Protocol)?;
            if self.bound && SocketAddr::new(peer.ip, peer.port) == self.peer {
                self.packet(&data.0)?;
            }
            return Ok(true);
        }
        Ok(false)
    }
    fn dispatch_payload(&mut self, raw: &[u8]) -> Result<bool> {
        match self.deliver(raw) {
            // A connected UDP socket filters source tuples, not source spoofing.
            // Unauthenticated malformed datagrams are loss, never a fatal verdict.
            Err(TransportError::Protocol | TransportError::Capacity)
                if self.config.mode == Mode::Udp =>
            {
                Ok(true)
            }
            result => result,
        }
    }

    fn received(&self, packet: Option<Result<Vec<u8>>>) -> Result<Vec<u8>> {
        // Cancellation also stops the reader and closes this channel. Either
        // select branch may win, but reader shutdown is not network failure.
        if self.shared.cancel.is_cancelled() {
            return Err(TransportError::Closed);
        }
        packet.ok_or(TransportError::Network)?
    }

    fn packet(&self, payload: &[u8]) -> Result<()> {
        self.shared.check()?;
        if payload.len() > crate::protocol::MAX_FRAME {
            return Ok(());
        }
        let mut state = self.shared.state.lock().unwrap();
        if state.receive_bytes + payload.len() > RECEIVE_BYTES {
            return Ok(());
        }
        match self.packets.try_send(payload.to_vec()) {
            Ok(()) => state.receive_bytes += payload.len(),
            Err(mpsc::error::TrySendError::Full(_)) => {}
            Err(mpsc::error::TrySendError::Closed(_)) => return Err(TransportError::Closed),
        }
        Ok(())
    }
    fn dispatch_response(&mut self, raw: &[u8], request: &Message) -> Result<Option<Message>> {
        if self.dispatch_payload(raw)? {
            return Ok(None);
        }
        let mut message = parse_stun(raw)?;
        if message.transaction_id != request.transaction_id {
            return Ok(None);
        }
        if message.typ.method != request.typ.method
            || !matches!(message.typ.class, CLASS_SUCCESS_RESPONSE | CLASS_ERROR_RESPONSE)
        {
            return if self.config.mode == Mode::Udp {
                Ok(None)
            } else {
                Err(TransportError::Protocol)
            };
        }
        if let Err(error) = self.validate_response(&mut message) {
            return if self.config.mode == Mode::Udp { Ok(None) } else { Err(error) };
        }
        Ok(Some(message))
    }

    async fn write_frame(
        &mut self,
        raw: &[u8],
        until: Instant,
        request: Option<&Message>,
    ) -> Result<Option<Message>> {
        let mut writer = self.writer.take().expect("one ordered transport writer");
        let result = async {
            if until <= Instant::now() {
                return Err(TransportError::Timeout);
            }
            let sending = timeout_at(until, writer.send(raw));
            tokio::pin!(sending);
            // At most one authenticated matching response is retained. Receiving
            // never restarts/cancels the write, including a partially flushed TLS frame.
            let mut response = None;
            loop {
                tokio::select! {
                    biased;
                    _ = self.shared.cancel.cancelled() => return Err(TransportError::Closed),
                    result = &mut sending => {
                        result.map_err(|_| TransportError::Timeout)??;
                        return Ok(response);
                    }
                    raw = self.incoming.recv() => {
                        let raw = self.received(raw)?;
                        if let Some(request) = request.filter(|_| response.is_none()) {
                            response = self.dispatch_response(&raw, request)?;
                        } else {
                            self.dispatch_payload(&raw)?;
                        }
                    }
                }
            }
        }.await;
        self.writer = Some(writer);
        if let Err(error) = &result {
            // Any interrupted TLS write may have emitted a partial frame.
            if self.config.mode == Mode::Tls {
                self.shared.fail(*error);
            }
        }
        result
    }

    async fn transaction(
        &mut self,
        request: &Message,
        until: Instant,
    ) -> Result<(Message, Instant)> {
        if self.shared.cancel.is_cancelled() {
            return Err(TransportError::Closed);
        }
        if until <= Instant::now() {
            return Err(TransportError::Timeout);
        }
        let sent = Instant::now();
        if let Some(response) = self.write_frame(&request.raw, until, Some(request)).await? {
            return Ok((response, sent));
        }
        let mut interval = Duration::from_millis(500);
        let mut retransmit = sent + interval;
        loop {
            tokio::select! {
                _ = self.shared.cancel.cancelled() => return Err(TransportError::Closed),
                _ = tokio::time::sleep_until(until) => return Err(TransportError::Timeout),
                raw = self.incoming.recv() => {
                    let raw = self.received(raw)?;
                    if let Some(message) = self.dispatch_response(&raw, request)? {
                        return Ok((message, sent));
                    }
                }
                _ = tokio::time::sleep_until(retransmit), if self.config.mode == Mode::Udp => {
                    if let Some(message) = self.write_frame(&request.raw, until, Some(request)).await? {
                        return Ok((message, sent));
                    }
                    interval = (interval * 2).min(Duration::from_secs(4));
                    retransmit = Instant::now() + interval;
                }
                command = self.commands.recv(), if self.bound && !self.commands.is_closed() => {
                    if let Some(command) = command {
                        if let Some(message) = self.send_command(command, until, Some(request)).await? {
                            return Ok((message, sent));
                        }
                    }
                }
            }
        }
    }
    fn authenticate(&self, response: &mut Message) -> Result<()> {
        let mut signed = false;
        let mut fingerprint = false;
        for attribute in &response.attributes.0 {
            if attribute.typ == ATTR_MESSAGE_INTEGRITY {
                if signed || attribute.length != 20 {
                    return Err(TransportError::Authentication);
                }
                signed = true;
            } else if signed {
                // STUN permits only FINGERPRINT after MESSAGE-INTEGRITY. Never
                // use a lifetime, error, realm or nonce outside its HMAC scope.
                if attribute.typ != ATTR_FINGERPRINT || fingerprint || attribute.length != 4 {
                    return Err(TransportError::Authentication);
                }
                fingerprint = true;
            }
        }
        if !signed {
            return Err(TransportError::Authentication);
        }
        self.integrity
            .as_ref()
            .ok_or(TransportError::Authentication)?
            .check(response)
            .map_err(|_| TransportError::Authentication)
    }
    fn response_code(response: &Message) -> Result<Option<u16>> {
        if response.typ.class != CLASS_ERROR_RESPONSE {
            return Ok(None);
        }
        let mut error = ErrorCodeAttribute::default();
        error
            .get_from(response)
            .map_err(|_| TransportError::Protocol)?;
        Ok(Some(error.code.0))
    }

    fn validate_response(&self, response: &mut Message) -> Result<()> {
        let code = Self::response_code(response)?;
        let unsigned_challenge = (self.integrity.is_none() && code == Some(401))
            || (code == Some(438) && !response.contains(ATTR_MESSAGE_INTEGRITY));
        if unsigned_challenge {
            // Challenges may be unsigned, but cannot authorize a lease or an
            // error verdict. Discard malformed challenges before state changes.
            let realm =
                Realm::get_from_as(response, ATTR_REALM).map_err(|_| TransportError::Protocol)?;
            let nonce =
                Nonce::get_from_as(response, ATTR_NONCE).map_err(|_| TransportError::Protocol)?;
            if realm.text.is_empty()
                || realm.text.len() > 763
                || nonce.text.is_empty()
                || nonce.text.len() > 763
                || self
                    .realm
                    .as_ref()
                    .is_some_and(|previous| previous.text != realm.text)
            {
                return Err(TransportError::Authentication);
            }
            return Ok(());
        }
        self.authenticate(response)
    }

    async fn control(&mut self, method: Method, until: Instant) -> Result<(Message, Instant)> {
        for _ in 0..3 {
            let request = self.request(method, false)?;
            let authenticated = self.integrity.is_some();
            let (response, sent) = self.transaction(&request, until).await?;
            let code = Self::response_code(&response)?;
            if (code == Some(401) && !authenticated && method == METHOD_ALLOCATE)
                || code == Some(438)
            {
                let realm = Realm::get_from_as(&response, ATTR_REALM)
                    .map_err(|_| TransportError::Protocol)?;
                if self
                    .realm
                    .as_ref()
                    .is_some_and(|previous| previous.text != realm.text)
                {
                    return Err(TransportError::Authentication);
                }
                let nonce = Nonce::get_from_as(&response, ATTR_NONCE)
                    .map_err(|_| TransportError::Protocol)?;
                if realm.text.is_empty()
                    || realm.text.len() > 763
                    || nonce.text.is_empty()
                    || nonce.text.len() > 763
                {
                    return Err(TransportError::Protocol);
                }
                self.integrity = Some(MessageIntegrity::new_long_term_integrity(
                    self.config.username.clone(),
                    realm.text.clone(),
                    self.config.password.clone(),
                ));
                self.realm = Some(realm);
                self.nonce = Some(nonce);
                continue;
            }
            if let Some(code) = code {
                return Err(match code {
                    401 | 403 | 441 => TransportError::Authentication,
                    437 => {
                        // A verified allocation-loss response revokes the route
                        // now; it must not enter refresh retries or backoff.
                        self.shared.fail(TransportError::Expired);
                        TransportError::Expired
                    }
                    _ => TransportError::Protocol,
                });
            }
            if !authenticated {
                return Err(TransportError::Authentication);
            }
            return Ok((response, sent));
        }
        Err(TransportError::Authentication)
    }
    fn accept_allocation(
        &mut self,
        response: &Message,
        sent: Instant,
        refreshing: bool,
    ) -> Result<()> {
        let mut lifetime = Lifetime::default();
        lifetime
            .get_from(response)
            .map_err(|_| TransportError::Protocol)?;
        let now = Instant::now();
        let end = lease_end(sent, lifetime.0, now)?;
        if refreshing {
            self.shared.check()?;
        }
        self.lifetime = lifetime.0;
        self.refresh_at = sent + lifetime.0 / 2;
        let mut state = self.shared.state.lock().unwrap();
        state.allocation = Some(end);
        if refreshing {
            state.refreshes += 1;
        }
        Ok(())
    }
    async fn bind(&mut self) -> Result<()> {
        let until = self.shared.check()?.min(Instant::now() + OP_TIMEOUT);
        let (_, sent) = self.control(METHOD_CHANNEL_BIND, until).await?;
        self.shared.check()?;
        self.shared.state.lock().unwrap().permission =
            Some(lease_end(sent, Duration::from_secs(300), Instant::now())?);
        self.bind_at = sent + Duration::from_secs(90);
        self.bound = true;
        Ok(())
    }
    async fn refresh(&mut self) -> Result<()> {
        for attempt in 0..3 {
            let end = self.shared.check()?;
            let until = end.min(Instant::now() + OP_TIMEOUT.min(self.lifetime / 12));
            match self.control(METHOD_REFRESH, until).await {
                Ok((response, sent)) => return self.accept_allocation(&response, sent, true),
                Err(error)
                    if matches!(error, TransportError::Network | TransportError::Timeout)
                        && attempt < 2 =>
                {
                    // Timeout on a TLS write poisons stream framing: the send
                    // wrapper fails the owner instead of retrying that stream.
                    let until = self
                        .shared
                        .check()?
                        .min(Instant::now() + Duration::from_secs(1 << attempt));
                    self.wait_retry(until).await?;
                }
                Err(error) => return Err(error),
            }
        }
        Err(TransportError::Timeout)
    }
    async fn wait_retry(&mut self, retry_at: Instant) -> Result<()> {
        loop {
            if self.shared.cancel.is_cancelled() {
                return Err(TransportError::Closed);
            }
            let expires = self.shared.check()?;
            if Instant::now() >= retry_at {
                return Ok(());
            }
            tokio::select! {
                _ = self.shared.cancel.cancelled() => return Err(TransportError::Closed),
                _ = tokio::time::sleep_until(retry_at.min(expires)) => {
                    self.shared.check()?;
                    return Ok(());
                }
                raw = self.incoming.recv() => {
                    let raw = self.received(raw)?;
                    self.dispatch_payload(&raw)?;
                }
                command = self.commands.recv(), if !self.commands.is_closed() => {
                    if let Some(command) = command {
                        self.send_command(command, Instant::now() + OP_TIMEOUT, None).await?;
                    }
                }
            }
        }
    }

    async fn send_command(
        &mut self,
        command: SendCommand,
        control_deadline: Instant,
        request: Option<&Message>,
    ) -> Result<Option<Message>> {
        let until = self
            .shared
            .check()?
            .min(Instant::now() + OP_TIMEOUT)
            .min(control_deadline);
        self.frame.clear();
        self.frame.extend_from_slice(&CHANNEL.to_be_bytes());
        self.frame
            .extend_from_slice(&(command.frame.len() as u16).to_be_bytes());
        self.frame.extend_from_slice(&command.frame);
        if self.config.mode == Mode::Tls {
            self.frame.resize((self.frame.len() + 3) & !3, 0);
        }
        let frame = std::mem::take(&mut self.frame);
        let result = self.write_frame(&frame, until, request).await.and_then(|response| {
            self.shared.check()?;
            Ok(response)
        });
        self.frame = frame;
        let status = result.as_ref().map(|_| ()).map_err(|error| *error);
        let _ = command.reply.send(status);
        if let Err(error) = status {
            self.shared.fail(error);
        }
        result
    }
    async fn loop_packets(&mut self) -> Result<()> {
        loop {
            let expiry = self.shared.check()?;
            let credential_wait = Duration::from_secs_f64(
                (self.config.expires - 15.0 - common::unix_time()).max(0.0),
            );
            let next = expiry
                .min(self.refresh_at)
                .min(self.bind_at)
                .min(Instant::now() + credential_wait);
            tokio::select! {
                _ = self.shared.cancel.cancelled() => return Ok(()),
                _ = tokio::time::sleep_until(next) => {
                    self.shared.check()?;
                    if Instant::now() >= self.refresh_at { self.refresh().await?; }
                    if Instant::now() >= self.bind_at { self.bind().await?; }
                }
                raw = self.incoming.recv() => {
                    let raw = self.received(raw)?;
                    self.dispatch_payload(&raw)?;
                }
                command = self.commands.recv() => {
                    let Some(command) = command else { return Ok(()); };
                    self.send_command(command, Instant::now() + OP_TIMEOUT, None).await?;
                }
            }
        }
    }
}

async fn owner(
    config: TurnConfig,
    peer: SocketAddr,
    shared: Arc<Shared>,
    commands: mpsc::Receiver<SendCommand>,
    packets: mpsc::Sender<Vec<u8>>,
    ready: oneshot::Sender<Result<()>>,
) -> Result<()> {
    let setup = async {
        let (writer, incoming, reader) = wire(&config, shared.clone()).await?;
        let now = Instant::now();
        let mut owner = Owner {
            writer: Some(writer),
            incoming,
            _reader: reader,
            shared: shared.clone(),
            packets,
            commands,
            config,
            peer,
            realm: None,
            nonce: None,
            integrity: None,
            lifetime: Duration::from_secs(120),
            refresh_at: now,
            bind_at: now,
            bound: false,
            frame: Vec::with_capacity(crate::protocol::MAX_FRAME + 4),
        };
        let (response, sent) = owner.control(METHOD_ALLOCATE, now + OP_TIMEOUT).await?;
        let mut relayed = RelayedAddress::default();
        relayed
            .get_from(&response)
            .map_err(|_| TransportError::Protocol)?;
        if !relayed.ip.is_ipv4() || relayed.port == 0 {
            return Err(TransportError::Protocol);
        }
        owner.accept_allocation(&response, sent, false)?;
        owner.bind().await?;
        Ok::<Owner, TransportError>(owner)
    };
    let initialized = tokio::select! {
        biased;
        _ = shared.cancel.cancelled() => Err(TransportError::Closed),
        result = timeout(OP_TIMEOUT, setup) => result.unwrap_or(Err(TransportError::Timeout)),
    };
    let mut owner = match initialized {
        Ok(owner) => owner,
        Err(error) => {
            let _ = ready.send(Err(error));
            return Err(error);
        }
    };
    if ready.send(Ok(())).is_err() {
        return Err(TransportError::Closed);
    }
    let result = tokio::select! {
        biased;
        _ = shared.cancel.cancelled() => Ok(()),
        result = owner.loop_packets() => result,
    };
    // A cancelled partial TLS write is never followed by another frame. Closing
    // both halves retires the allocation; UDP can safely send a best-effort delete.
    if owner.config.mode == Mode::Udp {
        if let Ok(delete) = owner.request(METHOD_REFRESH, true) {
            if let Some(writer) = owner.writer.as_mut() {
                let _ = timeout(Duration::from_secs(1), writer.send(&delete.raw)).await;
            }
        }
    }
    result
}

#[cfg(test)]
pub(crate) use tests::{gated_endpoint, gated_endpoint_expiring};

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn selects_only_genuine_mode_and_prefers_443() {
        let entries = json!([{"urls":["turns:turn.example:5349?transport=tcp","turn:turn.example:443?transport=udp","turns:turn.example:443?transport=tcp"],"username":"u","credential":"p"}]);
        assert_eq!(select(&entries, Mode::Tls, 123.0).unwrap().port, 443);
        assert_eq!(select(&entries, Mode::Udp, 123.0).unwrap().port, 443);
        for url in [
            "https://turn.example",
            "turns://turn.example",
            "turns:user@turn.example",
            "turns:turn.example?transport=udp",
            "turns:turn.example?transport=tcp&other=x",
            "turns:turn.example:0",
        ] {
            assert!(select(
                &json!([{"urls":url,"username":"u","credential":"p"}]),
                Mode::Tls,
                123.0
            )
            .is_err());
        }
    }

    #[test]
    fn expiry_cannot_be_extended_by_response_latency() {
        let sent = Instant::now();
        let lifetime = Duration::from_secs(120);
        let early = lease_end(sent, lifetime, sent + Duration::from_secs(1)).unwrap();
        let late = lease_end(sent, lifetime, sent + Duration::from_secs(119)).unwrap();
        assert_eq!(early, late);
        assert!(lease_end(sent, lifetime, sent + lifetime).is_err());
        assert!(lease_end(sent, Duration::ZERO, sent).is_err());
    }

    #[tokio::test]
    async fn peer_closing_during_tls_handshake_is_recoverable_network_loss() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let config = TurnConfig {
            mode: Mode::Tls,
            host: "127.0.0.1".into(),
            port: listener.local_addr().unwrap().port(),
            username: "test-user".into(),
            password: "test-password".into(),
            expires: common::unix_time() + 3600.0,
        };
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut hello = [0u8; 4096];
            assert!(stream.read(&mut hello).await.unwrap() > 0);
            // 模拟握手中的网络断开，没有发送证书或 TLS 验证失败告警。
        });
        let shared = Arc::new(Shared {
            state: StdMutex::new(State {
                allocation: None, permission: None, error: None,
                expires: config.expires, refreshes: 0, receive_bytes: 0,
            }),
            cancel: CancellationToken::new(),
        });
        let error = timeout(Duration::from_secs(5), wire(&config, shared)).await.unwrap().err().unwrap();
        peer.await.unwrap();
        assert_eq!(error, TransportError::Network);
        assert!(error.recoverable());
    }

    #[test]
    fn tls_verification_errors_never_become_recoverable_network_errors() {
        for kind in [std::io::ErrorKind::InvalidData, std::io::ErrorKind::ConnectionReset] {
            let error = std::io::Error::new(kind,
                rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer));
            let classified = tls_handshake_error(error);
            assert_eq!(classified, TransportError::TlsAuthentication);
            assert!(!classified.recoverable());
        }
        assert_eq!(tls_handshake_error(std::io::ErrorKind::TimedOut.into()), TransportError::Timeout);
        assert_eq!(tls_handshake_error(std::io::ErrorKind::Other.into()), TransportError::TlsAuthentication);
    }

    #[test]
    fn only_network_and_lost_allocations_are_recoverable() {
        for error in [
            TransportError::Network,
            TransportError::Timeout,
            TransportError::Expired,
        ] {
            assert!(error.recoverable());
        }
        for error in [
            TransportError::TlsAuthentication,
            TransportError::Authentication,
            TransportError::Protocol,
            TransportError::CredentialsExpired,
            TransportError::Configuration,
            TransportError::Closed,
        ] {
            assert!(!error.recoverable());
        }
    }

    #[test]
    fn lease_gate_checks_credentials_and_expired_permission() {
        let shared = Shared {
            state: StdMutex::new(State {
                allocation: Some(Instant::now() + Duration::from_secs(10)),
                permission: Some(Instant::now() - Duration::from_secs(1)),
                error: None,
                expires: common::unix_time() + 3600.0,
                refreshes: 0,
                receive_bytes: 0,
            }),
            cancel: CancellationToken::new(),
        };
        assert_eq!(shared.check(), Err(TransportError::Expired));
        shared.state.lock().unwrap().permission = None;
        assert!(shared.check().is_ok());
        shared.state.lock().unwrap().expires = common::unix_time() + 14.0;
        assert_eq!(shared.check(), Err(TransportError::CredentialsExpired));
    }

    async fn test_owner(mode: Mode) -> (Owner, UdpSocket, mpsc::Receiver<Vec<u8>>) {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let config = TurnConfig {
            mode: Mode::Udp,
            host: "127.0.0.1".into(),
            port: server.local_addr().unwrap().port(),
            username: "test-user".into(),
            password: "test-password".into(),
            expires: common::unix_time() + 3600.0,
        };
        let now = Instant::now();
        let shared = Arc::new(Shared {
            state: StdMutex::new(State {
                allocation: Some(now + Duration::from_secs(120)),
                permission: Some(now + Duration::from_secs(300)),
                error: None,
                expires: config.expires,
                refreshes: 0,
                receive_bytes: 0,
            }),
            cancel: CancellationToken::new(),
        });
        let (writer, incoming, reader) = wire(&config, shared.clone()).await.unwrap();
        let (packets, received) = mpsc::channel(RECEIVE_PACKETS);
        let realm = Realm::new(ATTR_REALM, "test-realm".into());
        let integrity = MessageIntegrity::new_long_term_integrity(
            config.username.clone(),
            realm.text.clone(),
            config.password.clone(),
        );
        let (_command_tx, commands) = mpsc::channel(1);
        let mut owner = Owner {
            writer: Some(writer),
            incoming,
            _reader: reader,
            shared,
            packets,
            commands,
            config,
            peer: "127.0.0.1:4321".parse().unwrap(),
            realm: Some(realm),
            nonce: Some(Nonce::new(ATTR_NONCE, "first-nonce".into())),
            integrity: Some(integrity),
            lifetime: Duration::from_secs(120),
            refresh_at: now + Duration::from_secs(60),
            bind_at: now + Duration::from_secs(90),
            bound: true,
            frame: Vec::new(),
        };
        owner.config.mode = mode;
        (owner, server, received)
    }

    fn success(
        request: &Message,
        lifetime: u64,
        integrity: &MessageIntegrity,
        correct_transaction: bool,
    ) -> Message {
        let mut attrs: Vec<Box<dyn Setter>> = vec![
            Box::new(request.clone()),
            Box::new(MessageType::new(request.typ.method, CLASS_SUCCESS_RESPONSE)),
        ];
        if !correct_transaction {
            attrs.push(Box::new(TransactionId::new()));
        }
        attrs.push(Box::new(Lifetime(Duration::from_secs(lifetime))));
        attrs.push(Box::new(integrity.clone()));
        attrs.push(Box::new(FINGERPRINT));
        let mut response = Message::new();
        response.build(&attrs).unwrap();
        response
    }

    #[tokio::test]
    async fn transaction_ignores_wrong_source_and_wrong_transaction() {
        let (mut owner, server, _packets) = test_owner(Mode::Udp).await;
        let integrity = owner.integrity.clone().unwrap();
        let request = owner.request(METHOD_REFRESH, false).unwrap();
        let responder = tokio::spawn(async move {
            let mut buffer = [0; 4096];
            let (length, client) = server.recv_from(&mut buffer).await.unwrap();
            let request = parse_stun(&buffer[..length]).unwrap();
            let attacker = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let forged_source = success(&request, 999, &integrity, true);
            attacker.send_to(&forged_source.raw, client).await.unwrap();
            let wrong_id = success(&request, 888, &integrity, false);
            server.send_to(&wrong_id.raw, client).await.unwrap();
            server.send_to(b"malformed STUN", client).await.unwrap();
            server.send_to(&[0x40, 0, 0, 20, 1], client).await.unwrap();
            let valid = success(&request, 120, &integrity, true);
            server.send_to(&valid.raw, client).await.unwrap();
        });
        let (response, _) = owner
            .transaction(&request, Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();
        let mut lifetime = Lifetime::default();
        lifetime.get_from(&response).unwrap();
        assert_eq!(lifetime.0, Duration::from_secs(120));
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn unsigned_or_invalid_integrity_cannot_extend_a_lease() {
        let (mut owner, server, _packets) = test_owner(Mode::Udp).await;
        let before = owner.shared.state.lock().unwrap().allocation;
        let valid_integrity = owner.integrity.clone().unwrap();
        let bad_integrity = MessageIntegrity::new_long_term_integrity(
            "wrong".into(),
            "test-realm".into(),
            "wrong".into(),
        );
        let responder = tokio::spawn(async move {
            let mut buffer = [0; 4096];
            let (length, client) = server.recv_from(&mut buffer).await.unwrap();
            let request = parse_stun(&buffer[..length]).unwrap();
            let response = success(&request, 3600, &bad_integrity, true);
            server.send_to(&response.raw, client).await.unwrap();
            let valid = success(&request, 120, &valid_integrity, true);
            server.send_to(&valid.raw, client).await.unwrap();
        });
        let (response, _) = owner
            .control(METHOD_REFRESH, Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();
        let mut lifetime = Lifetime::default();
        lifetime.get_from(&response).unwrap();
        assert_eq!(lifetime.0, Duration::from_secs(120));
        assert_eq!(owner.shared.state.lock().unwrap().allocation, before);
        responder.await.unwrap();

        let request = owner.request(METHOD_REFRESH, false).unwrap();
        let mut unsigned_lifetime = Message::new();
        unsigned_lifetime
            .build(&[
                Box::new(request),
                Box::new(MessageType::new(METHOD_REFRESH, CLASS_SUCCESS_RESPONSE)),
                Box::new(owner.integrity.clone().unwrap()),
                Box::new(Lifetime(Duration::from_secs(3600))),
            ])
            .unwrap();
        assert_eq!(
            owner.authenticate(&mut unsigned_lifetime),
            Err(TransportError::Authentication)
        );
    }

    #[tokio::test]
    async fn stale_nonce_challenges_are_bounded_and_update_only_nonce() {
        let (mut owner, server, _packets) = test_owner(Mode::Udp).await;
        let responder = tokio::spawn(async move {
            let mut buffer = [0; 4096];
            for attempt in 0..3 {
                let (length, client) = server.recv_from(&mut buffer).await.unwrap();
                let request = parse_stun(&buffer[..length]).unwrap();
                let nonce = Nonce::get_from_as(&request, ATTR_NONCE).unwrap();
                let expected = if attempt == 0 {
                    "first-nonce".to_owned()
                } else {
                    format!("nonce-{}", attempt - 1)
                };
                assert_eq!(nonce.text, expected);
                let mut response = Message::new();
                response
                    .build(&[
                        Box::new(request),
                        Box::new(MessageType::new(METHOD_REFRESH, CLASS_ERROR_RESPONSE)),
                        Box::new(stun::error_code::CODE_STALE_NONCE),
                        Box::new(Realm::new(ATTR_REALM, "test-realm".into())),
                        Box::new(Nonce::new(ATTR_NONCE, format!("nonce-{attempt}"))),
                        Box::new(FINGERPRINT),
                    ])
                    .unwrap();
                server.send_to(&response.raw, client).await.unwrap();
            }
        });
        assert!(matches!(
            owner
                .control(METHOD_REFRESH, Instant::now() + Duration::from_secs(2))
                .await,
            Err(TransportError::Authentication)
        ));
        responder.await.unwrap();
        assert_eq!(owner.nonce.as_ref().unwrap().text, "nonce-2");
        assert_eq!(owner.shared.state.lock().unwrap().refreshes, 0);
    }

    #[tokio::test]
    async fn cancellation_interrupts_control_without_waiting_for_network_timeout() {
        let (mut owner, server, _packets) = test_owner(Mode::Udp).await;
        let cancel = owner.shared.cancel.clone();
        let worker = tokio::spawn(async move {
            owner
                .control(METHOD_REFRESH, Instant::now() + Duration::from_secs(18))
                .await
        });
        let mut buffer = [0; 4096];
        timeout(Duration::from_secs(2), server.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        cancel.cancel();
        let result = timeout(Duration::from_secs(1), worker)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(result, Err(TransportError::Closed)));
        drop(server); // The peer remains alive until cancellation is observed.
    }

    #[tokio::test]
    async fn expired_control_deadline_sends_nothing_and_late_success_cannot_resurrect() {
        let (mut owner, server, _packets) = test_owner(Mode::Udp).await;
        let request = owner.request(METHOD_REFRESH, false).unwrap();
        assert!(matches!(
            owner
                .transaction(&request, Instant::now() - Duration::from_secs(1))
                .await,
            Err(TransportError::Timeout)
        ));
        let mut buffer = [0; 4096];
        assert_eq!(
            server.try_recv(&mut buffer).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        owner.shared.state.lock().unwrap().allocation =
            Some(Instant::now() - Duration::from_secs(1));
        let response = success(&request, 120, owner.integrity.as_ref().unwrap(), true);
        assert_eq!(
            owner.accept_allocation(&response, Instant::now(), true),
            Err(TransportError::Expired)
        );
        assert_eq!(owner.shared.state.lock().unwrap().refreshes, 0);
    }

    #[tokio::test]
    async fn udp_and_tls_channel_payloads_share_peer_and_expiry_gates() {
        for mode in [Mode::Udp, Mode::Tls] {
            let (mut owner, _server, mut packets) = test_owner(mode).await;
            let mut channel = vec![0x40, 0, 0, 3, b'o', b'n', b'e'];
            if mode == Mode::Tls {
                channel.push(0);
            }
            assert!(owner.deliver(&channel).unwrap());
            assert_eq!(packets.try_recv().unwrap(), b"one");
            let mut indication = Message::new();
            indication
                .build(&[
                    Box::new(TransactionId::new()),
                    Box::new(MessageType::new(METHOD_DATA, CLASS_INDICATION)),
                    Box::new(PeerAddress {
                        ip: owner.peer.ip(),
                        port: owner.peer.port() + 1,
                    }),
                    Box::new(Data(b"wrong-peer".to_vec())),
                ])
                .unwrap();
            assert!(owner.deliver(&indication.raw).unwrap());
            assert!(packets.try_recv().is_err());
            owner.shared.state.lock().unwrap().allocation =
                Some(Instant::now() - Duration::from_secs(1));
            assert_eq!(owner.deliver(&channel), Err(TransportError::Expired));
            assert!(packets.try_recv().is_err());
        }
    }

    #[tokio::test]
    async fn reader_eof_is_network_loss_unless_cancelled() {
        let (owner, server, _packets) = test_owner(Mode::Udp).await;
        assert_eq!(owner.received(None), Err(TransportError::Network));
        owner.shared.cancel.cancel();
        assert_eq!(owner.received(None), Err(TransportError::Closed));
        assert_eq!(
            owner.received(Some(Err(TransportError::Network))),
            Err(TransportError::Closed)
        );
        drop(server);
    }

    #[tokio::test]
    async fn malformed_datagrams_are_discarded_but_tls_protocol_errors_remain_fatal() {
        for mode in [Mode::Udp, Mode::Tls] {
            let (mut owner, _server, _packets) = test_owner(mode).await;
            for raw in [&b"not-STUN"[..], &[0x40, 0, 0, 20, 1][..]] {
                let expected = if mode == Mode::Udp {
                    Ok(true)
                } else {
                    Err(TransportError::Protocol)
                };
                assert_eq!(owner.dispatch_payload(raw), expected);
            }
            // Structurally valid traffic on an unbound channel is still ignored.
            assert_eq!(owner.dispatch_payload(&[0x40, 1, 0, 0]), Ok(true));
            assert!(owner.shared.check().is_ok());
        }
    }

    #[tokio::test]
    async fn verified_allocation_loss_revokes_immediately_without_refresh_retry() {
        let (mut owner, server, _packets) = test_owner(Mode::Udp).await;
        let integrity = owner.integrity.clone().unwrap();
        let responder = tokio::spawn(async move {
            let mut buffer = [0; 4096];
            let (length, client) = server.recv_from(&mut buffer).await.unwrap();
            let request = parse_stun(&buffer[..length]).unwrap();
            let mut response = Message::new();
            response
                .build(&[
                    Box::new(request),
                    Box::new(MessageType::new(METHOD_REFRESH, CLASS_ERROR_RESPONSE)),
                    Box::new(ErrorCodeAttribute {
                        code: stun::error_code::ErrorCode(437),
                        reason: b"lost".to_vec(),
                    }),
                    Box::new(integrity),
                    Box::new(FINGERPRINT),
                ])
                .unwrap();
            server.send_to(&response.raw, client).await.unwrap();
            server
        });
        assert_eq!(
            timeout(Duration::from_secs(2), owner.refresh())
                .await
                .unwrap(),
            Err(TransportError::Expired)
        );
        assert_eq!(owner.shared.check(), Err(TransportError::Expired));
        assert!(owner.shared.cancel.is_cancelled());
        let server = responder.await.unwrap();
        let mut buffer = [0; 4096];
        assert_eq!(
            server.try_recv(&mut buffer).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert_eq!(owner.shared.state.lock().unwrap().refreshes, 0);
    }

    #[tokio::test]
    async fn refresh_backoff_keeps_valid_lease_payloads_moving_in_both_directions() {
        let (mut owner, server, mut packets) = test_owner(Mode::Udp).await;
        let (commands, receiver) = mpsc::channel(1);
        owner.commands = receiver;
        let cancel = owner.shared.cancel.clone();
        let worker = tokio::spawn(async move {
            owner
                .wait_retry(Instant::now() + Duration::from_secs(10))
                .await
        });
        let (reply, completed) = oneshot::channel();
        commands
            .send(SendCommand {
                frame: b"up".to_vec(),
                reply,
            })
            .await
            .unwrap();
        let mut buffer = [0; 4096];
        let (length, client) = timeout(Duration::from_secs(2), server.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..length], &[0x40, 0, 0, 2, b'u', b'p']);
        timeout(Duration::from_secs(2), completed)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        server
            .send_to(&[0x40, 0, 0, 4, b'd', b'o', b'w', b'n'], client)
            .await
            .unwrap();
        assert_eq!(
            timeout(Duration::from_secs(2), packets.recv())
                .await
                .unwrap()
                .unwrap(),
            b"down"
        );
        cancel.cancel();
        assert_eq!(
            timeout(Duration::from_secs(1), worker)
                .await
                .unwrap()
                .unwrap(),
            Err(TransportError::Closed)
        );
        drop(server);
    }

    // Inject backpressure at the wire boundary, not at Endpoint::send. The
    // production command queue, owner scheduler, framing and receive gates run
    // unchanged. This does not simulate a TLS handshake or certificate checks.
    pub(super) struct GatedWriter {
        entered: mpsc::Sender<Vec<u8>>,
        release: mpsc::Receiver<()>,
        written: mpsc::Sender<Vec<u8>>,
    }
    impl GatedWriter {
        pub(super) async fn send(&mut self, raw: &[u8]) -> Result<()> {
            self.entered
                .try_send(raw.to_vec())
                .map_err(|_| TransportError::Capacity)?;
            self.release.recv().await.ok_or(TransportError::Closed)?;
            self.written
                .try_send(raw.to_vec())
                .map_err(|_| TransportError::Capacity)
        }
    }

    pub(crate) struct GatedEndpoint {
        pub(crate) endpoint: Arc<Endpoint>,
        pub(crate) incoming: mpsc::Sender<Result<Vec<u8>>>,
        pub(crate) entered: mpsc::Receiver<Vec<u8>>,
        pub(crate) release: mpsc::Sender<()>,
        pub(crate) written: mpsc::Receiver<Vec<u8>>,
    }

    pub(crate) fn gated_endpoint(lease: Duration) -> GatedEndpoint {
        gated_endpoint_with_refresh(lease, Duration::from_secs(60))
    }

    fn gated_endpoint_with_refresh(lease: Duration, refresh_after: Duration) -> GatedEndpoint {
        gated_endpoint_configured(lease, refresh_after, common::unix_time() + 3600.0)
    }

    pub(crate) fn gated_endpoint_expiring(lease: Duration, expires: f64) -> GatedEndpoint {
        gated_endpoint_configured(lease, Duration::from_secs(60), expires)
    }

    fn gated_endpoint_configured(lease: Duration, refresh_after: Duration, expires: f64) -> GatedEndpoint {
        let now = Instant::now();
        let shared = Arc::new(Shared {
            state: StdMutex::new(State {
                allocation: Some(now + lease),
                permission: Some(now + lease),
                error: None,
                expires,
                refreshes: 0,
                receive_bytes: 0,
            }),
            cancel: CancellationToken::new(),
        });
        let (commands, command_rx) = mpsc::channel(1);
        let (packets_tx, packets) = mpsc::channel(RECEIVE_PACKETS);
        let (incoming, incoming_rx) = mpsc::channel(64);
        let (entered_tx, entered) = mpsc::channel(1);
        let (release, release_rx) = mpsc::channel(1);
        let (written_tx, written) = mpsc::channel(1);
        let reader_cancel = shared.cancel.clone();
        let reader = ReaderGuard(tokio::spawn(async move {
            reader_cancel.cancelled().await;
        }));
        // Start at the established-allocation boundary. No UDP socket or
        // mode-flipped UDP writer stands in for the pending stream write.
        let mut owner = Owner {
            writer: Some(Writer::Gated(GatedWriter {
                entered: entered_tx,
                release: release_rx,
                written: written_tx,
            })),
            incoming: incoming_rx,
            _reader: reader,
            shared: shared.clone(),
            packets: packets_tx,
            commands: command_rx,
            config: TurnConfig {
                mode: Mode::Tls,
                host: "unused.invalid".into(),
                port: 443,
                username: "test-user".into(),
                password: "test-password".into(),
                expires,
            },
            peer: "127.0.0.1:4321".parse().unwrap(),
            realm: Some(Realm::new(ATTR_REALM, "test-realm".into())),
            nonce: Some(Nonce::new(ATTR_NONCE, "test-nonce".into())),
            integrity: Some(MessageIntegrity::new_long_term_integrity(
                "test-user".into(), "test-realm".into(), "test-password".into(),
            )),
            lifetime: Duration::from_secs(120),
            refresh_at: now + refresh_after,
            bind_at: now + Duration::from_secs(90),
            bound: true,
            frame: Vec::new(),
        };
        let owner_shared = shared.clone();
        let task = tokio::spawn(async move {
            let result = tokio::select! {
                biased;
                _ = owner_shared.cancel.cancelled() => Ok(()),
                result = owner.loop_packets() => result,
            };
            owner_shared.fail(result.err().unwrap_or(TransportError::Closed));
        });
        GatedEndpoint {
            endpoint: Arc::new(Endpoint {
                shared,
                commands,
                packets: Mutex::new(packets),
                owner: Mutex::new(Some(task)),
                expires,
            }),
            incoming,
            entered,
            release,
            written,
        }
    }

    #[tokio::test]
    async fn endpoint_receives_while_transport_write_is_pending() {
        let mut fixture = gated_endpoint(Duration::from_secs(120));
        let endpoint = fixture.endpoint.clone();
        let sending = tokio::spawn(async move { endpoint.send(b"up").await });
        let frame = timeout(Duration::from_secs(2), fixture.entered.recv())
            .await.unwrap().unwrap();
        assert_eq!(frame, [0x40, 0, 0, 2, b'u', b'p', 0, 0]);
        fixture.incoming.send(Ok(vec![0x40, 0, 0, 4, b'd', b'o', b'w', b'n']))
            .await.unwrap();
        let mut buffer = [0; 32];
        let received = timeout(Duration::from_millis(250), fixture.endpoint.recv(&mut buffer)).await;
        let remained_pending = !sending.is_finished();
        let remained_healthy = fixture.endpoint.health();
        // Release and join before the red assertion so failure leaves no worker.
        fixture.release.send(()).await.unwrap();
        let sent = timeout(Duration::from_secs(2), sending).await.unwrap().unwrap();
        let written = fixture.written.try_recv();
        fixture.endpoint.close().await;
        assert!(remained_pending, "uplink must remain gated during downlink delivery");
        assert_eq!(remained_healthy, Ok(()));
        assert_eq!(sent, Ok(()));
        assert_eq!(written.unwrap(), frame);
        assert!(fixture.written.try_recv().is_err(), "write must not be replayed");
        let length = received.expect("downlink blocked behind the pending transport write").unwrap();
        assert_eq!(&buffer[..length], b"down");
    }

    #[tokio::test]
    async fn endpoint_write_timeout_retires_transport() {
        // The lease bounds the real send deadline without changing OP_TIMEOUT.
        let mut fixture = gated_endpoint(Duration::from_secs(1));
        let endpoint = fixture.endpoint.clone();
        let sending = tokio::spawn(async move { endpoint.send(b"up").await });
        timeout(Duration::from_secs(2), fixture.entered.recv()).await.unwrap().unwrap();
        let sent = timeout(Duration::from_secs(3), sending).await.unwrap().unwrap();
        assert_eq!(sent, Err(TransportError::Timeout));
        assert_eq!(fixture.endpoint.failure().await, TransportError::Timeout);
        assert_eq!(fixture.endpoint.health(), Err(TransportError::Timeout));
        assert_eq!(fixture.endpoint.send(b"later").await, Err(TransportError::Timeout));
        fixture.endpoint.close().await;
        assert!(fixture.release.is_closed(), "timed-out writer must be dropped");
        assert_eq!(fixture.entered.try_recv(), Err(mpsc::error::TryRecvError::Disconnected));
        assert_eq!(fixture.written.try_recv(), Err(mpsc::error::TryRecvError::Disconnected));
    }

    #[tokio::test]
    async fn endpoint_preserves_control_response_during_pending_write() {
        for payload_write in [false, true] {
            let mut fixture = gated_endpoint_with_refresh(Duration::from_secs(120), Duration::ZERO);
            let request = timeout(Duration::from_secs(2), fixture.entered.recv())
                .await.unwrap().unwrap();
            let request = parse_stun(&request).unwrap();
            assert_eq!(request.typ, MessageType::new(METHOD_REFRESH, CLASS_REQUEST));
            let sending = if payload_write {
                fixture.release.send(()).await.unwrap();
                timeout(Duration::from_secs(2), fixture.written.recv()).await.unwrap().unwrap();
                let endpoint = fixture.endpoint.clone();
                let sending = tokio::spawn(async move { endpoint.send(b"up").await });
                let frame = timeout(Duration::from_secs(2), fixture.entered.recv())
                    .await.unwrap().unwrap();
                assert_eq!(frame, [0x40, 0, 0, 2, b'u', b'p', 0, 0]);
                Some(sending)
            } else {
                None
            };
            let integrity = MessageIntegrity::new_long_term_integrity(
                "test-user".into(), "test-realm".into(), "test-password".into(),
            );
            let response = success(&request, 120, &integrity, true);
            fixture.incoming.send(Ok(response.raw)).await.unwrap();
            fixture.incoming.send(Ok(vec![0x40, 0, 0, 4, b'd', b'o', b'w', b'n']))
                .await.unwrap();
            let mut buffer = [0; 32];
            let received = timeout(Duration::from_millis(250), fixture.endpoint.recv(&mut buffer)).await;
            let refreshes_before_write = fixture.endpoint.stats().refreshes;
            fixture.release.send(()).await.unwrap();
            timeout(Duration::from_secs(2), fixture.written.recv()).await.unwrap().unwrap();
            if let Some(sending) = sending {
                assert_eq!(timeout(Duration::from_secs(2), sending).await.unwrap().unwrap(), Ok(()));
            }
            let refreshed = timeout(Duration::from_secs(2), async {
                while fixture.endpoint.stats().refreshes == 0 {
                    tokio::task::yield_now().await;
                }
            }).await;
            let healthy = fixture.endpoint.health();
            fixture.endpoint.close().await;
            let length = received.expect("control write blocked downlink dispatch").unwrap();
            assert_eq!(&buffer[..length], b"down");
            assert_eq!(refreshes_before_write, 0, "write must finish before accepting its response");
            refreshed.expect("matching response was discarded during the pending write");
            assert_eq!(healthy, Ok(()));
            assert_eq!(fixture.endpoint.stats().refreshes, 1);
        }
    }

    #[tokio::test]
    async fn endpoint_rejects_invalid_integrity_during_pending_control_write() {
        let mut fixture = gated_endpoint_with_refresh(Duration::from_secs(120), Duration::ZERO);
        let request = timeout(Duration::from_secs(2), fixture.entered.recv())
            .await.unwrap().unwrap();
        let request = parse_stun(&request).unwrap();
        let wrong_integrity = MessageIntegrity::new_long_term_integrity(
            "test-user".into(), "test-realm".into(), "wrong-password".into(),
        );
        let response = success(&request, 120, &wrong_integrity, true);
        fixture.incoming.send(Ok(response.raw)).await.unwrap();
        let failure = timeout(Duration::from_secs(2), fixture.endpoint.failure()).await;
        fixture.endpoint.close().await;
        assert_eq!(failure.unwrap(), TransportError::Authentication);
        assert_eq!(fixture.endpoint.stats().refreshes, 0);
        assert!(fixture.release.is_closed());
        assert_eq!(fixture.written.try_recv(), Err(mpsc::error::TryRecvError::Disconnected));
    }
}
