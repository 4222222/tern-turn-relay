//! Isolated TURN experiment transport. Protocol transactions remain in `turn`.
//! Each endpoint owns a Tokio runtime so detached upstream tasks die on shutdown.
use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use async_trait::async_trait;
use rustls::pki_types::ServerName;
use stun::error_code::{ErrorCodeAttribute, CODE_STALE_NONCE, CODE_UNAUTHORIZED};
use stun::message::{Getter, Message};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, watch, Mutex, Notify};
use tokio::time::{timeout, timeout_at, Instant};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use turn::client::{Client, ClientConfig};
use turn::proto::channum::ChannelNumber;
use turn::proto::data::Data;
use turn::proto::lifetime::Lifetime;
use turn::proto::peeraddr::PeerAddress;
use util::Conn;

const OP_TIMEOUT: Duration = Duration::from_secs(18);
const CLOSE_TIMEOUT: Duration = Duration::from_secs(1);
const LEASE_MARGIN: Duration = Duration::from_millis(250);
const MAX_FRAME: usize = 65_535;
const MAX_PAYLOAD: usize = 65_040;
const MAX_PENDING: usize = 64;
const MAX_CONTROL: usize = 4096;

#[derive(Clone)]
pub struct TurnConfig {
    pub host: String,
    pub ip: String,
    pub port: u16,
    pub username: String,
    pub password: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportError {
    Configuration,
    TlsAuthentication,
    Network,
    Protocol,
    Authentication,
    Expired,
    Timeout,
    Closed,
    Capacity,
}

impl TransportError {
    pub fn recoverable(&self) -> bool {
        matches!(self, Self::Network | Self::Expired | Self::Timeout)
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Configuration => "invalid TURN transport configuration",
            Self::TlsAuthentication => "TURN TLS authentication failed",
            Self::Network => "TURN transport lost",
            Self::Protocol => "invalid TURN control response",
            Self::Authentication => "TURN authentication rejected",
            Self::Expired => "TURN lease expired",
            Self::Timeout => "TURN operation timed out",
            Self::Closed => "TURN endpoint stopped",
            Self::Capacity => "TURN transport capacity exceeded",
        })
    }
}
impl std::error::Error for TransportError {}

type Result<T, E = TransportError> = std::result::Result<T, E>;

#[derive(Clone, Copy, Debug, Default)]
pub struct TransportStats {
    pub refreshes: u64,
    pub remaining_ms: u64,
    pub lifetime_secs: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Allocate,
    Refresh,
    Permission,
    Bind,
}

struct Pending {
    kind: Kind,
    sent: Instant,
    raw: Vec<u8>,
    channel: Option<u16>,
    authenticated: bool,
    deleting: bool,
}

struct Leases {
    fatal: Option<TransportError>,
    allocation: Option<Instant>,
    permission: Option<Instant>,
    channel: Option<(u16, Instant)>,
    lifetime_secs: u64,
    refreshes: u64,
    pending: HashMap<[u8; 12], Pending>,
}

struct Shared {
    leases: StdMutex<Leases>,
    stop: CancellationToken,
    changed: Notify,
}

impl Shared {
    fn new() -> Self {
        Self {
            leases: StdMutex::new(Leases {
                fatal: None,
                allocation: None,
                permission: None,
                channel: None,
                lifetime_secs: 0,
                refreshes: 0,
                pending: HashMap::new(),
            }),
            stop: CancellationToken::new(),
            changed: Notify::new(),
        }
    }

    fn fail(&self, error: TransportError) -> TransportError {
        let mut leases = self.leases.lock().unwrap();
        let result = *leases.fatal.get_or_insert(error);
        drop(leases);
        self.stop.cancel();
        self.changed.notify_one();
        result
    }

    fn error(&self) -> TransportError {
        self.leases.lock().unwrap().fatal.unwrap_or(TransportError::Network)
    }

    fn check(&self, require_permission: bool) -> Result<Instant> {
        let leases = self.leases.lock().unwrap();
        if let Some(error) = leases.fatal {
            return Err(error);
        }
        let now = Instant::now();
        let mut until = leases.allocation.ok_or(TransportError::Protocol)?;
        if let Some(permission) = leases.permission {
            until = until.min(permission);
        } else if require_permission {
            return Err(TransportError::Protocol);
        }
        if let Some((_, channel)) = leases.channel {
            until = until.min(channel);
        }
        if until <= now {
            drop(leases);
            return Err(self.fail(TransportError::Expired));
        }
        Ok(until)
    }

    fn stats(&self) -> TransportStats {
        let leases = self.leases.lock().unwrap();
        let remaining_ms = if leases.fatal.is_some() {
            0
        } else {
            leases.allocation.map_or(0, |at| {
                at.saturating_duration_since(Instant::now()).as_millis() as u64
            })
        };
        TransportStats {
            refreshes: leases.refreshes,
            remaining_ms,
            lifetime_secs: leases.lifetime_secs,
        }
    }

    async fn watch_expiry(self: Arc<Self>) {
        loop {
            // Register before taking the snapshot so a new earlier deadline is not lost.
            let changed = self.changed.notified();
            let next = {
                let leases = self.leases.lock().unwrap();
                leases.allocation.into_iter()
                    .chain(leases.permission)
                    .chain(leases.channel.map(|(_, at)| at))
                    .chain(leases.pending.values().map(|p| p.sent + OP_TIMEOUT))
                    .min()
            };
            tokio::select! {
                biased;
                _ = self.stop.cancelled() => break,
                _ = changed => continue,
                _ = async {
                    if let Some(at) = next { tokio::time::sleep_until(at).await; }
                    else { std::future::pending::<()>().await; }
                } => {
                    // Recompute; a response may have extended the snapshot deadline.
                    let leases = self.leases.lock().unwrap();
                    let now = Instant::now();
                    let expired = leases.allocation.is_some_and(|at| at <= now)
                        || leases.permission.is_some_and(|at| at <= now)
                        || leases.channel.is_some_and(|(_, at)| at <= now);
                    let stalled = leases.pending.values().any(|p| p.sent + OP_TIMEOUT <= now);
                    drop(leases);
                    if expired || stalled {
                        self.fail(if expired { TransportError::Expired } else { TransportError::Timeout });
                        break;
                    }
                }
            }
        }
    }
}

fn safe_io(error: TransportError) -> util::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, error).into()
}

fn decode(raw: &[u8]) -> Result<Message> {
    let mut message = Message::new();
    message.unmarshal_binary(raw).map_err(|_| TransportError::Protocol)?;
    Ok(message)
}

fn wire_type(raw: &[u8]) -> Result<(u16, u16)> {
    if raw.len() < 20 || raw[0] & 0xc0 != 0 || raw[4..8] != [0x21, 0x12, 0xa4, 0x42] {
        return Err(TransportError::Protocol);
    }
    let len = u16::from_be_bytes([raw[2], raw[3]]) as usize;
    if len % 4 != 0 || raw.len() != 20 + len {
        return Err(TransportError::Protocol);
    }
    let typ = u16::from_be_bytes([raw[0], raw[1]]);
    Ok((typ & !0x0110, typ & 0x0110))
}

fn control_kind(method: u16) -> Option<Kind> {
    match method {
        0x0003 => Some(Kind::Allocate),
        0x0004 => Some(Kind::Refresh),
        0x0008 => Some(Kind::Permission),
        0x0009 => Some(Kind::Bind),
        _ => None,
    }
}

fn lease_end(sent: Instant, lifetime: Duration) -> Result<Instant> {
    let budget = lifetime.checked_sub(LEASE_MARGIN).ok_or(TransportError::Expired)?;
    let at = sent.checked_add(budget).ok_or(TransportError::Protocol)?;
    if at <= Instant::now() { return Err(TransportError::Expired); }
    Ok(at)
}

struct TlsConn {
    reader: Mutex<Option<ReadHalf<TlsStream<TcpStream>>>>,
    writer: Mutex<Option<WriteHalf<TlsStream<TcpStream>>>>,
    local: SocketAddr,
    remote: SocketAddr,
    peer: SocketAddr,
    shared: Arc<Shared>,
    wire_stop: CancellationToken,
}

impl TlsConn {
    // Returns false for an identical upstream UDP-style retransmission on TLS.
    fn outgoing(&self, raw: &[u8]) -> Result<bool> {
        if raw.first().is_some_and(|byte| byte & 0xc0 == 0x40) {
            self.shared.check(true)?;
            if raw.len() < 4 { return Err(TransportError::Protocol); }
            let channel = u16::from_be_bytes([raw[0], raw[1]]);
            let payload_len = u16::from_be_bytes([raw[2], raw[3]]) as usize;
            let leases = self.shared.leases.lock().unwrap();
            if raw.len() != ((4 + payload_len + 3) & !3)
                || !leases.channel.is_some_and(|(number, at)| number == channel && at > Instant::now())
            {
                return Err(TransportError::Expired);
            }
            return Ok(true);
        }
        let (method, class) = wire_type(raw)?;
        if class == 0x0010 && method == 0x0006 {
            self.shared.check(true)?;
            return Ok(true);
        }
        if class != 0 { return Err(TransportError::Protocol); }
        let kind = control_kind(method).ok_or(TransportError::Protocol)?;
        if raw.len() > MAX_CONTROL { return Err(TransportError::Capacity); }
        let message = decode(raw)?;
        let mut channel = None;
        let mut deleting = false;
        if kind == Kind::Permission || kind == Kind::Bind {
            let mut address = PeerAddress::default();
            address.get_from(&message).map_err(|_| TransportError::Protocol)?;
            if address.ip != self.peer.ip() || (kind == Kind::Bind && address.port != self.peer.port()) {
                return Err(TransportError::Protocol);
            }
        }
        if kind == Kind::Bind {
            let mut number = ChannelNumber::default();
            number.get_from(&message).map_err(|_| TransportError::Protocol)?;
            if !number.valid() { return Err(TransportError::Protocol); }
            channel = Some(number.0);
        }
        if kind == Kind::Refresh {
            let mut lifetime = Lifetime::default();
            lifetime.get_from(&message).map_err(|_| TransportError::Protocol)?;
            deleting = lifetime.0.is_zero();
        }
        let mut leases = self.shared.leases.lock().unwrap();
        if let Some(error) = leases.fatal {
            if !deleting { return Err(error); }
        }
        let now = Instant::now();
        if !deleting && (leases.allocation.is_some_and(|at| at <= now)
            || leases.permission.is_some_and(|at| at <= now)
            || leases.channel.is_some_and(|(_, at)| at <= now))
        {
            return Err(TransportError::Expired);
        }
        let id = message.transaction_id.0;
        if let Some(pending) = leases.pending.get(&id) {
            return if pending.raw == raw { Ok(false) } else { Err(TransportError::Protocol) };
        }
        if leases.pending.len() >= MAX_PENDING { return Err(TransportError::Capacity); }
        leases.pending.insert(id, Pending {
            kind,
            sent: Instant::now(),
            raw: raw.to_vec(),
            channel,
            // USERNAME attribute: initial anonymous Allocate has no username.
            authenticated: message.contains(stun::attributes::ATTR_USERNAME),
            deleting,
        });
        drop(leases);
        self.shared.changed.notify_one();
        Ok(true)
    }

    fn incoming(&self, raw: &[u8]) -> Result<()> {
        if raw.first().is_some_and(|byte| byte & 0xc0 == 0x40) {
            self.shared.check(true)?;
            let number = u16::from_be_bytes([raw[0], raw[1]]);
            let leases = self.shared.leases.lock().unwrap();
            let known_channel = leases.channel.is_some_and(|(channel, at)| channel == number && at > Instant::now());
            let binding_in_flight = leases.pending.values().any(|pending| pending.kind == Kind::Bind && pending.channel == Some(number));
            // TURN permits inbound ChannelData before the ChannelBind success response.
            if !known_channel && !binding_in_flight {
                return Err(TransportError::Protocol);
            }
            return Ok(());
        }
        let (method, class) = wire_type(raw)?;
        if class == 0x0010 && method == 0x0007 {
            self.shared.check(true)?;
            let message = decode(raw)?;
            let mut peer = PeerAddress::default();
            peer.get_from(&message).map_err(|_| TransportError::Protocol)?;
            let mut data = Data::default();
            data.get_from(&message).map_err(|_| TransportError::Protocol)?;
            if SocketAddr::new(peer.ip, peer.port) != self.peer { return Err(TransportError::Protocol); }
            return Ok(());
        }
        if class != 0x0100 && class != 0x0110 { return Err(TransportError::Protocol); }
        let kind = control_kind(method).ok_or(TransportError::Protocol)?;
        if raw.len() > MAX_CONTROL { return Err(TransportError::Capacity); }
        let message = decode(raw)?;
        let mut leases = self.shared.leases.lock().unwrap();
        let Some(pending) = leases.pending.remove(&message.transaction_id.0) else {
            // Late duplicates are not authority to extend a lease.
            return Ok(());
        };
        let now = Instant::now();
        if !pending.deleting && (leases.allocation.is_some_and(|at| at <= now)
            || leases.permission.is_some_and(|at| at <= now)
            || leases.channel.is_some_and(|(_, at)| at <= now))
        {
            return Err(TransportError::Expired);
        }
        if pending.kind != kind { return Err(TransportError::Protocol); }
        if leases.fatal.is_some() && !pending.deleting { return Err(leases.fatal.unwrap()); }
        if class == 0x0110 {
            let mut error = ErrorCodeAttribute::default();
            error.get_from(&message).map_err(|_| TransportError::Protocol)?;
            if (error.code == CODE_STALE_NONCE && kind != Kind::Bind)
                || (kind == Kind::Allocate && !pending.authenticated && error.code == CODE_UNAUTHORIZED)
                || pending.deleting
            {
                return Ok(());
            }
            return Err(if error.code == CODE_UNAUTHORIZED {
                TransportError::Authentication
            } else if error.code == stun::error_code::ErrorCode(437) || (error.code == CODE_STALE_NONCE && kind == Kind::Bind) {
                // Upstream cannot retry a stale-nonce ChannelBind; recreate this generation.
                TransportError::Expired
            } else {
                TransportError::Protocol
            });
        }
        if pending.deleting { return Ok(()); }
        match kind {
            Kind::Allocate | Kind::Refresh => {
                let mut lifetime = Lifetime::default();
                lifetime.get_from(&message).map_err(|_| TransportError::Protocol)?;
                leases.allocation = Some(lease_end(pending.sent, lifetime.0)?);
                leases.lifetime_secs = lifetime.0.as_secs();
                if kind == Kind::Refresh { leases.refreshes += 1; }
            }
            Kind::Permission => {
                leases.permission = Some(lease_end(pending.sent, Duration::from_secs(300))?);
            }
            Kind::Bind => {
                leases.channel = Some((pending.channel.ok_or(TransportError::Protocol)?, lease_end(pending.sent, Duration::from_secs(600))?));
                leases.permission = Some(lease_end(pending.sent, Duration::from_secs(300))?);
            }
        }
        drop(leases);
        self.shared.changed.notify_one();
        Ok(())
    }

    async fn read_packet(&self, buffer: &mut [u8]) -> Result<usize> {
        if buffer.len() < 20 { return Err(TransportError::Capacity); }
        let mut guard = self.reader.lock().await;
        let reader = guard.as_mut().ok_or(TransportError::Closed)?;
        let read = async {
            reader.read_exact(&mut buffer[..4]).await.map_err(|_| TransportError::Network)?;
            let length = u16::from_be_bytes([buffer[2], buffer[3]]) as usize;
            let total = match buffer[0] & 0xc0 {
                0 => {
                    if length % 4 != 0 { return Err(TransportError::Protocol); }
                    20 + length
                }
                0x40 => (4 + length + 3) & !3,
                _ => return Err(TransportError::Protocol),
            };
            if total > buffer.len() || total > MAX_FRAME { return Err(TransportError::Capacity); }
            reader.read_exact(&mut buffer[4..total]).await.map_err(|_| TransportError::Network)?;
            self.incoming(&buffer[..total])?;
            Ok(total)
        };
        tokio::select! {
            biased;
            _ = self.wire_stop.cancelled() => Err(TransportError::Closed),
            result = read => result,
        }
    }

    async fn write_packet(&self, raw: &[u8]) -> Result<usize> {
        let deleting = if wire_type(raw) == Ok((0x0004, 0)) {
            decode(raw).ok().is_some_and(|message| {
                let mut lifetime = Lifetime::default();
                lifetime.get_from(&message).is_ok() && lifetime.0.is_zero()
            })
        } else { false };
        let operation = async {
            let mut guard = self.writer.lock().await;
            let writer = guard.as_mut().ok_or(TransportError::Closed)?;
            // Recheck leases after waiting for write ownership.
            if !self.outgoing(raw)? { return Ok(raw.len()); }
            writer.write_all(raw).await.map_err(|_| TransportError::Network)?;
            writer.flush().await.map_err(|_| TransportError::Network)?;
            Ok(raw.len())
        };
        tokio::select! {
            biased;
            _ = self.wire_stop.cancelled() => Err(TransportError::Closed),
            _ = self.shared.stop.cancelled(), if !deleting => {
                // A cancelled partial write permanently poisons stream framing.
                self.wire_stop.cancel();
                Err(self.shared.error())
            },
            result = timeout(OP_TIMEOUT, operation) => result.unwrap_or(Err(TransportError::Timeout)),
        }
    }

    async fn shutdown(&self) {
        self.wire_stop.cancel();
        // Cancellation wakes in-progress reads/writes; no half survives runtime teardown.
        let _ = timeout(CLOSE_TIMEOUT, async {
            self.reader.lock().await.take();
            if let Some(mut writer) = self.writer.lock().await.take() {
                let _ = writer.shutdown().await;
            }
        }).await;
    }
}

#[async_trait]
impl Conn for TlsConn {
    async fn connect(&self, addr: SocketAddr) -> std::result::Result<(), util::Error> {
        if addr == self.remote { Ok(()) } else { Err(safe_io(TransportError::Configuration)) }
    }
    async fn recv(&self, buf: &mut [u8]) -> std::result::Result<usize, util::Error> {
        self.read_packet(buf).await.map_err(|error| safe_io(self.shared.fail(error)))
    }
    async fn recv_from(&self, buf: &mut [u8]) -> std::result::Result<(usize, SocketAddr), util::Error> {
        self.recv(buf).await.map(|n| (n, self.remote))
    }
    async fn send(&self, buf: &[u8]) -> std::result::Result<usize, util::Error> {
        self.write_packet(buf).await.map_err(|error| safe_io(self.shared.fail(error)))
    }
    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> std::result::Result<usize, util::Error> {
        if target != self.remote { return Err(safe_io(self.shared.fail(TransportError::Configuration))); }
        self.send(buf).await
    }
    fn local_addr(&self) -> std::result::Result<SocketAddr, util::Error> { Ok(self.local) }
    fn remote_addr(&self) -> Option<SocketAddr> { Some(self.remote) }
    async fn close(&self) -> std::result::Result<(), util::Error> { self.shutdown().await; Ok(()) }
    fn as_any(&self) -> &(dyn Any + Send + Sync) { self }
}

struct SendCommand {
    frame: Vec<u8>,
    until: Instant,
    reply: oneshot::Sender<Result<usize>>,
}

pub struct TurnEndpoint {
    shared: Arc<Shared>,
    commands: mpsc::Sender<SendCommand>,
    packets: Mutex<mpsc::Receiver<Vec<u8>>>,
    done: watch::Receiver<bool>,
}

impl TurnEndpoint {
    pub async fn connect(config: &TurnConfig, peer: SocketAddr) -> Result<Self> {
        let ip: IpAddr = config.ip.parse().map_err(|_| TransportError::Configuration)?;
        // A DNS name is required: an IP ServerName would omit SNI and change identity checks.
        if config.host.parse::<IpAddr>().is_ok() || config.host.is_empty()
            || config.username.is_empty() || config.password.is_empty() || config.port == 0
        {
            return Err(TransportError::Configuration);
        }
        ServerName::try_from(config.host.clone()).map_err(|_| TransportError::Configuration)?;
        let remote = SocketAddr::new(ip, config.port);
        let shared = Arc::new(Shared::new());
        let (commands, command_rx) = mpsc::channel(128);
        let (packet_tx, packets) = mpsc::channel(512);
        let (ready_tx, ready_rx) = oneshot::channel();
        let (done_tx, done) = watch::channel(false);
        let endpoint = Self { shared: shared.clone(), commands, packets: Mutex::new(packets), done };
        let config = config.clone();
        std::thread::Builder::new().name("rust-turn-owner".into()).spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build();
            match runtime {
                Ok(runtime) => {
                    runtime.block_on(run_owner(config, remote, peer, shared.clone(), command_rx, packet_tx, ready_tx));
                    // Cancels every detached upstream timer/listener/bind task, not just our handles.
                    drop(runtime);
                }
                Err(_) => { shared.fail(TransportError::Configuration); let _ = ready_tx.send(Err(TransportError::Configuration)); }
            }
            let _ = done_tx.send(true);
        }).map_err(|_| TransportError::Capacity)?;
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

    pub async fn send(&self, frame: &[u8]) -> Result<usize> {
        if frame.len() > MAX_PAYLOAD { return Err(TransportError::Capacity); }
        let until = self.shared.check(false)?.min(Instant::now() + OP_TIMEOUT);
        let (reply, response) = oneshot::channel();
        let operation = async {
            self.commands.send(SendCommand { frame: frame.to_vec(), until, reply }).await.map_err(|_| self.shared.error())?;
            response.await.map_err(|_| self.shared.error())?
        };
        tokio::select! {
            biased;
            _ = self.shared.stop.cancelled() => Err(self.shared.error()),
            result = timeout_at(until, operation) => result.unwrap_or_else(|_| Err(self.shared.fail(TransportError::Timeout))),
        }
    }

    pub async fn recv(&self, buffer: &mut [u8]) -> Result<usize> {
        self.shared.check(false)?;
        let receive = async {
            let mut packets = self.packets.lock().await;
            let packet = packets.recv().await.ok_or_else(|| self.shared.error())?;
            self.shared.check(true)?;
            if packet.len() > buffer.len() { return Err(TransportError::Capacity); }
            buffer[..packet.len()].copy_from_slice(&packet);
            Ok(packet.len())
        };
        tokio::select! {
            biased;
            _ = self.shared.stop.cancelled() => Err(self.shared.error()),
            result = receive => result,
        }
    }

    pub fn stats(&self) -> TransportStats { self.shared.stats() }

    pub fn abort(&self) { self.shared.fail(TransportError::Network); }

    pub async fn close(&self) {
        self.shared.fail(TransportError::Closed);
        let mut done = self.done.clone();
        let _ = timeout(Duration::from_secs(4), async {
            while !*done.borrow_and_update() {
                if done.changed().await.is_err() { break; }
            }
        }).await;
    }
}

impl Drop for TurnEndpoint {
    fn drop(&mut self) { self.shared.fail(TransportError::Closed); }
}

async fn create_transport(config: &TurnConfig, remote: SocketAddr, peer: SocketAddr, shared: Arc<Shared>) -> Result<Arc<TlsConn>> {
    let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    let tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions().map_err(|_| TransportError::Configuration)?
        .with_root_certificates(roots).with_no_client_auth();
    let name = ServerName::try_from(config.host.clone()).map_err(|_| TransportError::Configuration)?;
    let tcp = TcpStream::connect(remote).await.map_err(|_| TransportError::Network)?;
    tcp.set_nodelay(true).map_err(|_| TransportError::Network)?;
    let local = tcp.local_addr().map_err(|_| TransportError::Network)?;
    let tls = TlsConnector::from(Arc::new(tls_config)).connect(name, tcp).await.map_err(|error| {
        if error.kind() == io::ErrorKind::InvalidData { TransportError::TlsAuthentication }
        else { TransportError::Network }
    })?;
    let (reader, writer) = tokio::io::split(tls);
    Ok(Arc::new(TlsConn { reader: Mutex::new(Some(reader)), writer: Mutex::new(Some(writer)), local, remote, peer, shared, wire_stop: CancellationToken::new() }))
}

async fn run_owner(
    config: TurnConfig,
    remote: SocketAddr,
    peer: SocketAddr,
    shared: Arc<Shared>,
    mut commands: mpsc::Receiver<SendCommand>,
    packets: mpsc::Sender<Vec<u8>>,
    ready: oneshot::Sender<Result<()>>,
) {
    let setup = async {
        let wire = create_transport(&config, remote, peer, shared.clone()).await?;
        tokio::spawn(shared.clone().watch_expiry());
        let client = Client::new(ClientConfig {
            stun_serv_addr: String::new(),
            turn_serv_addr: remote.to_string(),
            username: config.username,
            password: config.password,
            realm: String::new(),
            software: String::new(),
            rto_in_ms: 0,
            conn: wire.clone(),
            vnet: None,
        }).await.map_err(|_| TransportError::Protocol)?;
        client.listen().await.map_err(|_| TransportError::Protocol)?;
        let relay: Arc<dyn Conn + Send + Sync> = Arc::new(client.allocate().await.map_err(|_| shared.error())?);
        shared.check(false)?;
        Ok::<_, TransportError>((wire, client, relay))
    };
    let result = tokio::select! {
        biased;
        _ = shared.stop.cancelled() => Err(shared.error()),
        result = timeout(OP_TIMEOUT, setup) => result.unwrap_or(Err(TransportError::Timeout)),
    };
    let (wire, client, relay) = match result {
        Ok(parts) => parts,
        Err(error) => { let error = shared.fail(error); let _ = ready.send(Err(error)); return; }
    };
    if ready.send(Ok(())).is_err() { shared.fail(TransportError::Closed); }
    let read_relay = relay.clone();
    let read_shared = shared.clone();
    let receiver = tokio::spawn(async move {
        let mut buffer = vec![0u8; MAX_FRAME];
        loop {
            let received = tokio::select! {
                biased;
                _ = read_shared.stop.cancelled() => break,
                result = read_relay.recv_from(&mut buffer) => result,
            };
            match received {
                Ok((n, from)) if from == peer => {
                    if read_shared.check(true).is_err() { break; }
                    // Bounded UDP-style queue: congestion drops packets, never grows memory.
                    if let Err(mpsc::error::TrySendError::Closed(_)) = packets.try_send(buffer[..n].to_vec()) {
                        read_shared.fail(TransportError::Closed);
                        break;
                    }
                }
                Ok(_) => { read_shared.fail(TransportError::Protocol); break; }
                Err(_) => { read_shared.fail(TransportError::Network); break; }
            }
        }
    });
    loop {
        let command = tokio::select! {
            biased;
            _ = shared.stop.cancelled() => break,
            command = commands.recv() => match command { Some(command) => command, None => break },
        };
        let result = tokio::select! {
            biased;
            _ = shared.stop.cancelled() => Err(shared.error()),
            result = timeout_at(command.until, async {
                shared.check(false)?;
                relay.send_to(&command.frame, peer).await.map_err(|_| shared.fail(TransportError::Network))?;
                shared.check(true)?;
                Ok(command.frame.len())
            }) => result.unwrap_or_else(|_| Err(shared.fail(TransportError::Timeout))),
        };
        let _ = command.reply.send(result);
    }
    shared.fail(TransportError::Closed);
    receiver.abort();
    let _ = receiver.await;
    // Upstream close is best-effort (no delete acknowledgement) and may hold transaction locks.
    let _ = timeout(CLOSE_TIMEOUT, relay.close()).await;
    let _ = timeout(CLOSE_TIMEOUT, client.close()).await;
    wire.shutdown().await;
    // run_owner returns; the dedicated runtime then destroys all remaining upstream tasks.
}
