//! Raw loopback TCP forwarding, independent of TURN and gateway recovery.
use crate::common::{self, Error, Result};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::mpsc,
    task::JoinSet,
    time::timeout,
};
use tokio_util::sync::CancellationToken;

pub const MAX_CONNECTIONS: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub address: SocketAddr,
    pub user: String,
}

impl Endpoint {
    pub fn value(&self) -> Value {
        json!({"host":self.address.ip().to_string(),"port":self.address.port(),"user":self.user})
    }
}

fn parse_resolution(config: &Value, text: &str) -> Result<Endpoint> {
    let invalid = || {
        Error::new(
            "ssh_resolution",
            "SSH configuration resolution returned invalid or ambiguous endpoint settings.",
        )
    };
    let mut fields = HashMap::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(' ') else {
            continue;
        };
        if matches!(
            key,
            "hostname" | "user" | "port" | "proxyjump" | "proxycommand"
        ) && fields.insert(key, value.trim()).is_some()
        {
            return Err(invalid());
        }
    }
    for key in ["proxyjump", "proxycommand"] {
        if !fields
            .get(key)
            .unwrap_or(&"none")
            .eq_ignore_ascii_case("none")
        {
            return Err(Error::new("ssh_proxy", "SSH ProxyJump/ProxyCommand is not supported. No proxy command was executed; use a direct SSH Host alias."));
        }
    }
    let host = fields.get("hostname").copied().ok_or_else(invalid)?;
    let user = fields.get("user").copied().ok_or_else(invalid)?;
    if Some(host) != config["target"]["host"].as_str()
        || Some(user) != config["target"]["user"].as_str()
    {
        return Err(Error::new("identity_mismatch", "Resolved SSH HostName/User does not match the configured target; refusing to forward to a different endpoint."));
    }
    let raw_port = fields.get("port").copied().ok_or_else(invalid)?;
    if raw_port.is_empty()
        || raw_port.len() > 5
        || !raw_port.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(invalid());
    }
    let port = raw_port
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(invalid)?;
    let ip = host.parse::<std::net::Ipv4Addr>().map_err(|_| invalid())?;
    Ok(Endpoint {
        address: SocketAddr::new(ip.into(), port),
        user: user.to_owned(),
    })
}

pub async fn resolve(config: &Value) -> Result<Endpoint> {
    let alias = config["ssh_destination"]
        .as_str()
        .ok_or_else(|| Error::new("ssh_resolution", "Missing SSH destination."))?;
    common::safe_alias(alias)?;
    let output = common::run(
        &common::ssh_executable()?,
        &["-G".into(), alias.into()],
        None,
        Duration::from_secs(5),
    )
    .await?;
    if !output.status.success() {
        return Err(Error::new(
            "ssh_resolution",
            "SSH configuration resolution failed; check the local SSH Host alias.",
        ));
    }
    let text = std::str::from_utf8(&output.stdout).map_err(|_| {
        Error::new(
            "ssh_resolution",
            "SSH configuration resolution returned invalid text.",
        )
    })?;
    parse_resolution(config, text)
}

struct ConnectionGuard(Arc<AtomicUsize>);
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

pub struct Forwarder {
    pub count: Arc<AtomicUsize>,
    cancel: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

impl Forwarder {
    pub async fn open(
        port: u16,
        endpoint: Endpoint,
        failures: mpsc::Sender<Error>,
        parent: &CancellationToken,
    ) -> Result<Self> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .map_err(|_| {
                Error::new("ssh_listener", "Cannot bind the loopback SSH TCP listener.")
            })?;
        let cancel = parent.child_token();
        let stopped = cancel.clone();
        let count = Arc::new(AtomicUsize::new(0));
        let active = count.clone();
        let task = tokio::spawn(async move {
            let mut clients = JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    _ = stopped.cancelled() => break,
                    _ = clients.join_next(), if !clients.is_empty() => {},
                    accepted = listener.accept() => {
                        let (mut local, peer) = match accepted {
                            Ok(pair) => pair,
                            Err(_) => { let _ = failures.try_send(Error::new("ssh_listener", "Loopback SSH listener failed.")); break; }
                        };
                        if peer.ip() != std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST) { continue; }
                        if active.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
                            let _ = failures.try_send(Error::new("ssh_capacity", "Concurrent SSH connection limit reached; disconnect unused SSH sessions and reconnect."));
                            continue;
                        }
                        active.fetch_add(1, Ordering::SeqCst);
                        let guard = ConnectionGuard(active.clone());
                        let failures = failures.clone();
                        let cancel = stopped.clone();
                        let address = endpoint.address;
                        clients.spawn(async move {
                            let _guard = guard;
                            let forward = async {
                                let mut remote = timeout(Duration::from_secs(10), TcpStream::connect(address)).await
                                    .map_err(|_| Error::new("ssh_timeout", "Connecting to the original SSH endpoint timed out; no SSH authentication or direct TURN fallback was attempted."))?
                                    .map_err(|_| Error::new("ssh_forward", "Raw SSH forwarding failed; check the original SSH endpoint."))?;
                                // Tokio propagates each half-close independently and uses bounded buffers.
                                tokio::io::copy_bidirectional_with_sizes(&mut local, &mut remote, 64 * 1024, 64 * 1024).await
                                    .map_err(|_| Error::new("ssh_forward", "Raw SSH forwarding failed; SSH credentials are handled only by the SSH client."))?;
                                Ok::<(), Error>(())
                            };
                            tokio::select! {
                                biased;
                                _ = cancel.cancelled() => {},
                                result = forward => if let Err(error) = result { let _ = failures.try_send(error); }
                            }
                        });
                    }
                }
            }
            clients.abort_all();
            while clients.join_next().await.is_some() {}
        });
        Ok(Self {
            count,
            cancel,
            task,
        })
    }

    pub async fn close(self) {
        self.cancel.cancel();
        let _ = self.task.await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolved_identity_proxy_and_port_are_strict() {
        let config = json!({"target":{"host":"8.8.8.8","user":"alice"}});
        let base = "hostname 8.8.8.8\nuser alice\nport 2222\nproxycommand none\n";
        assert_eq!(
            parse_resolution(&config, base).unwrap().address.port(),
            2222
        );
        for suffix in ["hostname 8.8.8.8\n", "proxyjump bastion\n", "port 0\n"] {
            assert!(parse_resolution(&config, &format!("{base}{suffix}")).is_err());
        }
        assert!(parse_resolution(&config, &base.replace("alice", "bob")).is_err());
        assert!(parse_resolution(&config, &base.replace("2222", "+22")).is_err());
        assert!(parse_resolution(&config, &base.replace("2222", "65536")).is_err());
    }

    #[tokio::test]
    async fn raw_forwarding_preserves_remote_reply_after_client_half_close() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let remote = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut connection, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            connection.read_to_end(&mut request).await.unwrap();
            assert_eq!(request, b"client-fin");
            connection.write_all(b"reply-after-fin").await.unwrap();
            connection.shutdown().await.unwrap();
        });
        let local = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = local.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let mut client = TcpStream::connect(address).await.unwrap();
            client.write_all(b"client-fin").await.unwrap();
            client.shutdown().await.unwrap();
            let mut reply = Vec::new();
            client.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, b"reply-after-fin");
        });
        let (mut accepted, _) = local.accept().await.unwrap();
        let mut upstream = TcpStream::connect(remote).await.unwrap();
        timeout(
            Duration::from_secs(2),
            tokio::io::copy_bidirectional_with_sizes(
                &mut accepted,
                &mut upstream,
                64 * 1024,
                64 * 1024,
            ),
        )
        .await
        .unwrap()
        .unwrap();
        client.await.unwrap();
        server.await.unwrap();
    }
}
