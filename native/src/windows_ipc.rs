//! Private, local-only Windows relay control pipe. No TCP control port or shared secret in argv.
use crate::common::{self, Error, Result};
use sha2::{Digest, Sha256};
use std::{
    io,
    os::windows::io::AsRawHandle,
    path::Path,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::windows::named_pipe::{ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions},
};
use windows_sys::Win32::{
    Foundation::{ERROR_PIPE_BUSY, HANDLE},
    System::Pipes::GetNamedPipeServerProcessId,
};

fn failure() -> Error {
    Error::new(
        "control_ipc",
        "Cannot verify or connect to the private Windows relay control pipe.",
    )
}

fn name(directory: &Path) -> Result<String> {
    common::private_dir(directory, false)?;
    let canonical = std::fs::canonicalize(directory).map_err(|_| failure())?;
    let canonical = crate::windows_security::normalize_system_path(&canonical)?;
    let text = canonical.to_str().ok_or_else(failure)?;
    Ok(format!(
        r"\\.\pipe\tern-turn-relay-{}",
        hex::encode(Sha256::digest(text.as_bytes()))
    ))
}

fn server(name: &str, first: bool) -> io::Result<NamedPipeServer> {
    let mut security = crate::windows_security::private_security_attributes().map_err(|_| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Private pipe security is unavailable.",
        )
    })?;
    unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .max_instances(16)
            .create_with_security_attributes_raw(name, security.as_ptr())
    }
}

pub(crate) struct Listener {
    name: String,
    pending: NamedPipeServer,
}

impl Listener {
    pub(crate) fn bind(directory: &Path) -> Result<Self> {
        let name = name(directory)?;
        let pending = server(&name, true).map_err(|_| failure())?;
        Ok(Self { name, pending })
    }

    pub(crate) async fn accept(&mut self) -> io::Result<(Stream, ())> {
        self.pending.connect().await?;
        // Preserve a listening instance before handing the connected instance to a worker.
        let next = server(&self.name, false)?;
        let connected = std::mem::replace(&mut self.pending, next);
        Ok((Stream::Server(connected), ()))
    }
}

pub(crate) enum Stream {
    Server(NamedPipeServer),
    Client(NamedPipeClient),
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Server(stream) => Pin::new(stream).poll_read(cx, buffer),
            Self::Client(stream) => Pin::new(stream).poll_read(cx, buffer),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Server(stream) => Pin::new(stream).poll_write(cx, data),
            Self::Client(stream) => Pin::new(stream).poll_write(cx, data),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Server(stream) => Pin::new(stream).poll_flush(cx),
            Self::Client(stream) => Pin::new(stream).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Server(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Client(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

pub(crate) async fn connect(directory: &Path) -> Result<(Stream, String)> {
    let pipe = name(directory)?;
    let identity = common::read_json(&directory.join("pid.json"), true)?;
    let expected_pid = identity["pid"]
        .as_u64()
        .filter(|pid| *pid > 0 && *pid <= u32::MAX as u64)
        .ok_or_else(failure)? as u32;
    let service_id = identity["service_id"]
        .as_str()
        .filter(|s| s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(failure)?
        .to_owned();
    for attempt in 0..8 {
        match ClientOptions::new().open(&pipe) {
            Ok(client) => {
                let mut actual_pid = 0u32;
                if unsafe {
                    GetNamedPipeServerProcessId(client.as_raw_handle() as HANDLE, &mut actual_pid)
                } == 0
                    || actual_pid != expected_pid
                {
                    return Err(failure());
                }
                return Ok((Stream::Client(client), service_id));
            }
            Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) && attempt < 7 => {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(_) => return Err(failure()),
        }
    }
    Err(failure())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Directory(std::path::PathBuf);
    impl Directory {
        fn new() -> Self {
            let root =
                std::env::temp_dir().join(format!("ttr-control-{:032x}", rand::random::<u128>()));
            common::private_dir(&root, true).unwrap();
            Self(root)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn first_instance_rejects_control_pipe_replacement() {
        let directory = Directory::new();
        let _listener = Listener::bind(&directory.0).unwrap();
        assert!(Listener::bind(&directory.0).is_err());
    }

    #[tokio::test]
    async fn mismatched_recorded_process_is_not_trusted() {
        let directory = Directory::new();
        let _listener = Listener::bind(&directory.0).unwrap();
        common::atomic_json(
            &directory.0.join("pid.json"),
            &serde_json::json!({
                "pid":u32::MAX,"service_id":"0123456789abcdef0123456789abcdef"
            }),
        )
        .unwrap();
        assert!(connect(&directory.0).await.is_err());
    }
}
