//! Linux-only, SSH-owned frontend. The original daemon is observed, never signalled.
use crate::common::{self, Result};
use crate::gateway::failure;
use serde_json::Value;

pub(crate) fn parse_json(bytes: &[u8]) -> Result<Value> {
    common::parse_json(bytes).map_err(|_| failure("protocol_error"))
}

pub async fn run(args: &[String]) -> Result<Value> {
    let options = common::Options::parse(args, &["--state-dir"], &[])?;
    if options.positionals.len() != 1 {
        return Err(failure("protocol_error"));
    }
    #[cfg(target_os = "linux")]
    {
        let operation = options.positionals[0].clone();
        let directory = options.get("--state-dir").map(str::to_owned);
        tokio::task::spawn_blocking(move || {
            linux::initialize()?;
            match operation.as_str() {
                "discover" if directory.is_none() => {
                    use std::io::Read;
                    let mut bytes = Vec::new();
                    std::io::stdin()
                        .take(65537)
                        .read_to_end(&mut bytes)
                        .map_err(|_| failure("control_eof"))?;
                    if bytes.len() > 65536 {
                        return Err(failure("protocol_error"));
                    }
                    crate::discovery::linux::discover(&parse_json(&bytes)?)
                }
                "provision" => {
                    let directory = directory.ok_or_else(|| failure("protocol_error"))?;
                    linux::provision(&directory)
                }
                _ => Err(failure("protocol_error")),
            }
        })
        .await
        .map_err(|_| failure("unknown"))?
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = options;
        Err(failure("security_error"))
    }
}

pub async fn serve(args: &[String]) -> Result<()> {
    let options = common::Options::parse(args, &["--state-dir"], &[])?;
    if options.positionals.as_slice() != ["serve"] {
        return Err(failure("protocol_error"));
    }
    let directory = options.required("--state-dir")?.to_owned();
    #[cfg(target_os = "linux")]
    {
        tokio::task::spawn_blocking(move || linux::serve(&directory))
            .await
            .map_err(|_| failure("unknown"))?
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = directory;
        Err(failure("security_error"))
    }
}

#[cfg(target_os = "linux")]
pub(crate) mod linux {
    use super::*;
    use crate::protocol::{self, ReplayWindow as Replay};
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde_json::json;
    use std::{
        collections::{BTreeMap, BTreeSet},
        ffi::{CStr, CString},
        fs::{self, File, Metadata, OpenOptions},
        io::Read,
        net::{Ipv4Addr, SocketAddr, UdpSocket},
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd},
            unix::{
                ffi::OsStrExt,
                fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
                process::CommandExt,
            },
        },
        path::{Path, PathBuf},
        process::{Child, Command, Stdio},
        sync::atomic::{AtomicBool, Ordering},
        thread,
        time::{Duration, Instant},
    };
    static STOPPED: AtomicBool = AtomicBool::new(false);
    extern "C" fn stop(_: libc::c_int) {
        STOPPED.store(true, Ordering::Relaxed);
    }
    pub(crate) fn initialize() -> Result<()> {
        unsafe {
            libc::umask(0o077);
        }
        for number in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
            if unsafe { libc::signal(number, stop as *const () as libc::sighandler_t) }
                == libc::SIG_ERR
            {
                return Err(failure("security_error"));
            }
        }
        Ok(())
    }
    fn interrupted() -> Result<()> {
        if STOPPED.load(Ordering::Relaxed) {
            Err(failure("control_eof"))
        } else {
            Ok(())
        }
    }
    pub(crate) fn uid() -> u32 {
        unsafe { libc::geteuid() }
    }
    pub(crate) fn account() -> Result<(String, PathBuf)> {
        let mut storage = vec![0u8; 65536];
        let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result = std::ptr::null_mut();
        let status = unsafe {
            libc::getpwuid_r(
                uid(),
                &mut entry,
                storage.as_mut_ptr().cast(),
                storage.len(),
                &mut result,
            )
        };
        if status != 0 || result.is_null() || entry.pw_name.is_null() || entry.pw_dir.is_null() {
            return Err(failure("security_error"));
        }
        let user = unsafe { CStr::from_ptr(entry.pw_name) }
            .to_str()
            .map_err(|_| failure("security_error"))?
            .to_owned();
        let home = unsafe { CStr::from_ptr(entry.pw_dir) }
            .to_str()
            .map_err(|_| failure("security_error"))?;
        Ok((user, path(home)?))
    }
    pub(crate) fn path(text: &str) -> Result<PathBuf> {
        common::safe_absolute(text).map_err(|_| failure("security_error"))?;
        Ok(PathBuf::from(text))
    }
    pub(crate) fn ancestors(path: &Path) -> Result<()> {
        for component in path.ancestors() {
            let info = fs::symlink_metadata(component).map_err(|_| failure("security_error"))?;
            if !info.is_dir() || ![0, uid()].contains(&info.uid()) || info.mode() & 0o022 != 0 {
                return Err(failure("security_error"));
            }
        }
        Ok(())
    }
    pub(crate) fn bounded(path: &Path, maximum: usize) -> Result<Vec<u8>> {
        let file = File::open(path).map_err(|_| failure("identity_mismatch"))?;
        let mut bytes = Vec::new();
        file.take(maximum as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| failure("identity_mismatch"))?;
        if bytes.len() > maximum {
            return Err(failure("security_error"));
        }
        Ok(bytes)
    }
    pub(crate) fn regular(path: &Path, private: bool) -> Result<File> {
        ancestors(path.parent().ok_or_else(|| failure("security_error"))?)?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| failure("security_error"))?;
        let info = file.metadata().map_err(|_| failure("security_error"))?;
        if !info.is_file()
            || info.uid() != uid()
            || info.nlink() != 1
            || info.mode() & 0o022 != 0
            || (private && info.mode() & 0o777 != 0o600)
        {
            return Err(failure("security_error"));
        }
        Ok(file)
    }
    pub(crate) fn process_stat(pid: u32) -> Result<(String, u32)> {
        let raw = bounded(&PathBuf::from(format!("/proc/{pid}/stat")), 8192)?;
        let text = std::str::from_utf8(&raw).map_err(|_| failure("identity_mismatch"))?;
        parse_stat(text)
    }
    fn parse_stat(text: &str) -> Result<(String, u32)> {
        let suffix = text
            .rsplit_once(')')
            .ok_or_else(|| failure("identity_mismatch"))?
            .1;
        let fields: Vec<_> = suffix.split_whitespace().collect();
        if fields.len() < 20
            || fields[0] == "Z"
            || fields[0] == "X"
            || fields[19].parse::<u64>().is_err()
        {
            return Err(failure("identity_mismatch"));
        }
        Ok((
            fields[19].to_owned(),
            fields[1]
                .parse()
                .map_err(|_| failure("identity_mismatch"))?,
        ))
    }
    fn executable_path(raw: &str, nlink: u64) -> Result<PathBuf> {
        let normalized = if let Some(value) = raw.strip_suffix(" (deleted)") {
            if nlink != 0 {
                return Err(failure("identity_mismatch"));
            }
            value
        } else {
            raw
        };
        let result = path(normalized)?;
        if result.file_name().and_then(|v| v.to_str()) != Some("tern") {
            return Err(failure("identity_mismatch"));
        }
        Ok(result)
    }
    fn executable_metadata(info: &Metadata) -> Result<()> {
        if !info.is_file()
            || ![0, uid()].contains(&info.uid())
            || info.mode() & 0o022 != 0
            || info.mode() & 0o111 == 0
        {
            Err(failure("security_error"))
        } else {
            Ok(())
        }
    }
    pub(crate) fn executable(pid: u32) -> Result<PathBuf> {
        // A single open file description binds path and metadata through exec.
        let file =
            File::open(format!("/proc/{pid}/exe")).map_err(|_| failure("identity_mismatch"))?;
        let running = file.metadata().map_err(|_| failure("identity_mismatch"))?;
        let raw = fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
            .map_err(|_| failure("identity_mismatch"))?;
        let result = executable_path(
            raw.to_str().ok_or_else(|| failure("identity_mismatch"))?,
            running.nlink(),
        )?;
        ancestors(result.parent().ok_or_else(|| failure("security_error"))?)?;
        executable_metadata(&running)?;
        executable_metadata(
            &fs::symlink_metadata(&result).map_err(|_| failure("identity_mismatch"))?,
        )?;
        let name =
            CString::new(result.as_os_str().as_bytes()).map_err(|_| failure("security_error"))?;
        if unsafe { libc::access(name.as_ptr(), libc::X_OK) } != 0 {
            return Err(failure("security_error"));
        }
        Ok(result)
    }
    pub(crate) fn command_line(pid: u32) -> Result<Vec<String>> {
        let raw = bounded(&PathBuf::from(format!("/proc/{pid}/cmdline")), 8192)?;
        if !raw.ends_with(&[0]) {
            return Err(failure("identity_mismatch"));
        }
        raw[..raw.len() - 1]
            .split(|b| *b == 0)
            .map(|bytes| {
                String::from_utf8(bytes.to_vec()).map_err(|_| failure("identity_mismatch"))
            })
            .collect()
    }
    fn identity(pid: u32, socket: &Path) -> Result<Value> {
        if fs::metadata(format!("/proc/{pid}"))
            .map_err(|_| failure("identity_mismatch"))?
            .uid()
            != uid()
        {
            return Err(failure("identity_mismatch"));
        }
        let (start, _) = process_stat(pid)?;
        let binary = executable(pid)?;
        let args = command_line(pid)?;
        if args.is_empty()
            || (args[0] != "tern" && Path::new(&args[0]) != binary)
            || args.iter().filter(|v| v.as_str() == "daemon").count() != 1
            || args.iter().filter(|v| v.as_str() == "--socket").count() != 1
            || !args
                .windows(2)
                .any(|pair| pair[0] == "--socket" && Path::new(&pair[1]) == socket)
        {
            return Err(failure("identity_mismatch"));
        }
        let boot = bounded(Path::new("/proc/sys/kernel/random/boot_id"), 128)?;
        let boot = std::str::from_utf8(&boot)
            .map_err(|_| failure("identity_mismatch"))?
            .trim();
        if boot.is_empty() {
            return Err(failure("identity_mismatch"));
        }
        if process_stat(pid)?.0 != start {
            return Err(failure("identity_mismatch"));
        }
        Ok(
            json!({"pid":pid,"start_time":start,"boot_id":boot,"executable_path":binary,"daemon_argv":args}),
        )
    }
    fn peer(socket: &Path) -> Result<(u32, u32)> {
        let raw = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if raw < 0 {
            return Err(failure("identity_mismatch"));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let bytes = socket.as_os_str().as_bytes();
        if bytes.len() >= addr.sun_path.len() {
            return Err(failure("security_error"));
        }
        for (out, byte) in addr.sun_path.iter_mut().zip(bytes) {
            *out = *byte as libc::c_char;
        }
        let connected = unsafe {
            libc::connect(
                fd.as_raw_fd(),
                (&addr as *const libc::sockaddr_un).cast(),
                std::mem::size_of_val(&addr) as libc::socklen_t,
            )
        };
        if connected != 0 {
            let code = std::io::Error::last_os_error().raw_os_error();
            if code != Some(libc::EINPROGRESS) {
                return Err(failure("identity_mismatch"));
            }
            let mut poll = libc::pollfd {
                fd: fd.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            };
            if unsafe { libc::poll(&mut poll, 1, 2000) } <= 0 {
                return Err(failure("identity_mismatch"));
            }
            let mut error: libc::c_int = 0;
            let mut length = std::mem::size_of_val(&error) as libc::socklen_t;
            if unsafe {
                libc::getsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    (&mut error as *mut libc::c_int).cast(),
                    &mut length,
                )
            } != 0
                || error != 0
            {
                return Err(failure("identity_mismatch"));
            }
        }
        let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of_val(&credentials) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut credentials as *mut libc::ucred).cast(),
                &mut length,
            )
        } != 0
            || length as usize != std::mem::size_of_val(&credentials)
            || credentials.pid <= 1
        {
            return Err(failure("identity_mismatch"));
        }
        Ok((credentials.pid as u32, credentials.uid))
    }
    pub(crate) struct DaemonPin {
        pub(crate) path: PathBuf,
        pub(crate) pid: u32,
        pub(crate) identity: Value,
        socket: (u64, u64),
    }
    impl DaemonPin {
        pub(crate) fn new(text: &str) -> Result<Self> {
            let path = path(text)?;
            ancestors(path.parent().ok_or_else(|| failure("security_error"))?)?;
            let info = socket_metadata(&path)?;
            let (pid, owner) = peer(&path)?;
            if owner != uid() {
                return Err(failure("identity_mismatch"));
            }
            let pin = Self {
                identity: identity(pid, &path)?,
                pid,
                path,
                socket: (info.dev(), info.ino()),
            };
            pin.check(true)?;
            Ok(pin)
        }
        pub(crate) fn check(&self, responsive: bool) -> Result<()> {
            let info = socket_metadata(&self.path)?;
            if (info.dev(), info.ino()) != self.socket
                || identity(self.pid, &self.path)? != self.identity
                || (responsive && peer(&self.path)? != (self.pid, uid()))
            {
                return Err(failure("identity_mismatch"));
            }
            Ok(())
        }
        fn record(&self) -> Value {
            let mut value = self.identity.clone();
            value["version"] = json!(2);
            value["daemon_socket"] = json!(self.path);
            value["socket_device"] = json!(self.socket.0);
            value["socket_inode"] = json!(self.socket.1);
            value
        }
        fn persist(&self, directory: &Path) -> Result<()> {
            self.check(true)?;
            let target = directory.join("daemon-identity.json");
            let current = self.record();
            match fs::symlink_metadata(&target) {
                Ok(_) => {
                    let file = regular(&target, true)?;
                    let mut raw = Vec::new();
                    file.take(8193)
                        .read_to_end(&mut raw)
                        .map_err(|_| failure("identity_mismatch"))?;
                    if raw.len() > 8192 {
                        return Err(failure("identity_mismatch"));
                    }
                    let saved = parse_json(&raw).map_err(|_| failure("identity_mismatch"))?;
                    if !migration_required(&saved, &current)? {
                        return Ok(());
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                Err(_) => return Err(failure("security_error")),
            }
            self.check(true)?;
            common::atomic_json(&target, &current).map_err(|_| failure("security_error"))
        }
        pub(crate) fn capture(
            &self,
            args: &[String],
            mut control: Option<&mut Control>,
            maximum: usize,
        ) -> Result<Value> {
            self.check(true)?;
            if let Some(c) = control.as_deref_mut() {
                c.startup()?;
            }
            let mut command = self.command()?;
            command
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null());
            let mut child = OwnedChild::spawn(command)?;
            let mut output = child.0.stdout.take().ok_or_else(|| failure("unknown"))?;
            nonblocking(output.as_raw_fd())?;
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut bytes = Vec::new();
            let mut chunk = [0u8; 8192];
            loop {
                interrupted()?;
                if let Some(c) = control.as_deref_mut() {
                    c.startup()?;
                }
                self.check(false)?;
                loop {
                    match output.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => {
                            if bytes.len() + n > maximum {
                                return Err(failure("protocol_error"));
                            }
                            bytes.extend_from_slice(&chunk[..n]);
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => return Err(failure("unknown")),
                    }
                }
                if let Some(status) = child.0.try_wait().map_err(|_| failure("unknown"))? {
                    if !status.success() {
                        return Err(failure("unknown"));
                    }
                    // Drain bytes written immediately before process exit.
                    loop {
                        match output.read(&mut chunk) {
                            Ok(0) => break,
                            Ok(n) => {
                                if bytes.len() + n > maximum {
                                    return Err(failure("protocol_error"));
                                }
                                bytes.extend_from_slice(&chunk[..n]);
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                            Err(_) => return Err(failure("unknown")),
                        }
                    }
                    self.check(true)?;
                    return parse_json(&bytes);
                }
                if Instant::now() >= deadline {
                    return Err(failure("connectivity_uncertain"));
                }
                thread::sleep(Duration::from_millis(50));
            }
        }
        fn command(&self) -> Result<Command> {
            self.check(true)?;
            let mut command = Command::new(
                self.identity["executable_path"]
                    .as_str()
                    .ok_or_else(|| failure("identity_mismatch"))?,
            );
            command
                .env("TERN_DAEMON_SOCKET", &self.path)
                .env("TERN_PANE_SOCKET", &self.path);
            Ok(command)
        }
    }
    fn socket_metadata(path: &Path) -> Result<Metadata> {
        ancestors(path.parent().ok_or_else(|| failure("security_error"))?)?;
        let info = fs::symlink_metadata(path).map_err(|_| failure("identity_mismatch"))?;
        if !info.file_type().is_socket() || info.uid() != uid() || info.mode() & 0o022 != 0 {
            return Err(failure("security_error"));
        }
        Ok(info)
    }
    fn migration_required(saved: &Value, current: &Value) -> Result<bool> {
        if saved == current {
            return Ok(false);
        }
        let stable = [
            "pid",
            "start_time",
            "boot_id",
            "daemon_socket",
            "socket_device",
            "socket_inode",
        ];
        let expected: BTreeSet<_> = stable
            .iter()
            .copied()
            .chain(["exe_device", "exe_inode"])
            .collect();
        let object = saved
            .as_object()
            .ok_or_else(|| failure("identity_mismatch"))?;
        if object.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected
            || stable.iter().any(|field| saved[*field] != current[*field])
            || saved["exe_device"].as_u64().is_none()
            || saved["exe_inode"].as_u64().unwrap_or(0) == 0
        {
            return Err(failure("identity_mismatch"));
        }
        Ok(true)
    }
    struct OwnedChild(Child);
    impl OwnedChild {
        fn spawn(mut command: Command) -> Result<Self> {
            let parent = unsafe { libc::getpid() };
            unsafe {
                command.pre_exec(move || {
                    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0
                        || libc::getppid() != parent
                    {
                        return Err(std::io::Error::from_raw_os_error(libc::ECHILD));
                    }
                    Ok(())
                });
            }
            command
                .spawn()
                .map(Self)
                .map_err(|_| failure("frontend_exit"))
        }
    }
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            if matches!(self.0.try_wait(), Ok(Some(_))) {
                return;
            }
            unsafe {
                libc::kill(self.0.id() as libc::pid_t, libc::SIGTERM);
            }
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline {
                if matches!(self.0.try_wait(), Ok(Some(_))) {
                    return;
                }
                thread::sleep(Duration::from_millis(20));
            }
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    fn nonblocking(fd: libc::c_int) -> Result<()> {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(failure("security_error"));
        }
        Ok(())
    }
    pub(crate) struct Control {
        fd: libc::c_int,
        buffer: Vec<u8>,
    }
    impl Drop for Control {
        fn drop(&mut self) {
            crate::gateway::wipe(&mut self.buffer);
        }
    }
    impl Control {
        fn new() -> Result<Self> {
            Self::from_fd(libc::STDIN_FILENO)
        }
        fn from_fd(fd: libc::c_int) -> Result<Self> {
            nonblocking(fd)?;
            Ok(Self {
                fd,
                buffer: Vec::with_capacity(8192),
            })
        }
        fn receive_ready(&mut self, events: libc::c_short) -> Result<Vec<Value>> {
            // Buffered pings cannot renew a generation whose control transport
            // has already closed, even when POLLIN is reported simultaneously.
            if events & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL | libc::POLLRDHUP) != 0 {
                return Err(failure("control_eof"));
            }
            if events & libc::POLLIN == 0 {
                return Ok(Vec::new());
            }
            self.receive()
        }
        fn receive(&mut self) -> Result<Vec<Value>> {
            let mut chunk = [0u8; 8193];
            let count = loop {
                let count = unsafe { libc::read(self.fd, chunk.as_mut_ptr().cast(), chunk.len()) };
                if count < 0
                    && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                {
                    continue;
                }
                break count;
            };
            if count == 0 {
                return Err(failure("control_eof"));
            }
            if count < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    return Ok(Vec::new());
                }
                return Err(failure("control_eof"));
            }
            self.buffer.extend_from_slice(&chunk[..count as usize]);
            crate::gateway::wipe(&mut chunk);
            if self.buffer.len() > 8192 {
                return Err(failure("protocol_error"));
            }
            let mut values = Vec::new();
            let mut consumed = 0;
            for (index, byte) in self.buffer.iter().enumerate() {
                if *byte == b'\n' {
                    let value = parse_json(&self.buffer[consumed..index])?;
                    if !value.is_object() {
                        return Err(failure("protocol_error"));
                    }
                    values.push(value);
                    consumed = index + 1;
                }
            }
            crate::gateway::wipe(&mut self.buffer[..consumed]);
            self.buffer.drain(..consumed);
            Ok(values)
        }
        fn initial(&mut self) -> Result<Value> {
            let deadline = Instant::now() + Duration::from_secs(15);
            loop {
                interrupted()?;
                let mut values = self.receive()?;
                if !values.is_empty() {
                    if values.len() != 1 || !self.buffer.is_empty() {
                        return Err(failure("protocol_error"));
                    }
                    return Ok(values.remove(0));
                }
                if Instant::now() >= deadline {
                    return Err(failure("connectivity_uncertain"));
                }
                thread::sleep(Duration::from_millis(20));
            }
        }
        fn startup(&mut self) -> Result<()> {
            interrupted()?;
            if !self.receive()?.is_empty() || !self.buffer.is_empty() {
                return Err(failure("protocol_error"));
            }
            Ok(())
        }
    }
    fn emit(value: &Value) -> Result<()> {
        let mut bytes = serde_json::to_vec(value).map_err(|_| failure("protocol_error"))?;
        bytes.push(b'\n');
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut offset = 0;
        while offset < bytes.len() {
            interrupted()?;
            let n = unsafe {
                libc::write(
                    libc::STDOUT_FILENO,
                    bytes[offset..].as_ptr().cast(),
                    bytes.len() - offset,
                )
            };
            if n > 0 {
                offset += n as usize;
                continue;
            }
            let e = std::io::Error::last_os_error();
            if !matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ) {
                return Err(failure("control_eof"));
            }
            if Instant::now() >= deadline {
                return Err(failure("send_timeout"));
            }
            thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }
    fn native_tree(root: &Path) -> Result<()> {
        common::private_dir(root, false).map_err(|_| failure("security_error"))?;
        let mut pending = vec![root.to_path_buf()];
        let mut count = 0;
        while let Some(directory) = pending.pop() {
            for entry in fs::read_dir(directory).map_err(|_| failure("security_error"))? {
                let entry = entry.map_err(|_| failure("security_error"))?;
                count += 1;
                if count > 256 {
                    return Err(failure("security_error"));
                }
                let info =
                    fs::symlink_metadata(entry.path()).map_err(|_| failure("security_error"))?;
                if info.uid() != uid()
                    || info.mode() & 0o077 != 0
                    || (!info.is_dir() && !info.is_file())
                    || (info.is_file() && info.nlink() != 1)
                {
                    return Err(failure("security_error"));
                }
                if info.is_dir() {
                    pending.push(entry.path());
                }
            }
        }
        Ok(())
    }
    fn add_id(value: &Value, out: &mut BTreeSet<String>) -> Result<()> {
        let id = match &value["id"] {
            Value::String(v) => v.clone(),
            v if v.as_u64().is_some() => v.as_u64().unwrap().to_string(),
            _ => return Err(failure("protocol_error")),
        };
        if id.is_empty() || id.len() > 256 || id.chars().any(char::is_control) {
            return Err(failure("protocol_error"));
        }
        out.insert(id);
        if out.len() > 4096 {
            return Err(failure("protocol_error"));
        }
        Ok(())
    }
    fn entries<'a>(value: &'a Value, name: &str) -> Result<&'a [Value]> {
        match value.get(name) {
            None => Ok(&[]),
            Some(Value::Array(v)) => Ok(v),
            _ => Err(failure("protocol_error")),
        }
    }
    fn inventory(value: &Value) -> Result<Value> {
        if !value["sessions"].is_array() {
            return Err(failure("protocol_error"));
        }
        let (mut sessions, mut tabs, mut panes) =
            (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
        for session in entries(value, "sessions")? {
            add_id(session, &mut sessions)?;
            for tab in entries(session, "tabs")? {
                add_id(tab, &mut tabs)?;
                for pane in entries(tab, "blocks")? {
                    add_id(pane, &mut panes)?;
                }
            }
        }
        for pane in entries(value, "detached")? {
            add_id(pane, &mut panes)?;
        }
        if sessions.is_empty() || tabs.is_empty() || panes.is_empty() {
            return Err(failure("identity_mismatch"));
        }
        Ok(json!({"session_ids":sessions,"tab_ids":tabs,"pane_ids":panes}))
    }
    struct Prepared {
        pin: DaemonPin,
        native: PathBuf,
        authorized: PathBuf,
        descriptor: Value,
        _lock: File,
    }
    fn prepare(
        directory: &str,
        request: &Value,
        mut control: Option<&mut Control>,
    ) -> Result<Prepared> {
        let pin = DaemonPin::new(
            request["daemon_socket"]
                .as_str()
                .ok_or_else(|| failure("protocol_error"))?,
        )?;
        let directory = path(directory)?;
        common::private_dir(&directory, true).map_err(|_| failure("security_error"))?;
        ancestors(&directory)?;
        let lock = common::lock(&directory.join("control.lock"), true).map_err(|e| {
            if e.code == "lock-busy" {
                failure("state_lock_busy")
            } else {
                failure("security_error")
            }
        })?;
        let native = directory.join("native");
        common::private_dir(&native, true).map_err(|_| failure("security_error"))?;
        native_tree(&native)?;
        // A previously pinned gateway cannot regenerate a missing identity.
        let key = fs::symlink_metadata(native.join("host_key")).is_ok();
        let cert = fs::symlink_metadata(native.join("host_cert.der")).is_ok();
        if key != cert || (request.get("gateway_fingerprint").is_some() && !key) {
            return Err(failure("identity_mismatch"));
        }
        pin.persist(&directory)?;
        let baseline = pin.capture(
            &["ls".into(), "--json".into()],
            control.as_deref_mut(),
            4 * 1024 * 1024,
        )?;
        let mut descriptor = inventory(&baseline)?;
        let response = pin.capture(
            &[
                "remote".into(),
                "host-key".into(),
                "--state-dir".into(),
                native
                    .to_str()
                    .ok_or_else(|| failure("security_error"))?
                    .into(),
            ],
            control.as_deref_mut(),
            65536,
        )?;
        native_tree(&native)?;
        let fingerprint = response["fingerprint"]
            .as_str()
            .ok_or_else(|| failure("protocol_error"))?;
        common::fingerprint(fingerprint).map_err(|_| failure("protocol_error"))?;
        if request
            .get("gateway_fingerprint")
            .is_some_and(|v| v != fingerprint)
            || request
                .get("original_fingerprint")
                .is_some_and(|v| v == fingerprint)
        {
            return Err(failure("identity_mismatch"));
        }
        let authorized = account()?.1.join(".ssh/authorized_keys");
        if regular(&authorized, false)?
            .metadata()
            .map_err(|_| failure("security_error"))?
            .len()
            == 0
        {
            return Err(failure("security_error"));
        }
        descriptor["ok"] = json!(true);
        descriptor["fingerprint"] = json!(fingerprint);
        descriptor["daemon_socket"] = json!(pin.path);
        descriptor["daemon_pid"] = json!(pin.pid);
        Ok(Prepared {
            pin,
            native,
            authorized,
            descriptor,
            _lock: lock,
        })
    }
    fn validate_request(request: &Value, serving: bool) -> Result<Ipv4Addr> {
        let object = request
            .as_object()
            .ok_or_else(|| failure("protocol_error"))?;
        let mut expected: BTreeSet<&str> = ["daemon_socket", "bind_host", "original_fingerprint"]
            .into_iter()
            .collect();
        if serving {
            expected.insert("session_key");
        }
        if object.contains_key("gateway_fingerprint") {
            expected.insert("gateway_fingerprint");
        }
        if object.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected {
            return Err(failure("protocol_error"));
        }
        common::fingerprint(request["original_fingerprint"].as_str().unwrap_or(""))
            .map_err(|_| failure("protocol_error"))?;
        if let Some(pin) = request.get("gateway_fingerprint") {
            common::fingerprint(pin.as_str().unwrap_or(""))
                .map_err(|_| failure("protocol_error"))?;
        }
        crate::discovery::public_ipv4(
            request["bind_host"]
                .as_str()
                .ok_or_else(|| failure("protocol_error"))?,
        )
    }
    pub(crate) fn provision(directory: &str) -> Result<Value> {
        let mut control = Control::new()?;
        let request = control.initial()?;
        validate_request(&request, false)?;
        Ok(prepare(directory, &request, None)?.descriptor)
    }
    struct Secret([u8; 32]);
    impl Drop for Secret {
        fn drop(&mut self) {
            crate::gateway::wipe(&mut self.0);
        }
    }
    struct Flow {
        replay: Replay,
        sequence: u64,
        peer: SocketAddr,
        socket: Option<UdpSocket>,
        active: Instant,
    }
    struct FlowTable {
        identities: BTreeMap<u64, Flow>,
        active: Vec<u64>,
    }
    impl FlowTable {
        fn new() -> Self {
            Self {
                identities: BTreeMap::new(),
                active: Vec::with_capacity(16),
            }
        }
        fn expire(&mut self, now: Instant) {
            let Self { identities, active } = self;
            active.retain(|id| {
                let flow = identities.get_mut(id).expect("active authenticated flow");
                if now.duration_since(flow.active) >= Duration::from_secs(60) {
                    flow.socket = None;
                    false
                } else {
                    true
                }
            });
        }
    }
    fn forward(
        public: &UdpSocket,
        native: u16,
        key: &[u8; 32],
        flows: &mut FlowTable,
        buffer: &mut [u8],
    ) -> Result<()> {
        let (size, peer) = match public.recv_from(buffer) {
            Ok(v) => v,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::ConnectionRefused
                ) =>
            {
                return Ok(())
            }
            Err(_) => return Err(failure("unknown")),
        };
        let Some((id, sequence, payload)) =
            protocol::decode(key, protocol::CLIENT_TO_SERVER, &buffer[..size])
        else {
            return Ok(());
        };
        if !flows.identities.contains_key(&id) {
            if flows.identities.len() >= 4096 {
                return Ok(());
            }
            flows.identities.insert(
                id,
                Flow {
                    replay: Replay::default(),
                    sequence: 0,
                    peer,
                    socket: None,
                    active: Instant::now(),
                },
            );
        }
        let flow = flows
            .identities
            .get_mut(&id)
            .ok_or_else(|| failure("unknown"))?;
        let newer = sequence > flow.replay.highest();
        if !flow.replay.accept(sequence) {
            return Ok(());
        }
        if newer {
            flow.peer = peer;
        }
        if flow.socket.is_none() {
            if flows.active.len() >= 16 {
                return Ok(());
            }
            let socket =
                UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|_| failure("unknown"))?;
            socket
                .set_nonblocking(true)
                .map_err(|_| failure("unknown"))?;
            socket
                .connect((Ipv4Addr::LOCALHOST, native))
                .map_err(|_| failure("unknown"))?;
            flow.socket = Some(socket);
            flows.active.push(id);
        }
        flow.active = Instant::now();
        if let Some(socket) = &flow.socket {
            let _ = socket.send(payload);
        }
        Ok(())
    }
    fn reply(
        public: &UdpSocket,
        key: &[u8; 32],
        id: u64,
        flow: &mut Flow,
        buffer: &mut [u8],
        encoded: &mut Vec<u8>,
    ) -> Result<()> {
        let Some(socket) = flow.socket.as_ref() else {
            return Ok(());
        };
        let size = match socket.recv(buffer) {
            Ok(size) => size,
            Err(_) => return Ok(()),
        };
        if size > protocol::MAX_PAYLOAD {
            return Ok(());
        }
        flow.sequence = flow
            .sequence
            .checked_add(1)
            .ok_or_else(|| failure("protocol_error"))?;
        protocol::encode_into(
            key,
            protocol::SERVER_TO_CLIENT,
            id,
            flow.sequence,
            &buffer[..size],
            encoded,
        )
        .map_err(|_| failure("protocol_error"))?;
        let _ = public.send_to(encoded, flow.peer);
        flow.active = Instant::now();
        Ok(())
    }
    pub(crate) fn serve(directory: &str) -> Result<()> {
        initialize()?;
        nonblocking(libc::STDOUT_FILENO)?;
        let mut control = Control::new()?;
        let mut request = control.initial()?;
        let host = validate_request(&request, true)?;
        let encoded = match request
            .as_object_mut()
            .and_then(|v| v.remove("session_key"))
        {
            Some(Value::String(value)) => value,
            _ => return Err(failure("protocol_error")),
        };
        let mut encoded = crate::gateway::SecretBytes(encoded.into_bytes());
        let mut bytes = crate::gateway::SecretBytes(
            STANDARD
                .decode(&encoded.0)
                .map_err(|_| failure("protocol_error"))?,
        );
        // STANDARD requires canonical padding and zero trailing bits.
        if bytes.0.len() != 32 || encoded.0.len() != 44 {
            return Err(failure("protocol_error"));
        }
        let mut key = Secret([0; 32]);
        key.0.copy_from_slice(&bytes.0);
        crate::gateway::wipe(&mut bytes.0);
        crate::gateway::wipe(&mut encoded.0);
        let prepared = prepare(directory, &request, Some(&mut control))?;
        control.startup()?;
        prepared.pin.check(true)?;
        let public = UdpSocket::bind((host, 0)).map_err(|_| failure("connectivity_uncertain"))?;
        public
            .set_nonblocking(true)
            .map_err(|_| failure("security_error"))?;
        let port = public.local_addr().map_err(|_| failure("unknown"))?.port();
        if port < 1024 {
            return Err(failure("security_error"));
        }
        let reservation =
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|_| failure("unknown"))?;
        let native_port = reservation
            .local_addr()
            .map_err(|_| failure("unknown"))?
            .port();
        drop(reservation);
        let mut command = prepared.pin.command()?;
        command
            .args([
                "remote",
                "serve",
                "--user",
                "--listen",
                &format!("127.0.0.1:{native_port}"),
                "--state-dir",
            ])
            .arg(&prepared.native)
            .arg("--authorized-keys")
            .arg(&prepared.authorized)
            .args(["--no-iroh", "--relay", "none", "--pkarr", "none"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = OwnedChild::spawn(command)?;
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            control.startup()?;
            prepared.pin.check(false)?;
            if child
                .0
                .try_wait()
                .map_err(|_| failure("frontend_exit"))?
                .is_some()
            {
                return Err(failure("frontend_exit"));
            }
            if crate::discovery::linux::udp_listeners(child.0.id())?
                .iter()
                .any(|v| v.port == native_port && v.address == "127.0.0.1")
            {
                break;
            }
            if Instant::now() >= deadline {
                return Err(failure("connectivity_uncertain"));
            }
            thread::sleep(Duration::from_millis(50));
        }
        prepared.pin.check(true)?;
        let mut descriptor = prepared.descriptor.clone();
        descriptor["host"] = json!(host.to_string());
        descriptor["port"] = json!(port);
        descriptor["native_frontend_pid"] = json!(child.0.id());
        emit(&descriptor)?;
        let mut heartbeat = Instant::now();
        let mut check = heartbeat;
        let mut probe = heartbeat;
        let mut flows = FlowTable::new();
        let mut fds = Vec::with_capacity(18);
        let mut ids = Vec::with_capacity(16);
        let mut incoming = vec![0u8; protocol::MAX_FRAME + 1];
        let mut reply_buffer = vec![0u8; protocol::MAX_PAYLOAD + 1];
        let mut encoded = Vec::with_capacity(protocol::MAX_FRAME);
        loop {
            interrupted()?;
            if child
                .0
                .try_wait()
                .map_err(|_| failure("frontend_exit"))?
                .is_some()
            {
                return Err(failure("frontend_exit"));
            }
            let now = Instant::now();
            if now.duration_since(heartbeat) > Duration::from_secs(45) {
                return Err(failure("heartbeat_timeout"));
            }
            if now.duration_since(check) >= Duration::from_secs(1) {
                let responsive = now.duration_since(probe) >= Duration::from_secs(5);
                prepared.pin.check(responsive)?;
                if responsive {
                    probe = now;
                }
                check = now;
                flows.expire(now);
            }
            fds.clear();
            ids.clear();
            fds.push(libc::pollfd {
                fd: control.fd,
                events: libc::POLLIN | libc::POLLRDHUP,
                revents: 0,
            });
            fds.push(libc::pollfd {
                fd: public.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            });
            for id in &flows.active {
                if let Some(socket) = flows
                    .identities
                    .get(id)
                    .and_then(|flow| flow.socket.as_ref())
                {
                    ids.push(*id);
                    fds.push(libc::pollfd {
                        fd: socket.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    });
                }
            }
            let count = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 250) };
            if count < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(failure("unknown"));
            }
            // Terminal control events win over buffered pings and all UDP data.
            if fds[0].revents != 0 {
                for message in control.receive_ready(fds[0].revents)? {
                    if message == json!({"op":"stop"}) {
                        return Ok(());
                    }
                    if message != json!({"op":"ping"}) {
                        return Err(failure("protocol_error"));
                    }
                    heartbeat = Instant::now();
                    emit(&json!({"ok":true,"op":"pong"}))?;
                }
            }
            if fds[1].revents & libc::POLLIN != 0 {
                forward(&public, native_port, &key.0, &mut flows, &mut incoming)?;
            }
            for (index, id) in ids.iter().enumerate() {
                if fds[index + 2].revents & libc::POLLIN != 0 {
                    if let Some(flow) = flows.identities.get_mut(id) {
                        reply(&public, &key.0, *id, flow, &mut reply_buffer, &mut encoded)?;
                    }
                }
            }
        }
        // Stack ownership closes every flow, the public socket and the key;
        // OwnedChild only terminates the frontend it spawned, never pin.pid.
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        fn current() -> Value {
            json!({"version":2,"pid":42,"start_time":"1000","boot_id":"boot","daemon_socket":"/run/user/1000/daemon.sock","socket_device":2,"socket_inode":3,"executable_path":"/home/test/bin/tern","daemon_argv":["tern","daemon","--socket","/run/user/1000/daemon.sock"]})
        }
        fn legacy() -> Value {
            json!({"pid":42,"start_time":"1000","boot_id":"boot","daemon_socket":"/run/user/1000/daemon.sock","socket_device":2,"socket_inode":3,"exe_device":99,"exe_inode":10})
        }
        #[test]
        fn stable_binding_survives_inode_upgrade_but_not_workspace_change() {
            assert!(migration_required(&legacy(), &current()).unwrap());
            assert!(!migration_required(&current(), &current()).unwrap());
            for (field, value) in [
                ("pid", json!(43)),
                ("start_time", json!("1001")),
                ("boot_id", json!("other")),
                ("socket_inode", json!(4)),
                ("exe_inode", json!(true)),
                ("unexpected", json!(1)),
            ] {
                let mut saved = legacy();
                saved[field] = value;
                assert!(migration_required(&saved, &current()).is_err());
            }
            for (field, value) in [
                ("version", json!(2.0)),
                ("executable_path", json!("/other/tern")),
                ("daemon_argv", json!(["tern", "daemon"])),
            ] {
                let mut saved = current();
                saved[field] = value;
                assert!(migration_required(&saved, &current()).is_err());
            }
        }
        #[test]
        fn only_actual_deleted_executable_suffix_is_normalized() {
            assert_eq!(
                executable_path("/home/test/tern (deleted)", 0).unwrap(),
                PathBuf::from("/home/test/tern")
            );
            assert!(executable_path("/home/test/tern (deleted)", 1).is_err());
            assert!(executable_path("/home/test/tern (deleted) (deleted)", 0).is_err());
            assert!(executable_path("/home/test/not-tern", 1).is_err());
        }
        #[test]
        fn process_stat_handles_parentheses_in_command() {
            let mut fields = vec!["S", "42"];
            fields.extend(std::iter::repeat("0").take(17));
            fields.push("1234");
            assert_eq!(
                parse_stat(&format!("99 (tern (daemon)) {}", fields.join(" "))).unwrap(),
                ("1234".to_owned(), 42)
            );
            fields[0] = "Z";
            assert!(parse_stat(&format!("99 (tern) {}", fields.join(" "))).is_err());
        }
        #[test]
        fn inventory_requires_complete_original_workspace() {
            let value = json!({"sessions":[{"id":1,"tabs":[{"id":"t","blocks":[{"id":"p"}]}]}],"detached":[{"id":2}]});
            assert_eq!(inventory(&value).unwrap()["pane_ids"], json!(["2", "p"]));
            assert!(inventory(&json!({"sessions":[]})).is_err());
            assert!(inventory(&json!({"sessions":[{"id":"s","tabs":true}]})).is_err());
        }
        #[test]
        fn authentication_and_replay_precede_flow_allocation() {
            let public = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            public.set_nonblocking(true).unwrap();
            let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let native = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let mut flows = FlowTable::new();
            let mut buffer = vec![0u8; protocol::MAX_FRAME + 1];
            let mut packet = Vec::new();
            sender
                .send_to(b"bare-quic", public.local_addr().unwrap())
                .unwrap();
            forward(
                &public,
                native.local_addr().unwrap().port(),
                &[7; 32],
                &mut flows,
                &mut buffer,
            )
            .unwrap();
            assert!(flows.identities.is_empty());
            protocol::encode_into(
                &[7; 32],
                protocol::CLIENT_TO_SERVER,
                5,
                1,
                b"payload",
                &mut packet,
            )
            .unwrap();
            sender
                .send_to(&packet, public.local_addr().unwrap())
                .unwrap();
            forward(
                &public,
                native.local_addr().unwrap().port(),
                &[7; 32],
                &mut flows,
                &mut buffer,
            )
            .unwrap();
            assert_eq!(flows.identities.len(), 1);
            let old_peer = flows.identities[&5].peer;
            flows.expire(Instant::now() + Duration::from_secs(61));
            sender
                .send_to(&packet, public.local_addr().unwrap())
                .unwrap();
            forward(
                &public,
                native.local_addr().unwrap().port(),
                &[7; 32],
                &mut flows,
                &mut buffer,
            )
            .unwrap();
            assert!(flows.identities[&5].socket.is_none());
            assert_eq!(flows.identities[&5].peer, old_peer);
            assert!(flows.active.is_empty());
        }
        #[test]
        fn control_eof_and_partial_startup_are_fail_closed() {
            use std::io::Write;
            use std::os::unix::net::UnixStream;
            let (mut writer, reader) = UnixStream::pair().unwrap();
            let mut control = Control::from_fd(reader.as_raw_fd()).unwrap();
            writer.write_all(b"{\"op\":\"ping\"}\n").unwrap();
            assert_eq!(control.receive().unwrap(), vec![json!({"op":"ping"})]);
            writer.write_all(b"{").unwrap();
            assert_eq!(control.startup().unwrap_err().code, "protocol_error");
            // A concurrent fork in another test can transiently inherit this
            // descriptor until exec closes CLOEXEC copies. Shutdown establishes
            // actual socket EOF, independently of those inherited descriptors.
            writer.shutdown(std::net::Shutdown::Write).unwrap();
            drop(writer);
            assert_eq!(control.receive().unwrap_err().code, "control_eof");
        }
        #[test]
        fn terminal_control_events_preempt_buffered_ping() {
            use std::io::Write;
            use std::os::unix::net::UnixStream;
            let (mut writer, reader) = UnixStream::pair().unwrap();
            let mut control = Control::from_fd(reader.as_raw_fd()).unwrap();
            writer.write_all(b"{\"op\":\"ping\"}\n").unwrap();
            for terminal in [
                libc::POLLHUP,
                libc::POLLERR,
                libc::POLLNVAL,
                libc::POLLRDHUP,
            ] {
                assert_eq!(
                    control
                        .receive_ready(libc::POLLIN | terminal)
                        .unwrap_err()
                        .code,
                    "control_eof"
                );
            }
            // No terminal-event path consumed or acknowledged the buffered ping.
            assert_eq!(control.receive().unwrap(), vec![json!({"op":"ping"})]);
        }
        #[test]
        fn buffered_ping_and_write_shutdown_prevent_udp_forwarding() {
            use std::io::Write;
            use std::os::unix::net::UnixStream;
            let (mut writer, reader) = UnixStream::pair().unwrap();
            let mut control = Control::from_fd(reader.as_raw_fd()).unwrap();
            let public = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            public.set_nonblocking(true).unwrap();
            let native = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            native.set_nonblocking(true).unwrap();
            let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let packet =
                protocol::encode(&[7; 32], protocol::CLIENT_TO_SERVER, 5, 1, b"payload").unwrap();
            sender
                .send_to(&packet, public.local_addr().unwrap())
                .unwrap();
            writer.write_all(b"{\"op\":\"ping\"}\n").unwrap();
            writer.shutdown(std::net::Shutdown::Write).unwrap();
            let mut fds = [
                libc::pollfd {
                    fd: control.fd,
                    events: libc::POLLIN | libc::POLLRDHUP,
                    revents: 0,
                },
                libc::pollfd {
                    fd: public.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            assert!(unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 1000) } > 0);
            assert_ne!(fds[0].revents & libc::POLLIN, 0);
            assert_ne!(fds[0].revents & libc::POLLRDHUP, 0);
            assert_ne!(fds[1].revents & libc::POLLIN, 0);
            let mut flows = FlowTable::new();
            let mut incoming = vec![0; protocol::MAX_FRAME + 1];
            // Exercise the same control-before-data gate as the serving loop.
            let result = control.receive_ready(fds[0].revents).and_then(|_| {
                forward(
                    &public,
                    native.local_addr().unwrap().port(),
                    &[7; 32],
                    &mut flows,
                    &mut incoming,
                )
            });
            assert_eq!(result.unwrap_err().code, "control_eof");
            assert!(flows.identities.is_empty());
            assert_eq!(
                native.recv_from(&mut incoming).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            assert_eq!(control.receive().unwrap(), vec![json!({"op":"ping"})]);
        }
        #[test]
        fn owned_frontend_cleanup_does_not_signal_original_process() {
            let mut original = Command::new("/bin/sleep");
            original.arg("30");
            let mut original = OwnedChild::spawn(original).unwrap();
            let mut frontend = Command::new("/bin/sleep");
            frontend.arg("30");
            let frontend = OwnedChild::spawn(frontend).unwrap();
            let pid = frontend.0.id();
            drop(frontend);
            assert!(original.0.try_wait().unwrap().is_none());
            assert_eq!(
                unsafe { libc::waitpid(pid as libc::pid_t, std::ptr::null_mut(), libc::WNOHANG) },
                -1
            );
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ECHILD)
            );
        }
        #[test]
        fn flow_capacity_preserves_replay_after_idle_reclamation() {
            let public = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            public.set_nonblocking(true).unwrap();
            let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let native = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let mut flows = FlowTable::new();
            let mut buffer = vec![0; protocol::MAX_FRAME + 1];
            let mut encoded = Vec::new();
            for id in 0..17 {
                protocol::encode_into(
                    &[7; 32],
                    protocol::CLIENT_TO_SERVER,
                    id,
                    1,
                    b"x",
                    &mut encoded,
                )
                .unwrap();
                sender
                    .send_to(&encoded, public.local_addr().unwrap())
                    .unwrap();
                forward(
                    &public,
                    native.local_addr().unwrap().port(),
                    &[7; 32],
                    &mut flows,
                    &mut buffer,
                )
                .unwrap();
            }
            assert_eq!(flows.active.len(), 16);
            assert_eq!(flows.identities.len(), 17);
            assert!(flows.identities[&16].socket.is_none());
            flows.expire(Instant::now() + Duration::from_secs(61));
            assert!(flows.active.is_empty());
            sender
                .send_to(&encoded, public.local_addr().unwrap())
                .unwrap();
            forward(
                &public,
                native.local_addr().unwrap().port(),
                &[7; 32],
                &mut flows,
                &mut buffer,
            )
            .unwrap();
            assert!(flows.active.is_empty());
            protocol::encode_into(
                &[7; 32],
                protocol::CLIENT_TO_SERVER,
                16,
                2,
                b"x",
                &mut encoded,
            )
            .unwrap();
            sender
                .send_to(&encoded, public.local_addr().unwrap())
                .unwrap();
            forward(
                &public,
                native.local_addr().unwrap().port(),
                &[7; 32],
                &mut flows,
                &mut buffer,
            )
            .unwrap();
            assert_eq!(flows.active, vec![16]);
            let peer = sender.local_addr().unwrap();
            for id in 17..4096 {
                flows.identities.insert(
                    id,
                    Flow {
                        replay: Replay::default(),
                        sequence: 0,
                        peer,
                        socket: None,
                        active: Instant::now(),
                    },
                );
            }
            protocol::encode_into(
                &[7; 32],
                protocol::CLIENT_TO_SERVER,
                4096,
                1,
                b"x",
                &mut encoded,
            )
            .unwrap();
            sender
                .send_to(&encoded, public.local_addr().unwrap())
                .unwrap();
            forward(
                &public,
                native.local_addr().unwrap().port(),
                &[7; 32],
                &mut flows,
                &mut buffer,
            )
            .unwrap();
            assert_eq!(flows.identities.len(), 4096);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_json_rejects_duplicate_and_trailing_input() {
        assert!(parse_json(br#"{"pid":1,"pid":1}"#).is_err());
        assert!(parse_json(br#"{"nested":{"key":1,"key":2}}"#).is_err());
        assert!(parse_json(b"{}{}").is_err());
        assert_eq!(parse_json(b"{\"version\":2}").unwrap()["version"], 2);
    }
}
