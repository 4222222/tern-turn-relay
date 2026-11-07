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
                "rebind-review" | "rebind-apply" => {
                    let directory = directory.ok_or_else(|| failure("protocol_error"))?;
                    let request = common::read_json_stdin(65536)
                        .map_err(|_| failure("protocol_error"))?;
                    if operation == "rebind-review" {
                        linux::rebind_review(&directory, &request)
                    } else {
                        linux::rebind_apply(&directory, &request)
                    }
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
            control: Option<&mut Control>,
            maximum: usize,
        ) -> Result<Value> {
            parse_json(&self.capture_output(args, control, maximum)?)
        }
        fn capture_output(
            &self,
            args: &[String],
            mut control: Option<&mut Control>,
            maximum: usize,
        ) -> Result<Vec<u8>> {
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
                    return Ok(bytes);
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
        if saved.get("version").is_some() {
            let socket = current["daemon_socket"].as_str()
                .ok_or_else(|| failure("identity_mismatch"))?;
            validate_rebind_record(saved, socket)?;
            validate_rebind_record(current, socket)?;
            if stable.iter().any(|field| saved[*field] != current[*field])
                || saved["executable_path"] != current["executable_path"]
            {
                return Err(failure("identity_mismatch"));
            }
            // An in-place exec keeps the authenticated process and socket alive.
            // Reversing the existing strict removal check permits only one new
            // canonical --handoff pair; all other arguments must remain exact.
            compatible_rebind_argv(current, saved)?;
            return Ok(true);
        }
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

    fn exact_fields(value: &Value, fields: &[&str]) -> Result<()> {
        let object = value.as_object().ok_or_else(|| failure("protocol_error"))?;
        if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
            return Err(failure("protocol_error"));
        }
        Ok(())
    }
    fn validate_rebind_request(request: &Value) -> Result<()> {
        exact_fields(request, &["daemon_socket", "bind_host", "original_state_dir", "original_fingerprint", "gateway_fingerprint"])?;
        let mut prepared = request.clone();
        prepared.as_object_mut().unwrap().remove("original_state_dir");
        validate_request(&prepared, false)?;
        for field in ["daemon_socket", "original_state_dir"] {
            path(request[field].as_str().ok_or_else(|| failure("protocol_error"))?)?;
        }
        if request["original_fingerprint"] == request["gateway_fingerprint"] {
            return Err(failure("identity_mismatch"));
        }
        Ok(())
    }
    fn validate_rebind_record(record: &Value, socket: &str) -> Result<()> {
        exact_fields(record, &["version", "pid", "start_time", "boot_id", "daemon_socket", "socket_device", "socket_inode", "executable_path", "daemon_argv"])
            .map_err(|_| failure("identity_mismatch"))?;
        let start = record["start_time"].as_str().unwrap_or("");
        let boot = record["boot_id"].as_str().unwrap_or("");
        if record["version"].as_u64() != Some(2)
            || !record["pid"].as_u64().is_some_and(|v| (2..=i32::MAX as u64).contains(&v))
            || !start.parse::<u64>().is_ok_and(|v| v > 0 && v.to_string() == start)
            || boot.len() != 36
            || !boot.bytes().enumerate().all(|(i, b)| if [8, 13, 18, 23].contains(&i) { b == b'-' } else { b.is_ascii_hexdigit() && !b.is_ascii_uppercase() })
            || record["daemon_socket"] != socket
            || record["socket_device"].as_u64().is_none()
            || record["socket_inode"].as_u64().unwrap_or(0) == 0
        {
            return Err(failure("identity_mismatch"));
        }
        path(socket)?;
        let executable = record["executable_path"].as_str().ok_or_else(|| failure("identity_mismatch"))?;
        executable_path(executable, 1)?;
        let args = record["daemon_argv"].as_array().ok_or_else(|| failure("identity_mismatch"))?;
        if args.is_empty() || args.len() > 256
            || args.iter().any(|v| v.as_str().is_none_or(|s| s.is_empty() || s.len() > 8192 || s.bytes().any(|b| b == 0 || b.is_ascii_control())))
            || (args[0] != "tern" && args[0] != executable)
            || args.iter().filter(|v| v.as_str() == Some("daemon")).count() != 1
            || args.iter().filter(|v| v.as_str() == Some("--socket")).count() != 1
            || !args.windows(2).any(|v| v[0] == "--socket" && v[1] == socket)
        {
            return Err(failure("identity_mismatch"));
        }
        Ok(())
    }
    fn compatible_rebind_argv(old: &Value, new: &Value) -> Result<()> {
        let old = old["daemon_argv"].as_array().ok_or_else(|| failure("identity_mismatch"))?;
        let new = new["daemon_argv"].as_array().ok_or_else(|| failure("identity_mismatch"))?;
        if old == new {
            return Ok(());
        }
        // A completed handoff is a one-shot startup argument, not a different
        // workspace. Permit only its removal; every other argument stays exact.
        // Keep both unmodified argv arrays in the review for apply-time checks.
        let handoff = old.iter().position(|v| v.as_str() == Some("--handoff"))
            .ok_or_else(|| failure("identity_mismatch"))?;
        if old.iter().filter(|v| v.as_str() == Some("--handoff")).count() != 1
            || new.iter().any(|v| v.as_str() == Some("--handoff"))
            || handoff + 1 >= old.len()
            || old.len() != new.len() + 2
        {
            return Err(failure("identity_mismatch"));
        }
        path(old[handoff + 1].as_str().ok_or_else(|| failure("identity_mismatch"))?)?;
        if !old[..handoff].iter().chain(old[handoff + 2..].iter()).eq(new.iter()) {
            return Err(failure("identity_mismatch"));
        }
        Ok(())
    }
    fn rebind_directory(directory: &str) -> Result<PathBuf> {
        let directory = path(directory)?;
        common::private_dir(&directory, false).map_err(|_| failure("security_error"))?;
        ancestors(&directory)?;
        Ok(directory)
    }
    fn rebind_lock(directory: &Path) -> Result<File> {
        // Opening the existing lock read-only keeps review strictly non-mutating.
        // flock uses the same inode and exclusion as prepare's common::lock.
        let file = regular(&directory.join("control.lock"), true)?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = std::io::Error::last_os_error();
            return Err(failure(if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
                "state_lock_busy"
            } else {
                "security_error"
            }));
        }
        Ok(file)
    }
    fn rebind_pin(directory: &Path) -> Result<Value> {
        common::read_json(&directory.join("daemon-identity.json"), true)
            .map_err(|_| failure("security_error"))
    }
    fn rebind_backup(directory: &Path, old: &Value) -> Result<PathBuf> {
        use sha2::{Digest, Sha256};
        let bytes = serde_json::to_vec(old).map_err(|_| failure("protocol_error"))?;
        Ok(directory.join(format!("daemon-identity.backup-{}.json", hex::encode(Sha256::digest(bytes)))))
    }
    fn old_daemon_absent(old: &Value, new: &Value) -> Result<()> {
        if old["boot_id"] != new["boot_id"] {
            return Ok(());
        }
        let pid = old["pid"].as_u64().ok_or_else(|| failure("identity_mismatch"))?;
        let proc = PathBuf::from(format!("/proc/{pid}"));
        match fs::symlink_metadata(&proc) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(failure("identity_mismatch")),
            Ok(_) => {}
        }
        let raw = bounded(&proc.join("stat"), 8192)?;
        let text = std::str::from_utf8(&raw).map_err(|_| failure("identity_mismatch"))?;
        let fields: Vec<_> = text.rsplit_once(')').ok_or_else(|| failure("identity_mismatch"))?.1.split_whitespace().collect();
        if fields.len() < 20 || fields[19].parse::<u64>().is_err() {
            return Err(failure("identity_mismatch"));
        }
        if fields[19] == old["start_time"].as_str().unwrap_or("") && !["Z", "X"].contains(&fields[0]) {
            // Even if it lost its socket, never replace another live old daemon.
            return Err(failure("identity_mismatch"));
        }
        Ok(())
    }
    fn identity_files(state: &Path, private: bool) -> Result<(Value, Vec<[u8; 32]>)> {
        use sha2::{Digest, Sha256};
        if private {
            common::private_dir(state, false).map_err(|_| failure("security_error"))?;
        } else {
            // Original Tern state may expose its public certificate, but its
            // directory must still be owned by this account and not writable
            // by others. Never chmod or otherwise modify original state.
            let info = fs::symlink_metadata(state).map_err(|_| failure("security_error"))?;
            if !info.is_dir() || info.uid() != uid() || info.mode() & 0o022 != 0 {
                return Err(failure("security_error"));
            }
        }
        ancestors(state)?;
        let mut files = Vec::with_capacity(2);
        let mut digests = Vec::with_capacity(2);
        for name in ["host_key", "host_cert.der"] {
            let mut file = regular(&state.join(name), private || name == "host_key")?;
            let info = file.metadata().map_err(|_| failure("security_error"))?;
            if info.len() == 0 || info.len() > 65536 {
                return Err(failure("identity_mismatch"));
            }
            let mut digest = Sha256::new();
            let mut buffer = [0u8; 4096];
            let mut total = 0;
            loop {
                let count = match file.read(&mut buffer) {
                    Ok(count) => count,
                    Err(_) => {
                        crate::gateway::wipe(&mut buffer);
                        return Err(failure("security_error"));
                    }
                };
                if count == 0 { break; }
                total += count;
                if total > 65536 {
                    crate::gateway::wipe(&mut buffer);
                    return Err(failure("security_error"));
                }
                digest.update(&buffer[..count]);
                crate::gateway::wipe(&mut buffer);
            }
            let after = file.metadata().map_err(|_| failure("security_error"))?;
            let metadata = |m: &Metadata| json!({"device":m.dev(),"inode":m.ino(),"size":m.len(),"mtime":m.mtime(),"mtime_ns":m.mtime_nsec(),"ctime":m.ctime(),"ctime_ns":m.ctime_nsec()});
            if total as u64 != info.len() || metadata(&after) != metadata(&info) {
                return Err(failure("identity_mismatch"));
            }
            files.push(metadata(&info));
            digests.push(digest.finalize().into());
        }
        Ok((json!(files), digests))
    }
    fn existing_fingerprint(pin: &DaemonPin, state: &Path, private: bool) -> Result<(String, Value)> {
        // Never invoke host-key for absent, empty, linked, or unsafe files.
        // The existing native command remains the authority for key/cert format.
        let before = identity_files(state, private)?;
        let response = pin.capture(&["remote".into(), "host-key".into(), "--state-dir".into(), state.to_str().ok_or_else(|| failure("security_error"))?.into()], None, 65536)?;
        let fingerprint = response["fingerprint"].as_str().ok_or_else(|| failure("protocol_error"))?;
        common::fingerprint(fingerprint).map_err(|_| failure("protocol_error"))?;
        if identity_files(state, private)? != before {
            return Err(failure("identity_mismatch"));
        }
        Ok((fingerprint.to_owned(), before.0))
    }
    fn rebind_snapshot(directory: &Path, request: &Value, old: &Value) -> Result<(Value, DaemonPin)> {
        validate_rebind_request(request)?;
        let socket = request["daemon_socket"].as_str().unwrap();
        validate_rebind_record(old, socket)?;
        let pin = DaemonPin::new(socket)?;
        let new = pin.record();
        validate_rebind_record(&new, socket)?;
        if old == &new || old["executable_path"] != new["executable_path"] {
            return Err(failure("identity_mismatch"));
        }
        compatible_rebind_argv(old, &new)?;
        old_daemon_absent(old, &new)?;
        let original = path(request["original_state_dir"].as_str().unwrap())?;
        if original.starts_with(directory) || directory.starts_with(&original) {
            return Err(failure("security_error"));
        }
        let native = directory.join("native");
        native_tree(&native)?;
        // Validate both existing identities before either native command runs.
        identity_files(&native, true)?;
        identity_files(&original, false)?;
        let (gateway_fingerprint, gateway_files) = existing_fingerprint(&pin, &native, true)?;
        let (original_fingerprint, original_files) = existing_fingerprint(&pin, &original, false)?;
        if gateway_fingerprint != request["gateway_fingerprint"]
            || original_fingerprint != request["original_fingerprint"]
            || identity_files(&native, true)?.0 != gateway_files
            || identity_files(&original, false)?.0 != original_files
        {
            return Err(failure("identity_mismatch"));
        }
        pin.check(true)?;
        let review = json!({"version":1,"state_dir":directory,"request":request,"old_identity":old,"new_identity":new,"gateway_fingerprint":gateway_fingerprint,"identity_files":{"gateway":gateway_files,"original":original_files},"backup_path":rebind_backup(directory, old)?});
        Ok((review, pin))
    }
    pub(crate) fn rebind_review(directory: &str, request: &Value) -> Result<Value> {
        validate_rebind_request(request)?;
        let directory = rebind_directory(directory)?;
        let _lock = rebind_lock(&directory)?;
        let old = rebind_pin(&directory)?;
        let (review, _) = rebind_snapshot(&directory, request, &old)?;
        Ok(json!({"ok":true,"review":review}))
    }
    fn preserve_rebind_backup(backup: &Path, old: &Value) -> Result<()> {
        use std::io::Write;
        let parent = backup.parent().ok_or_else(|| failure("security_error"))?;
        common::private_dir(parent, false).map_err(|_| failure("security_error"))?;
        ancestors(parent)?;
        match OpenOptions::new().write(true).create_new(true).mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(backup)
        {
            Ok(mut file) => {
                // Never overwrite an earlier backup, including an incomplete one.
                serde_json::to_writer(&mut file, old).map_err(|_| failure("security_error"))?;
                file.write_all(b"\n").map_err(|_| failure("security_error"))?;
                file.sync_all().map_err(|_| failure("security_error"))?;
                File::open(parent).and_then(|directory| directory.sync_all())
                    .map_err(|_| failure("security_error"))?;
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if common::read_json(backup, true).map_err(|_| failure("security_error"))? != *old {
                    return Err(failure("identity_mismatch"));
                }
                regular(backup, true)?.sync_all().map_err(|_| failure("security_error"))?;
                File::open(parent).and_then(|directory| directory.sync_all())
                    .map_err(|_| failure("security_error"))?;
                Ok(())
            }
            Err(_) => Err(failure("security_error")),
        }
    }
    // Only a caller-confirmed, byte-for-byte-equivalent JSON value may change
    // the pin (object key ordering is irrelevant). Version-2 pins only: legacy
    // inode-only records cannot establish the reviewed executable/argv binding.
    // A retry requires the original review, unchanged live/file identities, the
    // new pin, and its matching private backup. Incomplete/conflicting backups
    // fail closed and are never overwritten or automatically removed.
    pub(crate) fn rebind_apply(directory: &str, input: &Value) -> Result<Value> {
        exact_fields(input, &["review", "confirm"])?;
        if input["confirm"] != true {
            return Err(failure("protocol_error"));
        }
        let review = &input["review"];
        exact_fields(review, &["version", "state_dir", "request", "old_identity", "new_identity", "gateway_fingerprint", "identity_files", "backup_path"])?;
        if review["version"].as_u64() != Some(1) || review["state_dir"] != directory {
            return Err(failure("identity_mismatch"));
        }
        let directory = rebind_directory(directory)?;
        let _lock = rebind_lock(&directory)?;
        let old = &review["old_identity"];
        let (fresh, pin) = rebind_snapshot(&directory, &review["request"], old)?;
        if fresh != *review {
            return Err(failure("identity_mismatch"));
        }
        let saved = rebind_pin(&directory)?;
        let backup = rebind_backup(&directory, old)?;
        let already_applied = saved == review["new_identity"];
        if already_applied {
            if common::read_json(&backup, true).map_err(|_| failure("security_error"))? != *old {
                return Err(failure("identity_mismatch"));
            }
        } else {
            if saved != *old {
                return Err(failure("identity_mismatch"));
            }
            preserve_rebind_backup(&backup, old)?;
            // Re-review all public identities after durable backup and immediately
            // before mutation. A failed retry leaves both original pin and backup.
            if rebind_snapshot(&directory, &review["request"], old)?.0 != *review
                || rebind_pin(&directory)? != *old
            {
                return Err(failure("identity_mismatch"));
            }
            pin.check(true)?;
            common::atomic_json(&directory.join("daemon-identity.json"), &review["new_identity"])
                .map_err(|_| failure("security_error"))?;
        }
        Ok(json!({"ok":true,"applied":true,"already_applied":already_applied,"backup_path":backup,"daemon_identity":review["new_identity"],"gateway_fingerprint":review["gateway_fingerprint"]}))
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
    fn frontend_relay_args(version: &[u8]) -> Result<&'static [&'static str]> {
        let text = std::str::from_utf8(version).map_err(|_| failure("protocol_error"))?;
        let mut words = text.split_whitespace();
        if words.next() != Some("tern") {
            return Err(failure("protocol_error"));
        }
        let mut parts = words.next().ok_or_else(|| failure("protocol_error"))?.split('.');
        let mut numbers = [0u64; 3];
        for number in &mut numbers {
            let part = parts.next().ok_or_else(|| failure("protocol_error"))?;
            if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                return Err(failure("protocol_error"));
            }
            *number = part.parse().map_err(|_| failure("protocol_error"))?;
        }
        if parts.next().is_some() {
            return Err(failure("protocol_error"));
        }
        if numbers >= [0, 9, 12] {
            Ok(&["--relay", "none"])
        } else {
            Ok(&["--no-iroh", "--relay", "none", "--pkarr", "none"])
        }
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
        let version = prepared.pin.capture_output(
            &["--version".into()], Some(&mut control), 256,
        )?;
        let relay_args = frontend_relay_args(&version)?;
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
            .args(relay_args)
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
        #[test]
        fn frontend_version_selects_supported_relay_isolation() {
            assert_eq!(frontend_relay_args(b"tern 0.9.8 (f21d9a3)\n").unwrap(),
                &["--no-iroh", "--relay", "none", "--pkarr", "none"]);
            assert_eq!(frontend_relay_args(b"tern 0.9.12 (e498b49)\n").unwrap(),
                &["--relay", "none"]);
            assert_eq!(frontend_relay_args(b"tern 0.10.0 (build)\n").unwrap(),
                &["--relay", "none"]);
            for version in [b"".as_slice(), b"other 0.9.12", b"tern 0.9", b"tern 0.9.12.1",
                b"tern 0.9.12-dev", b"tern 0.-9.12", b"tern 0.9.18446744073709551616", b"tern \xff"] {
                assert!(frontend_relay_args(version).is_err());
            }
        }
        fn current() -> Value {
            json!({"version":2,"pid":42,"start_time":"1000","boot_id":"00000000-0000-4000-8000-000000000001","daemon_socket":"/run/user/1000/daemon.sock","socket_device":2,"socket_inode":3,"executable_path":"/home/test/bin/tern","daemon_argv":["tern","daemon","--socket","/run/user/1000/daemon.sock"]})
        }
        fn legacy() -> Value {
            json!({"pid":42,"start_time":"1000","boot_id":"00000000-0000-4000-8000-000000000001","daemon_socket":"/run/user/1000/daemon.sock","socket_device":2,"socket_inode":3,"exe_device":99,"exe_inode":10})
        }
        #[test]
        fn rebind_requires_explicit_confirmation_and_strict_schema() {
            let request = json!({"daemon_socket":"/run/user/1000/daemon.sock","bind_host":"8.8.8.8","original_state_dir":"/home/test/original","original_fingerprint":format!("SHA256:{}", "A".repeat(43)),"gateway_fingerprint":format!("SHA256:{}", "B".repeat(42) + "A")});
            assert!(validate_rebind_request(&request).is_ok());
            let mut extra = request.clone();
            extra["unexpected"] = json!(true);
            assert!(validate_rebind_request(&extra).is_err());
            let mut same_fingerprint = request.clone();
            same_fingerprint["gateway_fingerprint"] = request["original_fingerprint"].clone();
            assert!(validate_rebind_request(&same_fingerprint).is_err());
            let mut missing = request.clone();
            missing.as_object_mut().unwrap().remove("gateway_fingerprint");
            assert!(validate_rebind_request(&missing).is_err());
            assert!(rebind_apply("/missing", &json!({"review":{},"confirm":false})).is_err());
            assert!(rebind_apply("/missing", &json!({"review":{},"confirm":true,"extra":0})).is_err());
            assert!(rebind_apply("/missing", &json!({"review":{}})).is_err());
            assert!(validate_rebind_record(&current(), "/run/user/1000/daemon.sock").is_ok());
            assert!(validate_rebind_record(&legacy(), "/run/user/1000/daemon.sock").is_err());
            for (field, value) in [("version", json!(3)), ("pid", json!(0)), ("start_time", json!("bad")), ("boot_id", json!("bad")), ("socket_inode", json!(0)), ("extra", json!(0)), ("executable_path", json!("/other/../tern"))] {
                let mut record = current();
                record[field] = value;
                assert!(validate_rebind_record(&record, "/run/user/1000/daemon.sock").is_err(), "{field}");
            }
            let mut replacement = current();
            replacement["pid"] = json!(43);
            assert!(migration_required(&current(), &replacement).is_err());
        }
        #[test]
        fn rebind_allows_only_completed_handoff_argument_removal() {
            let mut old = current();
            old["daemon_argv"] = json!(["tern", "daemon", "--socket", "/run/user/1000/daemon.sock", "--handoff", "/home/test/.local/state/tern/daemon.state.handoff"]);
            let new = current();
            assert!(compatible_rebind_argv(&old, &new).is_ok());
            assert!(compatible_rebind_argv(&new, &new).is_ok());
            assert!(compatible_rebind_argv(&new, &old).is_err());
            for args in [
                json!(["tern", "daemon", "--socket", "/run/user/1000/daemon.sock", "--handoff", "relative"]),
                json!(["tern", "daemon", "--socket", "/run/user/1000/daemon.sock", "--handoff", "/home/test/../daemon.state.handoff"]),
                json!(["tern", "daemon", "--socket", "/run/user/1000/daemon.sock", "--handoff"]),
                json!(["tern", "daemon", "--socket", "/run/user/1000/daemon.sock", "--handoff", "/home/test/state", "--handoff", "/home/test/state"]),
                json!(["tern", "daemon", "--socket", "/run/user/1000/daemon.sock", "--unsafe", "--handoff", "/home/test/state"]),
            ] {
                old["daemon_argv"] = args;
                assert!(compatible_rebind_argv(&old, &new).is_err());
            }
        }
        struct RebindFixture(PathBuf);
        impl RebindFixture {
            fn new() -> Self {
                let path = account().unwrap().1.join(format!(".tern-rebind-test-{:032x}", rand::random::<u128>()));
                common::private_dir(&path, true).unwrap();
                Self(path)
            }
            fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
                use std::io::Write;
                let path = self.0.join(name);
                let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path).unwrap();
                file.write_all(bytes).unwrap();
                path
            }
        }
        impl Drop for RebindFixture {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        #[test]
        fn rebind_review_never_creates_missing_state_or_lock() {
            let fixture = RebindFixture::new();
            let request = json!({"daemon_socket":"/run/user/1000/daemon.sock","bind_host":"8.8.8.8","original_state_dir":"/home/test/original","original_fingerprint":format!("SHA256:{}", "A".repeat(43)),"gateway_fingerprint":format!("SHA256:{}", "B".repeat(42) + "A")});
            assert!(rebind_review(fixture.0.join("absent").to_str().unwrap(), &request).is_err());
            assert!(rebind_review(fixture.0.to_str().unwrap(), &request).is_err());
            assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 0);
            let lock = common::lock(&fixture.0.join("control.lock"), true).unwrap();
            let error = rebind_review(fixture.0.to_str().unwrap(), &request).unwrap_err();
            assert_eq!(error.code, "state_lock_busy");
            drop(lock);
            assert!(rebind_lock(&fixture.0).is_ok());
        }
        #[test]
        fn rebind_saved_pin_rejects_public_linked_and_duplicate_records() {
            use std::os::unix::fs::{symlink, PermissionsExt};
            let fixture = RebindFixture::new();
            let pin = fixture.0.join("daemon-identity.json");
            common::atomic_json(&pin, &current()).unwrap();
            assert_eq!(rebind_pin(&fixture.0).unwrap(), current());
            fs::set_permissions(&pin, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(rebind_pin(&fixture.0).is_err());
            fs::set_permissions(&pin, fs::Permissions::from_mode(0o600)).unwrap();
            let linked = fixture.0.join("linked.json");
            fs::hard_link(&pin, &linked).unwrap();
            assert!(rebind_pin(&fixture.0).is_err());
            fs::remove_file(&linked).unwrap();
            fs::write(&pin, b"{\"pid\":42,\"pid\":43}").unwrap();
            assert!(rebind_pin(&fixture.0).is_err());
            fs::rename(&pin, &linked).unwrap();
            symlink(&linked, &pin).unwrap();
            assert!(rebind_pin(&fixture.0).is_err());
        }
        #[test]
        fn rebind_backup_is_private_immutable_and_retryable() {
            use std::os::unix::fs::{symlink, PermissionsExt};
            let fixture = RebindFixture::new();
            let old = current();
            let backup = rebind_backup(&fixture.0, &old).unwrap();
            preserve_rebind_backup(&backup, &old).unwrap();
            let before = fs::metadata(&backup).unwrap();
            assert_eq!(before.mode() & 0o777, 0o600);
            assert_eq!(common::read_json(&backup, true).unwrap(), old);
            preserve_rebind_backup(&backup, &old).unwrap();
            assert_eq!(fs::metadata(&backup).unwrap().ino(), before.ino());
            let mut other = old.clone();
            other["pid"] = json!(43);
            assert!(preserve_rebind_backup(&backup, &other).is_err());
            assert_eq!(common::read_json(&backup, true).unwrap(), old);
            fs::set_permissions(&backup, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(preserve_rebind_backup(&backup, &old).is_err());
            fs::set_permissions(&backup, fs::Permissions::from_mode(0o600)).unwrap();
            let link = fixture.0.join("backup-link.json");
            symlink(&backup, &link).unwrap();
            assert!(preserve_rebind_backup(&link, &old).is_err());
            let hard_link = fixture.0.join("backup-hard-link.json");
            fs::hard_link(&backup, &hard_link).unwrap();
            assert!(preserve_rebind_backup(&backup, &old).is_err());
            fs::remove_file(&hard_link).unwrap();
            let partial = fixture.file("partial.json", b"{\"version\":");
            assert!(preserve_rebind_backup(&partial, &old).is_err());
            assert_eq!(fs::read(partial).unwrap(), b"{\"version\":");
        }
        #[test]
        fn rebind_identity_files_fail_closed_without_generating_keys() {
            use std::os::unix::fs::{symlink, PermissionsExt};
            let fixture = RebindFixture::new();
            assert!(identity_files(&fixture.0, true).is_err());
            assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 0);
            let key = fixture.file("host_key", b"existing private key");
            assert!(identity_files(&fixture.0, true).is_err());
            let cert = fixture.file("host_cert.der", b"existing certificate");
            let before = identity_files(&fixture.0, true).unwrap();
            assert_eq!(before.0.as_array().unwrap().len(), 2);
            assert!(!before.0.to_string().contains("private key"));
            fs::write(&key, b"modified private key").unwrap();
            assert_ne!(identity_files(&fixture.0, true).unwrap(), before);
            fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(identity_files(&fixture.0, true).is_err());
            fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
            fs::remove_file(&cert).unwrap();
            symlink(&key, &cert).unwrap();
            assert!(identity_files(&fixture.0, true).is_err());
        }
        #[test]
        fn rebind_original_identity_allows_public_certificate_not_public_key() {
            use std::os::unix::fs::{symlink, PermissionsExt};
            let fixture = RebindFixture::new();
            let key = fixture.file("host_key", b"existing private key");
            let cert = fixture.file("host_cert.der", b"existing public certificate");
            fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o755)).unwrap();
            fs::set_permissions(&cert, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(identity_files(&fixture.0, false).is_ok());
            assert_eq!(fs::metadata(&fixture.0).unwrap().mode() & 0o777, 0o755);
            assert_eq!(fs::metadata(&key).unwrap().mode() & 0o777, 0o600);
            assert_eq!(fs::metadata(&cert).unwrap().mode() & 0o777, 0o644);
            assert!(identity_files(&fixture.0, true).is_err());
            fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o700)).unwrap();
            assert!(identity_files(&fixture.0, true).is_err());
            fs::set_permissions(&cert, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(identity_files(&fixture.0, true).is_ok());
            fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o775)).unwrap();
            assert!(identity_files(&fixture.0, false).is_err());
            fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o755)).unwrap();
            fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(identity_files(&fixture.0, false).is_err());
            fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
            fs::set_permissions(&cert, fs::Permissions::from_mode(0o666)).unwrap();
            assert!(identity_files(&fixture.0, false).is_err());
            fs::set_permissions(&cert, fs::Permissions::from_mode(0o644)).unwrap();
            let linked = fixture.0.join("cert-link");
            fs::hard_link(&cert, &linked).unwrap();
            assert!(identity_files(&fixture.0, false).is_err());
            fs::remove_file(&linked).unwrap();
            if uid() == 0 {
                // The remote root test runner can exercise actual foreign owners.
                for target in [&key, &cert, &fixture.0] {
                    let target = CString::new(target.as_os_str().as_bytes()).unwrap();
                    assert_eq!(unsafe { libc::chown(target.as_ptr(), 1, !0) }, 0);
                    assert!(identity_files(&fixture.0, false).is_err());
                    assert_eq!(unsafe { libc::chown(target.as_ptr(), uid(), !0) }, 0);
                }
            }
            fs::remove_file(&cert).unwrap();
            symlink(&key, &cert).unwrap();
            assert!(identity_files(&fixture.0, false).is_err());
        }
        #[test]
        fn rebind_refuses_old_process_even_after_socket_disappears() {
            let pid = std::process::id();
            let mut old = current();
            old["pid"] = json!(pid);
            old["start_time"] = json!(process_stat(pid).unwrap().0);
            let mut new = old.clone();
            new["pid"] = json!(pid + 1);
            assert!(old_daemon_absent(&old, &new).is_err());
            old["start_time"] = json!("1");
            assert!(old_daemon_absent(&old, &new).is_ok());
            old["start_time"] = new["start_time"].clone();
            old["boot_id"] = json!("previous-boot");
            assert!(old_daemon_absent(&old, &new).is_ok());
        }

        #[test]
        fn same_process_handoff_upgrade_preserves_binding_boundaries() {
            let saved = current();
            let mut upgraded = saved.clone();
            upgraded["daemon_argv"] = json!(["tern", "daemon", "--socket", "/run/user/1000/daemon.sock",
                "--handoff", "/home/test/.local/state/tern/daemon.state.handoff"]);
            assert!(migration_required(&saved, &upgraded).unwrap());
            assert!(!migration_required(&upgraded, &upgraded).unwrap());
            for (field, value) in [
                ("pid", json!(43)), ("start_time", json!("1001")),
                ("boot_id", json!("00000000-0000-4000-8000-000000000002")),
                ("socket_device", json!(3)), ("socket_inode", json!(4)),
                ("daemon_socket", json!("/run/user/1000/other.sock")),
                ("executable_path", json!("/other/tern")), ("unexpected", json!(true)),
            ] {
                let mut changed = upgraded.clone();
                changed[field] = value;
                assert!(migration_required(&saved, &changed).is_err(), "{field}");
            }
            for args in [
                json!(["tern", "daemon", "--socket", "/run/user/1000/daemon.sock", "--handoff", "relative"]),
                json!(["tern", "daemon", "--socket", "/run/user/1000/daemon.sock", "--handoff", "/home/test/../state"]),
                json!(["tern", "daemon", "--socket", "/run/user/1000/daemon.sock", "--handoff"]),
                json!(["tern", "daemon", "--socket", "/run/user/1000/daemon.sock", "--unsafe", "--handoff", "/home/test/state"]),
                json!(["tern", "daemon", "--socket", "/run/user/1000/daemon.sock", "--handoff", "/home/test/state", "--handoff", "/home/test/state"]),
            ] {
                let mut changed = upgraded.clone();
                changed["daemon_argv"] = args;
                assert!(migration_required(&saved, &changed).is_err());
            }
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
