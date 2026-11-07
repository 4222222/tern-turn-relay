//! Installation ownership and reversible local mutations. Never stops a service.
use crate::common::{self, Error, Options, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::ffi::CString;
use std::fs::File;
#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::path::Component;
use std::time::Duration;

pub const PLUGIN: &str = "tern-turn-relay";
const PACKAGE_FILES: &[&str] = &[
    "plugin.toml",
    "window.luau",
    "onboarding.luau",
    "work-queue.luau",
    "bootstrap-runtime.sh",
    "bootstrap-runtime.ps1",
    "platform.luau",
    "release.json",
    "LICENSE",
    "THIRD_PARTY_NOTICES.txt",
    "README.md",
    "CHANGELOG.md",
    "docs/agent-setup.md",
];
fn io_error() -> Error {
    Error::with_exit("unsafe-path", "Cannot securely access the owned local installation; paths and private diagnostics were withheld.", 7)
}
fn changed() -> Error {
    Error::with_exit("review-changed", "Installation content or ownership changed; inspect and review again. User changes were preserved.", 6)
}
fn recovery_error() -> Error {
    Error::with_exit("recovery-required", "Installation failed and independent rollback was attempted; retained local files require manual recovery. No user changes were overwritten.", 7)
}
#[cfg(unix)]
fn cstring(value: &std::ffi::OsStr) -> Result<CString> {
    CString::new(value.as_bytes()).map_err(|_| io_error())
}
#[cfg(unix)]
pub(crate) fn home() -> Result<PathBuf> {
    let path = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(io_error)?;
    common::safe_absolute(path.to_str().ok_or_else(io_error)?)?;
    Ok(path)
}
#[cfg(unix)]
#[derive(Clone, Copy)]
enum AncestorPolicy {
    PrivateData,
    Executable { admin_gid: Option<libc::gid_t> },
}
#[cfg(unix)]
fn directory_permissions_trusted(
    owner: libc::uid_t,
    group: libc::gid_t,
    mode: u32,
    uid: libc::uid_t,
    policy: AncestorPolicy,
) -> bool {
    let sticky = owner == 0 && mode & (libc::S_ISVTX as u32) != 0;
    // macOS platform administrators manage installed applications. This extra
    // trust never applies to credential/configuration/package-data ancestry.
    let platform_admin = match policy {
        AncestorPolicy::Executable { admin_gid: Some(admin_gid) } => {
            owner == 0 && group == admin_gid && mode & 0o002 == 0
        }
        _ => false,
    };
    (owner == uid || owner == 0) && (!common::foreign_writable(mode, group) || sticky || platform_admin)
}
#[cfg(unix)]
fn trusted_directory_with_policy(file: &File, leaf: bool, policy: AncestorPolicy) -> Result<()> {
    let m = file.metadata().map_err(|_| io_error())?;
    let uid = unsafe { libc::getuid() };
    if !m.is_dir()
        || !directory_permissions_trusted(m.uid(), m.gid(), m.mode(), uid, policy)
        || (leaf && m.uid() != uid)
    {
        return Err(io_error());
    }
    Ok(())
}
#[cfg(unix)]
fn trusted_directory(file: &File, leaf: bool) -> Result<()> {
    trusted_directory_with_policy(file, leaf, AncestorPolicy::PrivateData)
}
#[cfg(target_os = "macos")]
fn executable_admin_gid() -> Result<Option<libc::gid_t>> {
    // Resolve the named system group through the platform account database;
    // do not assume an arbitrary group or hard-code macOS's usual numeric gid.
    let mut buffer = vec![0u8; 4096];
    loop {
        let mut group: libc::group = unsafe { std::mem::zeroed() };
        let mut result = std::ptr::null_mut();
        let status = unsafe {
            libc::getgrnam_r(
                b"admin\0".as_ptr().cast(),
                &mut group,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status == libc::ERANGE && buffer.len() < 65536 {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        if status != 0 { return Err(io_error()); }
        if result.is_null() { return Ok(None); }
        if group.gr_name.is_null()
            || unsafe { std::ffi::CStr::from_ptr(group.gr_name) }.to_bytes() != b"admin"
        {
            return Err(io_error());
        }
        return Ok(Some(group.gr_gid));
    }
}
#[cfg(all(unix, not(target_os = "macos")))]
fn executable_admin_gid() -> Result<Option<libc::gid_t>> {
    Ok(None)
}
/// Opens every ancestor using directory descriptors, never following symlinks.
#[cfg(unix)]
fn parent(path: &Path, create: bool) -> Result<Option<File>> {
    parent_with_policy(path, create, AncestorPolicy::PrivateData)
}
#[cfg(unix)]
fn parent_with_policy(path: &Path, create: bool, policy: AncestorPolicy) -> Result<Option<File>> {
    common::safe_absolute(path.to_str().ok_or_else(io_error)?)?;
    let base = path.parent().ok_or_else(io_error)?;
    let mut current = File::open("/").map_err(|_| io_error())?;
    for component in base.components() {
        let Component::Normal(name) = component else {
            continue;
        };
        let name = cstring(name)?;
        if create {
            let status = unsafe { libc::mkdirat(current.as_raw_fd(), name.as_ptr(), 0o700) };
            if status != 0
                && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists
            {
                return Err(io_error());
            }
        }
        let fd = unsafe {
            libc::openat(
                current.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            if !create && std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(io_error());
        }
        current = unsafe { File::from_raw_fd(fd) };
        trusted_directory_with_policy(&current, false, policy)?;
    }
    Ok(Some(current))
}
#[cfg(unix)]
pub(crate) fn owned_path(path: &Path, directory: bool) -> Result<()> {
    let Some(parent) = parent(path, false)? else {
        return Ok(());
    };
    let name = cstring(path.file_name().ok_or_else(io_error)?)?;
    let flags = libc::O_RDONLY
        | libc::O_NOFOLLOW
        | libc::O_CLOEXEC
        | libc::O_NONBLOCK
        | if directory { libc::O_DIRECTORY } else { 0 };
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        if std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
            return Ok(());
        }
        return Err(io_error());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    if directory {
        trusted_directory(&file, true)
    } else {
        let m = file.metadata().map_err(|_| io_error())?;
        if !m.is_file()
            || m.uid() != unsafe { libc::getuid() }
            || common::foreign_writable(m.mode(), m.gid())
            || m.nlink() != 1
        {
            return Err(io_error());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Snapshot {
    pub bytes: Vec<u8>,
    dev: u64,
    ino: u64,
    mode: u32,
    modified: (i64, i64),
    changed: (i64, i64),
    #[cfg(windows)]
    windows: crate::windows_security::FileStamp,
}
impl Snapshot {
    pub(crate) fn require_private(&self) -> Result<()> {
        if self.mode != 0o600 {
            return Err(io_error());
        }
        Ok(())
    }
}
#[cfg(unix)]
fn snapshot_at(directory: &File, name: &CString, limit: usize) -> Result<Option<Snapshot>> {
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        if std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(io_error());
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let m = file.metadata().map_err(|_| io_error())?;
    if !m.is_file()
        || m.uid() != unsafe { libc::getuid() }
        || m.nlink() != 1
        || common::foreign_writable(m.mode(), m.gid())
        || m.len() > limit as u64
    {
        return Err(io_error());
    }
    let mut bytes = Vec::with_capacity(m.len() as usize);
    (&mut file)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| io_error())?;
    let after = file.metadata().map_err(|_| io_error())?;
    if bytes.len() > limit
        || m.len() != after.len()
        || m.mtime() != after.mtime()
        || m.mtime_nsec() != after.mtime_nsec()
        || m.ctime() != after.ctime()
        || m.ctime_nsec() != after.ctime_nsec()
    {
        return Err(changed());
    }
    Ok(Some(Snapshot {
        bytes,
        dev: m.dev(),
        ino: m.ino(),
        mode: m.mode() & 0o777,
        modified: (m.mtime(), m.mtime_nsec()),
        changed: (m.ctime(), m.ctime_nsec()),
    }))
}
#[cfg(unix)]
pub(crate) fn snapshot(path: &Path, limit: usize) -> Result<Option<Snapshot>> {
    let Some(directory) = parent(path, false)? else {
        return Ok(None);
    };
    snapshot_at(
        &directory,
        &cstring(path.file_name().ok_or_else(io_error)?)?,
        limit,
    )
}
/// Atomic compare-and-swap with a pinned parent descriptor and fsynced private stage.
#[cfg(unix)]
pub(crate) fn replace(
    path: &Path,
    expected: Option<&Snapshot>,
    bytes: Option<&[u8]>,
    mode: u32,
) -> Result<()> {
    let directory = parent(path, bytes.is_some())?.ok_or_else(io_error)?;
    trusted_directory(&directory, true)?;
    let name = cstring(path.file_name().ok_or_else(io_error)?)?;
    let limit = expected
        .map(|s| s.bytes.len())
        .unwrap_or(0)
        .max(bytes.map(<[u8]>::len).unwrap_or(0))
        .max(65536);
    if snapshot_at(&directory, &name, limit)?.as_ref() != expected {
        return Err(changed());
    }
    let Some(bytes) = bytes else {
        if expected.is_some()
            && unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0
        {
            return Err(io_error());
        }
        directory.sync_all().map_err(|_| io_error())?;
        return Ok(());
    };
    let temp = CString::new(format!(".tern-write-{:032x}", rand::random::<u128>()))
        .map_err(|_| io_error())?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            temp.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(io_error());
    }
    let result = (|| {
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(bytes).map_err(|_| io_error())?;
        if unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) } != 0 {
            return Err(io_error());
        }
        file.sync_all().map_err(|_| io_error())?;
        if snapshot_at(&directory, &name, limit)?.as_ref() != expected {
            return Err(changed());
        }
        if unsafe {
            libc::renameat(
                directory.as_raw_fd(),
                temp.as_ptr(),
                directory.as_raw_fd(),
                name.as_ptr(),
            )
        } != 0
        {
            return Err(io_error());
        }
        directory.sync_all().map_err(|_| io_error())?;
        Ok(())
    })();
    unsafe {
        libc::unlinkat(directory.as_raw_fd(), temp.as_ptr(), 0);
    }
    result
}
#[cfg(windows)]
pub(crate) fn home() -> Result<PathBuf> { crate::windows_security::home() }
#[cfg(windows)]
pub(crate) fn owned_path(path: &Path, directory: bool) -> Result<()> {
    crate::windows_security::owned(path, directory)
}
#[cfg(windows)]
pub(crate) fn snapshot(path: &Path, limit: usize) -> Result<Option<Snapshot>> {
    Ok(crate::windows_security::snapshot(path, limit)?.map(|s| Snapshot {
        bytes: s.bytes, dev: s.stamp.identity.volume, ino: s.stamp.identity.index,
        mode: if s.stamp.private { 0o600 } else { 0o644 },
        modified: (s.stamp.identity.written as i64, 0), changed: (s.stamp.identity.created as i64, 0), windows: s.stamp,
    }))
}
#[cfg(windows)]
pub(crate) fn replace(path: &Path, expected: Option<&Snapshot>, bytes: Option<&[u8]>, _mode: u32) -> Result<()> {
    crate::windows_security::replace(path, expected.map(|s| (&s.windows, s.bytes.as_slice())), bytes)
}

fn json_bytes(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(value).map_err(|_| io_error())?;
    bytes.push(b'\n');
    Ok(bytes)
}
pub(crate) fn digest(path: &Path) -> Result<Value> {
    Ok(snapshot(path, 65536)?
        .map(|s| json!(hex::encode(Sha256::digest(&s.bytes))))
        .unwrap_or(Value::Null))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Registration {
    pub marker: PathBuf,
    pub source: PathBuf,
    pub kind: &'static str,
    dev: u64,
    ino: u64,
}
#[cfg(unix)]
fn normalize_link_target(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(io_error());
    }
    let mut result = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => result.push(name),
            Component::ParentDir => {
                if !result.pop() {
                    return Err(io_error());
                }
            }
            _ => return Err(io_error()),
        }
    }
    common::safe_absolute(result.to_str().ok_or_else(io_error)?)?;
    Ok(result)
}
#[cfg(unix)]
pub(crate) fn registration(plugins: &Path) -> Result<Option<Registration>> {
    owned_path(plugins, true)?;
    let mut found = Vec::new();
    let native = plugins.join(PLUGIN);
    match std::fs::symlink_metadata(&native) {
        Ok(m) => {
            if m.uid() != unsafe { libc::getuid() } {
                return Err(io_error());
            }
            let (source, kind) = if m.file_type().is_symlink() {
                let target = std::fs::read_link(&native).map_err(|_| io_error())?;
                let target = if target.is_absolute() {
                    target
                } else {
                    plugins.join(target)
                };
                let target = normalize_link_target(&target)?;
                owned_path(&target, true)?;
                (target, "linked")
            } else {
                owned_path(&native, true)?;
                if !m.is_dir() {
                    return Err(io_error());
                }
                (native.clone(), "native")
            };
            found.push(Registration {
                marker: native,
                source,
                kind,
                dev: m.dev(),
                ino: m.ino(),
            });
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(io_error()),
    }
    let marker = plugins.join(format!("{PLUGIN}.path"));
    if let Some(s) = snapshot(&marker, 8192)? {
        let text = std::str::from_utf8(&s.bytes).map_err(|_| io_error())?;
        let source = PathBuf::from(text.strip_suffix('\n').unwrap_or(text));
        owned_path(&source, true)?;
        found.push(Registration {
            marker,
            source,
            kind: "linked",
            dev: s.dev,
            ino: s.ino,
        });
    }
    if found.len() > 1 {
        return Err(Error::new("ambiguous-registration", "Both native and linked plugin registrations exist; preserve them and resolve the ambiguity first."));
    }
    Ok(found.pop())
}
#[cfg(windows)]
pub(crate) fn registration(plugins: &Path) -> Result<Option<Registration>> {
    owned_path(plugins, true)?;
    let mut found = Vec::new();
    let native = plugins.join(PLUGIN);
    if let Some(directory) = crate::windows_security::directory(&native, false, false)? {
        crate::windows_security::check_acl(&directory.file, false, true, false)?;
        let id = crate::windows_security::identity(&directory.file, true)?;
        found.push(Registration { marker: native.clone(), source: native, kind: "native", dev: id.volume, ino: id.index });
    }
    let marker = plugins.join(format!("{PLUGIN}.path"));
    if let Some(s) = snapshot(&marker, 8192)? {
        let text = std::str::from_utf8(&s.bytes).map_err(|_| io_error())?;
        let source = PathBuf::from(text.trim_end_matches(['\r', '\n']));
        common::safe_local_absolute(source.to_str().ok_or_else(io_error)?)?;
        let directory = crate::windows_security::directory(&source, false, false)?.ok_or_else(io_error)?;
        crate::windows_security::check_acl(&directory.file, false, true, false)?;
        found.push(Registration { marker, source, kind: "linked", dev: s.dev, ino: s.ino });
    }
    if found.len() > 1 { return Err(Error::new("ambiguous-registration", "发现多个插件注册，已保留所有文件，请先消除歧义。")); }
    Ok(found.pop())
}

#[derive(Clone)]
pub(crate) struct Paths {
    pub data: PathBuf,
    pub package: PathBuf,
    pub profile: PathBuf,
    pub ssh: PathBuf,
    pub aliases: PathBuf,
    pub tern: Option<PathBuf>,
}
impl Paths {
    pub fn plugins(&self) -> PathBuf {
        self.profile.join("plugins")
    }
    pub fn config(&self) -> PathBuf {
        self.data.join("config.json")
    }
    pub fn manifest(&self) -> PathBuf {
        self.data.join("installation.json")
    }
    pub fn credential(&self) -> PathBuf {
        self.data.join("credentials/cloudflare.json")
    }
    pub fn runtime(&self) -> PathBuf {
        self.data.join("runtime")
    }
    pub fn json(&self) -> Value {
        json!({"data_dir":self.data,"package_dir":self.package,"config_dir":self.profile,
            "config_file":self.config(),"credential_file":self.credential(),"ssh_config":self.ssh,"ssh_alias_config":self.aliases})
    }
}
/// XDG base directory: the variable when it is an absolute path (the spec
/// ignores relative values), else the home-relative fallback.
#[cfg(all(unix, not(target_os = "macos")))]
fn xdg_dir(variable: &str, fallback: &str) -> Result<PathBuf> {
    match std::env::var(variable) {
        Ok(value) if value.starts_with('/') => {
            common::safe_absolute(&value)?;
            Ok(PathBuf::from(value))
        }
        _ => Ok(home()?.join(fallback)),
    }
}
pub(crate) fn context(opts: &Options) -> Result<Paths> {
    #[cfg(target_os = "macos")]
    let default = home()?.join("Library/Application Support/Tern");
    #[cfg(all(unix, not(target_os = "macos")))]
    let default = xdg_dir("XDG_CONFIG_HOME", ".config")?.join("tern");
    #[cfg(windows)]
    let default = crate::windows_security::profile()?;
    #[cfg(windows)]
    let default_data = crate::windows_security::state_dir()?.join("plugin-data").join(PLUGIN);
    // Tern on Linux keeps the default profile's state under the XDG state
    // directory; a TERN_CONFIG_DIR profile keeps it inside the profile.
    #[cfg(all(unix, not(target_os = "macos")))]
    let default_data = xdg_dir("XDG_STATE_HOME", ".local/state")?.join("tern/plugin-data").join(PLUGIN);
    #[cfg(target_os = "macos")]
    let default_data = default.join("plugin-data").join(PLUGIN);
    let package_arg = opts.get("--package-dir").map(PathBuf::from);
    let supplied_data = opts.get("--data-dir").map(PathBuf::from);
    let native_profile = package_arg
        .as_ref()
        .filter(|p| {
            p.file_name().is_some_and(|n| n == PLUGIN)
                && p.parent()
                    .and_then(Path::file_name)
                    .is_some_and(|n| n == "plugins")
        })
        .and_then(|p| p.parent().and_then(Path::parent))
        .map(Path::to_path_buf);
    let inferred_linked =
        opts.get("--config-dir").is_none() && native_profile.is_none() && supplied_data.is_some();
    let profile = opts
        .get("--config-dir")
        .map(PathBuf::from)
        .or(native_profile)
        .or_else(|| supplied_data.as_ref().and_then(|path| {
            if path == &default_data { Some(default.clone()) }
            else { path.parent().and_then(Path::parent).map(Path::to_path_buf) }
        }))
        .unwrap_or(default.clone());
    let expected_data = if profile == default { default_data } else { profile.join("plugin-data").join(PLUGIN) };
    let data = supplied_data.unwrap_or_else(|| expected_data.clone());
    if data != expected_data {
        return Err(Error::new(
            "context-mismatch",
            "Plugin data must belong to the selected Tern profile.",
        ));
    }
    let package = package_arg.unwrap_or_else(|| profile.join("plugins").join(PLUGIN));
    for path in [&profile, &data, &package] {
        owned_path(path, true)?;
    }
    let aliases = home()?.join(".ssh/config");
    owned_path(&aliases, false)?;
    let mut ssh = opts
        .get("--ssh-config")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            if profile == default {
                aliases.clone()
            } else {
                data.join("ssh-config")
            }
        });
    let mut paths = Paths {
        data,
        package,
        profile,
        ssh: ssh.clone(),
        aliases,
        tern: opts.get("--tern").map(PathBuf::from),
    };
    if let Some(record) = manifest(&paths)? {
        if inferred_linked && record["package"] != json!(paths.package) {
            return Err(Error::new(
                "context-mismatch",
                "Supplied data does not own this linked plugin package.",
            ));
        }
        let recorded = PathBuf::from(record["ssh_config"].as_str().ok_or_else(io_error)?);
        if opts.get("--ssh-config").is_some() && ssh != recorded {
            return Err(Error::new(
                "context-mismatch",
                "An existing installation cannot move ownership to a different SSH config.",
            ));
        }
        ssh = recorded;
    } else if inferred_linked {
        return Err(Error::new(
            "ownership-required",
            "A linked custom profile requires its installation ownership record.",
        ));
    }
    owned_path(&ssh, false)?;
    paths.ssh = ssh;
    Ok(paths)
}
pub(crate) fn manifest(paths: &Paths) -> Result<Option<Value>> {
    if snapshot(&paths.manifest(), 65536)?.is_none() {
        return Ok(None);
    }
    let record = common::read_json(&paths.manifest(), true)?;
    if !matches!(record["schema"].as_u64(), Some(1 | 2))
        || record["plugin"] != PLUGIN
        || record["plugins"] != json!(paths.plugins())
        || record["package"].as_str().is_none()
        || record["ssh_config"].as_str().is_none()
    {
        return Err(Error::new(
            "invalid-installation",
            "Installation ownership record does not match this profile.",
        ));
    }
    let source = Path::new(record["package"].as_str().ok_or_else(io_error)?);
    owned_path(source, true)?;
    owned_path(
        Path::new(record["ssh_config"].as_str().ok_or_else(io_error)?),
        false,
    )?;
    if let Some(reg) = registration(&paths.plugins())? {
        if source != reg.source
            && !(is_retired(&record)? && reg.kind == "native" && reg.source == paths.package)
        {
            return Err(changed());
        }
    }
    if record["schema"] == 2
        && (record["runtime"] != "rust"
            || record["config_schema"] != 4
            || !record["package_files"].is_object())
    {
        return Err(io_error());
    }
    recorded_ssh_digest(&record)?;
    Ok(Some(record))
}
pub(crate) fn current(paths: &Paths) -> Result<Option<Value>> {
    if snapshot(&paths.config(), 65536)?.is_none() {
        return Ok(None);
    }
    Ok(Some(common::load_config(&paths.config(), false)?))
}
pub(crate) fn lifecycle(paths: &Paths) -> Result<(File, File)> {
    #[cfg(unix)]
    common::private_dir(&paths.data, true)?;
    #[cfg(windows)]
    crate::windows_security::directory(&paths.data, true, false)?.ok_or_else(io_error)?;
    common::private_dir(&paths.runtime(), true)?;
    let command = common::lock(&paths.runtime().join("command.lock"), true).map_err(|_| {
        Error::with_exit(
            "stopped-required",
            "Finish other lifecycle operations before changing this installation.",
            6,
        )
    })?;
    let service = common::lock(&paths.runtime().join("service.lock"), true).map_err(|_| {
        Error::with_exit(
            "stopped-required",
            "Disconnect TURN explicitly before changing this installation.",
            6,
        )
    })?;
    Ok((command, service))
}
pub(crate) fn runtime_ready() -> bool {
    std::env::current_exe()
        .ok()
        .and_then(|p| {
            #[cfg(windows)]
            let p = crate::windows_security::normalize_system_path(&p).ok()?;
            owned_path(&p, false).ok()?;
            let m = std::fs::symlink_metadata(&p).ok()?;
            #[cfg(unix)]
            { Some(m.is_file() && m.mode() & 0o111 != 0) }
            #[cfg(windows)]
            { Some(m.is_file() && p.extension().is_some_and(|s| s.eq_ignore_ascii_case("exe"))) }
        })
        .unwrap_or(false)
}

/// The Tern build the plugin runs under. Bootstrap `exec`s this program, so its
/// parent is the Tern process that ran the plugin action. PATH is never searched;
/// a replaced build (`tern (deleted)`) or a non-Tern parent fails closed.
#[cfg(target_os = "linux")]
fn default_tern() -> Result<PathBuf> {
    let parent = unsafe { libc::getppid() };
    let path = std::fs::read_link(format!("/proc/{parent}/exe")).map_err(|_| io_error())?;
    if path.file_name().and_then(|name| name.to_str()) != Some("tern") {
        return Err(Error::new(
            "tern-unavailable",
            "Cannot identify the running Tern executable; pass --tern with its absolute path.",
        ));
    }
    Ok(path)
}
#[cfg(all(unix, not(target_os = "linux")))]
fn default_tern() -> Result<PathBuf> {
    Ok(PathBuf::from("/Applications/Tern.app/Contents/MacOS/tern"))
}
#[cfg(unix)]
async fn tern(paths: &Paths, args: &[&str]) -> Result<std::process::Output> {
    let binary = match &paths.tern {
        Some(path) => path.clone(),
        None => default_tern()?,
    };
    let policy = AncestorPolicy::Executable { admin_gid: executable_admin_gid()? };
    let directory = parent_with_policy(&binary, false, policy)?.ok_or_else(io_error)?;
    let name = cstring(binary.file_name().ok_or_else(io_error)?)?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(io_error());
    }
    let executable = unsafe { File::from_raw_fd(fd) };
    let metadata = executable.metadata().map_err(|_| io_error())?;
    if !metadata.is_file()
        || ![0, unsafe { libc::getuid() }].contains(&metadata.uid())
        || common::foreign_writable(metadata.mode(), metadata.gid())
        || metadata.mode() & 0o111 == 0
    {
        return Err(io_error());
    }
    #[cfg(target_os = "macos")]
    let mut command = vec![
        format!(
            "TERN_CONFIG_DIR={}",
            paths.profile.to_str().ok_or_else(io_error)?
        ),
        format!(
            "TERN_DAEMON_SOCKET={}",
            paths
                .profile
                .join("daemon.sock")
                .to_str()
                .ok_or_else(io_error)?
        ),
        binary.to_str().ok_or_else(io_error)?.to_owned(),
    ];
    // Linux Tern resolves its daemon socket under XDG_RUNTIME_DIR for every
    // profile, so the inherited socket is kept. Only a custom profile is named;
    // the default profile is Tern's own XDG resolution.
    #[cfg(not(target_os = "macos"))]
    let mut command = {
        let profile = paths.profile.to_str().ok_or_else(io_error)?;
        let mut command = if paths.profile == xdg_dir("XDG_CONFIG_HOME", ".config")?.join("tern") {
            vec!["-u".to_owned(), "TERN_CONFIG_DIR".to_owned()]
        } else {
            vec![format!("TERN_CONFIG_DIR={profile}")]
        };
        command.push(binary.to_str().ok_or_else(io_error)?.to_owned());
        command
    };
    command.extend(args.iter().map(|s| (*s).to_owned()));
    common::run("/usr/bin/env", &command, None, Duration::from_secs(180)).await
}
#[cfg(windows)]
async fn tern(paths: &Paths, args: &[&str]) -> Result<std::process::Output> {
    let binary = match &paths.tern {
        Some(path) => path.clone(),
        None => crate::windows_security::known_folder(&windows_sys::Win32::UI::Shell::FOLDERID_LocalAppData)?.join("Programs/Tern/tern.exe"),
    };
    let _executable = crate::windows_security::open(&binary, false, true)?.ok_or_else(io_error)?;
    let args: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
    crate::windows_process::run_with_env(binary.to_str().ok_or_else(io_error)?, &args, None, Duration::from_secs(180),
        &[("TERN_CONFIG_DIR", paths.profile.to_str().ok_or_else(io_error)?)]).await
}

pub(crate) async fn verify_profile(paths: &Paths) -> Result<()> {
    let output = tern(paths, &["plugin", "dir"]).await?;
    let text = std::str::from_utf8(&output.stdout)
        .map_err(|_| io_error())?
        .trim_end_matches(['\r', '\n']);
    if !output.status.success() || Path::new(text) != paths.plugins() {
        return Err(Error::new(
            "context-mismatch",
            "Tern resolved a different plugin profile; no installation was changed.",
        ));
    }
    Ok(())
}
fn package_bytes(package: &Path) -> Result<Vec<(&'static str, Snapshot)>> {
    owned_path(package, true)?;
    let mut result = Vec::new();
    for &name in PACKAGE_FILES {
        let file = snapshot(&package.join(name), 4 * 1024 * 1024)?.ok_or_else(io_error)?;
        result.push((name, file));
    }
    let release = result
        .iter()
        .find(|(n, _)| *n == "release.json")
        .ok_or_else(io_error)?;
    let value = common::parse_json(&release.1.bytes)?;
    if value["schema"] != 1
        || value["version"] != env!("CARGO_PKG_VERSION")
        || !value["assets"].is_object()
    {
        return Err(Error::new(
            "runtime-mismatch",
            "The plugin package does not match this native runtime release.",
        ));
    }
    Ok(result)
}
/// Capture the actual installed distribution, not just the minimal migration copy.
/// Directory entries are recorded too, so new empty directories are not erased.
fn package_inventory(package: &Path) -> Result<Value> {
    owned_path(package, true)?;
    let mut files = serde_json::Map::new();
    let mut pending = vec![package.to_path_buf()];
    let mut total = 0usize;
    while let Some(directory) = pending.pop() {
        owned_path(&directory, true)?;
        for entry in std::fs::read_dir(&directory).map_err(|_| io_error())? {
            let path = entry.map_err(|_| io_error())?.path();
            let name = path
                .strip_prefix(package)
                .map_err(|_| io_error())?
                .to_str()
                .ok_or_else(io_error)?
                .to_owned();
            #[cfg(windows)]
            let name = name.replace('\\', "/");
            if name.len() > 1024 || files.len() >= 512 {
                return Err(Error::new("package-limit", "Installed package inventory exceeds its safe ownership limit; all files were preserved."));
            }
            let metadata = std::fs::symlink_metadata(&path).map_err(|_| io_error())?;
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                owned_path(&path, true)?;
                files.insert(format!("{name}/"), json!("directory"));
                pending.push(path);
            } else {
                let file = snapshot(&path, 16 * 1024 * 1024)?.ok_or_else(changed)?;
                total += file.bytes.len();
                if total > 64 * 1024 * 1024 {
                    return Err(Error::new("package-limit", "Installed package inventory exceeds its safe ownership limit; all files were preserved."));
                }
                files.insert(name, json!(hex::encode(Sha256::digest(&file.bytes))));
            }
        }
    }
    let value = Value::Object(files);
    if serde_json::to_vec(&value).map_err(|_| io_error())?.len() > 56 * 1024 {
        return Err(io_error());
    }
    Ok(value)
}
pub(crate) fn package_digest(package: &Path) -> Result<Value> {
    Ok(json!(hex::encode(Sha256::digest(
        serde_json::to_vec(&package_inventory(package)?).map_err(|_| io_error())?
    ))))
}
fn ensure_package_unchanged(package: &Path, expected: &Value) -> Result<()> {
    if !expected.is_object() || package_inventory(package)? != *expected {
        return Err(Error::with_exit("package-modified", "The plugin package contains modified or additional files; update/removal preserved them. Restore the owned distribution or retain a copy before retrying.", 6));
    }
    Ok(())
}
fn record(paths: &Paths, package: &Path, ssh_digest: Option<&str>, package_files: Value) -> Value {
    json!({"schema":2,"plugin":PLUGIN,"plugins":paths.plugins(),"package":package,
        "registration":"native","ssh_config":paths.ssh,"ssh_block_sha256":ssh_digest,
        "runtime":"rust","config_schema":4,"package_files":package_files,"retired":ssh_digest.is_none()})
}
fn is_retired(record: &Value) -> Result<bool> {
    match record.get("retired") {
        None => Ok(false),
        Some(Value::Bool(retired)) => Ok(*retired),
        _ => Err(changed()),
    }
}
fn recorded_ssh_digest(record: &Value) -> Result<Option<&str>> {
    if is_retired(record)? {
        if record.get("ssh_block_sha256") != Some(&Value::Null) {
            return Err(changed());
        }
        return Ok(None);
    }
    record["ssh_block_sha256"]
        .as_str()
        .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(Some)
        .ok_or_else(changed)
}
fn check_rule(paths: &Paths, record: &Value) -> Result<()> {
    let expected = recorded_ssh_digest(record)?;
    let bytes = snapshot(&paths.ssh, 65536)?;
    let text = std::str::from_utf8(bytes.as_ref().map(|s| s.bytes.as_slice()).unwrap_or(b""))
        .map_err(|_| io_error())?;
    if crate::ssh_config::block_digest(text)?.as_deref() != expected {
        return Err(changed());
    }
    Ok(())
}

struct Mutation {
    path: PathBuf,
    before: Option<Snapshot>,
    after: Option<Vec<u8>>,
    mode: u32,
}
struct Transaction {
    mutations: Vec<Mutation>,
}
impl Transaction {
    fn new() -> Self {
        Self {
            mutations: Vec::new(),
        }
    }
    fn put(
        &mut self,
        path: &Path,
        before: Option<Snapshot>,
        after: Option<Vec<u8>>,
        mode: u32,
    ) -> Result<()> {
        // Register before the operation: a directory fsync can fail after publication.
        self.mutations.push(Mutation {
            path: path.to_path_buf(),
            before,
            after,
            mode,
        });
        let mutation = self.mutations.last().ok_or_else(io_error)?;
        replace(
            path,
            mutation.before.as_ref(),
            mutation.after.as_deref(),
            mode,
        )
    }
    fn rollback(&self) -> Result<()> {
        let mut failed = false;
        for m in self.mutations.iter().rev() {
            let result = (|| {
                let now = snapshot(&m.path, 4 * 1024 * 1024)?;
                if now == m.before {
                    return Ok(());
                }
                if now.as_ref().map(|s| s.bytes.as_slice()) != m.after.as_deref() {
                    return Err(changed());
                }
                replace(
                    &m.path,
                    now.as_ref(),
                    m.before.as_ref().map(|s| s.bytes.as_slice()),
                    m.before.as_ref().map(|s| s.mode).unwrap_or(m.mode),
                )
            })();
            if result.is_err() {
                failed = true;
            }
        }
        if failed {
            Err(recovery_error())
        } else {
            Ok(())
        }
    }
}

#[cfg(unix)]
fn rename_no_replace(from: &File, name: &CString, to: &File, destination: &CString) -> Result<()> {
    #[cfg(target_os = "linux")]
    let status = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            from.as_raw_fd(),
            name.as_ptr(),
            to.as_raw_fd(),
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    #[cfg(target_os = "macos")]
    let status = unsafe {
        libc::renameatx_np(
            from.as_raw_fd(),
            name.as_ptr(),
            to.as_raw_fd(),
            destination.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if status != 0 {
        return Err(io_error());
    }
    Ok(())
}
#[cfg(unix)]
fn rename_owned_directory(source: &Path, destination: &Path) -> Result<()> {
    owned_path(source, true)?;
    let m = std::fs::symlink_metadata(source).map_err(|_| io_error())?;
    if !m.is_dir() || m.file_type().is_symlink() {
        return Err(io_error());
    }
    let from = parent(source, false)?.ok_or_else(io_error)?;
    let to = parent(destination, true)?.ok_or_else(io_error)?;
    trusted_directory(&from, true)?;
    trusted_directory(&to, true)?;
    match std::fs::symlink_metadata(destination) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err(changed()),
    }
    let current = std::fs::symlink_metadata(source).map_err(|_| io_error())?;
    if m.dev() != current.dev() || m.ino() != current.ino() {
        return Err(changed());
    }
    let from_name = cstring(source.file_name().ok_or_else(io_error)?)?;
    let to_name = cstring(destination.file_name().ok_or_else(io_error)?)?;
    rename_no_replace(&from, &from_name, &to, &to_name)?;
    Ok(())
}
#[cfg(unix)]
fn move_registration(paths: &Paths, expected: &Registration, destination: &Path) -> Result<()> {
    if registration(&paths.plugins())?.as_ref() != Some(expected) {
        return Err(changed());
    }
    let from = parent(&expected.marker, false)?.ok_or_else(io_error)?;
    let to = parent(destination, true)?.ok_or_else(io_error)?;
    trusted_directory(&from, true)?;
    trusted_directory(&to, true)?;
    if std::fs::symlink_metadata(destination).is_ok() {
        return Err(changed());
    }
    let source = cstring(expected.marker.file_name().ok_or_else(io_error)?)?;
    let target = cstring(destination.file_name().ok_or_else(io_error)?)?;
    rename_no_replace(&from, &source, &to, &target)?;
    Ok(())
}
#[cfg(windows)]
fn rename_owned_directory(source: &Path, destination: &Path) -> Result<()> {
    let expected = crate::windows_security::path_identity(source, true)?;
    crate::windows_security::move_owned(source, destination, Some(expected))
}
#[cfg(windows)]
fn move_registration(paths: &Paths, expected: &Registration, destination: &Path) -> Result<()> {
    if registration(&paths.plugins())?.as_ref() != Some(expected) { return Err(changed()); }
    crate::windows_security::move_owned(&expected.marker, destination, Some((expected.dev, expected.ino)))
}
fn object_identity(path: &Path, directory: bool) -> Result<(u64, u64)> {
    #[cfg(unix)]
    { let _ = directory; let m = std::fs::symlink_metadata(path).map_err(|_| io_error())?; Ok((m.dev(), m.ino())) }
    #[cfg(windows)]
    { crate::windows_security::path_identity(path, directory) }
}

fn retire_ownership(tx: &mut Transaction, paths: &Paths, record: &Value) -> Result<()> {
    let before = snapshot(&paths.manifest(), 65536)?.ok_or_else(changed)?;
    if common::read_json(&paths.manifest(), true)? != *record {
        return Err(changed());
    }
    let mut retired = record.clone();
    retired["retired"] = json!(true);
    retired["ssh_block_sha256"] = Value::Null;
    tx.put(
        &paths.manifest(),
        Some(before),
        Some(json_bytes(&retired)?),
        0o600,
    )
}
fn owned_rule_removal(
    paths: &Paths,
    record: &Value,
) -> Result<Option<crate::ssh_config::Prepared>> {
    match recorded_ssh_digest(record)? {
        Some(expected) => crate::ssh_config::removal(&paths.ssh, expected),
        None => {
            check_rule(paths, record)?;
            Ok(None)
        }
    }
}
fn uninstall_retained(paths: &Paths, reg: &Registration, record: Option<&Value>) -> Result<Value> {
    let ssh = match record {
        Some(record) => owned_rule_removal(paths, record)?,
        None => None,
    };
    let removed_rule = ssh.is_some();
    let mut tx = Transaction::new();
    let retained = paths
        .data
        .join("retained-packages")
        .join(format!("uninstall-{:032x}", rand::random::<u128>()));
    let result = (|| {
        if let Some(ssh) = ssh {
            tx.put(&paths.ssh, ssh.before, Some(ssh.bytes), 0o600)?;
        }
        if let Some(record) = record {
            retire_ownership(&mut tx, paths, record)?;
        }
        // Missing manifests and schema 1 provide no complete trusted inventory.
        // Retain the registration instead of recursively deleting unknown files.
        move_registration(paths, reg, &retained)?;
        Ok(())
    })();
    if let Err(error) = result {
        tx.rollback()?;
        return Err(error);
    }
    Ok(
        json!({"plugin_removed":reg.kind == "native","plugin_unlinked":reg.kind != "native",
        "marked_ssh_rule_removed":removed_rule,"retained_registration":retained,"installed_package_preserved":true,
        "configuration_preserved":true,"credentials_preserved":true,"managed_runtime_preserved":true,"data_preserved":true,
        "remote_daemon_preserved":true,"remote_gateway_state_preserved":true,"connection_started":false,"stop_requested":false,"reload_expected":true}),
    )
}
struct Migration {
    original: Registration,
    native: PathBuf,
    stage: PathBuf,
    backup_marker: PathBuf,
    activated: bool,
    identity: (u64, u64),
}
impl Migration {
    fn prepare(paths: &Paths, original: Registration, previous: &Value) -> Result<Self> {
        if original.kind != "linked"
            || previous["package"] != json!(original.source)
            || original.source.parent() != Some(paths.data.join("packages").as_path())
        {
            return Err(Error::new("ownership-required", "Legacy migration requires its owned durable package and matching installation record."));
        }
        owned_path(&original.source.join("relay.py"), false)?;
        if snapshot(&original.source.join("relay.py"), 4 * 1024 * 1024)?.is_none() {
            return Err(io_error());
        }
        let files = package_bytes(&paths.package)?;
        let stage = paths
            .data
            .join("retained-packages")
            .join(format!("migration-stage-{:032x}", rand::random::<u128>()));
        common::private_dir(&stage, true)?;
        for (name, file) in &files {
            replace(&stage.join(name), None, Some(&file.bytes), file.mode)?;
        }
        let backup_marker = paths
            .data
            .join("retained-packages")
            .join(format!("registration-{:032x}", rand::random::<u128>()));
        let identity = object_identity(&stage, true)?;
        Ok(Self {
            original,
            native: paths.plugins().join(PLUGIN),
            stage,
            backup_marker,
            activated: false,
            identity,
        })
    }
    fn activate(&mut self, paths: &Paths) -> Result<()> {
        if registration(&paths.plugins())?.as_ref() != Some(&self.original) {
            return Err(changed());
        }
        move_registration(paths, &self.original, &self.backup_marker)?;
        self.activated = true;
        rename_owned_directory(&self.stage, &self.native)?;
        Ok(())
    }
    fn rollback(&self, paths: &Paths) -> Result<()> {
        if !self.activated {
            return Ok(());
        }
        if let Some(reg) = registration(&paths.plugins())? {
            if reg.kind != "native"
                || reg.source != self.native
                || (reg.dev, reg.ino) != self.identity
            {
                return Err(changed());
            }
            rename_owned_directory(&self.native, &self.stage)?;
        }
        if object_identity(&self.backup_marker, self.original.kind == "native")? != (self.original.dev, self.original.ino) {
            return Err(changed());
        }
        #[cfg(unix)]
        {
        let from = parent(&self.backup_marker, false)?.ok_or_else(io_error)?;
        let to = parent(&self.original.marker, false)?.ok_or_else(io_error)?;
        let name = cstring(self.backup_marker.file_name().ok_or_else(io_error)?)?;
        let target = cstring(self.original.marker.file_name().ok_or_else(io_error)?)?;
        rename_no_replace(&from, &name, &to, &target)?;
        }
        #[cfg(windows)]
        crate::windows_security::move_owned(&self.backup_marker, &self.original.marker, Some((self.original.dev, self.original.ino)))?;
        Ok(())
    }
}

pub(crate) async fn apply(paths: &Paths, review: &Value) -> Result<Value> {
    verify_profile(paths).await?;
    let old_config = snapshot(&paths.config(), 65536)?;
    if digest(&paths.config())? != review["previous_config_sha256"] {
        return Err(changed());
    }
    let old_manifest = snapshot(&paths.manifest(), 65536)?;
    let previous = manifest(paths)?;
    let registration = registration(&paths.plugins())?.ok_or_else(|| {
        Error::new(
            "registration-required",
            "Install the native plugin in this Tern profile before configuration.",
        )
    })?;
    if registration.kind == "native" && registration.source != paths.package {
        return Err(changed());
    }
    let mut config = common::validate_config(review["configuration"].clone(), true)?;
    if package_digest(&paths.package)? != review["package_sha256"] {
        return Err(changed());
    }
    if let Some(record) = previous.as_ref().filter(|record| record["schema"] == 2) {
        if !is_retired(record)? {
            ensure_package_unchanged(&registration.source, &record["package_files"])?;
        }
    }
    if !crate::credentials::configured(Path::new(
        config["credential_file"].as_str().ok_or_else(io_error)?,
    ))? {
        return Err(Error::with_exit(
            "credential-absent",
            "Configure a Cloudflare TURN key before applying the target.",
            3,
        ));
    }
    let descriptor = crate::gateway::provision(&config).await?;
    let pin = descriptor["fingerprint"].as_str().ok_or_else(io_error)?;
    common::fingerprint(pin)?;
    if descriptor["daemon_socket"] != config["gateway"]["daemon_socket"]
        || descriptor["fingerprint"] == config["target"]["fingerprint"]
        || config["gateway"]
            .get("fingerprint")
            .is_some_and(|old| old != &descriptor["fingerprint"])
    {
        return Err(Error::new(
            "gateway-identity-changed",
            "Gateway identity or existing daemon binding changed; configuration was preserved.",
        ));
    }
    config["gateway"]["fingerprint"] = json!(pin);
    let config = common::validate_config(config, false)?;
    let expected_ssh = previous
        .as_ref()
        .map(recorded_ssh_digest)
        .transpose()?
        .flatten();
    let ssh = crate::ssh_config::prepare(&config, &paths.ssh, expected_ssh).await?;
    let mut migration = if registration.kind == "linked" {
        if review["migrate_native"] != true {
            return Err(changed());
        }
        Some(Migration::prepare(
            paths,
            registration.clone(),
            previous.as_ref().ok_or_else(changed)?,
        )?)
    } else {
        None
    };
    let package = paths.plugins().join(PLUGIN);
    let source = migration
        .as_ref()
        .map(|m| m.stage.as_path())
        .unwrap_or(&package);
    package_bytes(source)?;
    let new_record = record(
        paths,
        &package,
        Some(&ssh.digest),
        package_inventory(source)?,
    );
    let mut tx = Transaction::new();
    let result = (|| {
        if self::registration(&paths.plugins())?.as_ref() != Some(&registration)
            || digest(&paths.config())? != review["previous_config_sha256"]
        {
            return Err(changed());
        }
        if digest(&paths.manifest())? != review["installation_sha256"]
            || digest(&paths.ssh)? != review["ssh_config_sha256"]
            || package_digest(&paths.package)? != review["package_sha256"]
        {
            return Err(changed());
        }
        tx.put(
            &paths.config(),
            old_config,
            Some(json_bytes(&config)?),
            0o600,
        )?;
        tx.put(&paths.ssh, ssh.before, Some(ssh.bytes), 0o600)?;
        if let Some(m) = &mut migration {
            m.activate(paths)?;
        }
        tx.put(
            &paths.manifest(),
            old_manifest,
            Some(json_bytes(&new_record)?),
            0o600,
        )?;
        Ok(())
    })();
    if let Err(error) = result {
        let registration_recovered = migration
            .as_ref()
            .map(|m| m.rollback(paths).is_ok())
            .unwrap_or(true);
        let files_recovered = tx.rollback().is_ok();
        return Err(if registration_recovered && files_recovered {
            error
        } else {
            recovery_error()
        });
    }
    Ok(
        json!({"ok":true,"plugin":PLUGIN,"package":package,"config":paths.config(),"runtime":paths.runtime(),
        "registration":"native","configured":true,"connection_started":false,"stop_requested":false,
        "original_daemon_preserved":true,"runtime_kind":"rust"}),
    )
}

fn require_revoked_intent(paths: &Paths) -> Result<()> {
    // An unlocked service is not consent to resume it under a different runtime.
    // Do not parse, delete or forgive stale/invalid entries: explicit Stop owns revocation.
    match std::fs::symlink_metadata(paths.runtime().join("intent.json")) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(Error::with_exit("stopped-required", "Use explicit Stop to revoke the saved connection intent before migration, even when the backend is not running.", 6)),
    }
}
pub(crate) async fn migrate(paths: &Paths) -> Result<Value> {
    let _locks = lifecycle(paths)?;
    require_revoked_intent(paths)?;
    verify_profile(paths).await?;
    let raw = common::read_json(&paths.config(), true)?;
    let config = common::validate_config(raw.clone(), false)?;
    let previous = manifest(paths)?.ok_or_else(|| {
        Error::new(
            "ownership-required",
            "Explicit migration requires the existing installation ownership record.",
        )
    })?;
    check_rule(paths, &previous)?;
    let old_registration = registration(&paths.plugins())?.ok_or_else(changed)?;
    if previous["schema"] == 2 && raw["schema"] == 4 && old_registration.kind == "native" {
        return Ok(
            json!({"migrated":false,"already_native":true,"configuration_preserved":true,"connection_started":false,"stop_requested":false}),
        );
    }
    if raw["schema"] != 3 || previous["schema"] != 1 {
        return Err(Error::new("migration-required", "Migration requires a complete v0.3 schema-3 configuration and schema-1 ownership record."));
    }
    if old_registration.kind == "native" && paths.package != old_registration.source {
        return Err(changed());
    }
    // Provision is pinned and revalidates the original daemon without starting it.
    let descriptor = crate::gateway::provision(&config).await?;
    if descriptor["fingerprint"] != config["gateway"]["fingerprint"]
        || descriptor["daemon_socket"] != config["gateway"]["daemon_socket"]
    {
        return Err(changed());
    }
    let mut migration = if old_registration.kind == "linked" {
        Some(Migration::prepare(
            paths,
            old_registration.clone(),
            &previous,
        )?)
    } else {
        None
    };
    let package = paths.plugins().join(PLUGIN);
    let source = migration
        .as_ref()
        .map(|m| m.stage.as_path())
        .unwrap_or(&package);
    package_bytes(source)?;
    let new_record = record(
        paths,
        &package,
        recorded_ssh_digest(&previous)?,
        package_inventory(source)?,
    );
    let mut tx = Transaction::new();
    let result = (|| {
        require_revoked_intent(paths)?;
        check_rule(paths, &previous)?;
        if common::read_json(&paths.config(), true)? != raw
            || manifest(paths)?.as_ref() != Some(&previous)
            || registration(&paths.plugins())?.as_ref() != Some(&old_registration)
        {
            return Err(changed());
        }
        tx.put(
            &paths.config(),
            snapshot(&paths.config(), 65536)?,
            Some(json_bytes(&config)?),
            0o600,
        )?;
        if let Some(m) = &mut migration {
            m.activate(paths)?;
        }
        tx.put(
            &paths.manifest(),
            snapshot(&paths.manifest(), 65536)?,
            Some(json_bytes(&new_record)?),
            0o600,
        )?;
        Ok(())
    })();
    if let Err(error) = result {
        let reg_ok = migration
            .as_ref()
            .map(|m| m.rollback(paths).is_ok())
            .unwrap_or(true);
        let files_ok = tx.rollback().is_ok();
        return Err(if reg_ok && files_ok {
            error
        } else {
            recovery_error()
        });
    }
    Ok(
        json!({"migrated":true,"registration":"native","schema":4,"runtime_kind":"rust",
        "configuration_preserved":true,"credentials_preserved":true,"ssh_rule_preserved":true,
        "legacy_package_preserved":true,"managed_runtime_preserved":true,"remote_gateway_state_preserved":true,
        "remote_daemon_preserved":true,"connection_started":false,"stop_requested":false,"reload_expected":true}),
    )
}

pub(crate) async fn manage(paths: &Paths, action: &str) -> Result<Value> {
    let _locks = lifecycle(paths)?;
    verify_profile(paths).await?;
    let reg = registration(&paths.plugins())?.ok_or_else(changed)?;
    if reg.source != paths.package {
        return Err(changed());
    }
    let previous = manifest(paths)?;
    if action == "update" && reg.kind != "native" {
        return Err(Error::with_exit(
            "migration-required",
            "Complete the explicit native migration before updating a linked installation.",
            6,
        ));
    }
    if snapshot(&paths.config(), 65536)?.is_some() && previous.is_none() {
        return Err(Error::with_exit(
            "ownership-required",
            "Configured installations require their ownership record before management.",
            6,
        ));
    }
    let retired = previous
        .as_ref()
        .map(is_retired)
        .transpose()?
        .unwrap_or(false);
    if action == "uninstall"
        && (retired || previous.as_ref().is_none_or(|record| record["schema"] == 1))
    {
        return uninstall_retained(paths, &reg, previous.as_ref());
    }
    let owned_hashes = if let Some(record) = previous.as_ref().filter(|_| !retired) {
        if record["schema"] != 2 {
            return Err(Error::with_exit(
                "migration-required",
                "Migrate this v0.3 installation explicitly before native management.",
                6,
            ));
        }
        record["package_files"].clone()
    } else {
        package_inventory(&reg.source)?
    };
    ensure_package_unchanged(&reg.source, &owned_hashes)?;
    #[cfg(windows)]
    if action == "uninstall" {
        // 按已审核句柄移动注册，比让外部 CLI 对可变目录递归删除更严格。
        return uninstall_retained(paths, &reg, previous.as_ref());
    }
    if action == "update" {
        let retained = paths
            .data
            .join("retained-packages")
            .join(format!("pre-update-{:032x}", rand::random::<u128>()));
        let old_manifest = snapshot(&paths.manifest(), 65536)?;
        let old_config = snapshot(&paths.config(), 65536)?;
        move_registration(paths, &reg, &retained)?;
        let command = tern(
            paths,
            &[
                "plugin",
                "install",
                "github.com/jiwangyihao/tern-turn-relay",
                "--force",
            ],
        )
        .await;
        let mut tx = Transaction::new();
        let outcome = (|| {
            if !command.as_ref().is_ok_and(|o| o.status.success()) {
                return Err(Error::new(
                    "update-failed",
                    "Native plugin update failed; restoring the retained installation.",
                ));
            }
            let new = registration(&paths.plugins())?.ok_or_else(changed)?;
            if new.kind != "native" || new.source != reg.source {
                return Err(changed());
            }
            let inventory = package_inventory(&new.source)?;
            if PACKAGE_FILES
                .iter()
                .any(|name| inventory.get(*name).is_none())
            {
                return Err(changed());
            }
            if snapshot(&paths.config(), 65536)? != old_config {
                return Err(changed());
            }
            if let Some(mut record) = previous.clone() {
                record["package_files"] = inventory;
                tx.put(
                    &paths.manifest(),
                    old_manifest.clone(),
                    Some(json_bytes(&record)?),
                    0o600,
                )?;
            }
            Ok(())
        })();
        if let Err(error) = outcome {
            let rollback = (|| {
                if let Some(new) = registration(&paths.plugins())? {
                    if new.kind != "native" || new.source != reg.source {
                        return Err(changed());
                    }
                    let rejected = paths
                        .data
                        .join("retained-packages")
                        .join(format!("failed-update-{:032x}", rand::random::<u128>()));
                    move_registration(paths, &new, &rejected)?;
                }
                #[cfg(windows)]
                crate::windows_security::move_owned(&retained, &reg.source, Some((reg.dev, reg.ino)))?;
                #[cfg(unix)]
                rename_owned_directory(&retained, &reg.source)?;
                Ok(())
            })();
            let files_recovered = tx.rollback().is_ok();
            return Err(if rollback.is_ok() && files_recovered {
                error
            } else {
                recovery_error()
            });
        }
        return Ok(
            json!({"updated":true,"registration":"native","previous_package":retained,"configuration_preserved":true,
            "credentials_preserved":true,"managed_runtime_preserved":true,"data_preserved":true,"remote_daemon_preserved":true,
            "remote_gateway_state_preserved":true,"connection_started":false,"stop_requested":false,"reload_expected":true}),
        );
    }
    let ssh = if let Some(record) = &previous {
        owned_rule_removal(paths, record)?
    } else {
        None
    };
    let rule_removed = ssh.is_some();
    let mut tx = Transaction::new();
    if let Some(ssh) = ssh {
        if let Err(error) = tx.put(&paths.ssh, ssh.before, Some(ssh.bytes), 0o600) {
            tx.rollback()?;
            return Err(error);
        }
    }
    if let Some(record) = &previous {
        if let Err(error) = retire_ownership(&mut tx, paths, record) {
            tx.rollback()?;
            return Err(error);
        }
    }
    if registration(&paths.plugins())?.as_ref() != Some(&reg) {
        tx.rollback()?;
        return Err(changed());
    }
    let verb = if reg.kind == "native" {
        "remove"
    } else {
        "unlink"
    };
    let command = tern(paths, &["plugin", verb, PLUGIN]).await;
    match registration(&paths.plugins())? {
        None => Ok(
            json!({"plugin_removed":reg.kind == "native","plugin_unlinked":reg.kind != "native",
            "marked_ssh_rule_removed":rule_removed,"cli_reported_error":!command.as_ref().is_ok_and(|o| o.status.success()),
            "configuration_preserved":true,"credentials_preserved":true,"data_preserved":true,"managed_runtime_preserved":true,
            "remote_daemon_preserved":true,"remote_gateway_state_preserved":true,"connection_started":false,"stop_requested":false,
            "reload_expected":true,"secret_removal":"Use tern-turn-relay credentials remove-local separately with explicit authorization."}),
        ),
        Some(remaining) => {
            if remaining == reg {
                tx.rollback()?;
            }
            Err(Error::new("removal-unconfirmed", "Plugin removal was not confirmed; private data and independent changes were preserved."))
        }
    }
}

/// Public CLI wrapper uses the same review/consent boundary as the native UI.
pub async fn run(args: &[String]) -> Result<Value> {
    crate::onboarding::run(args).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::{symlink, PermissionsExt};
    fn temporary() -> PathBuf {
        #[cfg(unix)]
        let path = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("tern-install-test-{:032x}", rand::random::<u128>()));
        #[cfg(windows)]
        let path = std::env::temp_dir().join(format!("tern-install-test-{:032x}", rand::random::<u128>()));
        #[cfg(unix)]
        std::fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        #[cfg(windows)]
        common::private_dir(&path, true).unwrap();
        path
    }
    #[test]
    fn atomic_replacement_refuses_races_and_links() {
        let dir = temporary();
        let file = dir.join("key");
        replace(&file, None, Some(b"first"), 0o600).unwrap();
        let old = snapshot(&file, 64).unwrap().unwrap();
        replace(&file, Some(&old), Some(b"second"), 0o600).unwrap();
        assert!(replace(&file, Some(&old), Some(b"lost update"), 0o600).is_err());
        assert_eq!(snapshot(&file, 64).unwrap().unwrap().bytes, b"second");
        #[cfg(unix)]
        {
        symlink(&file, dir.join("link")).unwrap();
        assert!(snapshot(&dir.join("link"), 64).is_err());
        }
        std::fs::hard_link(&file, dir.join("hard")).unwrap();
        assert!(snapshot(&file, 64).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn rollback_restores_all_files_but_preserves_independent_edits() {
        let dir = temporary();
        let a = dir.join("a");
        let b = dir.join("b");
        replace(&a, None, Some(b"old"), 0o600).unwrap();
        let mut tx = Transaction::new();
        tx.put(
            &a,
            snapshot(&a, 64).unwrap(),
            Some(b"installed".to_vec()),
            0o600,
        )
        .unwrap();
        tx.put(&b, None, Some(b"new".to_vec()), 0o600).unwrap();
        let b_now = snapshot(&b, 64).unwrap();
        replace(&b, b_now.as_ref(), Some(b"user edit"), 0o600).unwrap();
        assert!(tx.rollback().is_err());
        assert_eq!(snapshot(&a, 64).unwrap().unwrap().bytes, b"old");
        assert_eq!(snapshot(&b, 64).unwrap().unwrap().bytes, b"user edit");
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn registration_rejects_ambiguity_and_unsafe_marker() {
        let dir = temporary();
        let plugins = dir.join("plugins");
        common::private_dir(&plugins, true).unwrap();
        common::private_dir(&plugins.join(PLUGIN), true).unwrap();
        replace(
            &plugins.join(format!("{PLUGIN}.path")),
            None,
            Some(format!("{}\n", dir.display()).as_bytes()),
            0o600,
        )
        .unwrap();
        assert!(registration(&plugins).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn package_inventory_accepts_source_distribution_and_detects_user_changes() {
        let dir = temporary();
        replace(
            &dir.join("native/src/main.rs"),
            None,
            Some(b"source"),
            0o600,
        )
        .unwrap();
        replace(
            &dir.join("docs/guide.txt"),
            None,
            Some(b"documentation"),
            0o600,
        )
        .unwrap();
        let owned = package_inventory(&dir).unwrap();
        assert!(ensure_package_unchanged(&dir, &owned).is_ok());
        replace(&dir.join("user-file"), None, Some(b"preserve"), 0o600).unwrap();
        assert_eq!(
            ensure_package_unchanged(&dir, &owned).unwrap_err().code,
            "package-modified"
        );
        assert_eq!(
            snapshot(&dir.join("user-file"), 64).unwrap().unwrap().bytes,
            b"preserve"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn private_metadata_does_not_require_valid_old_credential_json() {
        let dir = temporary();
        let path = dir.join("key");
        replace(&path, None, Some(b"damaged JSON"), 0o600).unwrap();
        assert!(snapshot(&path, 64)
            .unwrap()
            .unwrap()
            .require_private()
            .is_ok());
        #[cfg(unix)]
        {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(snapshot(&path, 64)
            .unwrap()
            .unwrap()
            .require_private()
            .is_err());
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn linked_migration_registration_swap_is_reversible() {
        let root = temporary();
        let data = root.join("plugin-data").join(PLUGIN);
        let source = data.join("packages/legacy");
        let package = root.join("new-package");
        replace(
            &source.join("relay.py"),
            None,
            Some(b"retained legacy source"),
            0o600,
        )
        .unwrap();
        for &name in PACKAGE_FILES {
            let content = if name == "release.json" {
                json_bytes(&json!({"schema":1,"version":env!("CARGO_PKG_VERSION"),"assets":{}}))
                    .unwrap()
            } else {
                b"release file".to_vec()
            };
            replace(&package.join(name), None, Some(&content), 0o600).unwrap();
        }
        let paths = Paths {
            data,
            package,
            profile: root.clone(),
            ssh: root.join("ssh-config"),
            aliases: root.join("aliases"),
            tern: None,
        };
        let marker = paths.plugins().join(format!("{PLUGIN}.path"));
        replace(
            &marker,
            None,
            Some(format!("{}\n", source.display()).as_bytes()),
            0o600,
        )
        .unwrap();
        let original = registration(&paths.plugins()).unwrap().unwrap();
        let previous = json!({"package":source});
        let mut migration = Migration::prepare(&paths, original.clone(), &previous).unwrap();
        migration.activate(&paths).unwrap();
        assert_eq!(
            registration(&paths.plugins()).unwrap().unwrap().kind,
            "native"
        );
        assert!(!marker.exists());
        migration.rollback(&paths).unwrap();
        assert_eq!(
            registration(&paths.plugins()).unwrap().as_ref(),
            Some(&original)
        );
        assert_eq!(
            snapshot(&source.join("relay.py"), 64)
                .unwrap()
                .unwrap()
                .bytes,
            b"retained legacy source"
        );
        std::fs::remove_dir_all(root).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn relative_legacy_links_normalize_without_following_filesystem_links() {
        assert_eq!(
            normalize_link_target(Path::new("/profile/plugins/../plugin-data/package")).unwrap(),
            Path::new("/profile/plugin-data/package")
        );
        assert!(normalize_link_target(Path::new("/../../escape")).is_err());
    }
    #[test]
    fn manifestless_uninstall_retains_user_files_and_unowned_ssh_content() {
        let root = temporary();
        let package = root.join("plugins").join(PLUGIN);
        let paths = Paths {
            data: root.join("plugin-data").join(PLUGIN),
            package: package.clone(),
            profile: root.clone(),
            ssh: root.join("ssh-config"),
            aliases: root.join("aliases"),
            tern: None,
        };
        replace(
            &package.join("plugin.toml"),
            None,
            Some(b"installed plugin"),
            0o600,
        )
        .unwrap();
        replace(
            &package.join("user-added.txt"),
            None,
            Some(b"must survive removal"),
            0o600,
        )
        .unwrap();
        replace(&paths.ssh, None, Some(b"Host user-owned\n"), 0o600).unwrap();
        assert!(manifest(&paths).unwrap().is_none());
        let reg = registration(&paths.plugins()).unwrap().unwrap();
        let result = uninstall_retained(&paths, &reg, None).unwrap();
        let retained = Path::new(result["retained_registration"].as_str().unwrap());
        assert!(registration(&paths.plugins()).unwrap().is_none());
        assert_eq!(
            snapshot(&retained.join("user-added.txt"), 64)
                .unwrap()
                .unwrap()
                .bytes,
            b"must survive removal"
        );
        assert_eq!(
            snapshot(&paths.ssh, 64).unwrap().unwrap().bytes,
            b"Host user-owned\n"
        );
        assert_eq!(result["installed_package_preserved"], true);
        assert_eq!(result["marked_ssh_rule_removed"], false);
        std::fs::remove_dir_all(root).unwrap();
    }
    fn owned_uninstall_fixture() -> (PathBuf, Paths, Value) {
        let root = temporary();
        let package = root.join("plugins").join(PLUGIN);
        let paths = Paths {
            data: root.join("plugin-data").join(PLUGIN),
            package: package.clone(),
            profile: root.clone(),
            ssh: root.join("ssh-config"),
            aliases: root.join("aliases"),
            tern: None,
        };
        replace(
            &package.join("plugin.toml"),
            None,
            Some(b"original package"),
            0o600,
        )
        .unwrap();
        let block = format!(
            "{}Match all\n{}",
            crate::ssh_config::BEGIN,
            crate::ssh_config::END
        );
        replace(
            &paths.ssh,
            None,
            Some(format!("{block}Host unrelated\n").as_bytes()),
            0o600,
        )
        .unwrap();
        let record = json!({"schema":2,"plugin":PLUGIN,"plugins":paths.plugins(),"package":package,
            "registration":"native","ssh_config":paths.ssh,"ssh_block_sha256":crate::ssh_config::block_digest(&block).unwrap(),
            "runtime":"rust","config_schema":4,"package_files":package_inventory(&package).unwrap()});
        replace(
            &paths.manifest(),
            None,
            Some(&json_bytes(&record).unwrap()),
            0o600,
        )
        .unwrap();
        (root, paths, record)
    }
    #[test]
    fn uninstall_retires_ssh_ownership_and_reinstall_preserves_saved_scope() {
        let (root, paths, record) = owned_uninstall_fixture();
        let reg = registration(&paths.plugins()).unwrap().unwrap();
        uninstall_retained(&paths, &reg, Some(&record)).unwrap();
        let retired = manifest(&paths).unwrap().unwrap();
        assert_eq!(retired["retired"], true);
        assert!(retired["ssh_block_sha256"].is_null());
        assert_eq!(retired["ssh_config"], record["ssh_config"]);
        assert_eq!(retired["package"], record["package"]);
        assert_eq!(
            snapshot(&paths.ssh, 128).unwrap().unwrap().bytes,
            b"Host unrelated\n"
        );
        replace(
            &paths.package.join("plugin.toml"),
            None,
            Some(b"reinstalled package"),
            0o600,
        )
        .unwrap();
        assert!(manifest(&paths).unwrap().unwrap()["retired"]
            .as_bool()
            .unwrap());
        assert!(check_rule(&paths, &retired).is_ok());
        let existing = snapshot(&paths.ssh, 128).unwrap();
        let foreign = format!(
            "{}Host user-edited\n{}Host unrelated\n",
            crate::ssh_config::BEGIN,
            crate::ssh_config::END
        );
        replace(
            &paths.ssh,
            existing.as_ref(),
            Some(foreign.as_bytes()),
            0o600,
        )
        .unwrap();
        assert!(check_rule(&paths, &retired).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn failed_uninstall_restores_manifest_and_ssh_ownership() {
        let (root, paths, record) = owned_uninstall_fixture();
        let mut stale = registration(&paths.plugins()).unwrap().unwrap();
        stale.ino = stale.ino.wrapping_add(1);
        let ssh_before = snapshot(&paths.ssh, 65536).unwrap().unwrap().bytes;
        assert!(uninstall_retained(&paths, &stale, Some(&record)).is_err());
        assert_eq!(manifest(&paths).unwrap().unwrap(), record);
        assert_eq!(
            snapshot(&paths.ssh, 65536).unwrap().unwrap().bytes,
            ssh_before
        );
        assert!(registration(&paths.plugins()).unwrap().is_some());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[tokio::test]
    async fn migration_requires_explicit_intent_revocation_even_when_service_is_unlocked() {
        let (root, paths, record) = owned_uninstall_fixture();
        common::private_dir(&paths.runtime(), true).unwrap();
        let config = json!({"schema":3,"ssh_destination":"server","listen_port":18377,
            "target":{"name":"server","host":"8.8.8.8","port":8377,"user":"example","fingerprint":"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
            "gateway":{"state_dir":"/home/example/gateway","daemon_socket":"/home/example/daemon.sock","fingerprint":"SHA256:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"},
            "credential_file":paths.credential(),"dependency_dir":paths.data.join("deps")});
        let original = json_bytes(&config).unwrap();
        replace(&paths.config(), None, Some(&original), 0o600).unwrap();
        let saved = json_bytes(&json!({"target":config["target"],"gateway":config["gateway"],"listen_port":18377,"ssh_destination":"server","mode":"tls"})).unwrap();
        let intent = paths.runtime().join("intent.json");
        for bytes in [
            saved,
            b"not valid JSON".to_vec(),
            b"{\"mode\":\"stale\"}".to_vec(),
        ] {
            replace(&intent, None, Some(&bytes), 0o600).unwrap();
            assert_eq!(migrate(&paths).await.unwrap_err().code, "stopped-required");
            assert_eq!(snapshot(&intent, 65536).unwrap().unwrap().bytes, bytes);
            assert_eq!(
                snapshot(&paths.config(), 65536).unwrap().unwrap().bytes,
                original
            );
            assert_eq!(manifest(&paths).unwrap().unwrap(), record);
            crate::intent::clear(&paths.runtime()).unwrap();
            assert!(require_revoked_intent(&paths).is_ok());
        }
        let outside = root.join("outside");
        replace(&outside, None, Some(b"preserve external target"), 0o600).unwrap();
        #[cfg(unix)]
        {
        symlink(&outside, &intent).unwrap();
        assert_eq!(migrate(&paths).await.unwrap_err().code, "stopped-required");
        crate::intent::clear(&paths.runtime()).unwrap();
        assert_eq!(
            snapshot(&outside, 64).unwrap().unwrap().bytes,
            b"preserve external target"
        );
        assert!(require_revoked_intent(&paths).is_ok());
        }
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn stale_registration_never_moves_a_replacement_directory() {
        let root = temporary();
        let package = root.join("plugins").join(PLUGIN);
        let paths = Paths {
            data: root.join("plugin-data").join(PLUGIN), package: package.clone(), profile: root.clone(),
            ssh: root.join("ssh-config"), aliases: root.join("aliases"), tern: None,
        };
        replace(&package.join("plugin.toml"), None, Some(b"original"), 0o600).unwrap();
        let reviewed = registration(&paths.plugins()).unwrap().unwrap();
        std::fs::rename(&package, root.join("retained-original")).unwrap();
        replace(&package.join("plugin.toml"), None, Some(b"user replacement"), 0o600).unwrap();
        let destination = paths.data.join("retained-packages/removed");
        assert_eq!(move_registration(&paths, &reviewed, &destination).unwrap_err().code, "review-changed");
        assert!(!destination.exists());
        assert_eq!(snapshot(&package.join("plugin.toml"), 64).unwrap().unwrap().bytes, b"user replacement");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn root_admin_group_write_is_allowed_only_for_executable_ancestry() {
        let executable = AncestorPolicy::Executable { admin_gid: Some(80) };
        assert!(directory_permissions_trusted(0, 80, 0o775, 501, executable));
        assert!(!directory_permissions_trusted(0, 80, 0o775, 501, AncestorPolicy::PrivateData));
        assert!(!directory_permissions_trusted(0, 80, 0o775, 501, AncestorPolicy::Executable { admin_gid: None }));
        for (owner, group, mode) in [(0, 80, 0o777), (0, 80, 0o757), (501, 80, 0o775), (0, 20, 0o775), (999, 80, 0o755)] {
            assert!(!directory_permissions_trusted(owner, group, mode, 501, executable));
        }
        for policy in [AncestorPolicy::PrivateData, executable] {
            assert!(directory_permissions_trusted(501, 20, 0o755, 501, policy));
            assert!(directory_permissions_trusted(0, 0, 0o755, 501, policy));
        }
        // Preserve the existing private-data policy for root-owned sticky /tmp.
        assert!(directory_permissions_trusted(0, 0, 0o1777, 501, AncestorPolicy::PrivateData));
    }
}
