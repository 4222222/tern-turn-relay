use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    fmt,
    fs::File,
    io::Read,
    net::Ipv4Addr,
    path::Path,
    process::Output,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
#[cfg(unix)]
use std::{ffi::{CString, OsStr}, io::Write, path::Component, os::{fd::{AsRawFd, FromRawFd}, unix::{ffi::OsStrExt, fs::MetadataExt}}};
#[cfg(unix)]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug, Clone)]
pub struct Error {
    pub code: &'static str,
    pub message: &'static str,
    pub exit_code: i32,
}
impl Error {
    pub fn new(code: &'static str, message: &'static str) -> Self {
        Self {
            code,
            message,
            exit_code: 7,
        }
    }
    pub fn with_exit(code: &'static str, message: &'static str, exit_code: i32) -> Self {
        Self {
            code,
            message,
            exit_code,
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message)
    }
}
impl std::error::Error for Error {}
fn path_error() -> Error {
    Error::new(
        "unsafe-path",
        "Private path ownership, type or permissions are invalid.",
    )
}
fn input_error() -> Error {
    Error::with_exit(
        "invalid-request",
        "Invalid bounded request or command arguments; values withheld.",
        2,
    )
}

pub struct Options {
    pub positionals: Vec<String>,
    values: HashMap<String, String>,
    flags: HashSet<String>,
}
impl Options {
    pub fn parse(args: &[String], value_flags: &[&str], bool_flags: &[&str]) -> Result<Self> {
        let mut result = Self {
            positionals: Vec::new(),
            values: HashMap::new(),
            flags: HashSet::new(),
        };
        let mut args = args.iter();
        while let Some(arg) = args.next() {
            if !arg.starts_with('-') {
                result.positionals.push(arg.clone());
                continue;
            }
            let (name, inline) = arg
                .split_once('=')
                .map_or((arg.as_str(), None), |(a, b)| (a, Some(b)));
            if value_flags.contains(&name) {
                let value = match inline {
                    Some(v) => v,
                    None => args.next().map(String::as_str).ok_or_else(input_error)?,
                };
                if value.is_empty()
                    || value.starts_with("--")
                    || result
                        .values
                        .insert(name.to_owned(), value.to_owned())
                        .is_some()
                {
                    return Err(input_error());
                }
            } else if bool_flags.contains(&name) && inline.is_none() {
                if !result.flags.insert(name.to_owned()) {
                    return Err(input_error());
                }
            } else {
                return Err(input_error());
            }
        }
        Ok(result)
    }
    pub fn get(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }
    pub fn required(&self, name: &str) -> Result<&str> {
        self.get(name).ok_or_else(input_error)
    }
    pub fn flag(&self, name: &str) -> bool {
        self.flags.contains(name)
    }
}

pub fn safe_alias(value: &str) -> Result<()> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 253
        || !(bytes[0].is_ascii_alphanumeric() || bytes[0] == b'_')
        || !bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(b))
    {
        return Err(input_error());
    }
    Ok(())
}
pub fn safe_absolute(value: &str) -> Result<()> {
    if value.len() > 4096
        || !value.starts_with('/')
        || value == "/"
        || value.starts_with("//")
        || value.ends_with('/')
        || value.bytes().any(|b| b < 32 || b == 127)
        || value
            .split('/')
            .skip(1)
            .any(|s| s.is_empty() || s == "." || s == "..")
    {
        return Err(path_error());
    }
    Ok(())
}
pub fn fingerprint(value: &str) -> Result<()> {
    let raw = value.strip_prefix("SHA256:").ok_or_else(input_error)?;
    let decoded = STANDARD_NO_PAD.decode(raw).map_err(|_| input_error())?;
    if decoded.len() != 32 || STANDARD_NO_PAD.encode(decoded) != raw {
        return Err(input_error());
    }
    Ok(())
}
#[cfg(unix)]
fn cname(value: &OsStr) -> Result<CString> {
    CString::new(value.as_bytes()).map_err(|_| path_error())
}
/// True when anyone besides the owner can modify the object through its mode.
/// Linux permits group write only for the current user's sole-member primary
/// group, freshly verified against complete local account files and files-only
/// NSS configuration. Other systems keep the strict 022 rule.
#[cfg(unix)]
pub fn foreign_writable(mode: u32, gid: u32) -> bool {
    mode & 0o002 != 0 || (mode & 0o020 != 0 && !private_group(gid))
}
#[cfg(target_os = "linux")]
fn private_group(gid: u32) -> bool {
    let (uid, primary) = unsafe { (libc::getuid(), libc::getgid()) };
    if gid != primary {
        return false;
    }
    // Do not use the ordinary permission checker here: it calls private_group.
    let read = |path: &str, limit: u64| -> Option<String> {
        let name = cname(OsStr::new(path)).ok()?;
        let fd = unsafe {
            libc::open(
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return None;
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let info = file.metadata().ok()?;
        if !info.is_file() || info.uid() != 0 || info.mode() & 0o022 != 0
            || info.nlink() != 1 || info.len() > limit
        {
            return None;
        }
        let mut text = String::new();
        file.take(limit + 1).read_to_string(&mut text).ok()?;
        (text.len() as u64 <= limit).then_some(text)
    };
    let Some(nsswitch) = read("/etc/nsswitch.conf", 65536) else { return false };
    if !files_only_accounts(&nsswitch) {
        return false;
    }
    let Some(passwd) = read("/etc/passwd", 4 << 20) else { return false };
    let Some(group) = read("/etc/group", 4 << 20) else { return false };
    user_private_group(&passwd, &group, uid, primary)
}
#[cfg(all(unix, not(target_os = "linux")))]
fn private_group(_gid: u32) -> bool {
    false
}
#[cfg(target_os = "linux")]
fn files_only_accounts(nsswitch: &str) -> bool {
    let (mut passwd, mut group) = (false, false);
    for line in nsswitch.lines() {
        let line = line.split('#').next().unwrap_or("");
        if !line.is_ascii() || line.contains('\\') || line.bytes().any(|b| b.is_ascii_control() && b != b'\t' && b != b'\r') {
            return false;
        }
        let line = line.trim_ascii();
        if line.is_empty() {
            continue;
        }
        let Some((database, sources)) = line.split_once(':') else { return false };
        let seen = match database.trim_ascii() {
            "passwd" => &mut passwd,
            "group" => &mut group,
            _ => continue,
        };
        let mut sources = sources.split_ascii_whitespace();
        if *seen || sources.next() != Some("files") || sources.next().is_some() {
            return false;
        }
        *seen = true;
    }
    passwd && group
}
/// Complete, unambiguous account records must identify exactly one account
/// with primary group `gid`, owned by `uid`, and no other group members.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn user_private_group(passwd: &str, group: &str, uid: u32, gid: u32) -> bool {
    let valid_name = |name: &str| {
        !name.is_empty() && !name.starts_with(['+', '-'])
            && !name.chars().any(|c| c.is_whitespace() || c == ',' || c == ':')
    };
    let id = |value: &str| -> Option<u32> {
        if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        value.parse::<u32>().ok().filter(|value| *value != u32::MAX)
    };
    let mut names = HashSet::new();
    let mut ids = HashSet::new();
    let mut name = None;
    for line in passwd.lines().filter(|line| !line.is_empty() && !line.starts_with('#')) {
        let mut fields = line.split(':');
        let record: [Option<&str>; 7] = std::array::from_fn(|_| fields.next());
        let [Some(entry_name), Some(_), Some(entry_uid), Some(entry_gid), Some(_), Some(_), Some(_)] = record else {
            return false;
        };
        let (Some(entry_uid), Some(entry_gid)) = (id(entry_uid), id(entry_gid)) else { return false };
        if fields.next().is_some() || line.bytes().any(|b| b.is_ascii_control())
            || !valid_name(entry_name) || !names.insert(entry_name) || !ids.insert(entry_uid)
        {
            return false;
        }
        if entry_gid == gid {
            if entry_uid != uid || name.is_some() {
                return false;
            }
            name = Some(entry_name);
        }
    }
    let Some(name) = name else { return false };
    names.clear();
    ids.clear();
    let mut members = HashSet::new();
    let mut defined = false;
    for line in group.lines().filter(|line| !line.is_empty() && !line.starts_with('#')) {
        let mut fields = line.split(':');
        let record: [Option<&str>; 4] = std::array::from_fn(|_| fields.next());
        let [Some(entry_name), Some(_), Some(entry_gid), Some(entry_members)] = record else { return false };
        let Some(entry_gid) = id(entry_gid) else { return false };
        if fields.next().is_some() || line.bytes().any(|b| b.is_ascii_control())
            || !valid_name(entry_name) || !names.insert(entry_name) || !ids.insert(entry_gid)
        {
            return false;
        }
        members.clear();
        if !entry_members.is_empty() && entry_members.split(',').any(|member| !valid_name(member) || !members.insert(member)) {
            return false;
        }
        if entry_gid == gid {
            if !(entry_members.is_empty() || entry_members == name) {
                return false;
            }
            defined = true;
        }
    }
    defined
}
#[cfg(unix)]
fn check_directory(file: &File, leaf_private: bool) -> Result<()> {
    let info = file.metadata().map_err(|_| path_error())?;
    let uid = unsafe { libc::geteuid() };
    if !info.is_dir()
        || (info.uid() != 0 && info.uid() != uid)
        || (foreign_writable(info.mode(), info.gid())
            && !(info.uid() == 0 && info.mode() & (libc::S_ISVTX as u32) != 0))
        || (leaf_private && (info.uid() != uid || info.mode() & 0o777 != 0o700))
    {
        return Err(path_error());
    }
    Ok(())
}
#[cfg(unix)]
fn directory_fd(path: &Path, create: bool, leaf_private: bool) -> Result<File> {
    if !path.is_absolute() {
        return Err(path_error());
    }
    let root = CString::new("/").unwrap();
    let fd = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(path_error());
    }
    let mut directory = unsafe { File::from_raw_fd(fd) };
    for part in path.components() {
        let name = match part {
            Component::RootDir => continue,
            Component::Normal(name) => cname(name)?,
            _ => return Err(path_error()),
        };
        let mut next = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if next < 0
            && create
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT)
        {
            let made = unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), 0o700) };
            if made < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
                return Err(path_error());
            }
            next = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
        }
        if next < 0 {
            return Err(path_error());
        }
        directory = unsafe { File::from_raw_fd(next) };
        check_directory(&directory, false)?;
    }
    check_directory(&directory, leaf_private)?;
    Ok(directory)
}
#[cfg(unix)]
fn parent_fd(path: &Path) -> Result<(File, CString)> {
    let parent = directory_fd(path.parent().ok_or_else(path_error)?, false, false)?;
    Ok((parent, cname(path.file_name().ok_or_else(path_error)?)?))
}
#[cfg(unix)]
pub fn private_dir(path: &Path, create: bool) -> Result<()> {
    directory_fd(path, create, true).map(|_| ())
}
#[cfg(unix)]
fn check_file(file: &File, private: bool, limit: u64) -> Result<()> {
    let info = file.metadata().map_err(|_| path_error())?;
    if !info.is_file()
        || info.uid() != unsafe { libc::geteuid() }
        || info.nlink() != 1
        || foreign_writable(info.mode(), info.gid())
        || (private && info.mode() & 0o777 != 0o600)
        || info.len() > limit
    {
        return Err(path_error());
    }
    Ok(())
}
// Reject duplicate keys at every nesting level before interpreting security decisions.
pub fn parse_json(data: &[u8]) -> Result<Value> {
    use serde::{
        de::{self, MapAccess, SeqAccess, Visitor},
        Deserialize, Deserializer,
    };
    struct Unique(Value);
    impl<'de> Deserialize<'de> for Unique {
        fn deserialize<D: Deserializer<'de>>(
            deserializer: D,
        ) -> std::result::Result<Self, D::Error> {
            struct Visit;
            impl<'de> Visitor<'de> for Visit {
                type Value = Unique;
                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    f.write_str("unambiguous JSON")
                }
                fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Unique, E> {
                    Ok(Unique(Value::Bool(v)))
                }
                fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Unique, E> {
                    Ok(Unique(json!(v)))
                }
                fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Unique, E> {
                    Ok(Unique(json!(v)))
                }
                fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Unique, E> {
                    serde_json::Number::from_f64(v)
                        .map(|n| Unique(Value::Number(n)))
                        .ok_or_else(|| E::custom("nonfinite number"))
                }
                fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Unique, E> {
                    Ok(Unique(Value::String(v.to_owned())))
                }
                fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Unique, E> {
                    Ok(Unique(Value::String(v)))
                }
                fn visit_unit<E: de::Error>(self) -> std::result::Result<Unique, E> {
                    Ok(Unique(Value::Null))
                }
                fn visit_none<E: de::Error>(self) -> std::result::Result<Unique, E> {
                    Ok(Unique(Value::Null))
                }
                fn visit_seq<A: SeqAccess<'de>>(
                    self,
                    mut a: A,
                ) -> std::result::Result<Unique, A::Error> {
                    let mut values = Vec::new();
                    while let Some(Unique(v)) = a.next_element()? {
                        values.push(v);
                    }
                    Ok(Unique(Value::Array(values)))
                }
                fn visit_map<A: MapAccess<'de>>(
                    self,
                    mut a: A,
                ) -> std::result::Result<Unique, A::Error> {
                    let mut values = serde_json::Map::new();
                    while let Some(key) = a.next_key::<String>()? {
                        if values.contains_key(&key) {
                            return Err(de::Error::custom("duplicate field"));
                        }
                        let Unique(value) = a.next_value()?;
                        values.insert(key, value);
                    }
                    Ok(Unique(Value::Object(values)))
                }
            }
            deserializer.deserialize_any(Visit)
        }
    }
    serde_json::from_slice::<Unique>(data)
        .map(|v| v.0)
        .map_err(|_| input_error())
}
#[cfg(unix)]
pub fn read_json(path: &Path, private: bool) -> Result<Value> {
    let (parent, name) = parent_fd(path)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                Error::with_exit("not-found", "Private file does not exist.", 3)
            } else {
                path_error()
            },
        );
    }
    let file = unsafe { File::from_raw_fd(fd) };
    check_file(&file, private, 65536)?;
    let mut data = Vec::new();
    file.take(65537)
        .read_to_end(&mut data)
        .map_err(|_| path_error())?;
    if data.len() > 65536 {
        return Err(input_error());
    }
    parse_json(&data)
}
pub fn read_json_stdin(limit: usize) -> Result<Value> {
    let mut data = Vec::new();
    std::io::stdin()
        .lock()
        .take(limit as u64 + 1)
        .read_to_end(&mut data)
        .map_err(|_| input_error())?;
    if data.len() > limit {
        return Err(input_error());
    }
    parse_json(&data)
}
#[cfg(unix)]
pub fn atomic_json(path: &Path, value: &Value) -> Result<()> {
    let (parent, name) = parent_fd(path)?;
    let existing = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if existing >= 0 {
        check_file(&unsafe { File::from_raw_fd(existing) }, false, 1024 * 1024)?;
    } else if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
        return Err(path_error());
    }
    let temporary = CString::new(format!(".tern-{:032x}.tmp", rand::random::<u128>())).unwrap();
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            temporary.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(path_error());
    }
    let result = (|| {
        let mut file = unsafe { File::from_raw_fd(fd) };
        serde_json::to_writer(&mut file, value).map_err(|_| input_error())?;
        file.write_all(b"\n").map_err(|_| path_error())?;
        file.sync_all().map_err(|_| path_error())?;
        if unsafe {
            libc::renameat(
                parent.as_raw_fd(),
                temporary.as_ptr(),
                parent.as_raw_fd(),
                name.as_ptr(),
            )
        } < 0
        {
            return Err(path_error());
        }
        parent.sync_all().map_err(|_| path_error())?;
        Ok(())
    })();
    if result.is_err() {
        unsafe { libc::unlinkat(parent.as_raw_fd(), temporary.as_ptr(), 0) };
    }
    result
}
#[cfg(unix)]
pub fn lock(path: &Path, nonblocking: bool) -> Result<File> {
    let (parent, name) = parent_fd(path)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(path_error());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    check_file(&file, true, u64::MAX)?;
    if unsafe {
        libc::flock(
            file.as_raw_fd(),
            libc::LOCK_EX | if nonblocking { libc::LOCK_NB } else { 0 },
        )
    } < 0
    {
        return Err(Error::new(
            "lock-busy",
            "Another operation owns the lifecycle lock.",
        ));
    }
    Ok(file)
}
#[cfg(unix)]
pub fn is_locked(path: &Path) -> Result<bool> {
    match path.symlink_metadata() {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(path_error()),
    }
    let (parent, name) = parent_fd(path)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(path_error());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    check_file(&file, true, u64::MAX)?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(false);
    }
    let code = std::io::Error::last_os_error().raw_os_error();
    if code == Some(libc::EWOULDBLOCK) || code == Some(libc::EAGAIN) {
        Ok(true)
    } else {
        Err(path_error())
    }
}
fn exact(value: &Value, fields: &[&str]) -> Result<()> {
    let object = value.as_object().ok_or_else(input_error)?;
    if object.len() != fields.len() || fields.iter().any(|key| !object.contains_key(*key)) {
        return Err(input_error());
    }
    Ok(())
}
fn global_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, d] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || a >= 224
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && (b == 168 || (b == 0 && ((c == 0 && d != 9 && d != 10) || c == 2))))
        || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
        || (a == 203 && b == 0 && c == 113))
}
pub fn validate_config(mut value: Value, allow_unprovisioned: bool) -> Result<Value> {
    let schema = value
        .get("schema")
        .and_then(Value::as_u64)
        .ok_or_else(input_error)?;
    if schema == 3 {
        exact(
            &value,
            &[
                "schema",
                "target",
                "gateway",
                "listen_port",
                "credential_file",
                "dependency_dir",
                "ssh_destination",
            ],
        )?;
        safe_absolute(value["dependency_dir"].as_str().ok_or_else(input_error)?)?;
        value.as_object_mut().unwrap().remove("dependency_dir");
        value["schema"] = json!(4);
    } else if schema != 4 {
        return Err(input_error());
    }
    exact(
        &value,
        &[
            "schema",
            "target",
            "gateway",
            "listen_port",
            "credential_file",
            "ssh_destination",
        ],
    )?;
    safe_alias(value["ssh_destination"].as_str().ok_or_else(input_error)?)?;
    let target = &value["target"];
    exact(target, &["name", "host", "port", "user", "fingerprint"])?;
    let host = target["host"].as_str().ok_or_else(input_error)?;
    let ip: Ipv4Addr = host.parse().map_err(|_| input_error())?;
    if !global_ipv4(ip) || ip.to_string() != host {
        return Err(input_error());
    }
    for name in ["name", "user"] {
        let field = target[name].as_str().ok_or_else(input_error)?;
        safe_alias(field)?;
        if field.len() > 64 {
            return Err(input_error());
        }
    }
    for (port, min) in [(&target["port"], 1), (&value["listen_port"], 1024)] {
        let port = port.as_u64().ok_or_else(input_error)?;
        if port < min || port > 65535 {
            return Err(input_error());
        }
    }
    let gateway = &value["gateway"];
    if allow_unprovisioned && gateway.get("fingerprint").is_none() {
        exact(gateway, &["state_dir", "daemon_socket"])?;
    } else {
        exact(gateway, &["state_dir", "daemon_socket", "fingerprint"])?;
        fingerprint(gateway["fingerprint"].as_str().ok_or_else(input_error)?)?;
        if gateway["fingerprint"] == target["fingerprint"] {
            return Err(input_error());
        }
    }
    fingerprint(target["fingerprint"].as_str().ok_or_else(input_error)?)?;
    for name in ["state_dir", "daemon_socket"] {
        safe_absolute(gateway[name].as_str().ok_or_else(input_error)?)?;
    }
    safe_local_absolute(value["credential_file"].as_str().ok_or_else(input_error)?)?;
    Ok(value)
}
pub fn load_config(path: &Path, allow_unprovisioned: bool) -> Result<Value> {
    validate_config(read_json(path, false)?, allow_unprovisioned)
}
pub fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
pub fn ssh_args(alias: &str, remote_command: &str) -> Vec<String> {
    let mut args = vec!["-T".to_owned()];
    for option in [
        "BatchMode=yes",
        "StrictHostKeyChecking=yes",
        "UpdateHostKeys=no",
        "ForwardAgent=no",
        "PasswordAuthentication=no",
        "KbdInteractiveAuthentication=no",
        "NumberOfPasswordPrompts=0",
        "ClearAllForwardings=yes",
        "PermitLocalCommand=no",
        "RequestTTY=no",
        "ControlMaster=no",
        "ControlPath=none",
        "ConnectTimeout=10",
        "ConnectionAttempts=1",
        "ServerAliveInterval=15",
        "ServerAliveCountMax=2",
        "EscapeChar=none",
    ] {
        args.extend(["-o".into(), option.into()]);
    }
    args.extend([alias.to_owned(), remote_command.to_owned()]);
    args
}
#[cfg(unix)]
async fn bounded_output<R: AsyncRead + Unpin>(reader: R) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    reader
        .take(1024 * 1024 + 1)
        .read_to_end(&mut data)
        .await
        .map_err(|_| Error::new("process-io", "Owned subprocess communication failed."))?;
    if data.len() > 1024 * 1024 {
        return Err(Error::new(
            "response-limit",
            "Owned subprocess output exceeded its limit.",
        ));
    }
    Ok(data)
}
// Every bounded helper owns a private process group, including SSH Match-exec children.
#[cfg(unix)]
struct OwnedProcessGroup(Option<libc::pid_t>);
#[cfg(unix)]
impl OwnedProcessGroup {
    fn terminate(&mut self) {
        if let Some(pid) = self.0.take() {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        }
    }
    async fn observe_exit(&mut self, events: &mut tokio::signal::unix::Signal) -> Result<()> {
        loop {
            let pid = self.0.ok_or_else(|| {
                Error::new(
                    "process-ownership-lost",
                    "Owned subprocess identity is no longer pinned.",
                )
            })?;
            let (status, signal, code) = {
                let mut information: libc::siginfo_t = unsafe { std::mem::zeroed() };
                let status = unsafe {
                    libc::waitid(
                        libc::P_PID,
                        pid as libc::id_t,
                        &mut information,
                        libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                    )
                };
                (
                    status,
                    information.si_signo,
                    if status < 0 {
                        std::io::Error::last_os_error().raw_os_error()
                    } else {
                        None
                    },
                )
            };
            if status < 0 {
                if code == Some(libc::EINTR) {
                    continue;
                }
                if code == Some(libc::ECHILD) {
                    self.0 = None;
                }
                return Err(Error::new(
                    "process-ownership-lost",
                    "Cannot observe the unreaped owned subprocess.",
                ));
            }
            if signal == libc::SIGCHLD {
                return Ok(());
            }
            if events.recv().await.is_none() {
                return Err(Error::new(
                    "process-wait",
                    "Owned subprocess exit notification ended.",
                ));
            }
        }
    }
}
#[cfg(unix)]
impl Drop for OwnedProcessGroup {
    fn drop(&mut self) {
        self.terminate();
    }
}
#[cfg(unix)]
pub async fn run(
    program: &str,
    args: &[String],
    input: Option<&[u8]>,
    deadline: Duration,
) -> Result<Output> {
    use std::{os::unix::process::CommandExt, process::Stdio};
    let mut exits =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::child()).map_err(|_| {
            Error::new(
                "process-wait",
                "Cannot register owned subprocess exit notification.",
            )
        })?;
    let mut command = tokio::process::Command::new(program);
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    command.as_std_mut().process_group(0);
    let mut child = command.spawn().map_err(|_| {
        Error::new(
            "process-start",
            "Cannot start the required owned subprocess.",
        )
    })?;
    let mut group = OwnedProcessGroup(child.id().map(|pid| pid as libc::pid_t));
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let operation = async {
        let send = async {
            if let Some(data) = input {
                stdin
                    .write_all(data)
                    .await
                    .map_err(|_| Error::new("process-io", "Owned subprocess input failed."))?;
            }
            drop(stdin);
            Ok(())
        };
        let (stdout, stderr, ()) =
            tokio::try_join!(bounded_output(stdout), bounded_output(stderr), send)?;
        // Keep the unreaped group leader as the ownership pin until descendants are stopped.
        group.observe_exit(&mut exits).await?;
        group.terminate();
        let status = child
            .wait()
            .await
            .map_err(|_| Error::new("process-wait", "Cannot observe owned subprocess exit."))?;
        Ok(Output {
            status,
            stdout,
            stderr,
        })
    };
    match tokio::time::timeout(deadline, operation).await {
        Ok(Ok(output)) => Ok(output),
        result => {
            group.terminate();
            let _ = child.kill().await;
            let _ = child.wait().await;
            match result {
                Ok(Err(error)) => Err(error),
                _ => Err(Error::new(
                    "process-timeout",
                    "Owned subprocess exceeded its operation deadline.",
                )),
            }
        }
    }
}
#[cfg(windows)]
pub async fn run(program: &str, args: &[String], input: Option<&[u8]>, deadline: Duration) -> Result<Output> {
    crate::windows_process::run(program, args, input, deadline).await
}

pub fn safe_local_absolute(value: &str) -> Result<()> {
    #[cfg(unix)]
    { safe_absolute(value) }
    #[cfg(windows)]
    { crate::windows_security::validate_path(value) }
}

pub fn ssh_executable() -> Result<String> {
    #[cfg(unix)]
    { Ok("/usr/bin/ssh".to_owned()) }
    #[cfg(windows)]
    { crate::windows_security::ssh_executable() }
}

#[cfg(windows)]
pub fn private_dir(path: &Path, create: bool) -> Result<()> {
    crate::windows_security::directory(path, create, true)?.ok_or_else(path_error).map(|_| ())
}
#[cfg(windows)]
pub fn read_json(path: &Path, private: bool) -> Result<Value> {
    let snapshot = crate::install::snapshot(path, 65536)?.ok_or_else(|| Error::with_exit("not-found", "私有文件不存在。", 3))?;
    if private { snapshot.require_private()?; }
    parse_json(&snapshot.bytes)
}
#[cfg(windows)]
pub fn atomic_json(path: &Path, value: &Value) -> Result<()> {
    let mut bytes = serde_json::to_vec(value).map_err(|_| input_error())?;
    bytes.push(b'\n');
    if bytes.len() > 65536 { return Err(input_error()); }
    let before = crate::install::snapshot(path, 1024 * 1024)?;
    crate::install::replace(path, before.as_ref(), Some(&bytes), 0o600)
}
#[cfg(windows)]
pub fn lock(path: &Path, nonblocking: bool) -> Result<File> {
    crate::windows_security::lock(path, nonblocking, true)?.ok_or_else(path_error)
}
#[cfg(windows)]
pub fn is_locked(path: &Path) -> Result<bool> {
    match crate::windows_security::lock(path, true, false) {
        Ok(_) => Ok(false),
        Err(error) if error.code == "lock-busy" => Ok(true),
        Err(error) => Err(error),
    }
}

pub fn unix_time() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}
pub fn public_status(
    config: Option<&Value>,
    state: &str,
    mode: Option<&str>,
    service_id: Option<&str>,
    error: Option<&str>,
) -> Value {
    let address = config.map(|c| {
        format!(
            "{}@127.0.0.1:{}",
            c["target"]["user"].as_str().unwrap_or(""),
            c["listen_port"].as_u64().unwrap_or(0)
        )
    });
    json!({"ok":state!="error","state":state,"mode":mode,"address":address,"target":config.map(|c|c["target"].clone()),"ssh_destination":config.map(|c|c["ssh_destination"].clone()),"relay_fingerprint":config.map(|c|c["gateway"]["fingerprint"].clone()),"daemon_socket":config.map(|c|c["gateway"]["daemon_socket"].clone()),"route_policy":"exclusive","ssh_connections":0,"queue_dropped_packets":0,"queue_dropped_bytes":0,"queued_packets":0,"queued_bytes":0,"congested":false,"bytes_up":0,"bytes_down":0,"flows":0,"error":error,"service_id":service_id,"credentials_expires_at":null})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_option_confusion() {
        assert!(Options::parse(
            &["--config".into(), "--stop".into()],
            &["--config"],
            &["--stop"]
        )
        .is_err());
        assert!(Options::parse(&["--yes".into(), "--yes".into()], &[], &["--yes"]).is_err());
    }
    #[test]
    fn rejects_remote_option_injection() {
        for alias in ["-oProxyCommand=x", "root@host", "host;id", "host\n"] {
            assert!(safe_alias(alias).is_err());
        }
    }
    #[test]
    fn rejects_noncanonical_paths() {
        for path in ["/a/../b", "//host/a", "/a//b", "/a/./b", "/a/", "relative"] {
            assert!(safe_absolute(path).is_err());
        }
    }
    #[test]
    fn shell_quotes_single_quotes() {
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
    }
    #[test]
    fn group_write_is_trusted_only_for_a_sole_member_private_group() {
        let passwd = "root:x:0:0:root:/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/sh\nbob:x:1001:1001::/home/bob:/bin/sh\n";
        let group = "root:x:0:\nalice:x:1000:\nbob:x:1001:\nstaff:x:50:alice,bob\nsolo:x:60:alice\n";
        assert!(user_private_group(passwd, group, 1000, 1000));
        // Another account's private group, or a shared group, still lets others write.
        assert!(!user_private_group(passwd, group, 1000, 1001));
        assert!(!user_private_group(passwd, group, 1000, 50));
        // No account has it as its primary group (typical setgid groups).
        assert!(!user_private_group(passwd, group, 1000, 60));
        // A second account sharing the primary group, or a listed second member.
        let shared = format!("{passwd}carol:x:1002:1000::/home/carol:/bin/sh\n");
        assert!(!user_private_group(&shared, group, 1000, 1000));
        assert!(!user_private_group(passwd, "alice:x:1000:carol\n", 1000, 1000));
        assert!(user_private_group(passwd, "alice:x:1000:alice\n", 1000, 1000));
        // Duplicate or malformed group definitions fail closed.
        assert!(!user_private_group(passwd, "alice:x:1000:\nalias:x:1000:\n", 1000, 1000));
        assert!(!user_private_group(passwd, "alice:x:1000\n", 1000, 1000));
        assert!(!user_private_group(passwd, "", 1000, 1000));
    }
    #[test]
    fn duplicate_security_decisions_are_rejected() {
        assert!(parse_json(br#"{"review":{"confirm":false,"confirm":true}}"#).is_err());
        assert!(parse_json(br#"{"items":[{"pin":"a","pin":"b"}]}"#).is_err());
        assert_eq!(
            parse_json(br#"{"confirm":false}"#).unwrap()["confirm"],
            false
        );
    }
    #[cfg(unix)]
    struct PrivateTestDir(std::path::PathBuf);
    #[cfg(unix)]
    impl PrivateTestDir {
        fn new() -> Self {
            use std::os::unix::fs::PermissionsExt;
            let root = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("ttr-security-{:032x}", rand::random::<u128>()));
            std::fs::create_dir(&root).unwrap();
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(root)
        }
    }
    #[cfg(unix)]
    impl Drop for PrivateTestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[cfg(unix)]
    #[test]
    fn private_json_rejects_links_and_public_permissions() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let root = PrivateTestDir::new();
        let source = root.0.join("key.json");
        atomic_json(&source, &json!({"value":"private"})).unwrap();
        let link = root.0.join("link.json");
        symlink(&source, &link).unwrap();
        assert!(read_json(&link, true).is_err());
        let hard = root.0.join("hard.json");
        std::fs::hard_link(&source, &hard).unwrap();
        assert!(read_json(&source, true).is_err());
        std::fs::remove_file(hard).unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_json(&source, true).is_err());
        assert_eq!(read_json(&source, false).unwrap()["value"], "private");
    }
    #[cfg(unix)]
    #[test]
    fn atomic_write_refuses_shared_inode_without_modification() {
        let root = PrivateTestDir::new();
        let source = root.0.join("config.json");
        atomic_json(&source, &json!({"binding":"original"})).unwrap();
        let hard = root.0.join("other.json");
        std::fs::hard_link(&source, &hard).unwrap();
        assert!(atomic_json(&source, &json!({"binding":"replacement"})).is_err());
        assert_eq!(
            serde_json::from_slice::<Value>(&std::fs::read(&hard).unwrap()).unwrap()["binding"],
            "original"
        );
    }
    #[cfg(unix)]
    #[test]
    fn lifecycle_observation_does_not_create_or_follow_locks() {
        use std::os::unix::fs::symlink;
        let root = PrivateTestDir::new();
        let path = root.0.join("service.lock");
        assert!(!is_locked(&path).unwrap());
        assert!(!path.exists());
        let held = lock(&path, true).unwrap();
        assert!(is_locked(&path).unwrap());
        drop(held);
        assert!(!is_locked(&path).unwrap());
        std::fs::remove_file(&path).unwrap();
        symlink(root.0.join("missing"), &path).unwrap();
        assert!(is_locked(&path).is_err());
    }
    #[test]
    fn schema_migration_preserves_identity_and_rejects_null_pin() {
        let target_pin = format!("SHA256:{}", STANDARD_NO_PAD.encode([1u8; 32]));
        let gateway_pin = format!("SHA256:{}", STANDARD_NO_PAD.encode([2u8; 32]));
        #[cfg(unix)]
        let credential = "/home/user/key.json".to_owned();
        #[cfg(windows)]
        let credential = crate::windows_security::home().unwrap().join("key.json").to_str().unwrap().to_owned();
        let old = json!({"schema":3,"target":{"name":"server","host":"8.8.8.8","port":8376,"user":"user","fingerprint":target_pin},"gateway":{"state_dir":"/home/user/gateway","daemon_socket":"/run/user/1000/tern.sock","fingerprint":gateway_pin},"listen_port":18377,"credential_file":credential,"dependency_dir":"/home/user/deps","ssh_destination":"server"});
        let migrated = validate_config(old.clone(), false).unwrap();
        assert_eq!(migrated["schema"], 4);
        assert!(migrated.get("dependency_dir").is_none());
        for field in [
            "target",
            "gateway",
            "credential_file",
            "ssh_destination",
            "listen_port",
        ] {
            assert_eq!(old[field], migrated[field]);
        }
        let mut bad = migrated;
        bad["gateway"]["fingerprint"] = Value::Null;
        assert!(validate_config(bad, true).is_err());
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn timed_out_helper_cannot_leave_a_descendant_writing_later() {
        let root = PrivateTestDir::new();
        let marker = root.0.join("late-write");
        let script = format!(
            "(sleep 0.3; printf leaked > {}) >/dev/null 2>&1 & wait",
            shell_quote(marker.to_str().unwrap())
        );
        let result = run(
            "/bin/sh",
            &["-c".to_owned(), script],
            None,
            Duration::from_millis(50),
        )
        .await;
        assert_eq!(result.unwrap_err().code, "process-timeout");
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(
            !marker.exists(),
            "owned descendant survived the operation deadline"
        );
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn group_cleanup_preserves_the_leaders_exit_status() {
        let output = run(
            "/bin/sh",
            &["-c".to_owned(), "exit 23".to_owned()],
            None,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(output.status.code(), Some(23));
    }
}
