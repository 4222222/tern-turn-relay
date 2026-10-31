//! Windows 私有文件边界：创建时 DACL、逐级固定目录句柄、拒绝重解析和共享 inode。
use crate::common::{Error, Result};
use std::{
    ffi::c_void,
    fs::File,
    io::{Read, Write},
    mem::{offset_of, size_of},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle},
    },
    path::{Path, PathBuf},
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
    System::{
        Threading::{GetCurrentProcess, OpenProcessToken},
        IO::OVERLAPPED,
    },
};

fn unsafe_path() -> Error {
    Error::new(
        "unsafe-path",
        "本机对象的归属、权限或身份不安全；详细路径已隐藏。",
    )
}
fn changed() -> Error {
    Error::with_exit(
        "review-changed",
        "本机资源已更改；已保留用户内容，请重新审核。",
        6,
    )
}
fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}
fn missing() -> bool {
    matches!(
        unsafe { GetLastError() },
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND
    )
}

pub fn safe_path(value: &str) -> Result<()> {
    let b = value.as_bytes();
    if b.len() < 4
        || b.len() > 32700
        || !b[0].is_ascii_alphabetic()
        || b[1] != b':'
        || !matches!(b[2], b'\\' | b'/')
        || value.chars().any(|c| c.is_control())
    {
        return Err(unsafe_path());
    }
    for part in value[3..].split(['\\', '/']) {
        if part.is_empty()
            || part == "."
            || part == ".."
            || part.ends_with([' ', '.'])
            || part.contains([':', '<', '>', '"', '|', '?', '*'])
        {
            return Err(unsafe_path());
        }
        let stem = part.split('.').next().unwrap_or("").to_ascii_uppercase();
        if matches!(
            stem.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        ) || ((stem.starts_with("COM") || stem.starts_with("LPT"))
            && matches!(
                &stem[3..],
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            ))
        {
            return Err(unsafe_path());
        }
    }
    Ok(())
}

struct LocalMemory(*mut c_void);
impl Drop for LocalMemory {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
fn sid_text(sid: PSID) -> Result<String> {
    let mut text = null_mut();
    if sid.is_null()
        || unsafe { IsValidSid(sid) } == 0
        || unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0
    {
        return Err(unsafe_path());
    }
    let _memory = LocalMemory(text.cast());
    let mut len = 0;
    while unsafe { *text.add(len) } != 0 {
        len += 1;
    }
    String::from_utf16(unsafe { std::slice::from_raw_parts(text, len) }).map_err(|_| unsafe_path())
}
fn current_sid() -> Result<String> {
    let mut token = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(unsafe_path());
    }
    let token = unsafe { File::from_raw_handle(token) };
    let mut size = 0;
    unsafe {
        GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut size);
    }
    if size == 0 || size > 65536 {
        return Err(unsafe_path());
    }
    let mut data = vec![0usize; (size as usize).div_ceil(size_of::<usize>())];
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            data.as_mut_ptr().cast(),
            size,
            &mut size,
        )
    } == 0
    {
        return Err(unsafe_path());
    }
    sid_text(unsafe { (*(data.as_ptr().cast::<TOKEN_USER>())).User.Sid })
}
pub struct OwnedSecurityAttributes {
    attributes: SECURITY_ATTRIBUTES,
    _descriptor: LocalMemory,
}
impl OwnedSecurityAttributes {
    pub fn as_ptr(&mut self) -> *mut c_void {
        (&mut self.attributes as *mut SECURITY_ATTRIBUTES).cast()
    }
}
fn security_attributes(sddl: &str) -> Result<OwnedSecurityAttributes> {
    let text: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut descriptor = null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(unsafe_path());
    }
    Ok(OwnedSecurityAttributes {
        attributes: SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        },
        _descriptor: LocalMemory(descriptor),
    })
}
pub fn private_security_attributes() -> Result<OwnedSecurityAttributes> {
    let sid = current_sid()?;
    security_attributes(&format!(
        "O:{sid}D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
    ))
}
const TRUSTED_INSTALLER: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
fn trusted(sid: &str, user: &str) -> bool {
    sid == user || matches!(sid, "S-1-5-18" | "S-1-5-32-544") || sid == TRUSTED_INSTALLER
}

/// 私有叶对象严格检查授权；普通宿主资源信任安装环境，仍记录 ACL 以检测审核后的更改。
pub fn check_acl(file: &File, private: bool, user_owned: bool, ancestor: bool) -> Result<Vec<u8>> {
    check_acl_for(file, private, user_owned, ancestor, &current_sid()?)
}
fn check_acl_for(
    file: &File,
    private: bool,
    user_owned: bool,
    ancestor: bool,
    user: &str,
) -> Result<Vec<u8>> {
    let mut owner = null_mut();
    let mut acl = null_mut();
    let mut descriptor = null_mut();
    let security_status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut acl,
            null_mut(),
            &mut descriptor,
        )
    };
    if security_status != ERROR_SUCCESS {
        return Err(unsafe_path());
    }
    let _descriptor = LocalMemory(descriptor);
    let owner = sid_text(owner)?;
    if (user_owned && owner != user)
        || !trusted(&owner, user)
        || acl.is_null()
        || unsafe { IsValidAcl(acl) } == 0
    {
        return Err(unsafe_path());
    }
    // 用户明确接受宿主信任模型；不要求祖先和普通配置排除所有额外身份。
    // 空 user 专用于系统程序验证，仍执行下面的严格检查。
    if !private && !user.is_empty() {
        let len = unsafe { GetSecurityDescriptorLength(descriptor) } as usize;
        return Ok(unsafe { std::slice::from_raw_parts(descriptor.cast::<u8>(), len) }.to_vec());
    }
    for i in 0..unsafe { (*acl).AceCount } as u32 {
        let mut ace = null_mut();
        if unsafe { GetAce(acl, i, &mut ace) } == 0 {
            return Err(unsafe_path());
        }
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if header.AceFlags & INHERIT_ONLY_ACE as u8 != 0 {
            continue;
        }
        // 对条件/对象特定等未知 ACE 失败关闭，不将其误当成拒绝授权。
        if header.AceType == 1 {
            continue;
        }
        if header.AceType != 0 || (header.AceSize as usize) < size_of::<ACCESS_ALLOWED_ACE>() {
            return Err(unsafe_path());
        }
        let allow = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = sid_text((&allow.SidStart as *const u32).cast_mut().cast())?;
        let write = if ancestor {
            DELETE | FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER | GENERIC_ALL | GENERIC_WRITE
        } else {
            DELETE
                | FILE_WRITE_DATA
                | FILE_APPEND_DATA
                | FILE_WRITE_EA
                | FILE_WRITE_ATTRIBUTES
                | WRITE_DAC
                | WRITE_OWNER
                | GENERIC_ALL
                | GENERIC_WRITE
        };
        if !trusted(&sid, user) && (private && allow.Mask != 0 || allow.Mask & write != 0) {
            return Err(unsafe_path());
        }
    }
    let len = unsafe { GetSecurityDescriptorLength(descriptor) } as usize;
    Ok(unsafe { std::slice::from_raw_parts(descriptor.cast::<u8>(), len) }.to_vec())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub volume: u64,
    pub index: u64,
    pub size: u64,
    pub written: u64,
    pub created: u64,
    pub attributes: u32,
}
pub fn identity(file: &File, directory: bool) -> Result<Identity> {
    identity_with_links(file, directory, false)
}
fn identity_with_links(file: &File, directory: bool, system_links: bool) -> Result<Identity> {
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
        || (!directory && (info.nNumberOfLinks == 0 || (!system_links && info.nNumberOfLinks != 1)))
    {
        return Err(unsafe_path());
    }
    Ok(Identity {
        volume: info.dwVolumeSerialNumber as u64,
        index: ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64,
        size: ((info.nFileSizeHigh as u64) << 32) | info.nFileSizeLow as u64,
        written: ((info.ftLastWriteTime.dwHighDateTime as u64) << 32)
            | info.ftLastWriteTime.dwLowDateTime as u64,
        created: ((info.ftCreationTime.dwHighDateTime as u64) << 32)
            | info.ftCreationTime.dwLowDateTime as u64,
        attributes: info.dwFileAttributes,
    })
}
fn open_raw(
    path: &Path,
    access: u32,
    share: u32,
    disposition: u32,
    attributes: Option<&mut OwnedSecurityAttributes>,
) -> Result<Option<File>> {
    let handle = unsafe {
        CreateFileW(
            wide(path).as_ptr(),
            access | READ_CONTROL,
            share,
            attributes.map_or(null(), |a| a.as_ptr().cast()),
            disposition,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return if missing() && disposition == OPEN_EXISTING {
            Ok(None)
        } else {
            Err(unsafe_path())
        };
    }
    Ok(Some(unsafe { File::from_raw_handle(handle) }))
}
/// 所有祖先都保持不允许 FILE_SHARE_DELETE 的句柄，直到该次操作完成。
pub struct Directory {
    _ancestors: Vec<File>,
    pub file: File,
}
pub fn directory(path: &Path, create: bool, private: bool) -> Result<Option<Directory>> {
    let text = path.to_str().ok_or_else(unsafe_path)?;
    let root_only = text.len() == 3
        && text.as_bytes()[0].is_ascii_alphabetic()
        && text.as_bytes()[1] == b':'
        && matches!(text.as_bytes()[2], b'\\' | b'/');
    if !root_only {
        safe_path(text)?;
    }
    let mut components = path.components();
    let mut cursor = PathBuf::from(components.next().ok_or_else(unsafe_path)?.as_os_str());
    cursor.push(components.next().ok_or_else(unsafe_path)?.as_os_str());
    let root = open_raw(
        &cursor,
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        OPEN_EXISTING,
        None,
    )?
    .ok_or_else(unsafe_path)?;
    identity(&root, true)?;
    check_acl(&root, false, false, true)?;
    let mut held = vec![root];
    for component in components {
        cursor.push(component.as_os_str());
        let mut next = open_raw(
            &cursor,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            OPEN_EXISTING,
            None,
        )?;
        if next.is_none() && create {
            let mut security = private_security_attributes()?;
            if unsafe { CreateDirectoryW(wide(&cursor).as_ptr(), security.as_ptr().cast()) } == 0
                && unsafe { GetLastError() } != ERROR_ALREADY_EXISTS
            {
                return Err(unsafe_path());
            }
            next = open_raw(
                &cursor,
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                OPEN_EXISTING,
                None,
            )?;
        }
        let Some(next) = next else {
            return Ok(None);
        };
        identity(&next, true)?;
        check_acl(&next, false, false, true)?;
        held.push(next);
    }
    let file = held.pop().ok_or_else(unsafe_path)?;
    check_acl(&file, private, private, root_only)?;
    Ok(Some(Directory {
        _ancestors: held,
        file,
    }))
}
pub fn parent(path: &Path, create: bool) -> Result<Option<Directory>> {
    safe_path(path.to_str().ok_or_else(unsafe_path)?)?;
    directory(path.parent().ok_or_else(unsafe_path)?, create, false)
}
pub struct Opened {
    pub file: File,
    pub _parent: Directory,
}
pub fn open(path: &Path, private: bool, executable: bool) -> Result<Option<Opened>> {
    let Some(parent) = parent(path, false)? else {
        return Ok(None);
    };
    let Some(file) = open_raw(path, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, None)? else {
        return Ok(None);
    };
    let system_file = executable && !private && is_system_executable_path(path)?;
    if system_file {
        // 系统组件可由 WinSxS 合法硬链接；不信任当前用户拥有或可写的替代品。
        check_acl_for(&file, false, false, false, "")?;
        identity_with_links(&file, false, true)?;
    } else {
        identity(&file, false)?;
        check_acl(&file, private, !executable, false)?;
    }
    Ok(Some(Opened {
        file,
        _parent: parent,
    }))
}

fn system_directory() -> Result<PathBuf> {
    let mut buffer = vec![0u16; 32768];
    let len = unsafe {
        windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW(
            buffer.as_mut_ptr(),
            buffer.len() as u32,
        )
    } as usize;
    if len == 0 || len >= buffer.len() {
        return Err(unsafe_path());
    }
    Ok(PathBuf::from(
        String::from_utf16(&buffer[..len]).map_err(|_| unsafe_path())?,
    ))
}
fn is_system_executable_path(path: &Path) -> Result<bool> {
    if !path
        .extension()
        .is_some_and(|s| s.eq_ignore_ascii_case("exe") || s.eq_ignore_ascii_case("com"))
    {
        return Ok(false);
    }
    let base = system_directory()?;
    let mut parts = path.components();
    for expected in base.components() {
        if !parts
            .next()
            .is_some_and(|part| part.as_os_str().eq_ignore_ascii_case(expected.as_os_str()))
        {
            return Ok(false);
        }
    }
    Ok(parts.next().is_some())
}
pub fn owned(path: &Path, is_directory: bool) -> Result<()> {
    if is_directory {
        if let Some(directory) = directory(path, false, false)? {
            check_acl(&directory.file, false, true, false)?;
        }
    } else {
        open(path, false, false)?;
    }
    Ok(())
}
pub fn create_file(path: &Path) -> Result<Opened> {
    let parent = parent(path, false)?.ok_or_else(unsafe_path)?;
    let mut security = private_security_attributes()?;
    let file = open_raw(
        path,
        GENERIC_READ | GENERIC_WRITE | DELETE,
        FILE_SHARE_READ,
        CREATE_NEW,
        Some(&mut security),
    )?
    .ok_or_else(unsafe_path)?;
    identity(&file, false)?;
    check_acl(&file, true, true, false)?;
    Ok(Opened {
        file,
        _parent: parent,
    })
}
pub fn lock(path: &Path, nonblocking: bool, create: bool) -> Result<Option<File>> {
    let Some(_parent) = parent(path, false)? else {
        return if create { Err(unsafe_path()) } else { Ok(None) };
    };
    let mut security = private_security_attributes()?;
    let Some(file) = open_raw(
        path,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        if create { OPEN_ALWAYS } else { OPEN_EXISTING },
        Some(&mut security),
    )?
    else {
        return Ok(None);
    };
    identity(&file, false)?;
    check_acl(&file, true, true, false)?;
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    if unsafe {
        LockFileEx(
            file.as_raw_handle(),
            LOCKFILE_EXCLUSIVE_LOCK
                | if nonblocking {
                    LOCKFILE_FAIL_IMMEDIATELY
                } else {
                    0
                },
            0,
            1,
            0,
            &mut overlapped,
        )
    } == 0
    {
        return Err(if unsafe { GetLastError() } == ERROR_LOCK_VIOLATION {
            Error::new("lock-busy", "另一个操作持有生命周期锁。")
        } else {
            unsafe_path()
        });
    }
    Ok(Some(file))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileStamp {
    pub identity: Identity,
    pub security: Vec<u8>,
    pub private: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub bytes: Vec<u8>,
    pub stamp: FileStamp,
}
pub fn snapshot_file(file: &mut File, limit: usize) -> Result<Snapshot> {
    let before = identity(file, false)?;
    let security = check_acl(file, false, true, false)?;
    let private = check_acl(file, true, true, false).is_ok();
    if before.size > limit as u64 {
        return Err(unsafe_path());
    }
    let mut bytes = Vec::with_capacity(before.size as usize);
    (&mut *file)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| unsafe_path())?;
    if bytes.len() > limit
        || identity(file, false)? != before
        || check_acl(file, false, true, false)? != security
    {
        return Err(changed());
    }
    Ok(Snapshot {
        bytes,
        stamp: FileStamp {
            identity: before,
            security,
            private,
        },
    })
}
pub fn snapshot(path: &Path, limit: usize) -> Result<Option<Snapshot>> {
    open(path, false, false)?
        .map(|mut opened| snapshot_file(&mut opened.file, limit))
        .transpose()
}
fn rename_handle(file: &File, destination: &Path) -> Result<()> {
    let name: Vec<u16> = destination.as_os_str().encode_wide().collect();
    let length = offset_of!(FILE_RENAME_INFO, FileName) + name.len() * 2;
    // Win32 在封送为 NT 路径时读取终止 NUL；长度字段不包含该终止符。
    let mut buffer = vec![0usize; (length + size_of::<u16>()).div_ceil(size_of::<usize>())];
    let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    unsafe {
        (*info).Anonymous.ReplaceIfExists = false;
        (*info).RootDirectory = null_mut();
        (*info).FileNameLength = (name.len() * 2) as u32;
        std::ptr::copy_nonoverlapping(name.as_ptr(), (*info).FileName.as_mut_ptr(), name.len());
        if SetFileInformationByHandle(
            file.as_raw_handle(),
            FileRenameInfo,
            info.cast(),
            length as u32,
        ) == 0
        {
            return Err(changed());
        }
    }
    Ok(())
}
fn delete_handle(file: &File) -> Result<()> {
    let info = FILE_DISPOSITION_INFO { DeleteFile: true };
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfo,
            (&info as *const FILE_DISPOSITION_INFO).cast(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    } == 0
    {
        return Err(unsafe_path());
    }
    Ok(())
}
/// 事务写锁保护已审核对象及命名空间，消除检查后同名替换的窗口。
/// TxF 不可用时失败关闭；不降级为先删除或仅按名称覆盖。
pub fn replace(
    path: &Path,
    expected: Option<(&FileStamp, &[u8])>,
    bytes: Option<&[u8]>,
) -> Result<()> {
    let _parent = parent(path, bytes.is_some())?.ok_or_else(unsafe_path)?;
    check_acl(&_parent.file, false, true, false)?;
    let transaction = FileTransaction::new()?;
    let limit = expected
        .map(|(_, bytes)| bytes.len())
        .unwrap_or(0)
        .max(bytes.map_or(0, <[u8]>::len))
        .max(65536);
    let mut current = transaction.open(
        path,
        GENERIC_READ | GENERIC_WRITE | DELETE,
        OPEN_EXISTING,
        None,
    )?;
    let now = current
        .as_mut()
        .map(|file| snapshot_file(file, limit))
        .transpose()?;
    if now.as_ref().map(|s| (&s.stamp, s.bytes.as_slice())) != expected {
        return Err(changed());
    }
    let replacing = current.is_some();
    let Some(bytes) = bytes else {
        if let Some(file) = &current {
            delete_handle(file)?;
        }
        drop(current);
        return transaction.commit();
    };
    let temporary = path.with_file_name(format!(".tern-write-{:032x}", rand::random::<u128>()));
    let mut security = private_security_attributes()?;
    let mut stage = transaction
        .open(
            &temporary,
            GENERIC_READ | GENERIC_WRITE | DELETE,
            CREATE_NEW,
            Some(&mut security),
        )?
        .ok_or_else(unsafe_path)?;
    identity(&stage, false)?;
    check_acl(&stage, true, true, false)?;
    stage.write_all(bytes).map_err(|_| unsafe_path())?;
    stage.sync_all().map_err(|_| unsafe_path())?;
    // 关闭文件句柄不释放事务写锁；未提交的新文件也不对其他进程可见。
    drop(stage);
    drop(current);
    #[cfg(test)]
    run_publication_hook();
    if unsafe {
        MoveFileTransactedW(
            wide(&temporary).as_ptr(),
            wide(path).as_ptr(),
            None,
            null(),
            if replacing {
                MOVEFILE_REPLACE_EXISTING
            } else {
                0
            },
            transaction.handle.as_raw_handle(),
        )
    } == 0
    {
        return Err(transaction_error());
    }
    transaction.commit()
}

fn transaction_error() -> Error {
    match unsafe { GetLastError() } {
        ERROR_TRANSACTIONAL_CONFLICT | ERROR_FILE_EXISTS | ERROR_ALREADY_EXISTS => changed(),
        _ => Error::new("atomic-update-unavailable", "Windows 原子事务更新不可用或失败；旧内容保持不变。需要支持事务的本机 NTFS，不能使用 ReFS 或 EFS 加密文件。"),
    }
}
struct FileTransaction {
    handle: File,
    active: bool,
}
impl FileTransaction {
    fn new() -> Result<Self> {
        let handle = unsafe { CreateTransaction(null_mut(), null_mut(), 0, 0, 0, 30000, null()) };
        if handle == INVALID_HANDLE_VALUE {
            return Err(transaction_error());
        }
        Ok(Self {
            handle: unsafe { File::from_raw_handle(handle) },
            active: true,
        })
    }
    fn open(
        &self,
        path: &Path,
        access: u32,
        disposition: u32,
        security: Option<&mut OwnedSecurityAttributes>,
    ) -> Result<Option<File>> {
        let handle = unsafe {
            CreateFileTransactedW(
                wide(path).as_ptr(),
                access | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_DELETE,
                security.map_or(null(), |s| s.as_ptr().cast()),
                disposition,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                null_mut(),
                self.handle.as_raw_handle(),
                null(),
                null(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return if missing() && disposition == OPEN_EXISTING {
                Ok(None)
            } else {
                Err(transaction_error())
            };
        }
        Ok(Some(unsafe { File::from_raw_handle(handle) }))
    }
    fn commit(mut self) -> Result<()> {
        #[cfg(test)]
        COMMIT_HOOK.with(|hook| {
            if let Some(callback) = hook.borrow_mut().take() {
                callback(self.handle.as_raw_handle());
            }
        });
        if unsafe { CommitTransaction(self.handle.as_raw_handle()) } == 0 {
            return Err(transaction_error());
        }
        self.active = false;
        Ok(())
    }
}
impl Drop for FileTransaction {
    fn drop(&mut self) {
        if self.active {
            unsafe {
                RollbackTransaction(self.handle.as_raw_handle());
            }
        }
    }
}
pub fn move_owned(source: &Path, destination: &Path, expected: Option<(u64, u64)>) -> Result<()> {
    let _from = parent(source, false)?.ok_or_else(unsafe_path)?;
    let _to = parent(destination, true)?.ok_or_else(unsafe_path)?;
    check_acl(&_from.file, false, true, false)?;
    check_acl(&_to.file, false, true, false)?;
    let file = open_raw(
        source,
        GENERIC_READ | DELETE,
        FILE_SHARE_READ,
        OPEN_EXISTING,
        None,
    )?
    .ok_or_else(changed)?;
    let is_directory = file.metadata().map_err(|_| unsafe_path())?.is_dir();
    let id = identity(&file, is_directory)?;
    check_acl(&file, false, true, false)?;
    if expected.is_some_and(|e| e != (id.volume, id.index)) {
        return Err(changed());
    }
    rename_handle(&file, destination)
}
pub fn path_identity(path: &Path, is_directory: bool) -> Result<(u64, u64)> {
    let id = if is_directory {
        identity(
            &directory(path, false, false)?.ok_or_else(unsafe_path)?.file,
            true,
        )?
    } else {
        identity(
            &open(path, false, false)?.ok_or_else(unsafe_path)?.file,
            false,
        )?
    };
    Ok((id.volume, id.index))
}
pub fn known_folder(id: &windows_sys::core::GUID) -> Result<PathBuf> {
    let mut path = null_mut();
    if unsafe { windows_sys::Win32::UI::Shell::SHGetKnownFolderPath(id, 0, null_mut(), &mut path) }
        < 0
    {
        return Err(unsafe_path());
    }
    let mut len = 0;
    while unsafe { *path.add(len) } != 0 {
        len += 1;
    }
    let text = String::from_utf16(unsafe { std::slice::from_raw_parts(path, len) });
    unsafe {
        windows_sys::Win32::System::Com::CoTaskMemFree(path.cast());
    }
    let text = text.map_err(|_| unsafe_path())?;
    safe_path(&text)?;
    Ok(PathBuf::from(text))
}
pub fn home() -> Result<PathBuf> {
    known_folder(&windows_sys::Win32::UI::Shell::FOLDERID_Profile)
}
pub fn profile() -> Result<PathBuf> {
    Ok(known_folder(&windows_sys::Win32::UI::Shell::FOLDERID_RoamingAppData)?.join("Tern"))
}
pub fn state_dir() -> Result<PathBuf> {
    Ok(known_folder(&windows_sys::Win32::UI::Shell::FOLDERID_LocalAppData)?.join("Tern"))
}
pub fn ssh_executable() -> Result<String> {
    let path = system_directory()?.join("OpenSSH/ssh.exe");
    open(&path, false, true)?
        .ok_or_else(|| Error::new("ssh-unavailable", "请安装 Windows 系统 OpenSSH 客户端。"))?;
    path.to_str().map(str::to_owned).ok_or_else(unsafe_path)
}

pub fn validate_path(value: &str) -> Result<()> {
    let path = Path::new(value);
    safe_path(value)?;
    if let Some(_parent) = parent(path, false)? {
        if let Some(file) = open_raw(
            path,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            OPEN_EXISTING,
            None,
        )? {
            identity(&file, file.metadata().map_err(|_| unsafe_path())?.is_dir())?;
        }
    }
    Ok(())
}

/// 仅供 current_exe 等可信系统 API 返回值使用；不得用于放宽用户路径输入。
pub fn normalize_system_path(path: &Path) -> Result<PathBuf> {
    let text = path.to_str().ok_or_else(unsafe_path)?;
    let text = text.strip_prefix(r"\\?\").unwrap_or(text);
    let text = text.trim_end_matches(['\\', '/']);
    safe_path(text)?;
    Ok(PathBuf::from(text))
}

#[cfg(test)]
thread_local! {
    static PUBLICATION_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = std::cell::RefCell::new(None);
    static COMMIT_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce(HANDLE)>>> = std::cell::RefCell::new(None);
}
#[cfg(test)]
fn run_publication_hook() {
    PUBLICATION_HOOK.with(|hook| {
        if let Some(callback) = hook.borrow_mut().take() {
            callback();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{common, install};
    use serde_json::json;

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let root = normalize_system_path(&std::env::temp_dir())
                .unwrap()
                .join(format!("ttr-win-security-{:032x}", rand::random::<u128>()));
            common::private_dir(&root, true).unwrap();
            Self(root)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn set_test_dacl(path: &Path, extra: &str) {
        let sid = current_sid().unwrap();
        let security = security_attributes(&format!(
            "O:{sid}D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA){extra}"
        ))
        .unwrap();
        let mut present = 0;
        let mut defaulted = 0;
        let mut acl = null_mut();
        assert_ne!(
            unsafe {
                GetSecurityDescriptorDacl(
                    security.attributes.lpSecurityDescriptor,
                    &mut present,
                    &mut acl,
                    &mut defaulted,
                )
            },
            0
        );
        let file = open_raw(
            path,
            WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            OPEN_EXISTING,
            None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            unsafe {
                SetSecurityInfo(
                    file.as_raw_handle(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    null_mut(),
                    null_mut(),
                    acl,
                    null_mut(),
                )
            },
            ERROR_SUCCESS
        );
    }

    #[test]
    fn rejects_dangerous_paths_without_rejecting_unicode_or_spaces() {
        for path in [
            r"relative",
            r"C:relative",
            r"\rooted",
            r"\\server\share\key",
            r"\\?\C:\key",
            r"\\.\pipe\key",
            r"C:\a\..\key",
            r"C:\a\.\key",
            r"C:\a\\key",
            r"C:\key:stream",
            r"C:\key.",
            r"C:\key ",
            r"C:\NUL.txt",
            r"C:\COM¹",
            "C:\\key\n",
        ] {
            assert!(safe_path(path).is_err(), "危险路径被接受");
        }
        assert!(safe_path(r"C:\用户目录\私有 配置\key.json").is_ok());
        assert!(common::safe_absolute(r"C:\remote\daemon.sock").is_err());
        assert!(common::safe_absolute("/run/user/1000/tern.sock").is_ok());
    }

    #[test]
    fn private_dacl_rejects_public_read_and_write_without_repairing_it() {
        let fixture = Fixture::new();
        let path = fixture.0.join("key.json");
        common::atomic_json(&path, &json!({"value":"original"})).unwrap();
        assert!(common::read_json(&path, true).is_ok());
        set_test_dacl(&path, "(A;;FR;;;WD)");
        assert!(common::read_json(&path, true).is_err());
        assert!(common::read_json(&path, false).is_ok());
        assert!(common::read_json(&path, true).is_err());
        set_test_dacl(&path, "(A;;FW;;;WD)");
        assert_eq!(common::read_json(&path, false).unwrap()["value"], "original");
        assert!(common::read_json(&path, true).is_err());
        let acl_before = check_acl(&open(&path, false, false).unwrap().unwrap().file, false, true, false).unwrap();
        assert_eq!(common::read_json(&path, false).unwrap()["value"], "original");
        assert_eq!(check_acl(&open(&path, false, false).unwrap().unwrap().file, false, true, false).unwrap(), acl_before);
        set_test_dacl(&path, "");
        set_test_dacl(&fixture.0, "(A;OICI;FR;;;WD)");
        assert!(common::private_dir(&fixture.0, false).is_err());
        let child = fixture.0.join("private-child");
        common::private_dir(&child, true).unwrap();
        common::atomic_json(&child.join("state.json"), &json!({"value":"protected"})).unwrap();
        assert_eq!(common::read_json(&child.join("state.json"), true).unwrap()["value"], "protected");
        set_test_dacl(&fixture.0, "");
    }

    #[test]
    fn hardlinks_are_rejected_and_atomic_failure_preserves_old_content() {
        let fixture = Fixture::new();
        let path = fixture.0.join("key.json");
        let hard = fixture.0.join("hard.json");
        common::atomic_json(&path, &json!({"value":"original"})).unwrap();
        std::fs::hard_link(&path, &hard).unwrap();
        assert!(common::read_json(&path, true).is_err());
        assert!(common::atomic_json(&path, &json!({"value":"replacement"})).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), std::fs::read(&hard).unwrap());
        std::fs::remove_file(&hard).unwrap();
        let before = std::fs::read(&path).unwrap();
        let held = open(&path, true, false).unwrap().unwrap();
        assert!(common::atomic_json(&path, &json!({"value":"replacement"})).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        drop(held);
        assert!(common::atomic_json(&path, &json!({"value":"x".repeat(65536)})).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        common::atomic_json(&path, &json!({"value":"updated"})).unwrap();
        assert_eq!(common::read_json(&path, true).unwrap()["value"], "updated");
        assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 1);
    }

    #[test]
    fn independent_lock_handles_are_exclusive_and_observation_never_unlocks_owner() {
        let fixture = Fixture::new();
        let path = fixture.0.join("service.lock");
        assert!(!common::is_locked(&path).unwrap());
        assert!(!path.exists());
        let held = common::lock(&path, true).unwrap();
        let contender = path.clone();
        std::thread::spawn(move || {
            assert_eq!(
                common::lock(&contender, true).unwrap_err().code,
                "lock-busy"
            );
            assert!(common::is_locked(&contender).unwrap());
            assert_eq!(
                common::lock(&contender, true).unwrap_err().code,
                "lock-busy"
            );
        })
        .join()
        .unwrap();
        assert!(std::fs::remove_file(&path).is_err());
        drop(held);
        assert!(!common::is_locked(&path).unwrap());
        let next = common::lock(&path, true).unwrap();
        assert!(common::is_locked(&path).unwrap());
        drop(next);
    }

    #[test]
    fn cas_rejects_missing_replaced_and_permission_changed_objects() {
        let fixture = Fixture::new();
        let path = fixture.0.join("owned");
        install::replace(&path, None, Some(b"same bytes"), 0o600).unwrap();
        let old = install::snapshot(&path, 64).unwrap().unwrap();
        std::fs::rename(&path, fixture.0.join("retained")).unwrap();
        assert_eq!(
            install::replace(&path, Some(&old), Some(b"lost update"), 0o600)
                .unwrap_err()
                .code,
            "review-changed"
        );
        install::replace(&path, None, Some(b"same bytes"), 0o600).unwrap();
        assert_eq!(
            install::replace(&path, Some(&old), None, 0o600)
                .unwrap_err()
                .code,
            "review-changed"
        );
        let current = install::snapshot(&path, 64).unwrap().unwrap();
        set_test_dacl(&path, "(A;;FR;;;WD)");
        assert_eq!(
            install::replace(&path, Some(&current), Some(b"lost update"), 0o600)
                .unwrap_err()
                .code,
            "review-changed"
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"same bytes");
        set_test_dacl(&path, "");
    }

    #[test]
    fn junction_and_its_children_are_rejected_without_following_target() {
        let fixture = Fixture::new();
        let target = fixture.0.join("target");
        let junction = fixture.0.join("junction");
        common::private_dir(&target, true).unwrap();
        common::private_dir(&junction, true).unwrap();
        common::atomic_json(&target.join("key.json"), &json!({"value":"original"})).unwrap();
        let substitute: Vec<u16> = format!(r"\??\{}", target.display())
            .encode_utf16()
            .collect();
        let print: Vec<u16> = target.as_os_str().encode_wide().collect();
        let data_length = 8 + (substitute.len() + print.len() + 2) * 2;
        let mut buffer = Vec::with_capacity(8 + data_length);
        // IO_REPARSE_TAG_MOUNT_POINT 与 REPARSE_DATA_BUFFER 的公开 Windows ABI。
        buffer.extend_from_slice(&0xA0000003u32.to_le_bytes());
        buffer.extend_from_slice(&(data_length as u16).to_le_bytes());
        buffer.extend_from_slice(&0u16.to_le_bytes());
        for field in [
            0,
            (substitute.len() * 2) as u16,
            ((substitute.len() + 1) * 2) as u16,
            (print.len() * 2) as u16,
        ] {
            buffer.extend_from_slice(&field.to_le_bytes());
        }
        for unit in substitute
            .into_iter()
            .chain(Some(0))
            .chain(print)
            .chain(Some(0))
        {
            buffer.extend_from_slice(&unit.to_le_bytes());
        }
        let file = open_raw(&junction, GENERIC_WRITE, 0, OPEN_EXISTING, None)
            .unwrap()
            .unwrap();
        let mut returned = 0;
        // FSCTL_SET_REPARSE_POINT；junction 不需要符号链接创建特权。
        assert_ne!(
            unsafe {
                windows_sys::Win32::System::IO::DeviceIoControl(
                    file.as_raw_handle(),
                    0x000900A4,
                    buffer.as_ptr().cast(),
                    buffer.len() as u32,
                    null_mut(),
                    0,
                    &mut returned,
                    null_mut(),
                )
            },
            0
        );
        drop(file);
        assert!(common::private_dir(&junction, false).is_err());
        assert!(common::safe_local_absolute(junction.to_str().unwrap()).is_err());
        assert!(common::read_json(&junction.join("key.json"), true).is_err());
        assert!(
            common::atomic_json(&junction.join("key.json"), &json!({"value":"replacement"}))
                .is_err()
        );
        assert_eq!(
            common::read_json(&target.join("key.json"), true).unwrap()["value"],
            "original"
        );
        std::fs::remove_dir(&junction).unwrap();
    }

    #[test]
    fn rename_publication_handles_every_utf16_alignment() {
        let fixture = Fixture::new();
        for length in 1..=16 {
            let path = fixture.0.join("a".repeat(length));
            common::atomic_json(&path, &json!({"value":"old"})).unwrap();
            common::atomic_json(&path, &json!({"value":"new"})).unwrap();
            assert_eq!(common::read_json(&path, true).unwrap()["value"], "new");
        }
    }

    #[test]
    fn system_executable_links_do_not_weaken_user_file_policy() {
        let powershell = system_directory()
            .unwrap()
            .join(r"WindowsPowerShell\v1.0\powershell.exe");
        let system = open(&powershell, false, true).unwrap().unwrap();
        assert!(check_acl_for(&system.file, false, false, false, "").is_ok());
        drop(system);
        let fixture = Fixture::new();
        let path = fixture.0.join("user.exe");
        install::replace(&path, None, Some(b"user content"), 0o600).unwrap();
        let owned = open(&path, false, true).unwrap().unwrap();
        assert!(check_acl_for(&owned.file, false, false, false, "").is_err());
        drop(owned);
        std::fs::hard_link(&path, fixture.0.join("alias.exe")).unwrap();
        assert!(!is_system_executable_path(&path).unwrap());
        assert!(open(&path, false, true).is_err());
        assert!(open(&path, true, false).is_err());
    }

    #[test]
    fn cas_never_overwrites_an_interleaved_user_replacement() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };
        let fixture = Fixture::new();
        let path = fixture.0.join("config.json");
        common::atomic_json(&path, &json!({"value":"reviewed"})).unwrap();
        let before = install::snapshot(&path, 65536).unwrap().unwrap();
        let replaced = Arc::new(AtomicBool::new(false));
        let observed = replaced.clone();
        let target = path.clone();
        let retained = fixture.0.join("reviewed-retained.json");
        PUBLICATION_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                std::thread::spawn(move || match std::fs::rename(&target, retained) {
                    Ok(()) => {
                        std::fs::write(&target, br#"{"value":"user replacement"}"#).unwrap();
                        observed.store(true, Ordering::SeqCst);
                    }
                    Err(error) => {
                        let code = error.raw_os_error().unwrap() as u32;
                        assert!(
                            [ERROR_TRANSACTIONAL_CONFLICT, ERROR_SHARING_VIOLATION].contains(&code)
                        );
                    }
                })
                .join()
                .unwrap();
            }))
        });
        let result = install::replace(&path, Some(&before), Some(br#"{"value":"staged"}"#), 0o600);
        if replaced.load(Ordering::SeqCst) {
            assert!(result.is_err(), "CAS 覆盖了检查之后出现的用户替代文件");
            assert_eq!(
                common::read_json(&path, true).unwrap()["value"],
                "user replacement"
            );
        } else {
            result.unwrap();
            assert_eq!(common::read_json(&path, true).unwrap()["value"], "staged");
        }
    }

    #[test]
    fn absent_target_created_during_publication_is_never_overwritten() {
        let fixture = Fixture::new();
        let path = fixture.0.join("new.json");
        let target = path.clone();
        PUBLICATION_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                std::thread::spawn(move || std::fs::write(target, br#"{"value":"user"}"#).unwrap())
                    .join()
                    .unwrap();
            }))
        });
        assert!(install::replace(&path, None, Some(br#"{"value":"staged"}"#), 0o600).is_err());
        assert_eq!(common::read_json(&path, true).unwrap()["value"], "user");
        assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 1);
    }

    #[test]
    fn aborted_commit_preserves_original_and_hides_uncommitted_changes() {
        let fixture = Fixture::new();
        let path = fixture.0.join("owned.json");
        common::atomic_json(&path, &json!({"value":"original"})).unwrap();
        for bytes in [Some(br#"{"value":"staged"}"#.as_slice()), None] {
            let before = install::snapshot(&path, 65536).unwrap().unwrap();
            let target = path.clone();
            COMMIT_HOOK.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move |transaction| {
                    assert_eq!(
                        std::fs::read(&target).unwrap(),
                        b"{\"value\":\"original\"}\n"
                    );
                    assert_ne!(unsafe { RollbackTransaction(transaction) }, 0);
                }))
            });
            assert_eq!(
                install::replace(&path, Some(&before), bytes, 0o600)
                    .unwrap_err()
                    .code,
                "atomic-update-unavailable"
            );
            assert_eq!(install::snapshot(&path, 65536).unwrap().unwrap(), before);
            assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 1);
        }
        let absent = fixture.0.join("absent.json");
        let target = absent.clone();
        COMMIT_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |transaction| {
                assert!(!target.exists());
                assert_ne!(unsafe { RollbackTransaction(transaction) }, 0);
            }))
        });
        assert!(install::replace(&absent, None, Some(b"new"), 0o600).is_err());
        assert!(!absent.exists());
        assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 1);
    }
}
