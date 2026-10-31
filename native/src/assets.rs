use crate::common::{self, Error, Result};
use futures_util::StreamExt;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, Write},
    path::{Path, PathBuf},
    time::Duration,
};

#[cfg(unix)]
use std::fs::OpenOptions;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

const MAX_BINARY: u64 = 64 * 1024 * 1024;
pub(crate) struct VerifiedAsset {
    pub file: File,
    pub digest: String,
    pub size: u64,
    #[cfg(windows)]
    _parent: crate::windows_security::Directory,
}
struct TemporaryAsset(PathBuf);
impl Drop for TemporaryAsset {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
fn invalid() -> Error {
    Error::new(
        "asset-integrity",
        "Native release manifest or executable verification failed.",
    )
}
pub fn manifest(directory: &Path) -> Result<Value> {
    let value = common::read_json(&directory.join("release.json"), true)?;
    if value["schema"] != 1
        || value["version"] != env!("CARGO_PKG_VERSION")
        || value.as_object().map(|m| m.len()) != Some(3)
    {
        return Err(invalid());
    }
    let assets = value["assets"].as_object().ok_or_else(invalid)?;
    let expected = [
        "tern-turn-relay-darwin-arm64",
        "tern-turn-relay-darwin-x86_64",
        "tern-turn-relay-linux-arm64",
        "tern-turn-relay-linux-x86_64",
        "tern-turn-relay-windows-x86_64.exe",
    ];
    if assets.len() != expected.len() {
        return Err(invalid());
    }
    for name in expected {
        let row = assets.get(name).ok_or_else(invalid)?;
        let hash = row["sha256"].as_str().ok_or_else(invalid)?;
        if row.as_object().map(|m| m.len()) != Some(2)
            || hash.len() != 64
            || !hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !matches!(row["size"].as_u64(),Some(n) if n>0 && n<=MAX_BINARY)
        {
            return Err(invalid());
        }
    }
    Ok(value)
}
fn verify(path: &Path, row: &Value) -> Result<VerifiedAsset> {
    #[cfg(unix)]
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| invalid())?;
    #[cfg(windows)]
    let crate::windows_security::Opened { mut file, _parent } = crate::windows_security::open(path, true, false)?.ok_or_else(invalid)?;
    let info = file.metadata().map_err(|_| invalid())?;
    #[cfg(unix)]
    if !info.is_file()
        || info.uid() != unsafe { libc::geteuid() }
        || info.nlink() != 1
        || info.mode() & 0o777 != 0o500
        || Some(info.len()) != row["size"].as_u64()
    {
        return Err(invalid());
    }
    #[cfg(windows)]
    if Some(crate::windows_security::identity(&file, false)?.size) != row["size"].as_u64() { return Err(invalid()); }
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 32768];
    loop {
        let count = file.read(&mut buffer).map_err(|_| invalid())?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    if hex::encode(digest.finalize()) != row["sha256"].as_str().ok_or_else(invalid)? {
        return Err(invalid());
    }
    file.rewind().map_err(|_| invalid())?;
    Ok(VerifiedAsset {
        file,
        digest: row["sha256"].as_str().ok_or_else(invalid)?.to_owned(),
        size: info.len(),
        #[cfg(windows)]
        _parent,
    })
}
pub async fn ensure_remote(arch: &str) -> Result<VerifiedAsset> {
    let arch = match arch {
        "x86_64" => "x86_64",
        "aarch64" | "arm64" => "arm64",
        _ => {
            return Err(Error::new(
                "unsupported-platform",
                "Remote native helper supports Linux x86_64 and arm64.",
            ))
        }
    };
    let executable = std::env::current_exe().map_err(|_| invalid())?;
    #[cfg(windows)]
    let executable = crate::windows_security::normalize_system_path(&executable)?;
    let directory = executable.parent().ok_or_else(invalid)?;
    common::private_dir(directory, false)?;
    #[cfg(windows)]
    let _directory = crate::windows_security::directory(directory, false, true)?.ok_or_else(invalid)?;
    let _lock = common::lock(&directory.join("assets.lock"), true)?;
    let value = manifest(directory)?;
    let name = format!("tern-turn-relay-linux-{arch}");
    let row = &value["assets"][&name];
    let destination = directory.join(&name);
    if destination.symlink_metadata().is_ok() {
        return verify(&destination, row);
    }
    let url = format!(
        "https://github.com/jiwangyihao/tern-turn-relay/releases/download/v{}/{}",
        env!("CARGO_PKG_VERSION"),
        name
    );
    let policy = reqwest::redirect::Policy::custom(|attempt| {
        let allowed = attempt.url().scheme() == "https"
            && matches!(
                attempt.url().host_str(),
                Some(
                    "github.com"
                        | "release-assets.githubusercontent.com"
                        | "objects.githubusercontent.com"
                )
            );
        if allowed && attempt.previous().len() < 5 {
            attempt.follow()
        } else {
            attempt.stop()
        }
    });
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(policy)
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(180))
        .build()
        .map_err(|_| invalid())?;
    let response = client.get(url).send().await.map_err(|_| {
        Error::new(
            "asset-download",
            "Cannot download the pinned native release asset.",
        )
    })?;
    if !response.status().is_success() {
        return Err(Error::new(
            "asset-download",
            "Pinned native release asset was not available.",
        ));
    }
    let expected_size = row["size"].as_u64().ok_or_else(invalid)?;
    if response
        .content_length()
        .is_some_and(|n| n != expected_size)
    {
        return Err(invalid());
    }
    let temporary_path = directory.join(format!(".asset-{:032x}", rand::random::<u128>()));
    #[cfg(unix)]
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary_path)
        .map_err(|_| invalid())?;
    #[cfg(windows)]
    let crate::windows_security::Opened { mut file, _parent: _temporary_parent } = crate::windows_security::create_file(&temporary_path)?;
    let temporary = TemporaryAsset(temporary_path);
    let result = async {
        let mut stream = response.bytes_stream();
        let mut size = 0u64;
        let mut digest = Sha256::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| {
                Error::new(
                    "asset-download",
                    "Pinned native release transfer was interrupted.",
                )
            })?;
            size += chunk.len() as u64;
            if size > expected_size {
                return Err(invalid());
            }
            digest.update(&chunk);
            file.write_all(&chunk).map_err(|_| invalid())?;
        }
        if size != expected_size
            || hex::encode(digest.finalize()) != row["sha256"].as_str().ok_or_else(invalid)?
        {
            return Err(invalid());
        }
        #[cfg(unix)]
        file.set_permissions(std::fs::Permissions::from_mode(0o500))
            .map_err(|_| invalid())?;
        file.sync_all().map_err(|_| invalid())?;
        drop(file);
        #[cfg(unix)]
        std::fs::rename(&temporary.0, &destination).map_err(|_| invalid())?;
        #[cfg(windows)]
        crate::windows_security::move_owned(&temporary.0, &destination, None)?;
        #[cfg(unix)]
        File::open(directory)
            .and_then(|f| f.sync_all())
            .map_err(|_| invalid())?;
        Ok(())
    }
    .await;
    result?;
    verify(&destination, row)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let base = std::env::temp_dir().canonicalize().unwrap();
            #[cfg(windows)]
            let base = crate::windows_security::normalize_system_path(&base).unwrap();
            let path = base.join(format!("ttr-asset-{:032x}", rand::random::<u128>()));
            #[cfg(unix)]
            std::fs::create_dir(&path).unwrap();
            #[cfg(unix)]
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            #[cfg(windows)]
            common::private_dir(&path, true).unwrap();
            Self(path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(unix)]
    #[test]
    fn verified_asset_keeps_the_validated_inode_when_path_is_replaced() {
        let fixture = Fixture::new();
        let path = fixture.0.join("helper");
        let bytes = b"verified release content";
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500)).unwrap();
        let digest = hex::encode(Sha256::digest(bytes));
        let row = serde_json::json!({"sha256":digest,"size":bytes.len()});
        let mut asset = verify(&path, &row).unwrap();
        std::fs::rename(&path, fixture.0.join("previous")).unwrap();
        std::fs::write(&path, b"unverified replacement").unwrap();
        let mut actual = Vec::new();
        asset.file.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, bytes);
        assert_eq!(asset.digest, digest);
        assert_eq!(asset.size, bytes.len() as u64);
    }

    #[test]
    fn executable_with_matching_size_but_wrong_digest_is_rejected() {
        let fixture = Fixture::new();
        let path = fixture.0.join("helper");
        #[cfg(unix)]
        {
            std::fs::write(&path, b"altered").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500)).unwrap();
        }
        #[cfg(windows)]
        crate::install::replace(&path, None, Some(b"altered"), 0o500).unwrap();
        let row = serde_json::json!({"sha256":hex::encode(Sha256::digest(b"trusted")),"size":7});
        assert!(verify(&path, &row).is_err());
    }

    #[test]
    fn executable_with_wrong_size_is_rejected() {
        let fixture = Fixture::new();
        let path = fixture.0.join("helper");
        crate::install::replace(&path, None, Some(b"trusted"), 0o500).unwrap();
        let row = serde_json::json!({"sha256":hex::encode(Sha256::digest(b"trusted")),"size":8});
        assert!(verify(&path, &row).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn verified_asset_blocks_path_replacement_until_handle_closes() {
        let fixture = Fixture::new();
        let path = fixture.0.join("helper.exe");
        crate::install::replace(&path, None, Some(b"trusted"), 0o500).unwrap();
        let row = serde_json::json!({"sha256":hex::encode(Sha256::digest(b"trusted")),"size":7});
        let mut asset = verify(&path, &row).unwrap();
        assert!(std::fs::rename(&path, fixture.0.join("previous")).is_err());
        assert!(std::fs::write(&path, b"altered").is_err());
        let mut bytes = Vec::new();
        asset.file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"trusted");
        drop(asset);
        std::fs::rename(&path, fixture.0.join("previous")).unwrap();
    }
}
