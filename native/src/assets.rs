use crate::common::{self, Error, Result};
use futures_util::StreamExt;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

const MAX_BINARY: u64 = 64 * 1024 * 1024;
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
fn verify(path: &Path, row: &Value) -> Result<()> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| invalid())?;
    let info = file.metadata().map_err(|_| invalid())?;
    if !info.is_file()
        || info.uid() != unsafe { libc::geteuid() }
        || info.nlink() != 1
        || info.mode() & 0o777 != 0o500
        || Some(info.len()) != row["size"].as_u64()
    {
        return Err(invalid());
    }
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
    Ok(())
}
pub async fn ensure_remote(arch: &str) -> Result<PathBuf> {
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
    let directory = executable.parent().ok_or_else(invalid)?;
    common::private_dir(directory, false)?;
    let _lock = common::lock(&directory.join("assets.lock"), true)?;
    let value = manifest(directory)?;
    let name = format!("tern-turn-relay-linux-{arch}");
    let row = &value["assets"][&name];
    let destination = directory.join(&name);
    if destination.symlink_metadata().is_ok() {
        verify(&destination, row)?;
        return Ok(destination);
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
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary_path)
        .map_err(|_| invalid())?;
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
        file.set_permissions(std::fs::Permissions::from_mode(0o500))
            .map_err(|_| invalid())?;
        file.sync_all().map_err(|_| invalid())?;
        drop(file);
        std::fs::rename(&temporary.0, &destination).map_err(|_| invalid())?;
        File::open(directory)
            .and_then(|f| f.sync_all())
            .map_err(|_| invalid())?;
        Ok(destination.clone())
    }
    .await;
    result
}
