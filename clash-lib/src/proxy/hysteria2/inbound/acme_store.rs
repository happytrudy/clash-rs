use std::{
    io,
    path::{Path, PathBuf},
};

use async_trait::async_trait;
use base64::{Engine as _, prelude::BASE64_URL_SAFE_NO_PAD};
use rustls_acme::{AccountCache, CertCache};
use sha2::{Digest, Sha256};
use tokio::{fs, io::AsyncWriteExt};

#[derive(Clone, Debug)]
pub(super) struct PrivateDirCache {
    dir: PathBuf,
}

impl PrivateDirCache {
    pub(super) fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    async fn read_if_exists(&self, file: String) -> io::Result<Option<Vec<u8>>> {
        read_private_file_if_exists(&self.dir.join(file)).await
    }

    async fn write(&self, file: String, contents: &[u8]) -> io::Result<()> {
        write_private_file(&self.dir.join(file), contents).await
    }
}

#[async_trait]
impl CertCache for PrivateDirCache {
    type EC = io::Error;

    async fn load_cert(
        &self,
        domains: &[String],
        directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EC> {
        self.read_if_exists(cache_file_name("cached_cert", domains, directory_url))
            .await
    }

    async fn store_cert(
        &self,
        domains: &[String],
        directory_url: &str,
        cert: &[u8],
    ) -> Result<(), Self::EC> {
        self.write(cache_file_name("cached_cert", domains, directory_url), cert)
            .await
    }
}

#[async_trait]
impl AccountCache for PrivateDirCache {
    type EA = io::Error;

    async fn load_account(
        &self,
        contact: &[String],
        directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EA> {
        self.read_if_exists(cache_file_name(
            "cached_account",
            contact,
            directory_url,
        ))
        .await
    }

    async fn store_account(
        &self,
        contact: &[String],
        directory_url: &str,
        account: &[u8],
    ) -> Result<(), Self::EA> {
        self.write(
            cache_file_name("cached_account", contact, directory_url),
            account,
        )
        .await
    }
}

fn cache_file_name(prefix: &str, parts: &[String], directory_url: &str) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update([0]);
    }
    hasher.update(directory_url.as_bytes());
    let hash = BASE64_URL_SAFE_NO_PAD.encode(hasher.finalize());
    format!("{prefix}_{hash}")
}

pub(super) async fn read_private_file_if_exists(
    path: &Path,
) -> io::Result<Option<Vec<u8>>> {
    match fs::read(path).await {
        Ok(contents) => {
            harden_private_file(path).await?;
            Ok(Some(contents))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

pub(super) async fn write_private_file(
    path: &Path,
    contents: &[u8],
) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent).await?;
    }

    let tmp = private_tmp_path(path);
    let result = async {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            opts.mode(0o600);
        }

        let mut file = opts.open(&tmp).await?;
        file.write_all(contents).await?;
        file.flush().await?;
        file.sync_all().await?;
        drop(file);

        fs::rename(&tmp, path).await?;
        harden_private_file(path).await
    }
    .await;

    if result.is_err() {
        let _ = fs::remove_file(&tmp).await;
    }
    result
}

pub(super) async fn ensure_private_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path).await?;
    harden_private_dir(path).await
}

pub(super) fn ensure_private_dir_sync(path: &Path) -> io::Result<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub(super) fn harden_private_file_sync(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

async fn harden_private_file(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await?;
    }
    Ok(())
}

async fn harden_private_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).await?;
    }
    Ok(())
}

fn private_tmp_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("acme-cache");
    let tmp_name = format!(
        ".{file_name}.tmp-{}-{:016x}",
        std::process::id(),
        rand::random::<u64>()
    );
    path.with_file_name(tmp_name)
}
