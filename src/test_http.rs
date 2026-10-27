use std::io;
use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tempfile::TempDir;

const PREFIX: &str = "http://127.0.0.1/__patchgate_test__/";

// Private Unix sockets keep test HTTP traffic inside the Nix sandbox.
pub(crate) struct Server {
    listener: UnixListener,
    socket: PathBuf,
    url: String,
    _directory: TempDir,
}

impl Server {
    pub(crate) fn bind() -> Result<Self> {
        let directory = tempfile::Builder::new().prefix("pgh-").tempdir_in("/tmp")?;
        let socket = directory.path().join("socket");
        let listener = UnixListener::bind(&socket)?;
        let name = directory
            .path()
            .file_name()
            .and_then(|name| name.to_str())
            .context("The private HTTP directory has no UTF-8 name")?;
        let url = format!("{PREFIX}{name}/v1");
        Ok(Self {
            listener,
            socket,
            url,
            _directory: directory,
        })
    }

    pub(crate) fn url(&self) -> &str {
        &self.url
    }

    pub(crate) fn socket_path(&self) -> &Path {
        &self.socket
    }

    pub(crate) fn accept(&self) -> io::Result<(UnixStream, SocketAddr)> {
        self.listener.accept()
    }

    pub(crate) fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.listener.set_nonblocking(nonblocking)
    }
}

pub(crate) fn socket_path(url: &str) -> Option<PathBuf> {
    let name = url.strip_prefix(PREFIX)?.strip_suffix("/v1")?;
    if !name.starts_with("pgh-")
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return None;
    }
    Some(Path::new("/tmp").join(name).join("socket"))
}
