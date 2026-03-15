// We need this for the `tarpc` macro,
// since we have no way of allowing this on the enums it generates.
#![expect(clippy::enum_variant_names)]

use std::collections::HashMap;
use std::ffi::CString;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tarpc::client::Config;
use tarpc::server::Channel;
use tarpc::tokio_serde::formats::Json;

use crate::CircId;
use crate::Server;
use crate::cli;
use crate::util::RunOnDrop;

#[tarpc::service]
pub trait Rpc {
    async fn circ_new(args: cli::CircNewArgs) -> Result<CircId, RequestError>;
    async fn circ_extend(args: cli::CircExtendArgs) -> Result<(), RequestError>;
    async fn circ_info(args: cli::CircInfoArgs) -> Result<CircInfo, RequestError>;
    async fn circ_resolve(args: cli::CircResolveArgs) -> Result<Vec<IpAddr>, RequestError>;
    async fn circ_bind(args: cli::CircBindArgs) -> Result<SocketAddr, RequestError>;
    async fn circ_bind_dir(args: cli::CircBindDirArgs) -> Result<SocketAddr, RequestError>;
    async fn circ_release(args: cli::CircReleaseArgs) -> Result<(), RequestError>;
    async fn circ_list(
        args: cli::CircListArgs,
    ) -> Result<HashMap<CircId, CircListEntry>, RequestError>;
}

pub async fn client_connect() -> anyhow::Result<RpcClient> {
    let bind_path = bind_path("dbgor");
    let mut transport = tarpc::serde_transport::unix::connect(bind_path, Json::default);
    transport.config_mut().max_frame_length(usize::MAX);

    Ok(RpcClient::new(Config::default(), transport.await?).spawn())
}

// It would be nice have this take a generic `Rpc`,
// but we can't because of https://github.com/google/tarpc/issues/421
pub async fn server_run<F>(build: impl FnOnce() -> F + Send + 'static) -> anyhow::Result<()>
where
    F: Future<Output = anyhow::Result<Server>> + Send,
{
    // TODO: Fix permissions race (set permissions before binding).
    let bind_path = bind_path("dbgor");
    let listener =
        tokio::net::UnixListener::bind(&bind_path).context("Failed to bind unix socket")?;

    chmod(&bind_path, 0o700).context("Failed to set permissions on unix socket")?;

    let mut listener = tarpc::serde_transport::unix::listen_on(listener, Json::default).await?;
    tracing::info!("Listening at {:?}", listener.local_addr());

    let bind_cleanup = RunOnDrop::new(|| std::fs::remove_file(bind_path));

    let task: tokio::task::JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
        async fn spawn(fut: impl Future<Output = ()> + Send + 'static) {
            tokio::spawn(fut);
        }

        // Build the server after binding the socket.
        let server = build().await?;

        listener.config_mut().max_frame_length(usize::MAX);
        listener
            // Ignore accept errors.
            .filter_map(|r| std::future::ready(r.ok()))
            .map(tarpc::server::BaseChannel::with_defaults)
            .map(|channel| channel.execute(server.clone().serve()).for_each(spawn))
            // Max 100 channels.
            .buffer_unordered(100)
            .for_each(|_| async {})
            .await;

        Ok(())
    });

    tokio::select! {
        result = task => result??,
        _ = tokio::signal::ctrl_c() => {
            eprintln!();
            tracing::debug!("Ctrl-C");
        }
    };

    tracing::debug!("Shutting down");
    bind_cleanup.run()?;

    Ok(())
}

fn bind_path(name: &str) -> PathBuf {
    match std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from) {
        Some(mut path) => {
            path.push(format!("{name}.sock"));
            path
        }
        None => {
            let mut path = PathBuf::from("/tmp");
            path.push(format!("{name}-{}.sock", unsafe { libc::getuid() }));
            path
        }
    }
}

fn chmod<P: AsRef<Path>>(path: P, perms: u32) -> std::io::Result<()> {
    let path = path.as_ref().as_os_str().as_bytes();
    let path = CString::new(path).unwrap();

    let rv = unsafe { libc::chmod(path.as_ptr(), perms) };
    if rv != 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CircInfo {
    pub path: Vec<String>,
    pub is_closed: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CircListEntry {
    pub is_closed: bool,
}

/// An error message we can send in an RPC request response.
///
/// We don't bother with sending structured error messages
/// since the client will just print them anyways.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RequestError(String);

impl RequestError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

impl std::fmt::Display for RequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

// It's written like this so that we can convert both std errors and anyhow errors into a
// `RequestError`. Trying to write these separately would cause conflicting trait implementations.
impl<E> From<E> for RequestError
where
    E: Into<anyhow::Error>,
{
    fn from(e: E) -> Self {
        Self(e.into().to_string())
    }
}
