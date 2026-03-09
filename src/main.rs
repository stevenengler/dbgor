mod circ;
mod cli;
mod rpc;
mod util;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context as _;
use arti_client::TorClient;
use clap::Parser;
use futures_util::StreamExt;
use tarpc::context::Context;
use tor_linkspec::{ChanTarget, HasRelayIds, OwnedCircTarget, RelayIdType};
use tor_proto::ClientTunnel;
use tor_rtcompat::tokio::PreferredRuntime;

use crate::cli::CircId;
use crate::rpc::Rpc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = cli::Cli::parse();

    let state = Arc::new(Mutex::new(State::default()));

    fn context_with_timeout(timeout: Duration) -> Context {
        let mut ctx = tarpc::context::current();
        ctx.deadline = std::time::Instant::now() + timeout;
        ctx
    }

    match &cli.command {
        cli::Commands::Server => {
            let name = env!("CARGO_PKG_NAME").replace('-', "_");
            let filter = tracing_subscriber::EnvFilter::builder()
                .with_default_directive(format!("{name}=info").parse().unwrap())
                .from_env()
                .unwrap();
            let subscriber = tracing_subscriber::FmtSubscriber::builder()
                .with_env_filter(filter)
                .with_writer(std::io::stderr)
                .finish();
            tracing::subscriber::set_global_default(subscriber)?;

            tracing::debug!("cli: {cli:#?}");

            rpc::server_run(move || async {
                tracing::info!("Arti bootstrapping...");

                let mut config = arti_client::TorClientConfig::builder();
                // Try to disable preemptive circuits. No idea if this is effective though.
                config.preemptive_circuits().disable_at_threshold(0);
                let config = config.build().unwrap();

                let tor_client = TorClient::with_runtime(
                    PreferredRuntime::current().context("Failed to get current runtime")?,
                );
                let tor_client = tor_client.config(config.clone());
                let tor_client = tor_client
                    .create_bootstrapped()
                    .await
                    .context("Failed to bootstrap")?;

                tracing::info!("Arti bootstrapping completed; ready to process requests");

                Ok(Server { tor_client, state })
            })
            .await?;
        }
        cli::Commands::CircNew(args) => {
            let client = rpc::client_connect().await?;
            let ctx = context_with_timeout(Duration::from_secs(60));

            let circ_id = client
                .circ_new(ctx, args.clone())
                .await?
                .map_err(anyhow::Error::msg)?;

            println!("{circ_id}")
        }
        cli::Commands::CircExtend(args) => {
            let client = rpc::client_connect().await?;
            let ctx = context_with_timeout(Duration::from_secs(60));

            client
                .circ_extend(ctx, args.clone())
                .await?
                .map_err(anyhow::Error::msg)?;
        }
        cli::Commands::CircInfo(args) => {
            let client = rpc::client_connect().await?;
            let ctx = context_with_timeout(Duration::from_secs(2));

            let info = client
                .circ_info(ctx, args.clone())
                .await?
                .map_err(anyhow::Error::msg)?;

            let info = serde_json::to_string_pretty(&info)?;
            println!("{info}");
        }
        cli::Commands::CircResolve(args) => {
            let client = rpc::client_connect().await?;
            let ctx = context_with_timeout(Duration::from_secs(60));

            let ips = client
                .circ_resolve(ctx, args.clone())
                .await?
                .map_err(anyhow::Error::msg)?;

            let ips = serde_json::to_string_pretty(&ips)?;
            println!("{ips}");
        }
        cli::Commands::CircRelease(args) => {
            let client = rpc::client_connect().await?;
            let ctx = context_with_timeout(Duration::from_secs(2));

            client
                .circ_release(ctx, args.clone())
                .await?
                .map_err(anyhow::Error::msg)?;
        }
        cli::Commands::CircList(args) => {
            let client = rpc::client_connect().await?;
            let ctx = context_with_timeout(Duration::from_secs(2));

            let list = client
                .circ_list(ctx, args.clone())
                .await?
                .map_err(anyhow::Error::msg)?;

            let list = serde_json::to_string_pretty(&list)?;
            println!("{list}");
        }
    }

    Ok(())
}

#[derive(Clone)]
struct Server {
    tor_client: TorClient<PreferredRuntime>,
    state: Arc<Mutex<State>>,
}

#[derive(Debug, Default)]
struct State {
    circuits: HashMap<CircId, Arc<tokio::sync::Mutex<Arc<ClientTunnel>>>>,
}

// TODO: Find some way to log all returned errors?
impl Rpc for Server {
    async fn circ_new(
        self,
        _: Context,
        mut args: crate::cli::CircNewArgs,
    ) -> Result<CircId, rpc::RequestError> {
        let netdir = self
            .tor_client
            .dirmgr()
            .netdir(tor_netdir::Timeliness::Timely)?;

        fn pop_front<T>(vec: &mut Vec<T>) -> Option<T> {
            if vec.is_empty() {
                return None;
            }
            Some(vec.remove(0))
        }

        let Some(first_hop) = pop_front(&mut args.relays) else {
            return Err(rpc::RequestError::new(
                "The cli should have required at least one hop",
            ));
        };
        let first_hop = first_hop.as_first_hop(&netdir)?;

        let mut remaining_path = Vec::new();
        for relay in args.relays {
            let target = relay
                .as_any_hop(&netdir)?
                .ok_or_else(|| rpc::RequestError::new("Not a valid circuit target"))?;
            remaining_path.push(OwnedCircTarget::from_circ_target(&target));
        }

        let path_display: Vec<_> = [&first_hop]
            .into_iter()
            .map(|x| x.identity(RelayIdType::Ed25519))
            .chain(
                remaining_path
                    .iter()
                    .map(|x| x.identity(RelayIdType::Ed25519)),
            )
            .collect();
        tracing::debug!("Building circuit: {path_display:?}");

        let chanmgr = self.tor_client.chanmgr();
        let tunnel = crate::circ::new_tunnel(chanmgr, netdir.params(), first_hop).await?;

        for relay in &remaining_path {
            crate::circ::extend_circ(tunnel.as_single_circ().unwrap(), relay, netdir.params())
                .await?;
        }

        let circ_id = CircId::new();
        self.state
            .lock()
            .unwrap()
            .circuits
            .insert(circ_id, Arc::new(tokio::sync::Mutex::new(Arc::new(tunnel))));
        Ok(circ_id)
    }

    async fn circ_extend(
        self,
        _: Context,
        args: crate::cli::CircExtendArgs,
    ) -> Result<(), rpc::RequestError> {
        let netdir = self
            .tor_client
            .dirmgr()
            .netdir(tor_netdir::Timeliness::Timely)?;

        let relays: Vec<_> = args
            .relays
            .into_iter()
            .map(|relay| {
                let relay = relay.as_any_hop(&netdir)?;
                relay.ok_or_else(|| rpc::RequestError::new("Not a valid circuit target"))
            })
            .collect::<Result<_, _>>()?;

        let tunnel = self
            .state
            .lock()
            .unwrap()
            .circuits
            .get(&args.circ)
            .ok_or_else(|| anyhow::anyhow!("Not a valid circuit"))?
            .clone();
        let tunnel = tunnel.lock().await;

        for relay in relays {
            crate::circ::extend_circ(tunnel.as_single_circ().unwrap(), &relay, netdir.params())
                .await?;
        }

        Ok(())
    }

    async fn circ_info(
        self,
        _: Context,
        args: crate::cli::CircInfoArgs,
    ) -> Result<rpc::CircInfo, rpc::RequestError> {
        let netdir = self
            .tor_client
            .dirmgr()
            .netdir(tor_netdir::Timeliness::Timely)?;

        let tunnel = self
            .state
            .lock()
            .unwrap()
            .circuits
            .get(&args.circ)
            .ok_or_else(|| anyhow::anyhow!("Not a valid circuit"))?
            .clone();
        let tunnel = tunnel.lock().await;
        let circ = tunnel.as_single_circ().unwrap();

        let path: Vec<_> = circ
            .single_path()
            .unwrap()
            .iter()
            .map(|entry| {
                if let Some(chan_target) = entry.as_chan_target() {
                    // Look for a relay with all the given IDs, then get its nickname.
                    let nickname = netdir
                        .by_ids(chan_target)
                        .map(|r| r.rs().nickname().to_string());

                    if let Some(nickname) = nickname {
                        format!("{nickname} - {}", chan_target.display_chan_target())
                    } else {
                        chan_target.display_chan_target().to_string()
                    }
                } else {
                    "<not chan target>".to_string()
                }
            })
            .collect();

        Ok(rpc::CircInfo {
            path,
            is_closed: circ.is_closing(),
        })
    }

    async fn circ_resolve(
        self,
        _: Context,
        args: crate::cli::CircResolveArgs,
    ) -> Result<Vec<IpAddr>, rpc::RequestError> {
        let tunnel = self
            .state
            .lock()
            .unwrap()
            .circuits
            .get(&args.circ)
            .ok_or_else(|| anyhow::anyhow!("Not a valid circuit"))?
            .clone();
        let tunnel = tunnel.lock().await;

        Ok(tunnel.resolve(&args.hostname).await?)
    }

    async fn circ_release(
        self,
        _: Context,
        args: crate::cli::CircReleaseArgs,
    ) -> Result<(), rpc::RequestError> {
        self.state
            .lock()
            .unwrap()
            .circuits
            .remove(&args.circ)
            .ok_or_else(|| anyhow::anyhow!("Not a valid circuit"))?;
        Ok(())
    }

    async fn circ_list(
        self,
        _: Context,
        _args: crate::cli::CircListArgs,
    ) -> Result<HashMap<CircId, rpc::CircListEntry>, rpc::RequestError> {
        let tunnels: Vec<_> = self
            .state
            .lock()
            .unwrap()
            .circuits
            .iter()
            .map(|(id, tunnel)| (*id, Arc::clone(tunnel)))
            .collect();

        let list = tunnels.into_iter().map(async |(id, tunnel)| {
            let tunnel = tunnel.lock().await;
            let circ = tunnel.as_single_circ().unwrap();

            (
                id,
                rpc::CircListEntry {
                    is_closed: circ.is_closing(),
                },
            )
        });

        let list = futures_util::stream::FuturesOrdered::from_iter(list);

        let list = list.collect::<HashMap<_, _>>().await;

        Ok(list)
    }
}
