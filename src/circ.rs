use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use either::Either;
use tor_chanmgr::ChanMgr;
use tor_linkspec::CircTarget;
use tor_proto::ClientTunnel;
use tor_proto::client::circuit::ClientCirc;
use tor_rtcompat::Runtime;

/// Create a new single-hop tunnel to `target`.
///
/// Will first open a channel to `target` if needed.
pub async fn new_tunnel<R: Runtime>(
    chanmgr: &ChanMgr<R>,
    net_params: &tor_netdir::params::NetParameters,
    target: FirstHop,
) -> anyhow::Result<ClientTunnel> {
    let chan_usage = tor_chanmgr::ChannelUsage::UserTraffic;
    let (chan, _) = chanmgr.get_or_launch(&target, chan_usage).await?;

    struct Timeouts;
    impl tor_proto::client::circuit::TimeoutEstimator for Timeouts {
        fn circuit_build_timeout(&self, _length: usize) -> Duration {
            Duration::from_secs(60)
        }
    }

    let (pending_circ, reactor) = chan.new_tunnel(Arc::new(Timeouts)).await?;
    tokio::spawn(async {
        let _ = reactor.run().await;
    });
    let circ_params = tor_circmgr::build::exit_circparams_from_netparams(net_params).unwrap();

    let circ = match target {
        FirstHop::Fast(_target) => pending_circ.create_firsthop_fast(circ_params).await?,
        FirstHop::Ntor(target) => pending_circ.create_firsthop(&target, circ_params).await?,
    };

    Ok(circ)
}

/// Extend a circuit to `target`.
pub async fn extend_circ(
    circ: &ClientCirc,
    target: &impl CircTarget,
    net_params: &tor_netdir::params::NetParameters,
) -> anyhow::Result<()> {
    let circ_params = tor_circmgr::build::exit_circparams_from_netparams(net_params).unwrap();
    circ.extend(target, circ_params).await?;
    Ok(())
}

/// The target for the first hop of a circuit.
pub enum FirstHop {
    Fast(tor_linkspec::OwnedChanTarget),
    Ntor(tor_linkspec::OwnedCircTarget),
}

impl tor_linkspec::HasAddrs for FirstHop {
    fn addrs(&self) -> impl Iterator<Item = SocketAddr> {
        match &self {
            Self::Fast(target) => Either::Left(target.addrs()),
            Self::Ntor(target) => Either::Right(target.addrs()),
        }
    }
}

impl tor_linkspec::HasRelayIds for FirstHop {
    fn identity(
        &self,
        key_type: tor_linkspec::RelayIdType,
    ) -> Option<tor_linkspec::RelayIdRef<'_>> {
        match &self {
            Self::Fast(target) => target.identity(key_type),
            Self::Ntor(target) => target.identity(key_type),
        }
    }
}

impl tor_linkspec::HasChanMethod for FirstHop {
    fn chan_method(&self) -> tor_linkspec::ChannelMethod {
        match &self {
            Self::Fast(target) => target.chan_method(),
            Self::Ntor(target) => target.chan_method(),
        }
    }
}

impl tor_linkspec::ChanTarget for FirstHop {}
