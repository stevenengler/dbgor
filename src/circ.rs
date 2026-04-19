use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use either::Either;
use tor_chanmgr::ChanMgr;
use tor_linkspec::CircTarget;
use tor_linkspec::OwnedChanTarget;
use tor_llcrypto::pk::curve25519::PublicKey as Curve25519PublicKey;
use tor_netdir::NetDir;
use tor_proto::ClientTunnel;
use tor_proto::client::circuit::ClientCirc;
use tor_protover::Protocols;
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

/// The target for a Create2 circuit.
pub struct Create2Hop {
    pub target: OwnedChanTarget,
    pub ntor: Curve25519PublicKey,
    pub protocols: Protocols,
}

impl tor_linkspec::HasAddrs for Create2Hop {
    fn addrs(&self) -> impl Iterator<Item = SocketAddr> {
        self.target.addrs()
    }
}

impl tor_linkspec::HasRelayIds for Create2Hop {
    fn identity(
        &self,
        key_type: tor_linkspec::RelayIdType,
    ) -> Option<tor_linkspec::RelayIdRef<'_>> {
        self.target.identity(key_type)
    }
}

impl tor_linkspec::HasChanMethod for Create2Hop {
    fn chan_method(&self) -> tor_linkspec::ChannelMethod {
        self.target.chan_method()
    }
}

impl tor_linkspec::ChanTarget for Create2Hop {}

impl tor_linkspec::CircTarget for Create2Hop {
    fn ntor_onion_key(&self) -> &tor_llcrypto::pk::curve25519::PublicKey {
        &self.ntor
    }

    fn protovers(&self) -> &Protocols {
        &self.protocols
    }
}

/// Get 'required-relay-protocols'.
pub fn relay_required_protocol_status(netdir: &NetDir) -> Protocols {
    // This is a hack to get around the fact that the internals aren't public.
    let status = netdir.relay_protocol_status();
    let json = serde_json::to_value(status).unwrap();
    let json = json.get("required").expect("no 'required' field");
    serde_json::from_value(json.clone()).unwrap()
}

/// Apply the protocol overrides to a base protocol set.
/// The overrides act on the protocol level, not the subprotocol level.
///
/// For example given:
/// - `protocols`: `A=1-3 B=2-4`
/// - `overrides`: `B=5 C=2-3`
///
/// this function will return `A=1-3 B=5 C=2-3`.
pub fn override_protocols(mut protocols: Protocols, overrides: &Protocols) -> Protocols {
    // This is ugly, but the `Protocols` (and related types) API is very limited so we need to work
    // around it.
    let known_protocols = [
        "Link=1-63".parse().unwrap(),
        "LinkAuth=1-63".parse().unwrap(),
        "Relay=1-63".parse().unwrap(),
        "DirCache=1-63".parse().unwrap(),
        "HSDir=1-63".parse().unwrap(),
        "HSIntro=1-63".parse().unwrap(),
        "HSRend=1-63".parse().unwrap(),
        "Desc=1-63".parse().unwrap(),
        "Microdesc=1-63".parse().unwrap(),
        "Cons=1-63".parse().unwrap(),
        "Padding=1-63".parse().unwrap(),
        "FlowCtrl=1-63".parse().unwrap(),
        "Conflux=1-63".parse().unwrap(),
    ];

    for all_subprotocols in &known_protocols {
        // If any subprotocols are set for this protocol.
        if !overrides.intersection(all_subprotocols).is_empty() {
            // Remove the entire protocol by removing all of its subprotocols.
            protocols = protocols.difference(all_subprotocols);
        }
    }

    // Add the protocol overrides.
    protocols.union(overrides)
}
