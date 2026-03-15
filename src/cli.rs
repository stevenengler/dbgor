use std::fmt::Display;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::anyhow;
use base64ct::Encoding as _;
use clap::{Args, Parser, Subcommand};
use const_format::formatcp;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};
use tor_linkspec::{CircTarget, HasAddrs, OwnedChanTarget, OwnedCircTarget, RelayId, RelayIdType};
use tor_llcrypto::pk::curve25519::PublicKey as Curve25519PublicKey;
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_netdir::NetDir;

use crate::circ::FirstHop;

// ANSI
const BOLD: &str = "\u{1b}[1m";
const BOLD_UNDERLINE: &str = "\u{1b}[1;4m";
const RST: &str = "\u{1b}[0m";

/// App name from Cargo.
const APP_NAME: &str = clap::crate_name!();

/// ANSI-formatted "Examples" heading.
const EXAMPLES_HEADING: &str = formatcp!("{BOLD_UNDERLINE}Examples:{RST}");

/// The prefix for all circuit IDs.
const CIRC_ID_PREFIX: &str = "c";

/// Tool for manually building circuits.
///
/// Start the RPC server using the `server` command.
/// All other commands act as RPC clients.
#[derive(Parser, Debug, Clone)]
#[command(version)]
// We use a lot of subcommands, so don't need an extra "help" subcommand.
#[clap(disable_help_subcommand = true)]
#[clap(max_term_width(100))]
#[clap(after_long_help = formatcp!("{EXAMPLES_HEADING}{ALL_EXAMPLES}"))]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

const ALL_EXAMPLES: &str = formatcp! {"
  # Start the server.
  {APP_NAME} {BOLD}server{RST}
{CIRC_NEW_EXAMPLES}\
{CIRC_EXTEND_EXAMPLES}\
{CIRC_INFO_EXAMPLES}\
{CIRC_RESOLVE_EXAMPLES}\
{CIRC_BIND_EXAMPLES}\
{CIRC_BIND_DIR_EXAMPLES}\
{CIRC_RELEASE_EXAMPLES}\
{CIRC_LIST_EXAMPLES}\
"};

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Run the server.
    Server,
    CircNew(CircNewArgs),
    CircExtend(CircExtendArgs),
    CircInfo(CircInfoArgs),
    CircResolve(CircResolveArgs),
    CircBind(CircBindArgs),
    CircBindDir(CircBindDirArgs),
    CircRelease(CircReleaseArgs),
    #[clap(visible_alias = "circ-ls")]
    CircList(CircListArgs),
}

/// Build a new circuit.
///
/// Prints the circuit ID handle for this new circuit.
///
/// Will use supplementary information from the consensus when needed.
/// For example to look up a relay by nickname, IP address, or identity.
///
/// Note that there might be more than one relay with the same IP:PORT or nickname,
/// in which case a relay will be chosen arbitrarily.
///
/// The circuit handle will be valid until it's released with `circ-release`, but
/// the circuit itself may be closed before the handle is released (for example if
/// a relay closes the circuit or there's an error).
#[derive(Args, Debug, Clone, Serialize, Deserialize)]
#[clap(after_long_help = formatcp!("{EXAMPLES_HEADING}{CIRC_NEW_EXAMPLES}"))]
pub struct CircNewArgs {
    /// The circuit to build.
    #[arg(required = true)]
    pub relays: Vec<TorTarget>,
}

const CIRC_NEW_EXAMPLES: &str = formatcp! {r#"
  # Build a circuit with one hop to a relay with the nickname "foo".
  {APP_NAME} {BOLD}circ-new{RST} name:foo

  # Build a circuit with multiple hops.
  {APP_NAME} {BOLD}circ-new{RST} name:foo addr:192.0.2.10:5001

  # Build a circuit to the relay with the given RSA identity.
  {APP_NAME} {BOLD}circ-new{RST} rsa:4EBB385C80A2CA5D671E16F1C722FBFB5F176891

  # Build a "CREATE_FAST" circuit to a relay which might not be in the consensus.
  {APP_NAME} {BOLD}circ-new{RST} fast:192.0.2.20:443,rsa:0A9B1B207FD13A6F117F95CAFA358EEE2234F19A

  # Build an "ntor" circuit to a relay which might not be in the consensus.
  {APP_NAME} {BOLD}circ-new{RST} \
    complete:192.0.2.30:9001,ed25519:qpL/LxLYVEXghU76iG3LsSI/UW7MBpIROZK0AB18560,QeRbF/o8G6udG72u/OJiSXW7eW6HzfYZpu8tQFyqVUE
"#};

/// Extend a circuit.
///
/// Will use supplementary information from the consensus when needed.
/// For example to look up a relay by nickname, IP address, or identity.
///
/// Note that there might be more than one relay with the same IP:PORT or nickname,
/// in which case a relay will be chosen arbitrarily.
///
/// The circuit ID must be the value given by a previous `circ-new` command.
///
/// See the `circ-new` command for additional examples of relay specifiers that can be used.
#[derive(Args, Debug, Clone, Serialize, Deserialize)]
#[clap(after_long_help = formatcp!("{EXAMPLES_HEADING}{CIRC_EXTEND_EXAMPLES}"))]
pub struct CircExtendArgs {
    /// The ID of the circuit to extend.
    pub circ: CircIdRef,
    /// The relays to extend to.
    #[arg(required = true)]
    pub relays: Vec<TorTarget>,
}

const CIRC_EXTEND_EXAMPLES: &str = formatcp! {r#"
  # Extend circuit "c1" by one hop to a relay with the nickname "foo".
  {APP_NAME} {BOLD}circ-extend{RST} c1 name:foo

  # Extend circuit "c1" by multiple hops.
  {APP_NAME} {BOLD}circ-extend{RST} c1 name:foo addr:192.0.2.10:5001
"#};

/// Information about a circuit.
///
/// The circuit ID must be the value given by a previous `circ-new` command.
#[derive(Args, Debug, Clone, Serialize, Deserialize)]
#[clap(after_long_help = formatcp!("{EXAMPLES_HEADING}{CIRC_INFO_EXAMPLES}"))]
pub struct CircInfoArgs {
    /// The ID of the circuit.
    pub circ: CircIdRef,
}

const CIRC_INFO_EXAMPLES: &str = formatcp! {r#"
  # Show information about circuit "c1".
  {APP_NAME} {BOLD}circ-info{RST} c1
"#};

/// Resolve a hostname.
///
/// Note that the circuit must end at an exit relay.
///
/// The circuit ID must be the value given by a previous `circ-new` command.
#[derive(Args, Debug, Clone, Serialize, Deserialize)]
#[clap(after_long_help = formatcp!("{EXAMPLES_HEADING}{CIRC_RESOLVE_EXAMPLES}"))]
pub struct CircResolveArgs {
    /// The ID of the circuit (ex: "c3").
    pub circ: CircIdRef,
    /// The hostname to resolve (ex: "torproject.org").
    pub hostname: String,
}

const CIRC_RESOLVE_EXAMPLES: &str = formatcp! {r#"
  # Resolve hostname "torproject.org" by the last hop of circuit "c1".
  {APP_NAME} {BOLD}circ-resolve{RST} c1 torproject.org
"#};

/// Open a listening socket at which new connections will be forwarded along the circuit.
///
/// Given a circuit ID and an address to listen at,
/// any incoming connections at that address will result in a new stream on that circuit.
/// Data will be proxied between that incoming connection and the stream.
///
/// Prints the local address of the listening socket.
/// This is useful when you provide an address with a port of 0.
///
/// This command can be useful when an application does not support SOCKS or HTTP proxies.
///
/// The socket will stop listening when the circuit is closed.
#[derive(Args, Debug, Clone, Serialize, Deserialize)]
#[clap(after_long_help = formatcp!("{EXAMPLES_HEADING}{CIRC_BIND_EXAMPLES}"))]
pub struct CircBindArgs {
    /// The ID of the circuit (ex: "c1").
    pub circ: CircIdRef,
    /// The address to listen at (ex: "127.0.0.1:9070").
    pub addr: SocketAddr,
    /// The destination address (ex: "example.com").
    pub dest_addr: String,
    /// The destination port (ex: 80).
    pub dest_port: u16,
}

const CIRC_BIND_EXAMPLES: &str = formatcp! {r#"
  # Make an HTTP request to "example.com" over circuit "c1".
  {APP_NAME} {BOLD}circ-bind{RST} c1 127.0.0.1:9070 example.com 80
  curl --header 'Host: example.com' 127.0.0.1:9070 | less
"#};

/// Open a listening socket at which new connections will be forwarded
/// to the relay's directory port.
///
/// Given a circuit ID and an address to listen at,
/// any incoming connections at that address will result in a new directory stream on that circuit.
/// Data will be proxied between that incoming connection and the stream.
///
/// Prints the local address of the listening socket.
/// This is useful when you provide an address with a port of 0.
///
/// This command can be useful when an application does not support SOCKS or HTTP proxies.
///
/// The socket will stop listening when the circuit is closed.
#[derive(Args, Debug, Clone, Serialize, Deserialize)]
#[clap(after_long_help = formatcp!("{EXAMPLES_HEADING}{CIRC_BIND_DIR_EXAMPLES}"))]
pub struct CircBindDirArgs {
    /// The ID of the circuit (ex: "c1").
    pub circ: CircIdRef,
    /// The address to listen at (ex: "127.0.0.1:9070").
    pub addr: SocketAddr,
}

const CIRC_BIND_DIR_EXAMPLES: &str = formatcp! {r#"
  # Download the latest consensus over circuit "c1".
  {APP_NAME} {BOLD}circ-bind-dir{RST} c1 127.0.0.1:9070
  curl 127.0.0.1:9070/tor/status-vote/current/consensus | less
"#};

/// Release an existing circuit.
///
/// This will destroy the circuit, unless it has already closed. If it is being used by another
/// request or a data stream, it will be closed after the request or stream has completed.
///
/// The circuit ID must be the value given by a previous `circ-new` command.
#[derive(Args, Debug, Clone, Serialize, Deserialize)]
#[clap(after_long_help = formatcp!("{EXAMPLES_HEADING}{CIRC_RELEASE_EXAMPLES}"))]
pub struct CircReleaseArgs {
    /// The ID of the circuit to release (ex: "c3").
    pub circ: CircIdRef,
    /// Force close the circuit.
    ///
    /// This will close the circuit and terminate all streams using it.
    /// Any other active uses of this circuit,
    /// such as other running commands, will likely fail.
    #[arg(long)]
    pub close: bool,
}

const CIRC_RELEASE_EXAMPLES: &str = formatcp! {r#"
  # Release circuit "c1". The circuit will close once it's no longer being used.
  {APP_NAME} {BOLD}circ-release{RST} c1

  # Release circuit "c1" and terminate it. Active streams or commands using it will likely fail.
  {APP_NAME} {BOLD}circ-release{RST} --close c1
"#};

/// List all circuits.
#[derive(Args, Debug, Clone, Serialize, Deserialize)]
#[clap(after_long_help = formatcp!("{EXAMPLES_HEADING}{CIRC_LIST_EXAMPLES}"))]
pub struct CircListArgs;

const CIRC_LIST_EXAMPLES: &str = formatcp! {r#"
  # List all circuits.
  {APP_NAME} {BOLD}circ-list{RST}
"#};

/// A circuit ID that may or may not represent a valid circuit.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, SerializeDisplay, DeserializeFromStr)]
pub struct CircIdRef(usize);

impl CircIdRef {
    pub fn new(id: usize) -> Self {
        Self(id)
    }
}

impl Display for CircIdRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{CIRC_ID_PREFIX}{}", self.0)
    }
}

impl FromStr for CircIdRef {
    type Err = CircIdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Some(id) = s.strip_prefix(CIRC_ID_PREFIX) else {
            return Err(CircIdParseError::MissingPrefix);
        };
        Ok(Self(usize::from_str(id)?))
    }
}

#[derive(thiserror::Error, Debug)]
pub enum CircIdParseError {
    #[error(r#"missing "{CIRC_ID_PREFIX}" prefix"#)]
    MissingPrefix,
    #[error("could not parse integer")]
    ParseInt(#[from] std::num::ParseIntError),
}

/// A circuit ID that represents a circuit.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct CircId(CircIdRef);

impl CircId {
    pub fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(1);
        Self(CircIdRef::new(NEXT.fetch_add(1, Ordering::Relaxed)))
    }
}

impl Display for CircId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::borrow::Borrow<CircIdRef> for CircId {
    fn borrow(&self) -> &CircIdRef {
        &self.0
    }
}

/// A target relay for circuit create or extend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TorTarget {
    Id(RelayId),
    Address(SocketAddr),
    Name(String),
    Complete(CompleteTarget),
    Fast(FastTarget),
}

impl FromStr for TorTarget {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.parse::<Identity>() {
            Ok(id) => return Ok(Self::Id(id.0)),
            Err(IdentParseError::UnknownType) => {}
            Err(e) => return Err(e.into()),
        }

        if let Some(x) = s.strip_prefix("addr:") {
            Ok(Self::Address(x.parse()?))
        } else if let Some(x) = s.strip_prefix("name:") {
            Ok(Self::Name(x.into()))
        } else if let Some(x) = s.strip_prefix("complete:") {
            Ok(Self::Complete(x.parse()?))
        } else if let Some(x) = s.strip_prefix("fast:") {
            Ok(Self::Fast(x.parse()?))
        } else {
            Err(anyhow::anyhow!("couldn't parse target"))
        }
    }
}

impl TorTarget {
    /// The target as something that can be used for the first hop of a circuit.
    pub fn as_first_hop(&self, netdir: &NetDir) -> anyhow::Result<FirstHop> {
        match self {
            Self::Id(id) => {
                let relay = netdir
                    .by_id(id.as_ref())
                    .ok_or_else(|| anyhow!("No relay found with identity {id}"))?;
                Ok(FirstHop::Ntor(OwnedCircTarget::from_circ_target(&relay)))
            }
            Self::Address(addr) => {
                // TODO: Should we return an error if there's more than one?
                let relay = netdir
                    .relays()
                    .find(|r| r.addrs().contains(addr))
                    .ok_or_else(|| anyhow!("No relay found with address {addr}"))?;
                Ok(FirstHop::Ntor(OwnedCircTarget::from_circ_target(&relay)))
            }
            Self::Name(name) => {
                // TODO: Should we return an error if there's more than one?
                let relay = netdir
                    .relays()
                    .find(|r| r.rs().nickname() == name)
                    .ok_or_else(|| anyhow!("No relay found with name {name}"))?;
                Ok(FirstHop::Ntor(OwnedCircTarget::from_circ_target(&relay)))
            }
            Self::Complete(target) => Ok(FirstHop::Ntor(OwnedCircTarget::from_circ_target(target))),
            Self::Fast(target) => Ok(FirstHop::Fast(OwnedChanTarget::from_chan_target(target))),
        }
    }

    /// The target as something that can be used as any hop of a circuit.
    pub fn as_any_hop(&self, netdir: &NetDir) -> anyhow::Result<Option<impl CircTarget + use<>>> {
        match self.as_first_hop(netdir)? {
            FirstHop::Ntor(x) => Ok(Some(x)),
            FirstHop::Fast(_) => Ok(None),
        }
    }
}

/// Target for a `RELAY_FAST` circuit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FastTarget {
    pub addr: SocketAddr,
    pub id: RelayId,
}

impl FromStr for FastTarget {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split(',');

        let addr = parts
            .next()
            .ok_or_else(|| anyhow::anyhow!("missing address"))?;
        let addr = addr.parse()?;

        let id = parts.next().ok_or_else(|| anyhow::anyhow!("missing id"))?;
        let id: Identity = id.parse()?;
        let id = id.0;

        if parts.next().is_some() {
            return Err(anyhow::anyhow!("unexpected part"));
        }

        Ok(Self { addr, id })
    }
}

impl tor_linkspec::HasAddrs for FastTarget {
    fn addrs(&self) -> impl Iterator<Item = SocketAddr> {
        [self.addr].into_iter()
    }
}

impl tor_linkspec::HasRelayIds for FastTarget {
    fn identity(
        &self,
        key_type: tor_linkspec::RelayIdType,
    ) -> Option<tor_linkspec::RelayIdRef<'_>> {
        if key_type == self.id.id_type() {
            return Some(self.id.as_ref());
        }
        None
    }
}

impl tor_linkspec::HasChanMethod for FastTarget {
    fn chan_method(&self) -> tor_linkspec::ChannelMethod {
        tor_linkspec::ChannelMethod::Direct(vec![self.addr])
    }
}

impl tor_linkspec::ChanTarget for FastTarget {}

/// Everything needed to build a circuit to the target relay; no consensus required.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompleteTarget {
    pub addr: SocketAddr,
    pub id: RelayId,
    pub ntor: NtorKey,
    pub protocols: tor_protover::Protocols,
}

impl FromStr for CompleteTarget {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split(',');

        let addr = parts
            .next()
            .ok_or_else(|| anyhow::anyhow!("missing address"))?;
        let addr = addr.parse()?;

        let id = parts.next().ok_or_else(|| anyhow::anyhow!("missing id"))?;
        let id: Identity = id.parse()?;
        let id = id.0;

        let ntor = parts
            .next()
            .ok_or_else(|| anyhow::anyhow!("missing ntor"))?;
        let ntor = base64ct::Base64Unpadded::decode_vec(ntor)
            .map_err(|_| anyhow::anyhow!("ntor not base64"))?;
        let ntor = NtorKey::from_bytes(&ntor).ok_or_else(|| anyhow::anyhow!("invalid ntor key"))?;

        if parts.next().is_some() {
            return Err(anyhow::anyhow!("unexpected part"));
        }

        // TODO: This wouldn't be easy to get on the cli.
        // For example: "Conflux=1 Cons=1-2 Desc=1-2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5
        // HSRend=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 Padding=2 Relay=1-4"
        //
        // Instead, maybe allow passing in a microdescriptor filename.
        //
        // We could get 'required-relay-protocols' from the consensus, but we don't have access to
        // that here.
        let protocols = "Conflux=1 Cons=1-2 Desc=1-2 DirCache=2 FlowCtrl=1-2 HSDir=2 \
                         HSIntro=4-5 HSRend=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 \
                         Padding=2 Relay=1-4"
            .parse()
            .unwrap();

        Ok(Self {
            addr,
            id,
            ntor,
            protocols,
        })
    }
}

impl tor_linkspec::HasAddrs for CompleteTarget {
    fn addrs(&self) -> impl Iterator<Item = SocketAddr> {
        [self.addr].into_iter()
    }
}

impl tor_linkspec::HasRelayIds for CompleteTarget {
    fn identity(
        &self,
        key_type: tor_linkspec::RelayIdType,
    ) -> Option<tor_linkspec::RelayIdRef<'_>> {
        if key_type == self.id.id_type() {
            return Some(self.id.as_ref());
        }
        None
    }
}

impl tor_linkspec::HasChanMethod for CompleteTarget {
    fn chan_method(&self) -> tor_linkspec::ChannelMethod {
        tor_linkspec::ChannelMethod::Direct(vec![self.addr])
    }
}

impl tor_linkspec::ChanTarget for CompleteTarget {}

impl tor_linkspec::CircTarget for CompleteTarget {
    fn ntor_onion_key(&self) -> &tor_llcrypto::pk::curve25519::PublicKey {
        &self.ntor.0
    }
    fn protovers(&self) -> &tor_protover::Protocols {
        &self.protocols
    }
}

/// An ntor key.
// We don't actually store this anywhere, just use it for parsing.
#[derive(Debug, Clone)]
pub struct NtorKey(pub Curve25519PublicKey);

impl NtorKey {
    fn from_bytes(b: &[u8]) -> Option<Self> {
        let b: [u8; 32] = b.try_into().ok()?;
        Some(Self(b.into()))
    }
}

impl Serialize for NtorKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.as_bytes().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for NtorKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = <[u8; 32]>::deserialize(deserializer)?;
        Ok(Self(Curve25519PublicKey::from(bytes)))
    }
}

/// An identity of a relay.
// We don't actually store this anywhere, just use it for parsing.
struct Identity(RelayId);

impl FromStr for Identity {
    type Err = IdentParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(x) = s.strip_prefix("rsa:") {
            let bytes = hex::decode(x)?;
            let id = RsaIdentity::from_bytes(&bytes)
                .ok_or(IdentParseError::Invalid(RelayIdType::Rsa))?
                .into();
            Ok(Self(id))
        } else if let Some(x) = s.strip_prefix("ed25519:") {
            let bytes = base64ct::Base64Unpadded::decode_vec(x)?;
            let id = Ed25519Identity::from_bytes(&bytes)
                .ok_or(IdentParseError::Invalid(RelayIdType::Ed25519))?
                .into();
            Ok(Self(id))
        } else {
            Err(IdentParseError::UnknownType)
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum IdentParseError {
    #[error("unknown id type")]
    UnknownType,
    #[error("could not decode hex")]
    DecodeHex(#[from] hex::FromHexError),
    #[error("could not decode base64")]
    DecodeBase64(#[from] base64ct::Error),
    #[error("invalid {0} id")]
    Invalid(RelayIdType),
}
