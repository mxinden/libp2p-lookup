use ansi_term::Style;
use futures::executor::block_on;
use futures::future::{FutureExt, TryFutureExt};
use futures::stream::StreamExt;
use libp2p::core;
use libp2p::core::either::EitherOutput;
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::{Boxed, Transport};
use libp2p::core::upgrade;
use libp2p::core::ConnectedPoint;
use libp2p::identify::{Identify, IdentifyConfig, IdentifyEvent, IdentifyInfo};
use libp2p::identity::Keypair;
use libp2p::kad::{
    record::store::MemoryStore, GetClosestPeersOk, Kademlia, KademliaConfig, KademliaEvent,
    QueryResult,
};
use libp2p::ping::{Ping, PingConfig, PingEvent};
use libp2p::swarm::{SwarmBuilder, SwarmEvent};
use libp2p::{
    dns, mplex, noise, tcp, yamux, InboundUpgradeExt, Multiaddr, NetworkBehaviour,
    OutboundUpgradeExt, PeerId, Swarm,
};
use std::io;
use std::str::FromStr;
use std::time::Duration;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "libp2p-lookup", about = "Lookup libp2p nodes.")]
enum Opt {
    /// Lookup peer by its address.
    Direct {
        /// Address of the peer.
        #[structopt(long)]
        address: Multiaddr,
    },
    /// Lookup peer by its ID via the Kademlia DHT.
    Dht {
        /// ID of the peer.
        #[structopt(long)]
        peer_id: PeerId,
        /// Network of the peer.
        #[structopt(long)]
        network: Network,
    },
}

#[async_std::main]
async fn main() {
    env_logger::init();
    let opt = Opt::from_args();

    let lookup = match opt {
        Opt::Dht { peer_id, network } => {
            let client = LookupClient::new(Some(network));
            client.lookup_on_dht(peer_id).boxed()
        }
        Opt::Direct { address } => {
            let client = LookupClient::new(None);
            client.lookup_directly(address).boxed()
        }
    };

    let timed_lookup = async_std::future::timeout(std::time::Duration::from_secs(20), lookup)
        .map_err(|_| LookupError::Timeout);

    match timed_lookup.await {
        Ok(Ok(peer)) => {
            println!("Lookup for peer with id {:?} succeeded.", peer.peer_id);
            println!("\n{}", peer);
        }
        Ok(Err(e)) | Err(e) => {
            eprintln!("Lookup failed.");
            eprintln!("\n{:?}", e);
            std::process::exit(1);
        }
    }
}

fn print_key(k: &str, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    writeln!(f, "{}:", Style::new().bold().paint(k))
}

fn print_key_value<V: std::fmt::Debug>(
    k: &str,
    v: V,
    f: &mut std::fmt::Formatter<'_>,
) -> std::fmt::Result {
    writeln!(f, "{}: {:?}", Style::new().bold().paint(k), v)
}

pub struct LookupClient {
    swarm: Swarm<LookupBehaviour>,
}

struct Peer {
    peer_id: PeerId,
    protocol_version: String,
    agent_version: String,
    listen_addrs: Vec<Multiaddr>,
    protocols: Vec<String>,
    observed_addr: Multiaddr,
}

impl std::fmt::Display for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        print_key_value("Protocol version", self.protocol_version.clone(), f)?;
        print_key_value("Agent version", self.agent_version.clone(), f)?;
        print_key_value("Observed address", self.observed_addr.clone(), f)?;
        if !self.listen_addrs.is_empty() {
            print_key("Listen addresses", f)?;
            for addr in &self.listen_addrs {
                println!("\t- {:?}", addr);
            }
        }
        if !self.protocols.is_empty() {
            print_key("Protocols", f)?;
            for protocol in &self.protocols {
                println!("\t- {:?}", protocol);
            }
        }

        Ok(())
    }
}

impl LookupClient {
    fn new(network: Option<Network>) -> Self {
        // Create a random key for ourselves.
        let local_key = Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());

        let behaviour = LookupBehaviour::new(
            local_key.clone(),
            network.clone().map(|n| n.protocol()).flatten(),
        );
        // TODO: Don't use legacy for noise when connecting to IPFS.
        let transport = build_transport(local_key, true);
        let mut swarm = SwarmBuilder::new(transport, behaviour, local_peer_id).build();

        if let Some(network) = network {
            for (addr, peer_id) in network.bootnodes() {
                swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
            }
        }

        LookupClient { swarm }
    }

    async fn lookup_directly(mut self, dst_addr: Multiaddr) -> Result<Peer, LookupError> {
        self.swarm.dial_addr(dst_addr.clone()).unwrap();

        loop {
            if let SwarmEvent::ConnectionEstablished {
                peer_id,
                endpoint,
                num_established,
            } = self.swarm.next().await.expect("Infinite Stream.")
            {
                assert_eq!(Into::<u32>::into(num_established), 1);
                match endpoint {
                    ConnectedPoint::Dialer { address } => {
                        if address == dst_addr {
                            return self.wait_for_identify(peer_id).await;
                        }
                    }
                    ConnectedPoint::Listener { .. } => {}
                }
            }
        }
    }

    async fn lookup_on_dht(mut self, peer: PeerId) -> Result<Peer, LookupError> {
        self.swarm.behaviour_mut().kademlia.get_closest_peers(peer);

        loop {
            match self.swarm.next().await.expect("Infinite Stream.") {
                SwarmEvent::ConnectionEstablished {
                    peer_id,
                    num_established,
                    ..
                } => {
                    assert_eq!(Into::<u32>::into(num_established), 1);
                    if peer_id == peer {
                        return self.wait_for_identify(peer).await;
                    }
                }
                SwarmEvent::Behaviour(Event::Kademlia(KademliaEvent::OutboundQueryCompleted {
                    result: QueryResult::Bootstrap(_),
                    ..
                })) => {
                    panic!("Unexpected bootstrap.");
                }
                SwarmEvent::Behaviour(Event::Kademlia(KademliaEvent::OutboundQueryCompleted {
                    result: QueryResult::GetClosestPeers(Ok(GetClosestPeersOk { peers, .. })),
                    ..
                })) => {
                    if !peers.contains(&peer) {
                        return Err(LookupError::FailedToFindPeerOnDht);
                    }
                    if !Swarm::is_connected(&self.swarm, &peer) {
                        // TODO: Kademlia might not be caching the address of the peer.
                        Swarm::dial(&mut self.swarm, &peer).unwrap();
                        return self.wait_for_identify(peer).await;
                    }
                }
                _ => {}
            }
        }
    }

    async fn wait_for_identify(&mut self, peer: PeerId) -> Result<Peer, LookupError> {
        loop {
            if let SwarmEvent::Behaviour(Event::Identify(IdentifyEvent::Received {
                peer_id,
                info:
                    IdentifyInfo {
                        protocol_version,
                        agent_version,
                        listen_addrs,
                        protocols,
                        observed_addr,
                        ..
                    },
            })) = self.swarm.next().await.expect("Infinite Stream.")
            {
                if peer_id == peer {
                    return Ok(Peer {
                        peer_id,
                        protocol_version,
                        agent_version,
                        listen_addrs,
                        protocols,
                        observed_addr,
                    });
                }
            }
        }
    }
}

#[derive(Debug)]
enum LookupError {
    Timeout,
    FailedToFindPeerOnDht,
}

#[derive(Debug)]
pub enum Event {
    Ping(PingEvent),
    Identify(IdentifyEvent),
    Kademlia(KademliaEvent),
}

impl From<PingEvent> for Event {
    fn from(e: PingEvent) -> Self {
        Event::Ping(e)
    }
}

impl From<IdentifyEvent> for Event {
    fn from(e: IdentifyEvent) -> Self {
        Event::Identify(e)
    }
}

impl From<KademliaEvent> for Event {
    fn from(e: KademliaEvent) -> Self {
        Event::Kademlia(e)
    }
}

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "Event", event_process = false)]
struct LookupBehaviour {
    pub(crate) kademlia: Kademlia<MemoryStore>,
    pub(crate) ping: Ping,
    pub(crate) identify: Identify,
}

impl LookupBehaviour {
    fn new(local_key: Keypair, protocol_name: Option<String>) -> Self {
        let local_peer_id = PeerId::from(local_key.public());

        // Create a Kademlia behaviour.
        let store = MemoryStore::new(local_peer_id);
        let mut kademlia_config = KademliaConfig::default();
        if let Some(protocol_name) = protocol_name {
            kademlia_config.set_protocol_name(protocol_name.into_bytes());
        }
        let kademlia = Kademlia::with_config(local_peer_id, store, kademlia_config);

        let ping = Ping::new(PingConfig::new().with_keep_alive(true));

        let user_agent = "substrate-node/v2.0.0-e3245d49d-x86_64-linux-gnu (unknown)".to_string();
        let proto_version = "/substrate/1.0".to_string();
        let identify = Identify::new(
            IdentifyConfig::new(proto_version, local_key.public()).with_agent_version(user_agent),
        );

        LookupBehaviour {
            kademlia,
            ping,
            identify,
        }
    }
}

fn build_transport(keypair: Keypair, noise_legacy: bool) -> Boxed<(PeerId, StreamMuxerBox)> {
    let tcp = tcp::TcpConfig::new().nodelay(true);
    let transport = block_on(dns::DnsConfig::system(tcp)).unwrap();

    let authentication_config = {
        let noise_keypair_legacy = noise::Keypair::<noise::X25519>::new()
            .into_authentic(&keypair)
            .unwrap();
        let noise_keypair_spec = noise::Keypair::<noise::X25519Spec>::new()
            .into_authentic(&keypair)
            .unwrap();

        let mut xx_config = noise::NoiseConfig::xx(noise_keypair_spec);
        let mut ix_config = noise::NoiseConfig::ix(noise_keypair_legacy);

        if noise_legacy {
            // Legacy noise configurations for backward compatibility.
            let noise_legacy = noise::LegacyConfig {
                recv_legacy_handshake: true,
                ..noise::LegacyConfig::default()
            };

            xx_config.set_legacy_config(noise_legacy.clone());
            ix_config.set_legacy_config(noise_legacy);
        }

        let extract_peer_id = |result| match result {
            EitherOutput::First((peer_id, o)) => (peer_id, EitherOutput::First(o)),
            EitherOutput::Second((peer_id, o)) => (peer_id, EitherOutput::Second(o)),
        };

        core::upgrade::SelectUpgrade::new(
            xx_config.into_authenticated(),
            ix_config.into_authenticated(),
        )
        .map_inbound(extract_peer_id)
        .map_outbound(extract_peer_id)
    };

    let multiplexing_config = {
        let mut mplex_config = mplex::MplexConfig::new();
        mplex_config.set_max_buffer_behaviour(mplex::MaxBufferBehaviour::Block);
        mplex_config.set_max_buffer_size(usize::MAX);

        let mut yamux_config = yamux::YamuxConfig::default();
        // Enable proper flow-control: window updates are only sent when
        // buffered data has been consumed.
        yamux_config.set_window_update_mode(yamux::WindowUpdateMode::on_read());

        core::upgrade::SelectUpgrade::new(yamux_config, mplex_config)
            .map_inbound(core::muxing::StreamMuxerBox::new)
            .map_outbound(core::muxing::StreamMuxerBox::new)
    };

    transport
        .upgrade(upgrade::Version::V1)
        .authenticate(authentication_config)
        .multiplex(multiplexing_config)
        .timeout(Duration::from_secs(20))
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
        .boxed()
}

#[derive(Debug, Clone)]
enum Network {
    Kusama,
    Polkadot,
    Ipfs,
}

impl FromStr for Network {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "kusama" => Ok(Self::Kusama),
            "polkadot" => Ok(Self::Polkadot),
            "ipfs" => Ok(Self::Ipfs),
            n => Err(format!("Network '{}' not supported.", n)),
        }
    }
}

impl Network {
    #[rustfmt::skip]
    fn bootnodes(&self) -> Vec<(Multiaddr, PeerId)> {
        match self {
            Network::Kusama => {
                vec![
                    ("/dns/p2p.cc3-0.kusama.network/tcp/30100".parse().unwrap(), FromStr::from_str("12D3KooWDgtynm4S9M3m6ZZhXYu2RrWKdvkCSScc25xKDVSg1Sjd").unwrap()),
                    ("/dns/p2p.cc3-1.kusama.network/tcp/30100".parse().unwrap(), FromStr::from_str("12D3KooWNpGriWPmf621Lza9UWU9eLLBdCFaErf6d4HSK7Bcqnv4").unwrap()),
                    ("/dns/p2p.cc3-2.kusama.network/tcp/30100".parse().unwrap(), FromStr::from_str("12D3KooWLmLiB4AenmN2g2mHbhNXbUcNiGi99sAkSk1kAQedp8uE").unwrap()),
                    ("/dns/p2p.cc3-3.kusama.network/tcp/30100".parse().unwrap(), FromStr::from_str("12D3KooWEGHw84b4hfvXEfyq4XWEmWCbRGuHMHQMpby4BAtZ4xJf").unwrap()),
                    ("/dns/p2p.cc3-4.kusama.network/tcp/30100".parse().unwrap(), FromStr::from_str("12D3KooWF9KDPRMN8WpeyXhEeURZGP8Dmo7go1tDqi7hTYpxV9uW").unwrap()),
                    ("/dns/p2p.cc3-5.kusama.network/tcp/30100".parse().unwrap(), FromStr::from_str("12D3KooWDiwMeqzvgWNreS9sV1HW3pZv1PA7QGA7HUCo7FzN5gcA").unwrap()),
                    ("/dns/kusama-bootnode-0.paritytech.net/tcp/30333".parse().unwrap(), FromStr::from_str("12D3KooWSueCPH3puP2PcvqPJdNaDNF3jMZjtJtDiSy35pWrbt5h").unwrap()),
                    ("/dns/kusama-bootnode-1.paritytech.net/tcp/30333".parse().unwrap(), FromStr::from_str("12D3KooWQKqane1SqWJNWMQkbia9qiMWXkcHtAdfW5eVF8hbwEDw").unwrap())
                ]
            }
            Network::Polkadot => {
                vec![
                    // ("/dns/p2p.cc1-0.polkadot.network/tcp/30100".parse().unwrap(), FromStr::from_str("12D3KooWEdsXX9657ppNqqrRuaCHFvuNemasgU5msLDwSJ6WqsKc").unwrap()),
                    ("/dns/p2p.cc1-1.polkadot.network/tcp/30100".parse().unwrap(), FromStr::from_str("12D3KooWAtx477KzC8LwqLjWWUG6WF4Gqp2eNXmeqAG98ehAMWYH").unwrap()),
                    ("/dns/p2p.cc1-2.polkadot.network/tcp/30100".parse().unwrap(), FromStr::from_str("12D3KooWAGCCPZbr9UWGXPtBosTZo91Hb5M3hU8v6xbKgnC5LVao").unwrap()),
                    ("/dns/p2p.cc1-3.polkadot.network/tcp/30100".parse().unwrap(), FromStr::from_str("12D3KooWJ4eyPowiVcPU46pXuE2cDsiAmuBKXnFcFPapm4xKFdMJ").unwrap()),
                    ("/dns/p2p.cc1-4.polkadot.network/tcp/30100".parse().unwrap(), FromStr::from_str("12D3KooWNMUcqwSj38oEq1zHeGnWKmMvrCFnpMftw7JzjAtRj2rU").unwrap()),
                    ("/dns/p2p.cc1-5.polkadot.network/tcp/30100".parse().unwrap(), FromStr::from_str("12D3KooWDs6LnpmWDWgZyGtcLVr3E75CoBxzg1YZUPL5Bb1zz6fM").unwrap()),
                    ("/dns/cc1-0.parity.tech/tcp/30333".parse().unwrap(), FromStr::from_str("12D3KooWSz8r2WyCdsfWHgPyvD8GKQdJ1UAiRmrcrs8sQB3fe2KU").unwrap()),
                    ("/dns/cc1-1.parity.tech/tcp/30333".parse().unwrap(), FromStr::from_str("12D3KooWFN2mhgpkJsDBuNuE5427AcDrsib8EoqGMZmkxWwx3Md4").unwrap()),
                ]
            }
            Network::Ipfs => {
                vec![
                    ("/ip4/104.131.131.82/tcp/4001".parse().unwrap(), FromStr::from_str("QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ").unwrap()),
                ]
            }
        }
    }

    fn protocol(&self) -> Option<String> {
        match self {
            Network::Kusama => Some("/ksmcc3/kad".to_string()),
            Network::Polkadot => Some("/dot/kad".to_string()),
            Network::Ipfs => None,
        }
    }
}
