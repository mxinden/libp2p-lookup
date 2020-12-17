use ansi_term::Style;
use futures::stream::{Stream, StreamExt};
use libp2p::core;
use libp2p::core::either::EitherOutput;
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::{Boxed, Transport};
use libp2p::core::upgrade;
use libp2p::identify::{Identify, IdentifyEvent, IdentifyInfo};
use libp2p::identity::Keypair;
use libp2p::kad::{
    record::store::MemoryStore, GetClosestPeersOk, Kademlia, KademliaConfig, KademliaEvent,
    QueryResult,
};
use libp2p::ping::{Ping, PingConfig, PingEvent};
use libp2p::swarm::{
    NetworkBehaviour, NetworkBehaviourAction, NetworkBehaviourEventProcess, PollParameters,
    SwarmBuilder,
};
use libp2p::{
    dns, mplex, noise, tcp, yamux, InboundUpgradeExt, Multiaddr, NetworkBehaviour,
    OutboundUpgradeExt, PeerId, Swarm,
};
use std::error::Error;
use std::io;
use std::pin::Pin;
use std::str::FromStr;
use std::task::{Context, Poll};
use std::time::Duration;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "libp2p-lookup", about = "Lookup libp2p nodes.")]
struct Opt {
    #[structopt(long)]
    peer_id: PeerId,
    #[structopt(long)]
    network: Network,
}

#[derive(Debug)]
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
                    ("/dns/p2p.cc1-0.polkadot.network/tcp/30100".parse().unwrap(), FromStr::from_str("12D3KooWEdsXX9657ppNqqrRuaCHFvuNemasgU5msLDwSJ6WqsKc").unwrap()),
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
}

#[async_std::main]
async fn main() {
    env_logger::init();
    let opt = Opt::from_args();

    let mut client = LookupClient::new(opt.network).unwrap();

    match client.lookup_peer(opt.peer_id.clone()).await {
        Ok(peer) => {
            println!("Lookup for peer with id {:?} succeeded.", opt.peer_id);
            println!("\n{}", peer);
        }
        Err(e) => {
            eprintln!("Lookup for peer with id {:?} failed.", opt.peer_id);
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
    fn new(network: Network) -> Result<LookupClient, Box<dyn Error>> {
        // Create a random key for ourselves.
        let local_key = Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());

        let behaviour = LookupBehaviour::new(local_key.clone(), Some("/ksmcc3/kad".to_string()))?;
        // TODO: Don't use legacy for noise when connecting to IPFS.
        let transport = build_transport(local_key, true);
        let mut swarm = SwarmBuilder::new(transport, behaviour, local_peer_id).build();

        for (addr, peer_id) in network.bootnodes() {
            swarm.kademlia.add_address(&peer_id, addr);
        }
        swarm.kademlia.bootstrap().unwrap();

        Ok(LookupClient { swarm })
    }

    async fn lookup_peer(&mut self, peer: PeerId) -> Result<Peer, LookupError> {
        let lookup = async {
            loop {
                match self.next().await.unwrap() {
                    Event::Ping(_) => {}
                    Event::Identify(IdentifyEvent::Received {
                        peer_id,
                        info:
                            IdentifyInfo {
                                protocol_version,
                                agent_version,
                                listen_addrs,
                                protocols,
                                ..
                            },
                        observed_addr,
                    }) => {
                        if peer_id == peer {
                            return Ok(Peer {
                                protocol_version,
                                agent_version,
                                listen_addrs,
                                protocols,
                                observed_addr,
                            });
                        }
                    }
                    Event::Identify(_) => {}
                    Event::Kademlia(KademliaEvent::QueryResult {
                        result: QueryResult::Bootstrap(Ok(_)),
                        ..
                    }) => {
                        self.swarm.kademlia.get_closest_peers(peer.clone());
                    }
                    Event::Kademlia(KademliaEvent::QueryResult {
                        result: QueryResult::Bootstrap(Err(e)),
                        ..
                    }) => panic!("Bootstrap failed with {:?}", e),
                    Event::Kademlia(KademliaEvent::QueryResult {
                        result: QueryResult::GetClosestPeers(Ok(GetClosestPeersOk { peers, .. })),
                        ..
                    }) => {
                        if !peers.contains(&peer) {
                            return Err(LookupError::FailedToFindPeerOnDHT);
                        }
                        if !Swarm::is_connected(&mut self.swarm, &peer) {
                            Swarm::dial(&mut self.swarm, &peer).unwrap();
                        }
                    }
                    Event::Kademlia(_) => {}
                }
            }
        };

        async_std::future::timeout(std::time::Duration::from_secs(30), lookup)
            .await
            .unwrap_or(Err(LookupError::Timeout(
                self.swarm.addresses_of_peer(&peer),
            )))
    }
}

#[derive(Debug)]
enum LookupError {
    Timeout(Vec<Multiaddr>),
    FailedToFindPeerOnDHT,
}

impl Stream for LookupClient {
    type Item = Event;
    fn poll_next(mut self: Pin<&mut Self>, ctx: &mut Context) -> Poll<Option<Self::Item>> {
        match self.swarm.poll_next_unpin(ctx) {
            Poll::Ready(Some(event)) => return Poll::Ready(Some(event)),
            Poll::Ready(None) => return Poll::Ready(None),
            Poll::Pending => {}
        }

        Poll::Pending
    }
}

#[derive(Debug)]
pub enum Event {
    Ping(PingEvent),
    Identify(IdentifyEvent),
    Kademlia(KademliaEvent),
}

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "Event", poll_method = "poll")]
struct LookupBehaviour {
    pub(crate) kademlia: Kademlia<MemoryStore>,
    pub(crate) ping: Ping,
    pub(crate) identify: Identify,

    #[behaviour(ignore)]
    event_buffer: Vec<Event>,
}

impl LookupBehaviour {
    fn new(local_key: Keypair, protocol_name: Option<String>) -> Result<Self, Box<dyn Error>> {
        let local_peer_id = PeerId::from(local_key.public());

        // Create a Kademlia behaviour.
        let store = MemoryStore::new(local_peer_id.clone());
        let mut kademlia_config = KademliaConfig::default();
        if let Some(protocol_name) = protocol_name {
            kademlia_config.set_protocol_name(protocol_name.into_bytes());
        }
        let kademlia = Kademlia::with_config(local_peer_id, store, kademlia_config);

        let ping = Ping::new(PingConfig::new().with_keep_alive(true));

        let user_agent = "substrate-node/v2.0.0-e3245d49d-x86_64-linux-gnu (unknown)".to_string();
        let proto_version = "/substrate/1.0".to_string();
        let identify = Identify::new(proto_version, user_agent, local_key.public());

        Ok(LookupBehaviour {
            kademlia,
            ping,
            identify,

            event_buffer: Vec::new(),
        })
    }

    fn poll<TEv>(
        &mut self,
        _: &mut Context,
        _: &mut impl PollParameters,
    ) -> Poll<NetworkBehaviourAction<TEv, Event>> {
        if !self.event_buffer.is_empty() {
            return Poll::Ready(NetworkBehaviourAction::GenerateEvent(
                self.event_buffer.remove(0),
            ));
        }

        Poll::Pending
    }
}

impl NetworkBehaviourEventProcess<PingEvent> for LookupBehaviour {
    fn inject_event(&mut self, event: PingEvent) {
        self.event_buffer.push(Event::Ping(event));
    }
}

impl NetworkBehaviourEventProcess<IdentifyEvent> for LookupBehaviour {
    fn inject_event(&mut self, event: IdentifyEvent) {
        self.event_buffer.push(Event::Identify(event));
    }
}

impl NetworkBehaviourEventProcess<KademliaEvent> for LookupBehaviour {
    fn inject_event(&mut self, event: KademliaEvent) {
        self.event_buffer.push(Event::Kademlia(event));
    }
}

fn build_transport(keypair: Keypair, noise_legacy: bool) -> Boxed<(PeerId, StreamMuxerBox)> {
    let tcp = tcp::TcpConfig::new().nodelay(true);
    let transport = dns::DnsConfig::new(tcp).unwrap();

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
            let mut noise_legacy = noise::LegacyConfig::default();
            noise_legacy.recv_legacy_handshake = true;

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
            .map_inbound(move |muxer| core::muxing::StreamMuxerBox::new(muxer))
            .map_outbound(move |muxer| core::muxing::StreamMuxerBox::new(muxer))
    };

    transport
        .upgrade(upgrade::Version::V1)
        .authenticate(authentication_config)
        .multiplex(multiplexing_config)
        .timeout(Duration::from_secs(20))
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
        .boxed()
}
