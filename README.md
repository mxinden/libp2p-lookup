# libp2p-lookup

Small helper tool that takes as input a [peer ID][peer-id] or
[address][multiaddr] and prints the output of the [libp2p-identify] protocol.
When provided with a peer ID, the address is looked up on the DHT before
connecting to the node. When provided with an address, the connection is
established right away.

### Installation

```
$ cargo install libp2p-lookup
```

### Usage

```
$ libp2p-lookup --help

libp2p-lookup 0.4.0
Lookup libp2p nodes.

USAGE:
    libp2p-lookup <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    dht       Lookup peer by its ID via the Kademlia DHT
    direct    Lookup peer by its address
    help      Prints this message or the help of the given subcommand(s)
```

#### Lookup peer by [address][multiaddr]

Generates random keypair with peer ID and connects to the provided address.

```
$ libp2p-lookup direct --address /dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa

Lookup for peer with id PeerId("QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa") succeeded.

Protocol version: "ipfs/0.1.0"
Agent version: "go-ipfs/0.8.0/48f94e2"
Observed address: "/ip4/2.200.106.157/tcp/56136"
Listen addresses:
        - "/ip4/147.75.77.187/tcp/4001"
        - "/ip6/2604:1380:0:c100::1/tcp/4001"
        - "/ip4/147.75.77.187/udp/4001/quic"
        - "/ip6/2604:1380:0:c100::1/udp/4001/quic"
Protocols:
        - "/p2p/id/delta/1.0.0"
        - "/ipfs/id/1.0.0"
        - "/ipfs/id/push/1.0.0"
        - "/ipfs/ping/1.0.0"
        - "/libp2p/circuit/relay/0.1.0"
        - "/ipfs/kad/1.0.0"
        - "/ipfs/lan/kad/1.0.0"
        - "/libp2p/autonat/1.0.0"
        - "/ipfs/bitswap/1.2.0"
        - "/ipfs/bitswap/1.1.0"
        - "/ipfs/bitswap/1.0.0"
        - "/ipfs/bitswap"
        - "/x/"
```

#### Lookup peer by [address][multiaddr] and keypair file

If your network nodes only allow certain PeerId's to connect, then you can provide your own keypair file (base58 encoded) to authenticate with the node.

```
$ libp2p-lookup direct --address /dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa --keypair-path ./path/to/keypair.base58

Lookup for peer with id PeerId("QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa") succeeded.

Protocol version: "ipfs/0.1.0"
Agent version: "go-ipfs/0.8.0/48f94e2"
Observed address: "/ip4/2.200.106.157/tcp/56136"
Listen addresses:
        - "/ip4/147.75.77.187/tcp/4001"
        - "/ip6/2604:1380:0:c100::1/tcp/4001"
        - "/ip4/147.75.77.187/udp/4001/quic"
        - "/ip6/2604:1380:0:c100::1/udp/4001/quic"
Protocols:
        - "/p2p/id/delta/1.0.0"
        - "/ipfs/id/1.0.0"
        - "/ipfs/id/push/1.0.0"
        - "/ipfs/ping/1.0.0"
        - "/libp2p/circuit/relay/0.1.0"
        - "/ipfs/kad/1.0.0"
        - "/ipfs/lan/kad/1.0.0"
        - "/libp2p/autonat/1.0.0"
        - "/ipfs/bitswap/1.2.0"
        - "/ipfs/bitswap/1.1.0"
        - "/ipfs/bitswap/1.0.0"
        - "/ipfs/bitswap"
        - "/x/"
```

#### Lookup peer by [peer ID][peer-id]

```
$ libp2p-lookup dht --network kusama --peer-id 12D3KooWQKqane1SqWJNWMQkbia9qiMWXkcHtAdfW5eVF8hbwEDw

Lookup for peer with id PeerId("12D3KooWQKqane1SqWJNWMQkbia9qiMWXkcHtAdfW5eVF8hbwEDw") succeeded.

Protocol version:       "/substrate/1.0"
Agent version:          "Parity Polkadot/v0.8.26-1-803da90-x86_64-linux-gnu (kusama-bootnode-1)"
Observed address:       "/ip4/84.189.93.68/tcp/55482"
Listen addresses:
        - "/dns/kusama-bootnode-1.paritytech.net/tcp/30333"
        - "/dns/kusama-bootnode-1.paritytech.net/tcp/30334/ws"
        - "/ip4/51.79.17.206/tcp/30333"
        - "/ip4/51.79.17.206/tcp/30334/ws"
        - "/dns4/kusama-bootnode-1.paritytech.net/tcp/30333"
        - "/dns4/kusama-bootnode-1.paritytech.net/tcp/30334/ws"
        - "/ip4/127.0.0.1/tcp/30334/ws"
        - "/ip4/127.0.0.1/tcp/30333"
        - "/ip4/51.79.17.206/tcp/30334/ws"
        - "/ip4/51.79.17.206/tcp/30333"
        - "/ip4/10.1.1.56/tcp/30334/ws"
        - "/ip4/10.1.1.56/tcp/30333"
        - "/ip6/::1/tcp/30334/ws"
        - "/ip6/::1/tcp/30333"
        - "/ip6/2607:5300:203:51ce::/tcp/30334/ws"
        - "/ip6/2607:5300:203:51ce::/tcp/30333"
Protocols:
        - "/ksmcc3/block-announces/1"
        - "/ksmcc3/transactions/1"
        - "/substrate/ksmcc3/6"
        - "/substrate/ksmcc3/5"
        - "/substrate/ksmcc3/4"
        - "/substrate/ksmcc3/3"
        - "/ipfs/ping/1.0.0"
        - "/ipfs/id/1.0.0"
        - "/ksmcc3/kad"
        - "/ksmcc3/sync/2"
        - "/ksmcc3/finality-proof/1"
        - "/ksmcc3/light/2"
```

[peer-id]: https://docs.libp2p.io/concepts/peer-id/
[multiaddr]: https://docs.libp2p.io/concepts/addressing/
[libp2p-identify]: https://github.com/libp2p/specs/tree/master/identify
