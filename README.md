# libp2p-lookup

**Work in progress.**

Small binary that takes as input a [peer
id](https://docs.libp2p.io/concepts/peer-id/), tries to find the corresponding
peer on the DHT, connect to the peer and prints the output of the
[libp2p-identify](https://github.com/libp2p/specs/tree/master/identify)
protocol.

```
$ libp2p-lookup --peer-id 12D3KooWQKqane1SqWJNWMQkbia9qiMWXkcHtAdfW5eVF8hbwEDw

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
