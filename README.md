# Setowire - Rust

A lightweight, portable P2P networking library built on UDP. No central servers, no brokers — peers find each other and communicate directly.

Built to be simple enough to reimplement in any language.

---

## Why Rust

Rust provides memory safety without garbage collection, making it ideal for high-performance network applications. This implementation offers:

- **Zero-cost abstractions** - no runtime overhead
- **Memory safety** - no buffer overflows or use-after-free bugs
- **Async I/O** - built on Tokio for efficient networking
- **Cross-compilation** - works on any platform Rust supports

---

## Install

Add to your `Cargo.toml`:

```toml
[dependencies]
setowire = { path = "setowire" }
tokio = { version = "1", features = ["full"] }
sha2 = "0.10"
```

---

## How it works

Peers discover each other through multiple strategies running in parallel — whichever works first wins:

- **DHT** — decentralized peer discovery by topic
- **Piping servers** — HTTPS rendezvous for peers behind strict NATs
- **LAN multicast** — instant discovery on local networks
- **HTTP bootstrap nodes** — fallback seed servers
- **Peer cache** — remembers peers from previous sessions

Once connected, all traffic is encrypted end-to-end with X25519 + ChaCha20-Poly1305. Peers that detect they have a full-cone NAT automatically become relays for others.

---

## File structure

```
constants.rs   — all tuneable parameters and frame type definitions
crypto.rs      — X25519 key exchange, ChaCha20-Poly1305 encrypt/decrypt
structs.rs     — BloomFilter, LRU, RingBuffer, PayloadCache
framing.rs     — packet fragmentation, jitter buffer, batch UDP sender
dht_lib.rs     — minimal DHT for decentralized topic-based discovery
peer.rs        — per-peer state: queues, congestion control, multipath
swarm.rs       — main class: discovery, mesh, relay, sync, gossip
index.rs       — entry point
chat.rs        — example terminal chat app
```

---

## Quick start

```rust
use setowire::{Swarm, Peer};
use sha2::Digest;
use tokio;

#[tokio::main]
async fn main() {
    let mut swarm = Swarm::new().await;
    let topic = sha2::Sha256::digest("my-topic");
    
    swarm.join(&topic[..], true, true);
    
    swarm.on_connection(Box::new(|peer: &Peer| {
        println!("New peer: {}", peer.id);
    }));
    
    swarm.on_data(Box::new(|data: &[u8], peer: &Peer| {
        println!("Got: {:?}", data);
    }));
    
    // Broadcast
    swarm.broadcast(b"Hello, world!");
    
    // Keep running
    tokio::signal::ctrl_c().await.unwrap();
}
```

---

## API

### `Swarm::new()`

Creates a new P2P swarm instance.

### `swarm.join(topic, announce, lookup)`

Start announcing and/or looking up peers on a topic. Returns nothing.

### `swarm.broadcast(data)`

Send data to all connected peers. Returns number of peers reached.

### `swarm.store(key, value)`

Store a value in the local cache and announce to the mesh.

### `swarm.fetch(key)`

Fetch a value from cache or network. Returns `Option<Vec<u8>>`.

### `swarm.destroy().await`

Graceful shutdown.

### Callbacks

```rust
swarm.on_connection(Box::new(|peer: &Peer| { ... }));
swarm.on_disconnection(Box::new(|peer_id: &str| { ... }));
swarm.on_data(Box::new(|data: &[u8], peer: &Peer| { ... }));
```

---

## Protocol

The wire protocol is plain UDP. Each packet starts with a 1-byte frame type:

| byte | type | description |
|---|---|---|
| `0x01` | DATA | encrypted application data |
| `0x03` | PING | keepalive + RTT measurement |
| `0x04` | PONG | keepalive reply |
| `0x0A` | GOAWAY | graceful disconnect |
| `0x0B` | FRAG | fragment of a large message |
| `0x13` | BATCH | multiple frames in one datagram |
| `0x14` | CHUNK_ACK | acknowledgement for reliable multi-chunk transfers |
| `0x20` | RELAY_ANN | peer announcing itself as relay |
| `0x21` | RELAY_REQ | request introduction via relay |
| `0x22` | RELAY_FWD | relay forwarding an introduction |
| `0x30` | PEX | peer exchange |

Handshake is two frames: `0xA1` (hello) and `0xA2` (hello ack). Each carries the sender's ID and raw X25519 public key. After that, all data is encrypted.

### Reliable chunk transfer

When a value larger than 900 bytes is requested via `fetch()`, the sender uses a sliding window protocol:

1. Sender splits the value into 900-byte chunks and sends the first 8 in parallel
2. Receiver sends a `CHUNK_ACK` frame for each chunk received
3. Sender retransmits any chunk that isn't acknowledged within 1.5 seconds
4. As each ACK arrives, the sender advances the window and sends the next chunk

Small values (≤ 900 bytes) are fire-and-forget.

---

## Porting to another language

The minimum you need to implement:

1. X25519 key exchange + HKDF-SHA256 to derive send/recv keys
2. ChaCha20-Poly1305 encrypt/decrypt with a 12-byte nonce (4-byte session ID + 8-byte counter)
3. The handshake frames (`0xA1` / `0xA2`)
4. DATA frame (`0x01`) with the encrypted payload
5. PING/PONG for keepalive

Everything else (DHT, relay, gossip, PEX, reliable chunks) is optional and can be added incrementally.

The session key derivation label is `p2p-v12-session` — both sides must use the same label. The peer with the lexicographically lower ID uses the first 32 bytes as send key; the other peer flips them.

---

## Chat example

```bash
cargo run --bin chat -- alice myroom
```

Commands: `/peers`, `/nat`, `/quit`

---

## License

MIT