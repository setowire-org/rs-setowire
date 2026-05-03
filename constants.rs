//! Constants module - all tuneable parameters and frame type definitions

// ============================================================================
// Server Configuration
// ============================================================================

/// Piping servers for NAT traversal
pub const PIPING_SERVERS: &[&str] = &[
    "ppng.io",
    "piping.nwtgck.org",
    "piping.onrender.com",
    "piping.glitch.me",
];

/// STUN servers for NAT type detection
pub const STUN_HOSTS: &[(&str, u16)] = &[
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
    ("stun2.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
    ("stun.stunprotocol.org", 3478),
    ("global.stun.twilio.com", 3478),
    ("stun.ekiga.net", 3478),
    ("stun.sipnet.com", 3478),
    ("stun.voipbuster.com", 3478),
];

// ============================================================================
// Frame Types
// ============================================================================

/// Frame type: Relay announcement
pub const F_RELAY_ANN: u8 = 0x20;
/// Frame type: Relay request
pub const F_RELAY_REQ: u8 = 0x21;
/// Frame type: Relay forward
pub const F_RELAY_FWD: u8 = 0x22;

/// Frame type: Peer exchange
pub const F_PEX: u8 = 0x30;

/// Frame type: LAN discovery
pub const F_LAN: u8 = 0x09;

/// Frame type: Data (encrypted payload)
pub const F_DATA: u8 = 0x01;
/// Frame type: Ping (keepalive)
pub const F_PING: u8 = 0x03;
/// Frame type: Pong (keepalive reply)
pub const F_PONG: u8 = 0x04;
/// Frame type: Fragment of large message
pub const F_FRAG: u8 = 0x0B;
/// Frame type: Graceful disconnect
pub const F_GOAWAY: u8 = 0x0A;
/// Frame type: Have (announce available keys)
pub const F_HAVE: u8 = 0x10;
/// Frame type: Want (request a key)
pub const F_WANT: u8 = 0x11;
/// Frame type: Chunk (data chunk)
pub const F_CHUNK: u8 = 0x12;
/// Frame type: Batch (multiple frames in one datagram)
pub const F_BATCH: u8 = 0x13;
/// Frame type: Chunk acknowledgement
pub const F_CHUNK_ACK: u8 = 0x14;

/// Frame type: Hello (handshake initiation)
pub const F_HELLO: u8 = 0xA1;
/// Frame type: Hello Ack (handshake response)
pub const F_HELLO_ACK: u8 = 0xA2;

// ============================================================================
// Peer Exchange
// ============================================================================

/// Maximum peers per PEX message
pub const PEX_MAX: usize = 20;
/// Interval between PEX messages (ms)
pub const PEX_INTERVAL: u64 = 60_000;

// ============================================================================
// Relay Configuration
// ============================================================================

/// NAT types that allow relay
pub const RELAY_NAT_OPEN: &[&str] = &["full_cone", "open"];
/// Maximum number of relays
pub const RELAY_MAX: usize = 20;
/// Interval between relay announcements (ms)
pub const RELAY_ANN_MS: u64 = 30_000;
/// How long to ban a relay (ms)
pub const RELAY_BAN_MS: u64 = 5 * 60_000;

// ============================================================================
// Bootstrap
// ============================================================================

/// Hardcoded seed peers (empty by default)
pub const HARDCODED_SEEDS: &[&str] = &[];

/// HTTP bootstrap servers
pub const HARDCODED_HTTP_BOOTSTRAP: &[&str] = &[
    "https://bootstrap-4eft.onrender.com",
    "https://bootsrtap.firestarp.workers.dev",
];

/// Bootstrap timeout (ms)
pub const BOOTSTRAP_TIMEOUT: u64 = 15_000;

// ============================================================================
// Peer Management
// ============================================================================

/// Maximum simultaneous connections
pub const MAX_PEERS: usize = 100;
/// Maximum addresses per peer
pub const MAX_ADDRS_PEER: usize = 4;
/// Peer timeout (ms)
pub const PEER_TIMEOUT: u64 = 60_000;
/// Announcement interval (ms)
pub const ANNOUNCE_MS: u64 = 18_000;
/// Heartbeat interval (ms)
pub const HEARTBEAT_MS: u64 = 1_000;
/// NAT punch attempts
pub const PUNCH_TRIES: usize = 8;
/// NAT punch interval (ms)
pub const PUNCH_INTERVAL: u64 = 300;

/// Peer cache emit interval (ms)
pub const PEER_CACHE_EMIT_MS: u64 = 30_000;

// ============================================================================
// Gossip
// ============================================================================

/// Maximum gossip entries
pub const GOSSIP_MAX: usize = 200_000;
/// Gossip TTL (ms)
pub const GOSSIP_TTL: u64 = 30_000;

// ============================================================================
// Mesh/Discovery
// ============================================================================

/// Default mesh degree
pub const D_DEFAULT: usize = 6;
/// Minimum mesh degree
pub const D_MIN: usize = 4;
/// Maximum mesh degree
pub const D_MAX: usize = 16;
/// Low threshold for mesh degree
pub const D_LOW: usize = 4;
/// High threshold for mesh degree
pub const D_HIGH: usize = 16;
/// Gossip fan-out
pub const D_GOSSIP: usize = 6;

/// Maximum IHAVE messages in buffer
pub const IHAVE_MAX: usize = 200;

// ============================================================================
// Framing
// ============================================================================

/// Batch MTU (bytes)
pub const BATCH_MTU: usize = 1400;
/// Batch flush interval (ms)
pub const BATCH_INTERVAL: u64 = 2;

// ============================================================================
// Queues
// ============================================================================

/// Control queue size
pub const QUEUE_CTRL: usize = 256;
/// Data queue size
pub const QUEUE_DATA: usize = 2048;

// ============================================================================
// Bloom Filter
// ============================================================================

/// Bloom filter bits
pub const BLOOM_BITS: usize = 64 * 1024 * 1024;
/// Bloom filter hash count
pub const BLOOM_HASHES: usize = 5;
/// Bloom filter rotation interval (ms)
pub const BLOOM_ROTATE: u64 = 5 * 60 * 1000;

// ============================================================================
// Sync/Cache
// ============================================================================

/// Sync cache max size
pub const SYNC_CACHE_MAX: usize = 10_000;
/// Chunk size for reliable transfer
pub const SYNC_CHUNK_SIZE: usize = 900;
/// Sync timeout (ms)
pub const SYNC_TIMEOUT: u64 = 30_000;
/// HAVE batch size
pub const HAVE_BATCH: usize = 64;

// ============================================================================
// Fragmentation
// ============================================================================

/// Maximum payload size
pub const MAX_PAYLOAD: usize = 1200;
/// Fragment header size
pub const FRAG_HDR: usize = 12;
/// Maximum data per fragment
pub const FRAG_DATA_MAX: usize = MAX_PAYLOAD - FRAG_HDR;
/// Fragment assembly timeout (ms)
pub const FRAG_TIMEOUT: u64 = 10_000;

// ============================================================================
// Congestion Control
// ============================================================================

/// Initial congestion window
pub const CWND_INIT: usize = 16;
/// Maximum congestion window
pub const CWND_MAX: usize = 512;
/// Window decay factor
pub const CWND_DECAY: f64 = 0.75;

// ============================================================================
// Rate Limiting
// ============================================================================

/// Rate limit (bytes/sec)
pub const RATE_PER_SEC: usize = 128;
/// Burst limit (bytes)
pub const RATE_BURST: usize = 256;

// ============================================================================
// RTT
// ============================================================================

/// RTT smoothing factor
pub const RTT_ALPHA: f64 = 0.125;
/// Initial RTT estimate (ms)
pub const RTT_INIT: f64 = 100.0;

// ============================================================================
// Timeouts
// ============================================================================

/// Drain timeout (ms)
pub const DRAIN_TIMEOUT: u64 = 2000;
/// STUN fast timeout (ms)
pub const STUN_FAST_TIMEOUT: u64 = 4000;

// ============================================================================
// Crypto
// ============================================================================

/// Authentication tag length
pub const TAG_LEN: usize = 16;
/// Nonce length
pub const NONCE_LEN: usize = 12;

// ============================================================================
// Multicast
// ============================================================================

/// Multicast address
pub const MCAST_ADDR: &str = "239.0.0.1";
/// Multicast port
pub const MCAST_PORT: u16 = 45678;