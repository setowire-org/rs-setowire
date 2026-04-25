//! Swarm module - main P2P networking class
//!
//! Handles:
//! - UDP socket management
//! - Peer discovery (DHT, HTTP bootstrap, LAN multicast)
//! - NAT traversal (STUN, punching, relay)
//! - Mesh maintenance
//! - Data sync

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::constants::*;
use crate::crypto::generate_x25519;
use crate::dht_lib::SimpleDht;
use crate::framing::BatchSender;
use crate::peer::Peer;
use crate::structs::{BloomFilter, Lru};

// ============================================================================
// Types
// ============================================================================

type ConnectionCallback = Box<dyn Fn(&Peer) + Send + Sync>;
type DisconnectionCallback = Box<dyn Fn(&str) + Send + Sync>;
type DataCallback = Box<dyn Fn(&[u8], &Peer) + Send + Sync>;

/// Peer cache entry
#[derive(Clone, Debug)]
pub struct PeerCacheEntry {
    pub id: Option<String>,
    pub ip: String,
    pub port: u16,
    pub last_seen: u64,
}

// ============================================================================
// Swarm
// ============================================================================

/// Main P2P swarm class
pub struct Swarm {
    /// Local socket
    socket: tokio::net::UdpSocket,
    /// Local IP address
    local_ip: String,
    /// Local port
    local_port: u16,
    /// External address (if discovered)
    external: Option<SocketAddr>,
    /// NAT type
    nat_type: String,
    /// Node ID (20 bytes hex)
    id: String,
    /// Key pair
    keypair: crate::crypto::KeyPair,
    /// Peers by ID
    peers: Arc<Mutex<HashMap<String, Peer>>>,
    /// Address to peer ID mapping
    addr_to_id: Arc<Mutex<HashMap<String, String>>>,
    /// Dialing in progress
    dialing: Arc<Mutex<HashSet<String>>>,
    /// Maximum peers
    max_peers: usize,
    /// Relay mode
    is_relay: bool,
    /// Bloom filter for deduplication
    bloom: Arc<Mutex<BloomFilter>>,
    /// Store cache
    store: Arc<Mutex<Lru<String, Vec<u8>>>>,
    /// DHT instance
    dht: Option<SimpleDht>,
    /// Batch sender
    batch: Arc<Mutex<BatchSender>>,
    /// Destroyed flag
    destroyed: Arc<Mutex<bool>>,
    /// Connection callback
    on_connection: Option<ConnectionCallback>,
    /// Disconnection callback
    on_disconnection: Option<DisconnectionCallback>,
    /// Data callback
    on_data: Option<DataCallback>,
    /// Running flag
    running: Arc<Mutex<bool>>,
}

impl Swarm {
    /// Create a new Swarm instance
    pub async fn new() -> Self {
        // Bind to random port
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
            .await
            .expect("Failed to bind UDP socket");

        let local_addr = socket.local_addr().expect("Failed to get local addr");
        let local_ip = local_addr.ip().to_string();
        let local_port = local_addr.port();

        // Generate key pair
        let keypair = generate_x25519(None);

        // Derive node ID from public key
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(&keypair.public);
        let hash = hasher.finalize();
        let id = hex::encode(&hash[..20]);

        Swarm {
            socket,
            local_ip,
            local_port,
            external: None,
            nat_type: "unknown".to_string(),
            id,
            keypair,
            peers: Arc::new(Mutex::new(HashMap::new())),
            addr_to_id: Arc::new(Mutex::new(HashMap::new())),
            dialing: Arc::new(Mutex::new(HashSet::new())),
            max_peers: MAX_PEERS,
            is_relay: false,
            bloom: Arc::new(Mutex::new(BloomFilter::new(None, None))),
            store: Arc::new(Mutex::new(Lru::new(SYNC_CACHE_MAX, None))),
            dht: None,
            batch: Arc::new(Mutex::new(BatchSender::new())),
            destroyed: Arc::new(Mutex::new(false)),
            on_connection: None,
            on_disconnection: None,
            on_data: None,
            running: Arc::new(Mutex::new(false)),
        }
    }

    /// Get node ID
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get NAT type
    pub fn nat_type(&self) -> &str {
        &self.nat_type
    }

    /// Get public address (if discovered)
    pub fn public_addr(&self) -> Option<String> {
        self.external.map(|a| a.to_string())
    }

    /// Get connected peer count
    pub fn peer_count(&self) -> usize {
        // This is a simplified version
        0
    }

    /// Join a topic
    pub fn join(&mut self, _topic: &[u8], _announce: bool, _lookup: bool) {
        // Join topic for peer discovery
        // This would trigger DHT, HTTP bootstrap, LAN multicast, etc.
    }

    /// Broadcast data to all peers
    pub fn broadcast(&self, _data: &[u8]) -> usize {
        0
    }

    /// Set connection callback
    pub fn on_connection(&mut self, cb: ConnectionCallback) {
        self.on_connection = Some(cb);
    }

    /// Set disconnection callback
    pub fn on_disconnection(&mut self, cb: DisconnectionCallback) {
        self.on_disconnection = Some(cb);
    }

    /// Set data callback
    pub fn on_data(&mut self, cb: DataCallback) {
        self.on_data = Some(cb);
    }

    /// Destroy the swarm
    pub async fn destroy(&mut self) {
        *self.destroyed.lock().await = true;
        *self.running.lock().await = false;
        
        // Close all peer connections
        let mut peers = self.peers.lock().await;
        for (_, peer) in peers.drain() {
            let mut p = peer;
            p.destroy();
        }
    }

    /// Send to peer
    pub async fn send_to(&self, _peer_id: &str, _data: &[u8]) -> bool {
        false
    }

    /// Store a value
    pub fn store(&self, _key: &str, _value: &[u8]) {
        // Store in local cache
    }

    /// Fetch a value
    pub async fn fetch(&self, _key: &str) -> Option<Vec<u8>> {
        None
    }

    /// Get local address
    pub fn local_addr(&self) -> SocketAddr {
        self.socket.local_addr().unwrap()
    }

    /// Get reference to socket
    pub fn socket_ref(&self) -> &tokio::net::UdpSocket {
        &self.socket
    }
}

impl Default for Swarm {
    fn default() -> Self {
        // Must use async context - use tokio::runtime
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async { Self::new().await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_swarm_creation() {
        let swarm = Swarm::new().await;
        assert_eq!(swarm.id.len(), 40); // 20 bytes = 40 hex chars
        assert_eq!(swarm.nat_type(), "unknown");
    }

    #[tokio::test]
    async fn test_swarm_destroy() {
        let mut swarm = Swarm::new().await;
        swarm.destroy().await;
        assert!(*swarm.destroyed.lock().await);
    }
}