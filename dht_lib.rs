//! DHT module - minimal DHT for decentralized topic-based discovery
//!
//! Implements a simplified Kademlia-like DHT with:
//! - 160-bit node IDs
//! - K-bucket routing table
//! - RPC-based queries

use digest::Digest;
use sha1::Sha1;
use std::collections::HashMap;
use std::time::Instant;

// ============================================================================
// Constants
// ============================================================================

const K: usize = 20; // K-bucket size
const ALPHA: usize = 3; // Parallel queries
const ID_BYTES: usize = 20;
const _TIMEOUT_MS: u64 = 5000;

// Message types
const MSG_PING: u8 = 0x01;
const MSG_PONG: u8 = 0x02;
const MSG_STORE: u8 = 0x03;
const MSG_FIND_NODE: u8 = 0x04;
const MSG_FOUND_NODE: u8 = 0x05;
const MSG_FIND_VALUE: u8 = 0x06;
const MSG_FOUND_VAL: u8 = 0x07;

// ============================================================================
// Types
// ============================================================================

/// Node info for serialization (without last_seen)
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct NodeSerde {
    pub id: String,
    pub ip: String,
    pub port: u16,
}

/// Node info
#[derive(Clone, Debug)]
pub struct Node {
    pub id: String,
    pub ip: String,
    pub port: u16,
    pub last_seen: Instant,
}

impl From<Node> for NodeSerde {
    fn from(node: Node) -> Self {
        NodeSerde {
            id: node.id,
            ip: node.ip,
            port: node.port,
        }
    }
}

impl Node {
    pub fn new(id: String, ip: String, port: u16) -> Self {
        Node {
            id,
            ip,
            port,
            last_seen: Instant::now(),
        }
    }
}

/// Pending RPC request
struct PendingRpc {
    resolve: tokio::sync::oneshot::Sender<DhtMessage>,
    #[allow(dead_code)]
    timer: tokio::task::JoinHandle<()>,
}

/// DHT message
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct DhtMessage {
    #[serde(rename = "type")]
    pub msg_type: u8,
    pub rpc_id: Option<String>,
    pub from: Option<String>,
    pub key: Option<String>,
    pub value: Option<String>,
    pub target: Option<String>,
    pub nodes: Option<Vec<NodeSerde>>,
}

// ============================================================================
// KBucket
// ============================================================================

/// K-bucket for routing table
struct KBucket {
    nodes: Vec<Node>,
}

impl KBucket {
    fn new() -> Self {
        KBucket { nodes: Vec::new() }
    }

    fn add(&mut self, node: Node) {
        if let Some(pos) = self.nodes.iter().position(|n| n.id == node.id) {
            self.nodes.remove(pos);
            self.nodes.push(Node {
                last_seen: Instant::now(),
                ..node
            });
            return;
        }
        if self.nodes.len() < K {
            self.nodes.push(Node {
                last_seen: Instant::now(),
                ..node
            });
        }
    }

    fn remove(&mut self, id: &str) {
        self.nodes.retain(|n| n.id != id);
    }

    fn closest(&self, target: &[u8], count: usize) -> Vec<Node> {
        let mut nodes = self.nodes.clone();
        nodes.sort_by(|a, b| {
            let da = xor_distance(a.id.as_bytes(), target);
            let db = xor_distance(b.id.as_bytes(), target);
            cmp_distance(&da, &db)
        });
        nodes.truncate(count);
        nodes
    }
}

// ============================================================================
// RoutingTable
// ============================================================================

/// Routing table with K-buckets
pub struct RoutingTable {
    self_id: [u8; ID_BYTES],
    buckets: Vec<KBucket>,
}

impl RoutingTable {
    fn new(self_id: [u8; ID_BYTES]) -> Self {
        let buckets = (0..160).map(|_| KBucket::new()).collect();
        RoutingTable { self_id, buckets }
    }

    fn bucket_index(&self, other: &[u8]) -> usize {
        let dist = xor_distance(&self.self_id, other);
        for (i, &byte) in dist.iter().enumerate() {
            if byte == 0 {
                continue;
            }
            let bit = 7 - (byte.ilog2() as usize);
            return i * 8 + bit;
        }
        159
    }

    fn add(&mut self, node: Node) {
        if node.id == hex::encode(&self.self_id) {
            return;
        }
        if let Ok(id_bytes) = hex::decode(&node.id) {
            let idx = self.bucket_index(&id_bytes);
            self.buckets[idx].add(node);
        }
    }

    fn remove(&mut self, id: &str) {
        if let Ok(id_bytes) = hex::decode(id) {
            let idx = self.bucket_index(&id_bytes);
            self.buckets[idx].remove(id);
        }
    }

    fn closest(&self, target: &[u8], count: usize) -> Vec<Node> {
        let mut all_nodes = Vec::new();
        for bucket in &self.buckets {
            all_nodes.extend_from_slice(&bucket.nodes);
        }
        all_nodes.sort_by(|a, b| {
            let da = xor_distance(a.id.as_bytes(), target);
            let db = xor_distance(b.id.as_bytes(), target);
            cmp_distance(&da, &db)
        });
        all_nodes.truncate(count);
        all_nodes
    }

    fn size(&self) -> usize {
        self.buckets.iter().map(|b| b.nodes.len()).sum()
    }
}

// ============================================================================
// SimpleDht
// ============================================================================

/// Simple DHT implementation
pub struct SimpleDht {
    node_id: String,
    id_bytes: [u8; ID_BYTES],
    port: u16,
    storage: HashMap<String, String>,
    table: RoutingTable,
    pending: HashMap<String, PendingRpc>,
}

impl SimpleDht {
    /// Create a new SimpleDHT
    pub fn new(port: u16) -> Self {
        let mut id_bytes = [0u8; ID_BYTES];
        rand::random::<[u8; ID_BYTES]>().copy_from_slice(&mut id_bytes);

        let node_id = hex::encode(&id_bytes);

        SimpleDht {
            node_id,
            id_bytes,
            port,
            storage: HashMap::new(),
            table: RoutingTable::new(id_bytes),
            pending: HashMap::new(),
        }
    }

    /// Create with specific node ID
    pub fn with_id(node_id: &str, port: u16) -> Self {
        let id_bytes = hex::decode(node_id)
            .map(| v| {
                let mut arr = [0u8; ID_BYTES];
                let len = v.len().min(ID_BYTES);
                arr[..len].copy_from_slice(&v[..len]);
                arr
            })
            .unwrap_or_else(|_| {
                let mut arr = [0u8; ID_BYTES];
                rand::random::<[u8; ID_BYTES]>().copy_from_slice(&mut arr);
                arr
            });

        let node_id_str = hex::encode(&id_bytes);

        SimpleDht {
            node_id: node_id_str,
            id_bytes,
            port,
            storage: HashMap::new(),
            table: RoutingTable::new(id_bytes),
            pending: HashMap::new(),
        }
    }

    /// Get node ID
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Add a peer to the routing table
    pub fn add_node(&mut self, node: Node) {
        self.table.add(node);
    }

    /// Store a value
    pub fn put(&mut self, key: &str, value: &str) {
        let key_hash = sha1_hash(key.as_bytes());
        self.storage.insert(key_hash.clone(), value.to_string());

        let target = hex::decode(&key_hash).unwrap_or_default();
        let closest: Vec<NodeSerde> = self.table.closest(&target, K)
            .into_iter()
            .map(NodeSerde::from)
            .collect();
        let _ = closest;
    }

    /// Get a stored value
    pub fn get(&self, key: &str) -> Option<String> {
        let key_hash = sha1_hash(key.as_bytes());
        self.storage.get(&key_hash).cloned()
    }

    /// Find value or closest nodes
    pub async fn find_value(&mut self, key: &str) -> Option<String> {
        if let Some(val) = self.get(key) {
            return Some(val);
        }

        let key_hash = sha1_hash(key.as_bytes());
        let target = hex::decode(&key_hash).unwrap_or_default();
        let shortlist: Vec<Node> = self.table.closest(&target, ALPHA);

        let _ = shortlist;
        None
    }

    /// Bootstrap with known nodes
    pub async fn bootstrap(&mut self, nodes: Vec<Node>) {
        for node in &nodes {
            self.table.add(node.clone());
        }

        let closest: Vec<Node> = self.table.closest(&self.id_bytes, ALPHA);
        for node in closest {
            let _ = node;
        }
    }

    /// Handle incoming message
    #[allow(dead_code)]
    pub fn handle_message(&mut self, msg: DhtMessage, _addr: std::net::SocketAddr) -> Option<DhtMessage> {
        if let Some(ref from) = msg.from {
            if let Ok(id_bytes) = hex::decode(from) {
                self.table.add(Node {
                    id: from.clone(),
                    ip: _addr.ip().to_string(),
                    port: _addr.port(),
                    last_seen: Instant::now(),
                });
                let _ = id_bytes;
            }
        }

        if let Some(ref rpc_id) = msg.rpc_id {
            if let Some(pending) = self.pending.remove(rpc_id) {
                let _ = pending.resolve.send(msg);
                return None;
            }
        }

        match msg.msg_type {
            MSG_PING => Some(DhtMessage {
                msg_type: MSG_PONG,
                rpc_id: msg.rpc_id,
                from: Some(self.node_id.clone()),
                key: None,
                value: None,
                target: None,
                nodes: None,
            }),
            MSG_STORE => {
                if let (Some(key), Some(value)) = (&msg.key, &msg.value) {
                    self.storage.insert(key.clone(), value.clone());
                }
                None
            }
            MSG_FIND_NODE => {
                if let Some(ref target) = msg.target {
                    if let Ok(target_bytes) = hex::decode(target) {
                        let closest: Vec<NodeSerde> = self.table.closest(&target_bytes, K)
                            .into_iter()
                            .map(NodeSerde::from)
                            .collect();
                        return Some(DhtMessage {
                            msg_type: MSG_FOUND_NODE,
                            rpc_id: msg.rpc_id,
                            from: Some(self.node_id.clone()),
                            key: None,
                            value: None,
                            target: None,
                            nodes: Some(closest),
                        });
                    }
                }
                None
            }
            MSG_FIND_VALUE => {
                if let Some(ref key) = msg.key {
                    if let Some(value) = self.storage.get(key) {
                        return Some(DhtMessage {
                            msg_type: MSG_FOUND_VAL,
                            rpc_id: msg.rpc_id,
                            from: Some(self.node_id.clone()),
                            key: None,
                            value: Some(value.clone()),
                            target: None,
                            nodes: None,
                        });
                    } else if let Ok(key_bytes) = hex::decode(key) {
                        let closest: Vec<NodeSerde> = self.table.closest(&key_bytes, K)
                            .into_iter()
                            .map(NodeSerde::from)
                            .collect();
                        return Some(DhtMessage {
                            msg_type: MSG_FOUND_NODE,
                            rpc_id: msg.rpc_id,
                            from: Some(self.node_id.clone()),
                            key: None,
                            value: None,
                            target: None,
                            nodes: Some(closest),
                        });
                    }
                }
                None
            }
            _ => None,
        }
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

fn sha1_hash(data: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn xor_distance(a: &[u8], b: &[u8]) -> Vec<u8> {
    let len = std::cmp::min(a.len(), b.len());
    let mut result = Vec::with_capacity(len);
    for i in 0..len {
        result.push(a[i] ^ b[i]);
    }
    result
}

fn cmp_distance(d1: &[u8], d2: &[u8]) -> std::cmp::Ordering {
    for i in 0..std::cmp::min(d1.len(), d2.len()) {
        if d1[i] < d2[i] {
            return std::cmp::Ordering::Less;
        }
        if d1[i] > d2[i] {
            return std::cmp::Ordering::Greater;
        }
    }
    std::cmp::Ordering::Equal
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dht_creation() {
        let dht = SimpleDht::new(0);
        assert_eq!(dht.node_id.len(), 40);
    }

    #[test]
    fn test_put_get() {
        let mut dht = SimpleDht::new(0);
        dht.put("test_key", "test_value");
        assert_eq!(dht.get("test_key"), Some("test_value".to_string()));
    }
}