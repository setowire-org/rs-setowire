//! Swarm module - main P2P networking class
//!
//! Handles:
//! - UDP socket management
//! - Peer discovery (DHT, HTTP bootstrap, LAN multicast)
//! - NAT traversal (STUN, punching, relay)
//! - Mesh maintenance
//! - Data sync

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::Mutex;
use tokio::time::{interval, sleep};

use crate::constants::*;
use crate::crypto::{
    create_hello_frame, create_hello_ack_frame,
    derive_session_flipped, encrypt, decrypt,
    generate_x25519, parse_handshake_frame,
};
use crate::dht_lib::SimpleDht;
use crate::framing::BatchSender;
use crate::peer::Peer;
use crate::structs::{BloomFilter, Lru};

// ============================================================================
// Types
// ============================================================================

type ConnectionCallback    = Arc<dyn Fn(&Peer) + Send + Sync>;
type DisconnectionCallback = Arc<dyn Fn(&str)  + Send + Sync>;
type DataCallback          = Arc<dyn Fn(&[u8], &Peer) + Send + Sync>;

/// Peer cache entry
#[derive(Clone, Debug)]
pub struct PeerCacheEntry {
    pub id: Option<String>,
    pub ip: String,
    pub port: u16,
    pub last_seen: u64,
}

// ============================================================================
// Helper functions
// ============================================================================

fn get_local_ip() -> String {
    for target in ["8.8.8.8:80", "1.1.1.1:53", "9.9.9.9:53", "192.0.2.1:80"] {
        if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
            if socket.connect(target).is_ok() {
                if let Ok(addr) = socket.local_addr() {
                    if is_usable_local_ip(addr.ip()) {
                        return addr.ip().to_string();
                    }
                }
            }
        }
    }
    "127.0.0.1".to_string()
}

fn is_usable_local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_unspecified()
                && !v4.is_loopback()
                && !v4.is_link_local()
                && !v4.is_broadcast()
        }
        IpAddr::V6(v6) => !v6.is_unspecified() && !v6.is_loopback(),
    }
}

fn peer_announcement(
    id: &str,
    external: Option<SocketAddr>,
    local_ip: &str,
    local_port: u16,
    nat_type: &str,
) -> serde_json::Value {
    match external {
        Some(addr) => serde_json::json!({
            "id": id,
            "ip": addr.ip().to_string(),
            "port": addr.port(),
            "lip": local_ip,
            "lport": local_port,
            "nat": nat_type,
        }),
        None => serde_json::json!({
            "id": id,
            "lip": local_ip,
            "lport": local_port,
            "nat": nat_type,
        }),
    }
}

fn parse_piping_messages(text: &str) -> Vec<serde_json::Value> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    if let Ok(msg) = serde_json::from_str::<serde_json::Value>(trimmed) {
        return vec![msg];
    }
    trimmed
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line.trim()).ok())
        .collect()
}

async fn piping_post_json(client: &reqwest::Client, url: &str, body: &serde_json::Value) {
    let _ = client
        .post(url)
        .json(body)
        .timeout(Duration::from_secs(8))
        .send()
        .await;
}

async fn piping_get_text(client: &reqwest::Client, url: &str) -> Option<String> {
    let resp = client
        .get(url)
        .timeout(Duration::from_secs(120))
        .send()
        .await
        .ok()?;
    resp.text().await.ok()
}

async fn piping_post_all_json(client: &reqwest::Client, path: &str, body: &serde_json::Value) {
    for server in PIPING_SERVERS {
        let url = format!("https://{}{}", server, path);
        piping_post_json(client, &url, body).await;
    }
}

async fn dial_discovered_peer(
    info: &serde_json::Value,
    my_id: &str,
    id_bytes: [u8; 8],
    keypair: &crate::crypto::KeyPair,
    socket: &Arc<tokio::net::UdpSocket>,
    dialing: &Arc<Mutex<HashSet<String>>>,
) {
    let peer_id = match info.get("id").and_then(|v| v.as_str()) {
        Some(id) if id != my_id => id,
        _ => return,
    };

    let mut targets = Vec::<SocketAddr>::new();
    if let (Some(ip), Some(port)) = (
        info.get("ip").and_then(|v| v.as_str()),
        info.get("port").and_then(|v| v.as_u64()),
    ) {
        if let Ok(addr) = format!("{}:{}", ip, port as u16).parse() {
            targets.push(addr);
        }
    }
    if let (Some(ip), Some(port)) = (
        info.get("lip").and_then(|v| v.as_str()),
        info.get("lport").and_then(|v| v.as_u64()),
    ) {
        if let Ok(addr) = format!("{}:{}", ip, port as u16).parse() {
            if !targets.contains(&addr) {
                targets.push(addr);
            }
        }
    }
    if targets.is_empty() {
        return;
    }

    let key = peer_id.to_string();
    {
        let mut dg = dialing.lock().await;
        if dg.contains(&key) {
            return;
        }
        dg.insert(key.clone());
    }

    let frame = create_hello_frame(&id_bytes, &keypair.public);
    for target in targets {
        for i in 0..PUNCH_TRIES {
            let socket = socket.clone();
            let frame = frame.clone();
            tokio::spawn(async move {
                sleep(Duration::from_millis(i as u64 * PUNCH_INTERVAL)).await;
                let _ = socket.send_to(&frame, target).await;
            });
        }
    }

    let dialing = dialing.clone();
    tokio::spawn(async move {
        sleep(Duration::from_millis(PUNCH_TRIES as u64 * PUNCH_INTERVAL + 3_000)).await;
        dialing.lock().await.remove(&key);
    });
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ============================================================================
// Swarm
// ============================================================================

pub struct Swarm {
    socket: Arc<tokio::net::UdpSocket>,
    local_ip: String,
    local_port: u16,
    external: Option<SocketAddr>,
    nat_type: String,
    id: String,
    id_bytes: [u8; 8],       // primeiros 8 bytes do hash da chave pública
    keypair: crate::crypto::KeyPair,
    peers: Arc<Mutex<HashMap<String, Peer>>>,
    addr_to_id: Arc<Mutex<HashMap<String, String>>>,
    dialing: Arc<Mutex<HashSet<String>>>,
    max_peers: usize,
    is_relay: bool,
    relays: Arc<Mutex<HashMap<String, (String, u16)>>>,
    relay_bans: Arc<Mutex<HashMap<String, u64>>>,
    relay_http_tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    topic_hash: Option<String>,
    bloom: Arc<Mutex<BloomFilter>>,
    store: Arc<Mutex<Lru<String, Vec<u8>>>>,
    dht: Option<SimpleDht>,
    batch: Arc<Mutex<BatchSender>>,
    destroyed: Arc<Mutex<bool>>,
    on_connection: Option<ConnectionCallback>,
    on_disconnection: Option<DisconnectionCallback>,
    on_data: Option<DataCallback>,
    running: Arc<Mutex<bool>>,
}

async fn stun_probe(socket: &Arc<tokio::net::UdpSocket>, host: &str, port: u16) -> Option<(String, SocketAddr)> {
    //println!("STUN: resolving {}:{}", host, port);
    let stun_addr = tokio::net::lookup_host((host, port))
        .await
        .ok()?
        .find(|addr| addr.is_ipv4())?;
    //println!("STUN: trying {}", stun_addr);

    let mut req = [0u8; 20];
    req[0] = 0x00; req[1] = 0x01; // Binding Request
    req[4] = 0x21; req[5] = 0x12; req[6] = 0xA4; req[7] = 0x42; // Magic cookie
    // Transaction ID aleatório
    for i in 8..20 { req[i] = rand::random(); }

    if let Err(e) = socket.send_to(&req, stun_addr).await {
        eprintln!("STUN: send error: {}", e);
        return None;
    }

    let mut buf = [0u8; 512];
    match tokio::time::timeout(Duration::from_millis(STUN_FAST_TIMEOUT), socket.recv_from(&mut buf)).await {
        Ok(Ok((len, _))) => {
            //println!("STUN: received {} bytes from {}", len, host);
            if len < 20 || buf[0] != 0x01 || buf[1] != 0x01 {
                //eprintln!("STUN: invalid response header");
                return None;
            }
            let mut off = 20;
            while off + 4 <= len {
                let attr_type = u16::from_be_bytes([buf[off], buf[off + 1]]);
                let attr_len  = u16::from_be_bytes([buf[off + 2], buf[off + 3]]) as usize;
                if off + 4 + attr_len > len { break; }
                if attr_type == 0x0020 && attr_len >= 8 {
                    if buf[off + 5] != 0x01 {
                        off += 4 + ((attr_len + 3) & !3);
                        continue;
                    }
                    let xor_port = u16::from_be_bytes([buf[off + 6], buf[off + 7]]);
                    let port = xor_port ^ 0x2112;
                    let ip_bytes = [
                        buf[off + 8]  ^ 0x21,
                        buf[off + 9]  ^ 0x12,
                        buf[off + 10] ^ 0xA4,
                        buf[off + 11] ^ 0x42,
                    ];
                    let ip = std::net::Ipv4Addr::from(ip_bytes);
                    let addr = SocketAddr::new(ip.into(), port);
                    //println!("STUN: success, external address = {}", addr);
                    return Some(("full_cone".to_string(), addr));
                }
                off += 4 + ((attr_len + 3) & !3);
            }
            eprintln!("STUN: XOR-MAPPED-ADDRESS not found");
            None
        },
        Ok(Err(e)) => {
            eprintln!("STUN: recv error: {}", e);
            None
        },
        Err(_) => {
            //eprintln!("STUN: timeout");
            None
        },
    }
}

async fn public_ip_from_web() -> Option<String> {
    let client = reqwest::Client::new();
    for url in &["https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"] {
        if let Ok(resp) = client.get(*url).send().await {
            if let Ok(ip) = resp.text().await {
                let ip = ip.trim().to_string();
                if !ip.is_empty() && ip.parse::<std::net::IpAddr>().is_ok() {
                    return Some(ip);
                }
            }
        }
    }
    None
}

impl Swarm {
    pub async fn new() -> Self {
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
            .await
            .expect("Failed to bind UDP socket");

        let local_addr = socket.local_addr().expect("Failed to get local addr");
        let local_ip = get_local_ip();
        let local_port = local_addr.port();

        let keypair = generate_x25519(None);

        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(&keypair.public);
        let hash = hasher.finalize();
        let id = hex::encode(&hash[..20]);
        let id_bytes: [u8; 8] = hash[..8].try_into().unwrap_or([0u8; 8]);

        Swarm {
            socket: Arc::new(socket),
            local_ip,
            local_port,
            external: None,
            nat_type: "unknown".to_string(),
            id,
            id_bytes,
            keypair,
            peers: Arc::new(Mutex::new(HashMap::new())),
            addr_to_id: Arc::new(Mutex::new(HashMap::new())),
            dialing: Arc::new(Mutex::new(HashSet::new())),
            max_peers: MAX_PEERS,
            is_relay: false,
            relays: Arc::new(Mutex::new(HashMap::new())),
            relay_bans: Arc::new(Mutex::new(HashMap::new())),
            relay_http_tasks: Arc::new(Mutex::new(Vec::new())),
            topic_hash: None,
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

    pub fn id(&self) -> &str { &self.id }
    pub fn nat_type(&self) -> &str { &self.nat_type }
    pub fn local_addr(&self) -> SocketAddr {
        let ip = self
            .local_ip
            .parse::<IpAddr>()
            .unwrap_or_else(|_| IpAddr::from([127, 0, 0, 1]));
        SocketAddr::new(ip, self.local_port)
    }

    /// Join a topic (compatibility with JS)
    pub async fn join(&mut self, topic: &[u8], _announce: bool, _lookup: bool) {
        use sha2::Sha256;
        use sha1::Sha1;
        use digest::Digest;

        let sha256_hash = Sha256::digest(topic);
        let topic_hex = hex::encode(sha256_hash);

        let mut sha1_hasher = Sha1::new();
        sha1_hasher.update(topic_hex.as_bytes());
        let sha1_result = sha1_hasher.finalize();
        let topic_hash = hex::encode(sha1_result)[..12].to_string();

        self.topic_hash = Some(topic_hash.clone());

        if *self.running.lock().await {
            self.start_discovery_tasks().await;
            if RELAY_NAT_OPEN.contains(&self.nat_type.as_str()) {
                self.become_relay().await;
            }
        }
    }

    async fn start_discovery_tasks(&self) {
        // Start Piping discovery (main method for topic-based peer discovery)
        self.start_piping_discovery().await;

        // Start HTTP bootstrap discovery (additional source of peers)
        self.start_bootstrap_discovery().await;
    }

    /// Start the swarm: STUN, relay, receive loop, maintenance
    pub async fn start(&mut self) {
        self.detect_nat().await;

        *self.running.lock().await = true;

        if self.topic_hash.is_some() {
            self.start_discovery_tasks().await;
        }

        if RELAY_NAT_OPEN.contains(&self.nat_type.as_str()) {
            self.become_relay().await;
        }

        // Clone everything needed for the receive loop
        let socket = self.socket.clone();
        let peers = self.peers.clone();
        let addr_to_id = self.addr_to_id.clone();
        let dialing = self.dialing.clone();
        let keypair = self.keypair.clone();
        let id = self.id.clone();
        let id_bytes = self.id_bytes;
        let topic_hash = self.topic_hash.clone();
        let destroyed = self.destroyed.clone();
        let on_conn = self.on_connection.clone();
        let on_disc = self.on_disconnection.clone();
        let on_data = self.on_data.clone();
        let relays = self.relays.clone();
        let local_port = self.local_port;

        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                if *destroyed.lock().await { break; }
                let (len, src) = match socket.recv_from(&mut buf).await {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                if len < 1 { continue; }
                // Ignorar pacotes do próprio socket (loopback)
                if src.port() == local_port && src.ip().is_loopback() { continue; }

                handle_frame(
                    &buf[..len], src,
                    &peers, &addr_to_id, &dialing,
                    &keypair, &id, id_bytes, &topic_hash,
                    &on_conn, &on_disc, &on_data,
                    &relays, &socket, &destroyed,
                ).await;
            }
        });

        // Start heartbeat
        let hb_socket = self.socket.clone();
        let hb_peers = self.peers.clone();
        let hb_destroyed = self.destroyed.clone();
        let hb_id_raw = hex::decode(&self.id).unwrap_or_default();
        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_millis(HEARTBEAT_MS));
            loop {
                ticker.tick().await;
                if *hb_destroyed.lock().await { break; }
                let ts = now_millis();
                let mut ping = vec![F_PING];
                ping.extend_from_slice(&ts.to_be_bytes());
                ping.extend_from_slice(&hb_id_raw);
                let mut peers = hb_peers.lock().await;
                for (_, peer) in peers.iter_mut() {
                    peer.last_ping_sent = ts;
                    let _ = hb_socket.send_to(&ping, peer.remote_addr).await;
                }
            }
        });

        // Peer timeout cleanup
        let to_peers = self.peers.clone();
        let to_addr = self.addr_to_id.clone();
        let to_disc = self.on_disconnection.clone();
        let to_destroyed = self.destroyed.clone();
        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(10));
            loop {
                ticker.tick().await;
                if *to_destroyed.lock().await { break; }
                //let now = SystemTime::now();
                let mut dead = Vec::new();
                {
                    let peers = to_peers.lock().await;
                    for (id, peer) in peers.iter() {
                        if peer.last_seen.elapsed() > Duration::from_millis(PEER_TIMEOUT) {
                            dead.push(id.clone());
                        }
                    }
                }
                for pid in dead {
                    if let Some(mut p) = to_peers.lock().await.remove(&pid) {
                        p.destroy();
                        if let Some(ref cb) = to_disc { cb(&pid); }
                    }
                    to_addr.lock().await.retain(|_, v| v != &pid);
                }
            }
        });
    }

    async fn detect_nat(&mut self) {
        // 1. Try STUN servers
        for (host, port) in STUN_HOSTS.iter().take(3) {
            //println!("[STUN] trying {}:{}", host, port);
            if let Some((nat_type, addr)) = stun_probe(&self.socket, host, *port).await {
                //println!("[STUN] success: {} {}", nat_type, addr);
                self.nat_type = nat_type;
                self.external = Some(addr);
                return;
            }
        }

        // 2. Fallback HTTP (get IP, but not port)
        //println!("[STUN] all STUN probes failed, trying HTTP fallback...");
        if let Some(ip_str) = public_ip_from_web().await {
            if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
                let port = self.local_port;
                let addr = SocketAddr::new(ip, port);
                self.external = Some(addr);
                self.nat_type = "full_cone".to_string();
                //println!("[STUN] HTTP fallback success: {}", addr);
                return;
            }
        }

        //println!("[STUN] all methods failed, defaulting to symmetric");
        self.nat_type = "symmetric".to_string();
    }

    /// Returns the public socket address discovered via STUN, if available
    pub async fn external_addr(&self) -> Option<SocketAddr> {
        self.external
    }

    async fn start_bootstrap_discovery(&self) {
        let topic = match &self.topic_hash {
            Some(t) => t.clone(),
            None => return,
        };
        let id = self.id.clone();
        let id_bytes = self.id_bytes;
        let keypair = self.keypair.clone();
        let local_ip = self.local_ip.clone();
        let local_port = self.local_port;
        let socket = self.socket.clone();
        let destroyed = self.destroyed.clone();
        let relays = self.relays.clone();
        let external = self.external;   // Option<SocketAddr>
        let nat_type = self.nat_type.clone();

        tokio::spawn(async move {
            let client = match reqwest::Client::builder().timeout(Duration::from_secs(8)).build() {
                Ok(client) => client,
                Err(_) => return,
            };
            loop {
                if *destroyed.lock().await { break; }
                for server in HARDCODED_HTTP_BOOTSTRAP.iter() {
                    let announce_url = format!("{}/announce", server);
                    let peers_url = format!("{}/peers", server);

                    // 1. Anunciar-se
                    let mut body = peer_announcement(&id, external, &local_ip, local_port, &nat_type);
                    body["topic"] = serde_json::Value::String(topic.clone());
                    let _ = client.post(&announce_url).json(&body).send().await;

                    // 2. Obter lista de peers
                    if let Ok(resp) = client.get(&peers_url).send().await {
                        if let Ok(peers) = resp.json::<Vec<serde_json::Value>>().await {
                            for peer in peers.iter().take(30) {
                                let peer_id = peer.get("id").and_then(|v| v.as_str()).unwrap_or("");
                                let ip = peer.get("ip").and_then(|v| v.as_str()).unwrap_or("");
                                let port = peer.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                                if peer_id == id || port == 0 { continue; }

                                // Guarda o peer como possível relay se ele se anunciar como tal
                                if peer.get("relay").and_then(|v| v.as_bool()).unwrap_or(false) {
                                    if let Ok(mut map) = relays.try_lock() {
                                        map.insert(peer_id.to_string(), (ip.to_string(), port));
                                    }
                                }

                                // Envia HELLO directo
                                let dest: SocketAddr = match format!("{}:{}", ip, port).parse() {
                                    Ok(a) => a,
                                    Err(_) => continue,
                                };
                                let frame = create_hello_frame(&id_bytes, &keypair.public);
                                let _ = socket.send_to(&frame, dest).await;
                            }
                        }
                    }
                }
                sleep(Duration::from_secs(10)).await;
            }
        });
    }

    async fn become_relay(&mut self) {
        if self.is_relay { return; }
        if !RELAY_NAT_OPEN.contains(&self.nat_type.as_str()) { return; }
        self.is_relay = true;

        let topic = self.topic_hash.clone().unwrap_or_default();
        let id = self.id.clone();
        let socket = self.socket.clone();
        let peers = self.peers.clone();
        let destroyed = self.destroyed.clone();
        let tasks = self.relay_http_tasks.clone();

        for server in PIPING_SERVERS {
            let topic = topic.clone();
            let id = id.clone();
            let socket = socket.clone();
            let peers = peers.clone();
            let destroyed = destroyed.clone();
            let tasks = tasks.clone();

            let handle = tokio::spawn(async move {
                relay_read_inbox(server.to_string(), topic, id, socket, peers, destroyed).await;
            });
            if let Ok(mut t) = tasks.try_lock() {
                t.push(handle);
            };
        }
    }

    #[allow(dead_code)]
    async fn start_inbox_reader(&self) {
        let topic = match &self.topic_hash {
            Some(t) => t.clone(),
            None => return,
        };
        let id = self.id.clone();
        let socket = self.socket.clone();
        let peers = self.peers.clone();
        let destroyed = self.destroyed.clone();
        let tasks = self.relay_http_tasks.clone();

        for server in PIPING_SERVERS {
            let topic = topic.clone();
            let id = id.clone();
            let socket = socket.clone();
            let peers = peers.clone();
            let destroyed = destroyed.clone();
            let tasks = tasks.clone();

            let handle = tokio::spawn(async move {
                read_own_inbox(server.to_string(), topic, id, socket, peers, destroyed).await;
            });
            if let Ok(mut t) = tasks.try_lock() {
                t.push(handle);
            };
        }
    }

    #[allow(dead_code)]
    async fn start_piping_discovery_legacy(&self) {
        let topic = match &self.topic_hash {
            Some(t) => t.clone(),
            None => return,
        };
        let id = self.id.clone();
        let id_bytes = self.id_bytes;
        let keypair = self.keypair.clone();
        let socket = self.socket.clone();
        let dialing = self.dialing.clone();
        let destroyed = self.destroyed.clone();
        let external = self.external;
        let local_ip = self.local_ip.clone();
        let local_port = self.local_port;
        let nat_type = self.nat_type.clone();
        let announce_path = format!("/p2p-{}-announce", topic);
        let inbox_path = format!("/p2p-{}-{}", topic, id);
        let me = peer_announcement(&id, external, &local_ip, local_port, &nat_type);
        let inbox_id = id.clone();
        let inbox_id_bytes = id_bytes;
        let inbox_keypair = keypair.clone();
        let inbox_socket = socket.clone();
        let inbox_dialing = dialing.clone();
        let inbox_destroyed = destroyed.clone();
        let inbox_path_for_task = inbox_path.clone();

        tokio::spawn(async move {
            let client = match reqwest::Client::builder().timeout(Duration::from_secs(8)).build() {
                Ok(client) => client,
                Err(_) => return,
            };
            loop {
                if *destroyed.lock().await { break; }
                for server in PIPING_SERVERS {
                    let url = format!("https://{}{}", server, announce_path);

                    // Anunciar este peer
                    let body = me.clone();
                    let _ = client.post(&url).json(&body).send().await;

                    // Procurar outros peers (long‑poll)
                    if let Ok(resp) = client.get(&url).send().await {
                        if let Ok(text) = resp.text().await {
                            for peer in parse_piping_messages(&text) {
                                let peer_id = peer.get("id").and_then(|v| v.as_str()).unwrap_or("");
                                if peer_id == id { continue; }
                                let peer_inbox = format!("https://{}/p2p-{}-{}", server, topic, peer_id);
                                let _ = client.post(&peer_inbox).json(&me).send().await;
                                dial_discovered_peer(&peer, &id, id_bytes, &keypair, &socket, &dialing).await;
                            }
                        }
                    }
                }
                sleep(Duration::from_secs(5)).await;
            }
        });

        tokio::spawn(async move {
            let client = match reqwest::Client::builder().timeout(Duration::from_secs(8)).build() {
                Ok(client) => client,
                Err(_) => return,
            };
            loop {
                if *inbox_destroyed.lock().await { break; }
                for server in PIPING_SERVERS {
                    let url = format!("https://{}{}", server, inbox_path_for_task);
                    if let Ok(resp) = client.get(&url).send().await {
                        if let Ok(text) = resp.text().await {
                            for peer in parse_piping_messages(&text) {
                                dial_discovered_peer(
                                    &peer,
                                    &inbox_id,
                                    inbox_id_bytes,
                                    &inbox_keypair,
                                    &inbox_socket,
                                    &inbox_dialing,
                                ).await;
                            }
                        }
                    }
                }
                sleep(Duration::from_millis(100)).await;
            }
        });
    }

    async fn start_piping_discovery(&self) {
        let topic = match &self.topic_hash {
            Some(t) => t.clone(),
            None => return,
        };
        let id = self.id.clone();
        let id_bytes = self.id_bytes;
        let keypair = self.keypair.clone();
        let socket = self.socket.clone();
        let dialing = self.dialing.clone();
        let destroyed = self.destroyed.clone();
        let announce_path = format!("/p2p-{}-announce", topic);
        let inbox_path = format!("/p2p-{}-{}", topic, id);
        let me = peer_announcement(
            &id,
            self.external,
            &self.local_ip,
            self.local_port,
            &self.nat_type,
        );

        let announce_destroyed = destroyed.clone();
        let announce_path_for_task = announce_path.clone();
        let announce_body = me.clone();
        tokio::spawn(async move {
            let client = match reqwest::Client::builder().build() {
                Ok(client) => client,
                Err(_) => return,
            };
            for delay in [0u64, 2_000, 5_000] {
                if delay > 0 {
                    sleep(Duration::from_millis(delay)).await;
                }
                if *announce_destroyed.lock().await { return; }
                for server in PIPING_SERVERS {
                    let client = client.clone();
                    let url = format!("https://{}{}", server, announce_path_for_task);
                    let body = announce_body.clone();
                    tokio::spawn(async move {
                        piping_post_json(&client, &url, &body).await;
                    });
                }
            }

            let mut ticker = interval(Duration::from_millis(ANNOUNCE_MS));
            loop {
                ticker.tick().await;
                if *announce_destroyed.lock().await { break; }
                for server in PIPING_SERVERS {
                    let client = client.clone();
                    let url = format!("https://{}{}", server, announce_path_for_task);
                    let body = announce_body.clone();
                    tokio::spawn(async move {
                        piping_post_json(&client, &url, &body).await;
                    });
                }
            }
        });

        for server in PIPING_SERVERS {
            let server = server.to_string();
            let announce_server = server.clone();
            let topic = topic.clone();
            let id = id.clone();
            let keypair = keypair.clone();
            let socket = socket.clone();
            let dialing = dialing.clone();
            let destroyed = destroyed.clone();
            let announce_path = announce_path.clone();
            let me = me.clone();
            tokio::spawn(async move {
                let client = match reqwest::Client::builder().build() {
                    Ok(client) => client,
                    Err(_) => return,
                };
                let url = format!("https://{}{}", announce_server, announce_path);
                loop {
                    if *destroyed.lock().await { break; }
                    if let Some(text) = piping_get_text(&client, &url).await {
                        for peer in parse_piping_messages(&text) {
                            let peer_id = peer.get("id").and_then(|v| v.as_str()).unwrap_or("");
                            if peer_id == id { continue; }
                            let peer_inbox = format!("/p2p-{}-{}", topic, peer_id);
                            piping_post_all_json(&client, &peer_inbox, &me).await;
                            dial_discovered_peer(&peer, &id, id_bytes, &keypair, &socket, &dialing).await;
                        }
                    } else {
                        sleep(Duration::from_secs(2)).await;
                    }
                    sleep(Duration::from_millis(100)).await;
                }
            });

            let server = server.to_string();
            let id = self.id.clone();
            let id_bytes = self.id_bytes;
            let keypair = self.keypair.clone();
            let socket = self.socket.clone();
            let dialing = self.dialing.clone();
            let destroyed = self.destroyed.clone();
            let inbox_path = inbox_path.clone();
            tokio::spawn(async move {
                let client = match reqwest::Client::builder().build() {
                    Ok(client) => client,
                    Err(_) => return,
                };
                let url = format!("https://{}{}", server, inbox_path);
                loop {
                    if *destroyed.lock().await { break; }
                    if let Some(text) = piping_get_text(&client, &url).await {
                        for peer in parse_piping_messages(&text) {
                            if peer.get("id").and_then(|v| v.as_str()) == Some(id.as_str()) {
                                continue;
                            }
                            dial_discovered_peer(
                                &peer,
                                &id,
                                id_bytes,
                                &keypair,
                                &socket,
                                &dialing,
                            ).await;
                        }
                    } else {
                        sleep(Duration::from_secs(2)).await;
                    }
                    sleep(Duration::from_millis(100)).await;
                }
            });
        }
    }

    pub async fn broadcast(&self, data: &[u8]) -> usize {
        let mut peers = self.peers.lock().await;
        let count = peers.len();

        for (peer_id, peer) in peers.iter_mut() {
            let mut payload = data.to_vec();

            // Se tivermos sessão, cifra com a chave desse peer
            if let Some(mut session) = peer.session.take() {
                let seq = peer.next_send_seq();
                let mut seq_buf = vec![0u8; 4];
                seq_buf.copy_from_slice(&seq.to_be_bytes());
                seq_buf.extend_from_slice(data);
                let encrypted = encrypt(&mut session, &seq_buf);
                peer.session = Some(session);      // devolve a sessão (com send_ctr atualizado)
                payload = encrypted;
            }

            let mut frame = vec![F_DATA];
            frame.extend_from_slice(&payload);

            if self.socket.send_to(&frame, peer.remote_addr).await.is_err() {
                let _ = self.send_via_relay(peer_id, F_DATA, &payload).await;
            }
        }

        count
    }

    pub async fn send_to(&self, peer_id: &str, data: &[u8]) -> bool {
        let mut peers = self.peers.lock().await;          // added `mut`
        let peer = match peers.get_mut(peer_id) {
            Some(p) => p,
            None => return false,
        };

        let addr = peer.remote_addr;
        let mut payload = data.to_vec();

        if let Some(mut session) = peer.session.take() {
            let seq = peer.next_send_seq();
            let mut seq_buf = vec![0u8; 4];
            seq_buf.copy_from_slice(&seq.to_be_bytes());
            seq_buf.extend_from_slice(data);
            let encrypted = encrypt(&mut session, &seq_buf);
            peer.session = Some(session);
            payload = encrypted;
        }
        drop(peers);   // release lock before sending

        let mut frame = vec![F_DATA];
        frame.extend_from_slice(&payload);

        if self.socket.send_to(&frame, addr).await.is_ok() {
            return true;
        }
        self.send_via_relay(peer_id, F_DATA, &payload).await
    }

    pub async fn list_peers(&self) -> Vec<(String, f64, bool)> {
        let peers = self.peers.lock().await;
        peers.iter()
            .map(|(id, peer)| (id.clone(), peer.rtt, peer.in_mesh))
            .collect()
    }

    pub async fn send_via_relay(&self, dest_id: &str, frame_type: u8, payload: &[u8]) -> bool {
        let topic = match &self.topic_hash {
            Some(t) => t.as_str(),
            None => return false,
        };
        let relay_id = self.get_relay().await;
        if relay_id.is_none() { return false; }
        let _relay_id = relay_id.unwrap();

        let mut msg = Vec::with_capacity(20 + 1 + payload.len());
        if let Ok(id_bytes) = hex::decode(dest_id) {
            let len = id_bytes.len().min(20);
            msg.extend_from_slice(&id_bytes[..len]);
            if len < 20 {
                msg.extend(vec![0u8; 20 - len]);
            }
        } else {
            return false;
        }
        msg.push(frame_type);
        msg.extend_from_slice(payload);

        for server in PIPING_SERVERS {
            let url = format!("https://{}/p2p-{}-relay", server, topic);
            if let Ok(client) = reqwest::Client::builder().timeout(Duration::from_secs(5)).build() {
                if client.post(&url).body(msg.clone()).send().await.is_ok() {
                    return true;
                }
            }
        }
        false
    }

    pub async fn get_relay(&self) -> Option<String> {
        let relays = self.relays.lock().await;
        relays.keys().next().cloned()
    }

    pub fn on_connection(&mut self, cb: ConnectionCallback)    { self.on_connection = Some(cb); }
    pub fn on_disconnection(&mut self, cb: DisconnectionCallback) { self.on_disconnection = Some(cb); }
    pub fn on_data(&mut self, cb: DataCallback)                { self.on_data = Some(cb); }

    pub async fn destroy(&mut self) {
        *self.destroyed.lock().await = true;
        *self.running.lock().await = false;
        if let Ok(mut tasks) = self.relay_http_tasks.try_lock() {
            for h in tasks.drain(..) { h.abort(); }
        }
        let mut peers = self.peers.lock().await;
        for (_, mut p) in peers.drain() { p.destroy(); }
    }
}

// ============================================================================
// Frame handler (UDP receive)
// ============================================================================

async fn handle_frame(
    data: &[u8],
    src: SocketAddr,
    peers: &Arc<Mutex<HashMap<String, Peer>>>,
    addr_to_id: &Arc<Mutex<HashMap<String, String>>>,
    dialing: &Arc<Mutex<HashSet<String>>>,
    keypair: &crate::crypto::KeyPair,
    my_id: &str,
    my_id_bytes: [u8; 8],
    topic_hash: &Option<String>,
    on_conn: &Option<ConnectionCallback>,
    on_disc: &Option<DisconnectionCallback>,
    on_data: &Option<DataCallback>,
    relays: &Arc<Mutex<HashMap<String, (String, u16)>>>,
    socket: &Arc<tokio::net::UdpSocket>,
    _destroyed: &Arc<Mutex<bool>>,
) {
    if data.is_empty() { return; }
    match data[0] {
        F_HELLO => {
            if data.len() < 41 { return; }
            if &data[1..9] == &my_id_bytes { return; }
            if let Some((_, their_pub)) = parse_handshake_frame(data) {
                let their_wire_id = hex::encode(&data[1..9]);
                let mut pg = peers.lock().await;
                if pg.len() >= MAX_PEERS { return; }
                let session = derive_session_flipped(
                    &keypair.private, their_pub,
                    my_id, &their_wire_id,
                );
                let ack = create_hello_ack_frame(&my_id_bytes, &keypair.public);
                let _ = socket.send_to(&ack, src).await;

                let is_new = !pg.contains_key(&their_wire_id);
                let p = pg.entry(their_wire_id.clone())
                    .or_insert_with(|| Peer::new(their_wire_id.clone(), src));
                p.their_pub = Some(*their_pub);
                p.session = Some(session);
                p.in_mesh = true;
                if is_new {
                    if let Some(ref cb) = on_conn { cb(p); }
                    let peers_snap: Vec<(String, SocketAddr)> = pg.iter().map(|(id, p)| (id.clone(), p.remote_addr)).collect();
                    drop(pg);
                    // enviar PEX
                    if !peers_snap.is_empty() {
                        let mut frame = vec![F_PEX, peers_snap.len() as u8];
                        for (pid, addr) in peers_snap {
                            if let Ok(idb) = hex::decode(&pid[..16.min(pid.len())]) {
                                frame.extend_from_slice(&idb[..8.min(idb.len())]);
                            } else {
                                frame.extend_from_slice(&[0u8; 8]);
                            }
                            match addr.ip() {
                                std::net::IpAddr::V4(v4) => frame.extend_from_slice(&v4.octets()),
                                _ => frame.extend_from_slice(&[0,0,0,0]),
                            }
                            frame.extend_from_slice(&addr.port().to_be_bytes());
                        }
                        let _ = socket.send_to(&frame, src).await;
                    }
                }
                addr_to_id.lock().await.insert(src.to_string(), their_wire_id);
            }
        }
        F_HELLO_ACK => {
            if data.len() < 41 { return; }
            if &data[1..9] == &my_id_bytes { return; }
            if let Some((_, their_pub)) = parse_handshake_frame(data) {
                let their_wire_id = hex::encode(&data[1..9]);
                let mut pg = peers.lock().await;
                if pg.len() >= MAX_PEERS { return; }
                let session = derive_session_flipped(
                    &keypair.private, their_pub,
                    my_id, &their_wire_id,
                );
                let is_new = !pg.contains_key(&their_wire_id);
                let p = pg.entry(their_wire_id.clone())
                    .or_insert_with(|| Peer::new(their_wire_id.clone(), src));
                p.their_pub = Some(*their_pub);
                p.session = Some(session);
                p.in_mesh = true;
                if is_new {
                    if let Some(ref cb) = on_conn { cb(p); }
                    let peers_snap: Vec<(String, SocketAddr)> = pg.iter().map(|(id, p)| (id.clone(), p.remote_addr)).collect();
                    drop(pg);
                    if !peers_snap.is_empty() {
                        let mut frame = vec![F_PEX, peers_snap.len() as u8];
                        for (pid, addr) in peers_snap {
                            if let Ok(idb) = hex::decode(&pid[..16.min(pid.len())]) {
                                frame.extend_from_slice(&idb[..8.min(idb.len())]);
                            } else {
                                frame.extend_from_slice(&[0u8; 8]);
                            }
                            match addr.ip() {
                                std::net::IpAddr::V4(v4) => frame.extend_from_slice(&v4.octets()),
                                _ => frame.extend_from_slice(&[0,0,0,0]),
                            }
                            frame.extend_from_slice(&addr.port().to_be_bytes());
                        }
                        let _ = socket.send_to(&frame, src).await;
                    }
                }
                addr_to_id.lock().await.insert(src.to_string(), their_wire_id);
            }
        }
        F_DATA => {
            let src_str = src.to_string();
            let pid = addr_to_id.lock().await.get(&src_str).cloned();
            if let Some(pid) = pid {
                let mut pg = peers.lock().await;
                if let Some(peer) = pg.get_mut(&pid) {
                    peer.touch(src, None);
                    if let Some(ref session) = peer.session {
                        let encrypted = &data[1..];
                        if let Some(plain) = decrypt(session, encrypted) {
                            let payload = if plain.len() >= 4 { &plain[4..] } else { &plain[..] };
                            if let Some(ref cb) = on_data { cb(payload, peer); }
                        }
                    }
                }
            }
        }
        F_PING => {
            //eprintln!("DEBUG: received PING from {}", src);
            let mut pong = vec![F_PONG];
            let id_raw = hex::decode(my_id).unwrap_or_default();
            pong.extend_from_slice(&id_raw);
            let _ = socket.send_to(&pong, src).await;
            let src_str = src.to_string();
            if let Some(pid) = addr_to_id.lock().await.get(&src_str).cloned() {
                if let Some(peer) = peers.lock().await.get_mut(&pid) {
                    peer.last_seen = Instant::now();
                    peer.open = true;
                }
            }
        }
        F_PONG => {
            let src_str = src.to_string();
            let pid = addr_to_id.lock().await.get(&src_str).cloned();
            if let Some(pid) = pid {
                if let Some(peer) = peers.lock().await.get_mut(&pid) {
                    if peer.last_ping_sent > 0 {
                        let rtt = (now_millis() as f64) - (peer.last_ping_sent as f64);
                        if rtt > 0.0 && rtt < 100000.0 {
                            peer.rtt = peer.rtt * (1.0 - RTT_ALPHA) + rtt * RTT_ALPHA;
                        }
                        peer.last_ping_sent = 0;
                    }
                    peer.last_seen = Instant::now();
                    peer.open = true;
                }
            } else if data.len() >= 9 {
                let wire_id = hex::encode(&data[1..9]);
                let pg = peers.lock().await;
                if pg.contains_key(&wire_id) {
                    drop(pg);
                    addr_to_id.lock().await.insert(src_str.clone(), wire_id.clone());
                    if let Some(peer) = peers.lock().await.get_mut(&wire_id) {
                        if peer.last_ping_sent > 0 {
                            let rtt = (now_millis() as f64) - (peer.last_ping_sent as f64);
                            if rtt > 0.0 && rtt < 100000.0 {
                                peer.rtt = peer.rtt * (1.0 - RTT_ALPHA) + rtt * RTT_ALPHA;
                            }
                            peer.last_ping_sent = 0;
                        }
                        peer.last_seen = Instant::now();
                        peer.open = true;
                    }
                }
            }
        }
        F_GOAWAY => {
            let src_str = src.to_string();
            if let Some(pid) = addr_to_id.lock().await.remove(&src_str) {
                if let Some(mut p) = peers.lock().await.remove(&pid) {
                    p.destroy();
                    if let Some(ref cb) = on_disc { cb(&pid); }
                }
            }
        }
        F_LAN => {
            if let Ok(msg) = std::str::from_utf8(&data[1..]) {
                let parts: Vec<&str> = msg.split(':').collect();
                if parts.len() < 3 { return; }
                let peer_id = parts[0];
                let ip = parts[1];
                let port: u16 = parts[2].parse().unwrap_or(0);
                let their_topic = parts.get(3).copied().unwrap_or("");
                if peer_id == my_id || port == 0 { return; }
                if let Some(ref my_topic) = topic_hash {
                    if !their_topic.is_empty() && their_topic != my_topic { return; }
                }
                let dest: SocketAddr = match format!("{}:{}", ip, port).parse() {
                    Ok(a) => a, Err(_) => return,
                };
                let mut dg = dialing.lock().await;
                if !dg.contains(peer_id) {
                    dg.insert(peer_id.to_string());
                    drop(dg);
                    let frame = create_hello_frame(&my_id_bytes, &keypair.public);
                    let _ = socket.send_to(&frame, dest).await;
                }
            }
        }
        F_PEX => {
            if data.len() < 2 { return; }
            let count = data[1] as usize;
            let mut i = 2;
            for _ in 0..count {
                if i + 14 > data.len() { break; }
                let peer_id = hex::encode(&data[i..i+8]);
                let ip_bytes: [u8; 4] = [data[i+8], data[i+9], data[i+10], data[i+11]];
                let port = u16::from_be_bytes([data[i+12], data[i+13]]);
                i += 14;
                if port == 0 || peer_id == my_id { continue; }
                if peers.lock().await.contains_key(&peer_id) { continue; }
                let dest = SocketAddr::new(std::net::Ipv4Addr::from(ip_bytes).into(), port);
                let frame = create_hello_frame(&my_id_bytes, &keypair.public);
                let _ = socket.send_to(&frame, dest).await;
            }
        }
        F_RELAY_ANN => {
            if data.len() < 22 { return; }
            let relay_id = hex::encode(&data[1..21]);
            let addr_len = data[21] as usize;
            if data.len() < 22 + addr_len + 2 { return; }
            let addr_str = std::str::from_utf8(&data[22..22+addr_len]).unwrap_or("");
            let port = u16::from_be_bytes([data[22+addr_len], data[23+addr_len]]);
            // Extrai IP da string (formato "ip:port" ou "ip")
            let ip = if let Some((ip, _)) = addr_str.split_once(':') {
                ip.to_string()
            } else {
                addr_str.to_string()
            };
            if let Ok(mut map) = relays.try_lock() {
                map.insert(relay_id, (ip, port));
            }
        }
        F_RELAY_REQ => {
            // Recebido por um relay: o pedido contém o target peer id (20 bytes)
            if data.len() < 21 { return; }
            let target_id = &data[1..21];
            let target_hex = hex::encode(target_id);
            // Envia F_RELAY_FWD para o solicitante e para o target
            let fwd = {
                let mut f = vec![F_RELAY_FWD];
                f.extend_from_slice(target_id);
                f.extend_from_slice(&src.ip().to_string().as_bytes());
                f.push(0); // separador
                f.extend_from_slice(&src.port().to_be_bytes());
                f
            };
            let _ = socket.send_to(&fwd, src).await;
            if let Some(peer) = peers.lock().await.get(&target_hex) {
                let mut fwd2 = vec![F_RELAY_FWD];
                let my_id_bytes = &my_id_bytes;
                fwd2.extend_from_slice(my_id_bytes);
                fwd2.extend_from_slice(&src.ip().to_string().as_bytes());
                fwd2.push(0);
                fwd2.extend_from_slice(&src.port().to_be_bytes());
                let _ = socket.send_to(&fwd2, peer.remote_addr).await;
            }
        }
        F_RELAY_FWD => {
            // Recebido por um peer: contém id do peer remoto e IP/porta
            if data.len() < 21 { return; }
            let _remote_id = hex::encode(&data[1..21]);
            let rest = &data[21..];
            if let Some(pos) = rest.iter().position(|&b| b == 0) {
                let ip = std::str::from_utf8(&rest[..pos]).unwrap_or("");
                let port_bytes = &rest[pos+1..];
                if port_bytes.len() >= 2 {
                    let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
                    let dest: SocketAddr = format!("{}:{}", ip, port).parse().unwrap();
                    let frame = create_hello_frame(&my_id_bytes, &keypair.public);
                    let _ = socket.send_to(&frame, dest).await;
                }
            }
        }
        _ => {}
    }
}

// ============================================================================
// Relay HTTP helpers
// ============================================================================

#[allow(dead_code)]
async fn read_own_inbox(
    server: String,
    topic: String,
    peer_id: String,
    socket: Arc<tokio::net::UdpSocket>,
    _peers: Arc<Mutex<HashMap<String, Peer>>>,
    destroyed: Arc<Mutex<bool>>,
) {
    let inbox_url = format!("https://{}/p2p-{}-{}", server, topic, peer_id);
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build() {
        Ok(c) => c,
        Err(_) => return,
    };
    loop {
        if *destroyed.lock().await { break; }
        if let Ok(resp) = client.get(&inbox_url).send().await {
            if let Ok(bytes) = resp.bytes().await {
                if bytes.len() >= 2 {
                    let frame_type = bytes[0];
                    let payload = &bytes[1..];
                    // Processa como se fosse um frame UDP
                    // Aqui podes chamar o handler apropriado, mas por simplicidade
                    // reencaminha para o socket local (loopback) para ser processado pelo receive loop
                    let mut frame = vec![frame_type];
                    frame.extend_from_slice(payload);
                    // Envia para si mesmo via loopback para ser tratado pelo handle_frame
                    let local_addr = socket.local_addr().unwrap();
                    let _ = socket.send_to(&frame, local_addr).await;
                }
            }
        }
        sleep(Duration::from_secs(2)).await;
    }
}

async fn relay_read_inbox(
    server: String,
    topic: String,
    _relay_id: String,
    socket: Arc<tokio::net::UdpSocket>,
    peers: Arc<Mutex<HashMap<String, Peer>>>,
    destroyed: Arc<Mutex<bool>>,
) {
    let inbox_url = format!("https://{}/p2p-{}-relay", server, topic);
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build() {
        Ok(c) => c,
        Err(_) => return,
    };
    loop {
        if *destroyed.lock().await { break; }
        if let Ok(resp) = client.get(&inbox_url).send().await {
            if let Ok(bytes) = resp.bytes().await {
                if bytes.len() >= 21 {
                    let dest_id = hex::encode(&bytes[..20]);
                    let frame_type = bytes[20];
                    let payload = &bytes[21..];
                    let pg = peers.lock().await;
                    if let Some(peer) = pg.get(&dest_id) {
                        let mut frame = vec![frame_type];
                        frame.extend_from_slice(payload);
                        let _ = socket.send_to(&frame, peer.remote_addr).await;
                    } else {
                        drop(pg);
                        let inbox_url = format!("https://{}/p2p-{}-{}", server, topic, dest_id);
                        let mut body = vec![frame_type];
                        body.extend_from_slice(payload);
                        let _ = client.post(&inbox_url).body(body).send().await;
                    }
                }
            }
        }
        sleep(Duration::from_secs(2)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_swarm_creation() {
        let swarm = Swarm::new().await;
        assert_eq!(swarm.id.len(), 40);
    }
}
