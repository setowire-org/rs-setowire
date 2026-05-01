//! Swarm module - main P2P networking class

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::Mutex;
use tokio::time::{interval, timeout, sleep};

use crate::constants::*;
use crate::crypto::{create_hello_frame, create_hello_ack_frame, derive_session_flipped, encrypt, decrypt, generate_x25519, parse_handshake_frame};
use crate::dht_lib::SimpleDht;
use crate::framing::BatchSender;
use crate::peer::Peer;
use crate::structs::{BloomFilter, Lru};

// ============================================================================
// Helper: get local IP address
// ============================================================================

fn get_local_ip() -> String {
    // Try to get the IP by connecting to an external address (doesn't actually send)
    // This is a standard trick to get the local IP
    if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
        // Connect to a public IP (doesn't actually send anything)
        if socket.connect("8.8.8.8:80").is_ok() {
            if let Ok(addr) = socket.local_addr() {
                if !addr.ip().is_unspecified() {
                    return addr.ip().to_string();
                }
            }
        }
    }
    // Fallback: try to use the local IP from socket after binding
    // This is a Windows-specific workaround
    if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if let Ok(addr) = socket.local_addr() {
            // On Windows, sometimes the IP shows as 0.0.0.0 but we can query
            // by connecting to a specific address
            if let Ok(socket2) = std::net::UdpSocket::bind("0.0.0.0:0") {
                if socket2.connect("1.1.1.1:53").is_ok() {
                    if let Ok(addr2) = socket2.local_addr() {
                        return addr2.ip().to_string();
                    }
                }
            }
        }
    }
    // Last resort: return localhost
    "127.0.0.1".to_string()
}

// ============================================================================
// Types
// ============================================================================

pub type ConnectionCallback    = Arc<dyn Fn(&Peer) + Send + Sync>;
pub type DisconnectionCallback = Arc<dyn Fn(&str)  + Send + Sync>;
pub type DataCallback          = Arc<dyn Fn(&[u8], &Peer) + Send + Sync>;
pub type NatCallback           = Arc<dyn Fn() + Send + Sync>;

// ============================================================================
// Swarm
// ============================================================================

/// Main P2P swarm class
pub struct Swarm {
    pub socket:      Arc<tokio::net::UdpSocket>,
    pub local_ip:    String,
    pub local_port:  u16,
    pub external:    Option<SocketAddr>,
    pub nat_type:    String,
    /// Full 40-char hex ID: SHA256(pubkey)[:20].to_hex()
    pub id:          String,
    /// First 8 bytes of SHA256(pubkey) — sent on wire in HELLO/HELLO_ACK
    pub id_bytes:    [u8; 8],
    pub keypair:     crate::crypto::KeyPair,
    pub peers:       Arc<Mutex<HashMap<String, Peer>>>,
    addr_to_id:      Arc<Mutex<HashMap<String, String>>>,
    dialing:         Arc<Mutex<HashSet<String>>>,
    pub max_peers:   usize,
    pub is_relay:    bool,
    pub topic_hash:        Option<String>,
    /// For Piping discovery: topic hash (set via join())
    piping_topic_hash:   Option<String>,
    bloom:               Arc<Mutex<BloomFilter>>,
    store:           Arc<Mutex<Lru<String, Vec<u8>>>>,
    gossip_seen:     Arc<Mutex<Lru<String, ()>>>,
    dht:             Option<SimpleDht>,
    batch:           Arc<Mutex<BatchSender>>,
    destroyed:       Arc<Mutex<bool>>,
    // FIX C1: callbacks são Arc (não Box) para poderem ser clonados para tasks
    on_connection:    Option<ConnectionCallback>,
    on_disconnection: Option<DisconnectionCallback>,
    on_data:          Option<DataCallback>,
    on_nat:           Option<NatCallback>,
    running:         Arc<Mutex<bool>>,
}

impl Swarm {
    pub async fn new() -> Self {
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
            .await
            .expect("Failed to bind UDP socket");

        let local_addr = socket.local_addr().expect("Failed to get local addr");
        // Get real local IP - bind to 0.0.0.0 gives 0.0.0.0 which is useless for LAN
        let local_ip = get_local_ip();
        let local_port = local_addr.port();

        let keypair = generate_x25519(None);

        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(&keypair.public);
        let hash = hasher.finalize();
        let id       = hex::encode(&hash[..20]);
        let id_bytes: [u8; 8] = hash[..8].try_into().unwrap_or([0u8; 8]);

        Swarm {
            socket:    Arc::new(socket),
            local_ip,
            local_port,
            external:  None,
            nat_type:  "unknown".to_string(),
            id,
            id_bytes,
            keypair,
            peers:      Arc::new(Mutex::new(HashMap::new())),
            addr_to_id: Arc::new(Mutex::new(HashMap::new())),
            dialing:    Arc::new(Mutex::new(HashSet::new())),
            max_peers:  MAX_PEERS,
            is_relay:   false,
            topic_hash:        None,
            piping_topic_hash: None,
            bloom:             Arc::new(Mutex::new(BloomFilter::new(None, None))),
            store:       Arc::new(Mutex::new(Lru::new(SYNC_CACHE_MAX, None))),
            gossip_seen: Arc::new(Mutex::new(Lru::new(GOSSIP_MAX, Some(GOSSIP_TTL)))),
            dht:         None,
            batch:       Arc::new(Mutex::new(BatchSender::new())),
            destroyed:   Arc::new(Mutex::new(false)),
            on_connection:    None,
            on_disconnection: None,
            on_data:          None,
            on_nat:           None,
            running:     Arc::new(Mutex::new(false)),
        }
    }

    pub fn id(&self) -> &str { &self.id }
    pub fn nat_type(&self) -> &str { &self.nat_type }
    pub fn public_addr(&self) -> Option<String> { self.external.map(|a| a.to_string()) }
    pub fn peer_count(&self) -> usize { self.peers.try_lock().map(|g| g.len()).unwrap_or(0) }

    /// Join a topic. topicHash = sha1(hex(topic))[:6] → 12 hex chars
    pub fn join(&mut self, topic: &[u8], _announce: bool, _lookup: bool) {
        use sha1::Sha1;
        use digest::Digest;
        let topic_hex = hex::encode(topic);
        let mut hasher = Sha1::new();
        hasher.update(topic_hex.as_bytes());
        let result = hasher.finalize();
        let topic_hash = hex::encode(&result[..6]);
        let topic_hash_for_diag = topic_hash.clone();
        self.topic_hash = Some(topic_hash.clone());
        self.piping_topic_hash = Some(topic_hash);
        
    }

    // FIX C1: callbacks são Arc para poder clonar sem mover
    pub fn on_connection(&mut self, cb: ConnectionCallback)    { self.on_connection    = Some(cb); }
    pub fn on_disconnection(&mut self, cb: DisconnectionCallback) { self.on_disconnection = Some(cb); }
    pub fn on_data(&mut self, cb: DataCallback)                { self.on_data          = Some(cb); }
    pub fn on_nat(&mut self, cb: NatCallback)                  { self.on_nat           = Some(cb); }

    pub async fn destroy(&mut self) {
        *self.destroyed.lock().await = true;
        *self.running.lock().await   = false;
        let mut peers = self.peers.lock().await;
        for (_, mut peer) in peers.drain() {
            // send GOAWAY
            let _ = self.socket.send_to(&[F_GOAWAY], peer.remote_addr).await;
            peer.destroy();
        }
    }

    /// Send encrypted DATA frame to a specific peer (by wire-id key in peers map)
    pub async fn send_to(&self, peer_id: &str, data: &[u8]) -> bool {
        let mut peers_guard = self.peers.lock().await;
        if let Some(peer) = peers_guard.get_mut(peer_id) {
            let seq = peer.next_send_seq();
            if let Some(ref mut session) = peer.session {
                let mut seq_buf = vec![0u8; 4 + data.len()];
                seq_buf[0..4].copy_from_slice(&seq.to_be_bytes());
                seq_buf[4..].copy_from_slice(data);
                let encrypted = encrypt(session, &seq_buf);
                let addr = peer.remote_addr;
                drop(peers_guard);
                let mut frame = vec![F_DATA];
                frame.extend_from_slice(&encrypted);
                return self.socket.send_to(&frame, addr).await.is_ok();
            }
        }
        false
    }

    // FIX C2: broadcast() itera todos os peers e envia de verdade
    pub fn broadcast(&self, data: &[u8]) -> usize {
        let data  = data.to_vec();
        let peers = self.peers.clone();
        let sock  = self.socket.clone();
        tokio::spawn(async move {
            let peer_ids: Vec<String> = {
                let pg = peers.lock().await;
                pg.keys().cloned().collect()
            };
            let mut count = 0usize;
            for pid in peer_ids {
                let mut pg = peers.lock().await;
                if let Some(peer) = pg.get_mut(&pid) {
                    let seq = peer.next_send_seq();
                    if let Some(ref mut session) = peer.session {
                        let mut seq_buf = vec![0u8; 4 + data.len()];
                        seq_buf[0..4].copy_from_slice(&seq.to_be_bytes());
                        seq_buf[4..].copy_from_slice(&data);
                        let encrypted = encrypt(session, &seq_buf);
                        let addr = peer.remote_addr;
                        drop(pg);
                        let mut frame = vec![F_DATA];
                        frame.extend_from_slice(&encrypted);
                        if sock.send_to(&frame, addr).await.is_ok() { count += 1; }
                        continue;
                    }
                }
                drop(pg);
            }
        });
        // retorna contagem estimada de peers (não podemos aguardar sem async)
        self.peers.try_lock().map(|g| g.len()).unwrap_or(0)
    }

    pub fn store(&self, _key: &str, _value: &[u8]) {}
    pub async fn fetch(&self, _key: &str) -> Option<Vec<u8>> { None }
    pub fn local_addr(&self) -> SocketAddr { self.socket.local_addr().unwrap() }
    pub fn socket_ref(&self) -> &tokio::net::UdpSocket { &self.socket }

    /// Get list of connected peers with details
    pub async fn list_peers(&self) -> Vec<(String, SocketAddr, f64, bool)> {
        let pg = self.peers.lock().await;
        pg.values().map(|p| (p.id.clone(), p.remote_addr, p.rtt, p.open)).collect()
    }

    /// Start the swarm — receive loop, LAN multicast, STUN, heartbeat, HTTP bootstrap.
    pub async fn start(&mut self) {
        *self.running.lock().await = true;

        // FIX C1: clonar Arc dos callbacks, não mover com .take()
        let on_connection    = self.on_connection.clone();
        let on_data          = self.on_data.clone();
        let on_disconnection = self.on_disconnection.clone();
        let on_nat_stun      = self.on_nat.clone();

        let socket      = self.socket.clone();
        let peers       = self.peers.clone();
        let addr_to_id  = self.addr_to_id.clone();
        let dialing     = self.dialing.clone();
        let destroyed   = self.destroyed.clone();
        let keypair     = self.keypair.clone();
        let id          = self.id.clone();
        let id_bytes    = self.id_bytes;
        let local_port  = self.local_port;
        let topic_hash  = self.topic_hash.clone();

        // =========================================================
        // Receive loop
        // =========================================================
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                if *destroyed.lock().await { break; }

                match timeout(Duration::from_millis(500), socket.recv_from(&mut buf)).await {
                    Ok(Ok((len, src))) => {
                        if len < 1 { continue; }

                        // FIX C3: filtro de self só por porta, NÃO por IP.
                        // Dois processos na mesma máquina têm IPs iguais mas portas diferentes.
                        if src.port() == local_port { continue; }

                        match buf[0] {
                            // ------------------------------------------
                            // HELLO (0xA1)
                            // ------------------------------------------
                            0xA1 => {
                                
                                if len < 41 { continue; }
                                if &buf[1..9] == &id_bytes { continue; }

                                if let Some((_, their_pub)) = parse_handshake_frame(&buf[..len]) {
                                    let their_wire_id = hex::encode(&buf[1..9]);
                                    

                                    let session = derive_session_flipped(
                                        &keypair.private,
                                        their_pub,
                                        &id,
                                        &their_wire_id,
                                    );

                                    // ACK primeiro, depois registra peer
                                    let ack = create_hello_ack_frame(&id_bytes, &keypair.public);
                                    
                                    let _ = socket.send_to(&ack, src).await;

                                    let mut pg = peers.lock().await;
                                    if pg.len() >= MAX_PEERS { continue; }

                                    let is_new = !pg.contains_key(&their_wire_id);
                                    let p = pg.entry(their_wire_id.clone()).or_insert_with(|| Peer::new(their_wire_id.clone(), src));
                                    p.their_pub = Some(*their_pub);
                                    p.session   = Some(session);
                                    if is_new {
                                        if let Some(ref cb) = on_connection { cb(p); }
                                        // PEX: enviar lista de peers conhecidos para o novo peer
                                        drop(pg);
                                        let peers_snapshot: Vec<(String, SocketAddr)> = {
                                            let pg = peers.lock().await;
                                            pg.iter().map(|(id, p)| (id.clone(), p.remote_addr)).collect()
                                        };
                                        if !peers_snapshot.is_empty() {
                                            let mut frame = vec![F_PEX, peers_snapshot.len() as u8];
                                            for (pid, addr) in peers_snapshot {
                                                if let Ok(id_bytes) = hex::decode(&pid[..16.min(pid.len())]) {
                                                    if id_bytes.len() >= 8 {
                                                        frame.extend_from_slice(&id_bytes[..8]);
                                                    } else {
                                                        frame.extend_from_slice(&[0u8; 8]);
                                                    }
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

                            // ------------------------------------------
                            // HELLO_ACK (0xA2)
                            // ------------------------------------------
                            0xA2 => {
                                if len < 41 { continue; }
                                if &buf[1..9] == &id_bytes { continue; }

                                if let Some((_, their_pub)) = parse_handshake_frame(&buf[..len]) {
                                    let their_wire_id = hex::encode(&buf[1..9]);

                                    let session = derive_session_flipped(
                                        &keypair.private,
                                        their_pub,
                                        &id,
                                        &their_wire_id,
                                    );

                                    let mut pg = peers.lock().await;
                                    if pg.len() >= MAX_PEERS { continue; }

                                    let is_new = !pg.contains_key(&their_wire_id);
                                    let p = pg.entry(their_wire_id.clone()).or_insert_with(|| Peer::new(their_wire_id.clone(), src));
                                    p.their_pub = Some(*their_pub);
                                    p.session   = Some(session);
                                    if is_new {
                                        if let Some(ref cb) = on_connection { cb(p); }
                                        // PEX: enviar lista de peers conhecidos para o novo peer
                                        drop(pg);
                                        let peers_snapshot: Vec<(String, SocketAddr)> = {
                                            let pg = peers.lock().await;
                                            pg.iter().map(|(id, p)| (id.clone(), p.remote_addr)).collect()
                                        };
                                        if !peers_snapshot.is_empty() {
                                            let mut frame = vec![F_PEX, peers_snapshot.len() as u8];
                                            for (pid, addr) in peers_snapshot {
                                                if let Ok(id_bytes) = hex::decode(&pid[..16.min(pid.len())]) {
                                                    if id_bytes.len() >= 8 {
                                                        frame.extend_from_slice(&id_bytes[..8]);
                                                    } else {
                                                        frame.extend_from_slice(&[0u8; 8]);
                                                    }
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

                            // ------------------------------------------
                            // F_LAN (0x09) recebido no socket principal
                            // ------------------------------------------
                            b if b == F_LAN => {
                                if len > 1 {
                                    if let Ok(msg) = std::str::from_utf8(&buf[1..len]) {
                                        let parts: Vec<&str> = msg.split(':').collect();
                                        if parts.len() < 3 { continue; }
                                        let peer_id    = parts[0];
                                        let ip         = parts[1];
                                        let port: u16  = parts[2].parse().unwrap_or(0);
                                        let their_topic = parts.get(3).copied().unwrap_or("");

                                        if peer_id == id { continue; }
                                        if port == 0    { continue; }

                                        if let Some(ref my_topic) = topic_hash {
                                            if !their_topic.is_empty() && their_topic != my_topic {
                                                continue;
                                            }
                                        }

                                        let dial_dest: SocketAddr = match format!("{}:{}", ip, port).parse() {
                                            Ok(a) => a, Err(_) => continue,
                                        };

                                        let mut dg = dialing.lock().await;
                                        if !dg.contains(peer_id) {
                                            dg.insert(peer_id.to_string());
                                            drop(dg);
                                            let frame = create_hello_frame(&id_bytes, &keypair.public);
                                            let _ = socket.send_to(&frame, dial_dest).await;
                                        }
                                    }
                                }
                            }

                            // ------------------------------------------
                            // DATA (0x01)
                            // ------------------------------------------
                            0x01 => {
                                let src_str = src.to_string();
                                let pid_opt = addr_to_id.lock().await.get(&src_str).cloned();
                                if let Some(pid) = pid_opt {
                                    let mut pg = peers.lock().await;
                                    if let Some(peer) = pg.get_mut(&pid) {
                                        // FIX C4: touch ao receber dados
                                        peer.touch(src, None);
                                        if let Some(ref mut session) = peer.session {
                                            let data = &buf[1..len];
                                            if let Some(plain) = decrypt(session, data) {
                                                // strip 4-byte seq prefix
                                                let payload = if plain.len() >= 4 { &plain[4..] } else { &plain[..] };
                                                if let Some(ref cb) = on_data {
                                                    cb(payload, peer);
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            // ------------------------------------------
                            // PING (0x03): [F_PING][u64 ts BE][20-byte id]
                            // ------------------------------------------
                            0x03 => {
                                let id_raw = hex::decode(&id).unwrap_or_default();
                                let mut pong = Vec::with_capacity(1 + id_raw.len());
                                pong.push(F_PONG);
                                pong.extend_from_slice(&id_raw);
                                let _ = socket.send_to(&pong, src).await;

                                let src_str = src.to_string();
                                if let Some(pid) = addr_to_id.lock().await.get(&src_str).cloned() {
                                    if let Some(peer) = peers.lock().await.get_mut(&pid) {
                                        peer.touch(src, None);
                                    }
                                }
                            }

                            // ------------------------------------------
                            // PONG (0x04): [F_PONG][20-byte id]
                            // ------------------------------------------
                            0x04 => {
                                let src_str = src.to_string();
                                let pid_opt = {
                                    let a2i = addr_to_id.lock().await;
                                    a2i.get(&src_str).cloned()
                                };
                                // fallback: procura pelo ID embutido no PONG (20 bytes)
                                let pid_opt = if pid_opt.is_some() {
                                    pid_opt
                                } else if len >= 9 {
                                    // tenta 8 bytes wire-id primeiro
                                    let wire_id = hex::encode(&buf[1..9]);
                                    let pg = peers.lock().await;
                                    if pg.contains_key(&wire_id) { Some(wire_id) } else { None }
                                } else {
                                    None
                                };

                                if let Some(pid) = pid_opt {
                                    if let Some(peer) = peers.lock().await.get_mut(&pid) {
                                        peer.touch(src, None);
                                    }
                                    addr_to_id.lock().await.insert(src_str, pid);
                                }
                            }

                            // ------------------------------------------
                            // GOAWAY (0x0A)
                            // ------------------------------------------
                            0x0A => {
                                let src_str = src.to_string();
                                if let Some(pid) = addr_to_id.lock().await.remove(&src_str) {
                                    if let Some(mut peer) = peers.lock().await.remove(&pid) {
                                        peer.destroy();
                                        if let Some(ref cb) = on_disconnection { cb(&pid); }
                                    }
                                }
                            }

                            // ------------------------------------------
                            // PEX (0x30): [F_PEX][count][peer1_id(8) + ip(4) + port(2)]...
                            // ------------------------------------------
                            0x30 => {
                                if len < 2 { continue; }
                                let count = buf[1] as usize;
                                let mut i = 2;
                                for _ in 0..count {
                                    if i + 14 > len { break; }
                                    let peer_id = hex::encode(&buf[i..i+8]);
                                    let ip_bytes: [u8; 4] = [buf[i+8], buf[i+9], buf[i+10], buf[i+11]];
                                    let port = u16::from_be_bytes([buf[i+12], buf[i+13]]);
                                    i += 14;
                                    
                                    if port == 0 { continue; }
                                    if peer_id == id { continue; }
                                    
                                    // Já está conectado?
                                    if peers.lock().await.contains_key(&peer_id) { continue; }
                                    
                                    // Dial o peer
                                    let dest = SocketAddr::new(std::net::Ipv4Addr::from(ip_bytes).into(), port);
                                    let frame = create_hello_frame(&id_bytes, &keypair.public);
                                    let _ = socket.send_to(&frame, dest).await;
                                }
                            }

                            _ => {}
                        }
                    }
                    Ok(Err(_)) => break,
                    Err(_)     => continue,
                }
            }
        });

        // =========================================================
        // LAN Multicast — periodic announcements
        // =========================================================
        let ann_socket    = self.socket.clone();
        let ann_id        = self.id.clone();
        let ann_topic     = self.topic_hash.clone();
        let ann_local_ip  = self.local_ip.clone();
        let ann_port      = self.local_port;
        let ann_destroyed = self.destroyed.clone();

        tokio::spawn(async move {
            let mcast_dest = SocketAddr::new(
                std::net::Ipv4Addr::new(239, 0, 0, 1).into(),
                MCAST_PORT,
            );
            let mut ticker = interval(Duration::from_secs(5));
            loop {
                ticker.tick().await;
                if *ann_destroyed.lock().await { break; }
                let topic = ann_topic.as_deref().unwrap_or("");
                let msg   = format!("{}:{}:{}:{}", ann_id, ann_local_ip, ann_port, topic);
                let pkt: Vec<u8> = std::iter::once(F_LAN).chain(msg.bytes()).collect();
                let _ = ann_socket.send_to(&pkt, mcast_dest).await;
            }
        });

        // =========================================================
        // LAN Multicast — receive socket (porta fixa 45678)
        // =========================================================
        let mcast_main_socket = self.socket.clone();
        let mcast_id_bytes    = self.id_bytes;
        let mcast_keypair     = self.keypair.clone();
        let mcast_id          = self.id.clone();
        let mcast_topic       = self.topic_hash.clone();
        let mcast_dialing     = self.dialing.clone();
        let mcast_destroyed   = self.destroyed.clone();

        tokio::spawn(async move {
            let mcast_addr = std::net::Ipv4Addr::new(239, 0, 0, 1);
            let recv_sock  = match tokio::net::UdpSocket::bind(format!("0.0.0.0:{}", MCAST_PORT)).await {
                Ok(s)  => s,
                Err(_) => return,
            };
            let _ = recv_sock.join_multicast_v4(mcast_addr, std::net::Ipv4Addr::new(0, 0, 0, 0));

            let mut buf = [0u8; 512];
            loop {
                if *mcast_destroyed.lock().await { break; }
                match timeout(Duration::from_millis(500), recv_sock.recv_from(&mut buf)).await {
                    Ok(Ok((len, _))) => {
                        if len > 1 && buf[0] == F_LAN {
if let Ok(msg) = std::str::from_utf8(&buf[1..len]) {
                            let parts: Vec<&str> = msg.split(':').collect();
                            if parts.len() < 3 { continue; }
                            let peer_id    = parts[0];
                            let ip         = parts[1];
                            let port: u16  = parts[2].parse().unwrap_or(0);
                            let their_topic = parts.get(3).copied().unwrap_or("");

                            if peer_id == mcast_id { continue; }
                            if port == 0 { continue; }

                            if let Some(ref my_topic) = mcast_topic {
                                if !their_topic.is_empty() && their_topic != my_topic {
                                    continue;
                                }
                            }

                            let dest: SocketAddr = match format!("{}:{}", ip, port).parse() {
                                Ok(a) => a, Err(_) => continue,
                            };

                            let mut dg = mcast_dialing.lock().await;
                            if !dg.contains(peer_id) {
                                dg.insert(peer_id.to_string());
                                drop(dg);
                                let frame = create_hello_frame(&mcast_id_bytes, &mcast_keypair.public);
                                let _ = mcast_main_socket.send_to(&frame, dest).await;
                            }
                        }
                        }
                    }
                    _ => continue,
                }
            }
        });

        // =========================================================
        // FIX C5: Heartbeat — envia PING a cada HEARTBEAT_MS para cada peer
        // Sem isso, o lado JS desconecta por timeout (PEER_TIMEOUT = 60s)
        // Formato JS: [0x03][u64 ts BE][20-byte id]
        // =========================================================
        {
            let hb_socket    = self.socket.clone();
            let hb_peers     = self.peers.clone();
            let hb_id        = self.id.clone();
            let hb_destroyed = self.destroyed.clone();

            tokio::spawn(async move {
                let id_raw = hex::decode(&hb_id).unwrap_or_default();
                let mut ticker = interval(Duration::from_millis(HEARTBEAT_MS));
                loop {
                    ticker.tick().await;
                    if *hb_destroyed.lock().await { break; }

                    let ts = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;

                    let mut ping = Vec::with_capacity(1 + 8 + id_raw.len());
                    ping.push(F_PING);
                    ping.extend_from_slice(&ts.to_be_bytes());
                    ping.extend_from_slice(&id_raw);

                    let addrs: Vec<SocketAddr> = {
                        let pg = hb_peers.lock().await;
                        pg.values().map(|p| p.remote_addr).collect()
                    };
                    for addr in addrs {
                        let _ = hb_socket.send_to(&ping, addr).await;
                    }
                }
            });
        }

        // =========================================================
        // Peer timeout — remove peers inativos
        // =========================================================
        {
            let to_peers     = self.peers.clone();
            let to_addr2id   = self.addr_to_id.clone();
            let to_disc      = self.on_disconnection.clone();
            let to_destroyed = self.destroyed.clone();

            tokio::spawn(async move {
                let mut ticker = interval(Duration::from_secs(10));
                loop {
                    ticker.tick().await;
                    if *to_destroyed.lock().await { break; }

                    let timeout_ms = Duration::from_millis(PEER_TIMEOUT);
                    let dead: Vec<String> = {
                        let pg = to_peers.lock().await;
                        pg.iter()
                            .filter(|(_, p)| p.last_seen.elapsed() > timeout_ms)
                            .map(|(id, _)| id.clone())
                            .collect()
                    };
                    for pid in dead {
                        if let Some(mut p) = to_peers.lock().await.remove(&pid) {
                            p.destroy();
                            if let Some(ref cb) = to_disc { cb(&pid); }
                        }
                        // limpar addr_to_id
                        to_addr2id.lock().await.retain(|_, v| v != &pid);
                    }
                }
            });
        }

        // =========================================================
        // STUN — descobre IP externo e NAT type
        // =========================================================
        let stun_socket    = self.socket.clone();
        let stun_destroyed = self.destroyed.clone();

        tokio::spawn(async move {
            for (host, port) in STUN_HOSTS.iter().take(3) {
                if *stun_destroyed.lock().await { return; }
                if let Some(_ext) = stun_probe(&stun_socket, host, *port).await {
                    if let Some(ref cb) = on_nat_stun { cb(); }
                    break;
                }
                sleep(Duration::from_millis(500)).await;
            }
        });

        // =========================================================
        // HTTP Bootstrap
        // =========================================================
        self.query_http_bootstrap().await;

        // =========================================================
        // HTTP Piping Discovery (Bug #3 fix)
        // POST /announce e GET /lookup para cada servidor
        // =========================================================
        if let Some(ref topic_hash) = self.piping_topic_hash {
            let topic = topic_hash.clone();
            let id = self.id.clone();
            let id_bytes = self.id_bytes;
            let keypair = self.keypair.clone();
            let local_ip = self.local_ip.clone();
            let local_port = self.local_port;
            let socket = self.socket.clone();

            tokio::spawn(async move {
                // POST announce para cada servidor
                for server in PIPING_SERVERS {
                    let url = format!("https://{}/p2p-{}", server, topic);
                    let client = match reqwest::Client::builder()
                        .timeout(Duration::from_secs(8))
                        .build() {
                        Ok(c) => c, Err(_) => continue,
                    };
                    let body = serde_json::json!({
                        "id": id,
                        "ip": local_ip,
                        "port": local_port,
                    });
                    let _ = client.post(&url).json(&body).send().await;
                }

                // GET lookup (long poll loop) para cada servidor
                for server in PIPING_SERVERS {
                    let url = format!("https://{}/p2p-{}", server, topic);
                    let socket = socket.clone();
                    let id_bytes = id_bytes;
                    let keypair = keypair.clone();

                    tokio::spawn(async move {
                        let client = match reqwest::Client::builder()
                            .timeout(Duration::from_secs(30))
                            .build() {
                            Ok(c) => c, Err(_) => return,
                        };
                        loop {
                            match client.get(&url).send().await {
                                Ok(resp) => {
                                    match resp.json::<serde_json::Value>().await {
                                        Ok(peers) => {
                                            if let Some(arr) = peers.as_array() {
                                                for peer in arr.iter().take(10) {
                                                    if let (Some(ip), Some(port)) = (
                                                        peer.get("ip").and_then(|v| v.as_str()),
                                                        peer.get("port").and_then(|v| v.as_u64()),
                                                    ) {
                                                        let dest: SocketAddr = match format!("{}:{}", ip, port).parse() {
                                                            Ok(a) => a, Err(_) => continue,
                                                        };
                                                        let frame = create_hello_frame(&id_bytes, &keypair.public);
                                                        let _ = socket.send_to(&frame, dest).await;
                                                    }
                                                }
                                            }
                                        }
                                        Err(_) => { }
                                    }
                                }
                                Err(_) => { }
                            }
                            tokio::time::sleep(Duration::from_secs(5)).await;
                        }
                    });
                }
            });
        }
    }

    /// Dial a peer directly
    pub async fn dial(&self, ip: &str, port: u16) {
        let dest: SocketAddr = match format!("{}:{}", ip, port).parse() {
            Ok(a) => a, Err(_) => return,
        };
        let frame = create_hello_frame(&self.id_bytes, &self.keypair.public);
        let _ = self.socket.send_to(&frame, dest).await;
    }

    async fn query_http_bootstrap(&self) {
        let id         = self.id.clone();
        let id_bytes   = self.id_bytes;
        let keypair    = self.keypair.clone();
        let local_ip   = self.local_ip.clone();
        let local_port = self.local_port;
        let socket     = self.socket.clone();

        tokio::spawn(async move {
            let client = match reqwest::Client::builder().timeout(Duration::from_secs(10)).build() {
                Ok(c) => c, Err(_) => return,
            };

            for server in HARDCODED_HTTP_BOOTSTRAP.iter() {
                let body = serde_json::json!({ "id": id, "ip": local_ip, "port": local_port });
                let _ = client.post(format!("{}/announce", server)).json(&body).send().await;

                if let Ok(resp) = client.get(format!("{}/peers", server)).send().await {
                    if let Ok(list) = resp.json::<Vec<serde_json::Value>>().await {
                        for peer in list.iter().take(30) {
                            if let (Some(pip), Some(pport)) = (
                                peer.get("ip").and_then(|v| v.as_str()),
                                peer.get("port").and_then(|v| v.as_u64()),
                            ) {
                                let frame = create_hello_frame(&id_bytes, &keypair.public);
                                let _ = socket.send_to(&frame, format!("{}:{}", pip, pport)).await;
                            }
                        }
                    }
                }
            }
        });
    }
}

// ============================================================================
// STUN probe (RFC 5389)
// ============================================================================

async fn stun_probe(socket: &Arc<tokio::net::UdpSocket>, host: &str, port: u16) -> Option<SocketAddr> {
    use std::net::ToSocketAddrs;
    let stun_addr: SocketAddr = format!("{}:{}", host, port).to_socket_addrs().ok()?.next()?;

    let mut req = [0u8; 20];
    req[0] = 0x00; req[1] = 0x01;
    req[2] = 0x00; req[3] = 0x00;
    req[4] = 0x21; req[5] = 0x12; req[6] = 0xA4; req[7] = 0x42;

    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let txn = COUNTER.fetch_add(1, Ordering::Relaxed);
    for (i, byte) in txn.to_be_bytes().iter().enumerate() { req[8 + i] = *byte; }

    socket.send_to(&req, stun_addr).await.ok()?;

    let mut buf = [0u8; 512];
    match timeout(Duration::from_millis(STUN_FAST_TIMEOUT), socket.recv_from(&mut buf)).await {
        Ok(Ok((len, _))) if len >= 20 && buf[0] == 0x01 && buf[1] == 0x01 => {
            let mut off = 20usize;
            while off + 4 <= len {
                let attr_type = u16::from_be_bytes([buf[off], buf[off + 1]]);
                let attr_len  = u16::from_be_bytes([buf[off + 2], buf[off + 3]]) as usize;
                if attr_type == 0x0020 && attr_len >= 8 && off + 11 <= len {
                    let port = u16::from_be_bytes([buf[off + 5], buf[off + 6]]) ^ 0x2112;
                    let ip   = [buf[off+7]^0x21, buf[off+8]^0x12, buf[off+9]^0xA4, buf[off+10]^0x42];
                    return Some(SocketAddr::new(ip.into(), port));
                }
                off += 4 + attr_len;
                if attr_len % 4 != 0 { off += 4 - (attr_len % 4); }
            }
            None
        }
        _ => None,
    }
}

// ============================================================================
// Default + tests
// ============================================================================

impl Default for Swarm {
    fn default() -> Self {
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
        assert_eq!(swarm.id.len(), 40);
        assert_eq!(swarm.id_bytes.len(), 8);
    }

    #[tokio::test]
    async fn test_topic_hash() {
        let mut swarm = Swarm::new().await;
        swarm.join(b"test-topic", false, false);
        assert_eq!(swarm.topic_hash.unwrap().len(), 12);
    }

    #[tokio::test]
    async fn test_swarm_destroy() {
        let mut swarm = Swarm::new().await;
        swarm.destroy().await;
    }
}