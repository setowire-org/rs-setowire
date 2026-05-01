//! Swarm module - main P2P networking class

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tokio::time::{interval, timeout, sleep};

use crate::constants::*;
use crate::crypto::{create_hello_frame, create_hello_ack_frame, derive_session_flipped, encrypt, decrypt, generate_x25519, parse_handshake_frame};
use crate::dht_lib::SimpleDht;
use crate::framing::BatchSender;
use crate::peer::Peer;
use crate::structs::{BloomFilter, Lru};

// ============================================================================
// Types
// ============================================================================

pub type ConnectionCallback = Box<dyn Fn(&Peer) + Send + Sync>;
pub type DisconnectionCallback = Box<dyn Fn(&str) + Send + Sync>;
pub type DataCallback = Box<dyn Fn(&[u8], &Peer) + Send + Sync>;
pub type NatCallback = Box<dyn Fn() + Send + Sync>;

// ============================================================================
// Swarm
// ============================================================================

/// Main P2P swarm class
pub struct Swarm {
    pub socket: Arc<tokio::net::UdpSocket>,
    pub local_ip: String,
    pub local_port: u16,
    pub external: Option<SocketAddr>,
    pub nat_type: String,
    /// Full 40-char hex ID: SHA256(pubkey)[:20].to_hex()  — used for session key-flip logic
    pub id: String,
    /// First 8 bytes of SHA256(pubkey) — sent on the wire in HELLO/HELLO_ACK frames
    pub id_bytes: [u8; 8],
    pub keypair: crate::crypto::KeyPair,
    pub peers: Arc<Mutex<HashMap<String, Peer>>>,
    addr_to_id: Arc<Mutex<HashMap<String, String>>>,
    dialing: Arc<Mutex<HashSet<String>>>,
    pub max_peers: usize,
    pub is_relay: bool,
    pub topic_hash: Option<String>,
    bloom: Arc<Mutex<BloomFilter>>,
    store: Arc<Mutex<Lru<String, Vec<u8>>>>,
    /// Gossip deduplication cache with TTL (matches JS: this._gossipSeen = new LRU(GOSSIP_MAX, GOSSIP_TTL))
    gossip_seen: Arc<Mutex<Lru<String, ()>>>,
    dht: Option<SimpleDht>,
    batch: Arc<Mutex<BatchSender>>,
    destroyed: Arc<Mutex<bool>>,
    on_connection: Option<ConnectionCallback>,
    on_disconnection: Option<DisconnectionCallback>,
    on_data: Option<DataCallback>,
    on_nat: Option<NatCallback>,
    running: Arc<Mutex<bool>>,
}

impl Swarm {
    pub async fn new() -> Self {
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
            .await
            .expect("Failed to bind UDP socket");

        let local_addr = socket.local_addr().expect("Failed to get local addr");
        let local_ip = local_addr.ip().to_string();
        let local_port = local_addr.port();

        let keypair = generate_x25519(None);

        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(&keypair.public);
        let hash = hasher.finalize();
        // 40-char hex string — matches JS: SHA256(pubKey).slice(0,20).toString('hex')
        let id = hex::encode(&hash[..20]);
        // 8-byte wire ID — first 8 bytes of the same hash, copied into HELLO frames
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
            topic_hash: None,
            bloom: Arc::new(Mutex::new(BloomFilter::new(None, None))),
            store: Arc::new(Mutex::new(Lru::new(SYNC_CACHE_MAX, None))),
            gossip_seen: Arc::new(Mutex::new(Lru::new(GOSSIP_MAX, Some(GOSSIP_TTL)))),
            dht: None,
            batch: Arc::new(Mutex::new(BatchSender::new())),
            destroyed: Arc::new(Mutex::new(false)),
            on_connection: None,
            on_disconnection: None,
            on_data: None,
            on_nat: None,
            running: Arc::new(Mutex::new(false)),
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn nat_type(&self) -> &str {
        &self.nat_type
    }

    pub fn public_addr(&self) -> Option<String> {
        self.external.map(|a| a.to_string())
    }

    pub fn peer_count(&self) -> usize {
        self.peers.try_lock().map(|g| g.len()).unwrap_or(0)
    }

    /// Join a topic. Mirrors JS exactly:
    ///   topicHex = Buffer.isBuffer(topic) ? topic.toString('hex') : String(topic)
    ///   topicHash = sha1(topicHex).slice(0, 12)   // 12 hex chars = 6 bytes
    pub fn join(&mut self, topic: &[u8], _announce: bool, _lookup: bool) {
        use sha1::Sha1;
        use digest::Digest;

        // FIX div-1: JS converts the raw topic bytes to a hex string BEFORE hashing.
        // Using from_utf8() here was wrong — it broke for any binary topic (the common case).
        let topic_hex = hex::encode(topic);

        let mut hasher = Sha1::new();
        hasher.update(topic_hex.as_bytes());
        let result = hasher.finalize();
        // 6 bytes → 12 hex chars, same as JS .slice(0, 12) on the hex digest
        self.topic_hash = Some(hex::encode(&result[..6]));
    }

    pub fn broadcast(&self, data: &[u8]) -> usize {
        println!("[*] broadcast: {} bytes", data.len());
        0
    }

    pub fn on_connection(&mut self, cb: ConnectionCallback) {
        self.on_connection = Some(cb);
    }

    pub fn on_disconnection(&mut self, cb: DisconnectionCallback) {
        self.on_disconnection = Some(cb);
    }

    pub fn on_data(&mut self, cb: DataCallback) {
        self.on_data = Some(cb);
    }

    pub fn on_nat(&mut self, cb: NatCallback) {
        self.on_nat = Some(cb);
    }

    pub async fn destroy(&mut self) {
        *self.destroyed.lock().await = true;
        *self.running.lock().await = false;
        let mut peers = self.peers.lock().await;
        for (_, peer) in peers.drain() {
            drop(peer);
        }
    }

    pub async fn send_to(&self, peer_id: &str, data: &[u8]) -> bool {
        let mut peers_guard = self.peers.lock().await;
        if let Some(peer) = peers_guard.get_mut(peer_id) {
            // Get seq first (before session borrow)
            let seq = peer.next_send_seq();
            if let Some(ref mut session) = peer.session {
                // Bug B fix: use peer.send_seq for payload prefix (separate from session.send_ctr used in nonce)
                // JS: peer._sendSeq goes in payload, sess.sendCtr goes in ChaCha20 nonce
                let mut seq_buf = vec![0u8; 4 + data.len()];
                seq_buf[0..4].copy_from_slice(&seq.to_be_bytes());
                seq_buf[4..].copy_from_slice(data);

                let encrypted = encrypt(session, &seq_buf);
                let addr = peer.remote_addr;
                drop(peers_guard);

                let mut frame = vec![0x01u8]; // F_DATA
                frame.extend_from_slice(&encrypted);
                return self.socket.send_to(&frame, addr).await.is_ok();
            }
        }
        false
    }

    pub fn store(&self, _key: &str, _value: &[u8]) {}

    pub async fn fetch(&self, _key: &str) -> Option<Vec<u8>> {
        None
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.socket.local_addr().unwrap()
    }

    pub fn socket_ref(&self) -> &tokio::net::UdpSocket {
        &self.socket
    }

    /// Start the swarm — binds receive loop, LAN multicast, STUN, HTTP bootstrap.
    pub async fn start(&mut self) {
        *self.running.lock().await = true;

        let socket      = self.socket.clone();
        let peers       = self.peers.clone();
        let addr_to_id  = self.addr_to_id.clone();
        let dialing     = self.dialing.clone();
        let destroyed   = self.destroyed.clone();

        let on_connection    = self.on_connection.take();
        let on_data          = self.on_data.take();
        let on_disconnection = self.on_disconnection.take();
        let keypair          = self.keypair.clone();
        let id               = self.id.clone();
        let id_bytes         = self.id_bytes;
        let local_ip         = self.local_ip.clone();
        let local_port       = self.local_port;
        let topic_hash       = self.topic_hash.clone();
        let on_nat           = self.on_nat.take();

        // =========================================================
        // Receive loop — runs on the MAIN socket (random port)
        // All HELLOs, DATA, PING/PONG go through here so that
        // addr_to_id mappings are always resolved on the same socket
        // the remote peer will reply to.
        // =========================================================
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                if *destroyed.lock().await { break; }

                match timeout(Duration::from_millis(500), socket.recv_from(&mut buf)).await {
                    Ok(Ok((len, src))) => {
                        if len < 1 { continue; }

                        // Ignore our own reflections (can happen on loopback)
                        if src.ip().to_string() == local_ip && src.port() == local_port {
                            continue;
                        }

                        match buf[0] {
                            // --------------------------------------------------
                            // HELLO (0xA1): [type(1)][id_bytes(8)][pub_key(32)]
                            // --------------------------------------------------
                            0xA1 => {
                                if len < 41 { continue; }

                                // FIX div-2: self-check compares 8 wire bytes directly,
                                // not a re-derived string of a different length.
                                if &buf[1..9] == &id_bytes { continue; }

                                if let Some((_, their_pub)) = parse_handshake_frame(&buf[..len]) {
                                    // Wire ID is the 8 bytes sent in the frame — this is the
                                    // peer's key in our maps, matching what the JS side uses.
                                    let their_wire_id = hex::encode(&buf[1..9]); // 16-char hex

                                    // Key-flip logic mirrors JS exactly:
                                    //   JS: iAmLo = this._id < pid
                                    //   this._id = 40-char hex (our full ID)
                                    //   pid      = buf.slice(1,9).toString('hex') = 16-char hex
                                    // Same string comparison, same result.
                                    let session = derive_session_flipped(
                                        &keypair.private,
                                        their_pub,
                                        &id,            // our 40-char hex
                                        &their_wire_id, // their 16-char hex
                                    );

                                    // Reply with HELLO_ACK before touching the peer map
                                    let ack = create_hello_ack_frame(&id_bytes, &keypair.public);
                                    let _ = socket.send_to(&ack, src).await;

                                    let mut pg = peers.lock().await;
                                    if pg.len() >= MAX_PEERS { continue; }

                                    if let Some(existing) = pg.get_mut(&their_wire_id) {
                                        existing.their_pub = Some(*their_pub);
                                        existing.session   = Some(session);
                                    } else {
                                        let mut p = Peer::new(their_wire_id.clone(), src);
                                        p.their_pub = Some(*their_pub);
                                        p.session   = Some(session);
                                        if let Some(ref cb) = on_connection { cb(&p); }
                                        pg.insert(their_wire_id.clone(), p);
                                    }
                                    drop(pg);
                                    addr_to_id.lock().await.insert(src.to_string(), their_wire_id);
                                }
                            }

                            // --------------------------------------------------
                            // HELLO_ACK (0xA2): same layout as HELLO
                            // --------------------------------------------------
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

                                    if let Some(existing) = pg.get_mut(&their_wire_id) {
                                        existing.their_pub = Some(*their_pub);
                                        existing.session   = Some(session);
                                    } else {
                                        let mut p = Peer::new(their_wire_id.clone(), src);
                                        p.their_pub = Some(*their_pub);
                                        p.session   = Some(session);
                                        if let Some(ref cb) = on_connection { cb(&p); }
                                        pg.insert(their_wire_id.clone(), p);
                                    }
                                    drop(pg);
                                    addr_to_id.lock().await.insert(src.to_string(), their_wire_id);
                                }
                            }

                            // --------------------------------------------------
                            // LAN multicast announcement received on main socket.
                            // The multicast recv socket forwards these to here by
                            // re-sending them on 127.0.0.1:<local_port> so the
                            // receive loop handles everything in one place.
                            // --------------------------------------------------
                            b if b == F_LAN => {
                                if len > 1 {
                                    if let Ok(msg) = std::str::from_utf8(&buf[1..len]) {
                                        let parts: Vec<&str> = msg.split(':').collect();
                                        if parts.len() >= 3 {
                                            let peer_id    = parts[0];
                                            let ip         = parts[1];
                                            let port: u16  = parts[2].parse().unwrap_or(0);
                                            let their_topic = parts.get(3).copied().unwrap_or("");

                                            if peer_id == id { continue; }

                                            // Topic filter
                                            if let Some(ref my_topic) = topic_hash {
                                                if !their_topic.is_empty() && their_topic != my_topic {
                                                    continue;
                                                }
                                            }

                                            if port == 0 { continue; }
                                            let dial_dest: SocketAddr =
                                                match format!("{}:{}", ip, port).parse() {
                                                    Ok(a) => a,
                                                    Err(_) => continue,
                                                };

                                            let mut dial_guard = dialing.lock().await;
                                            if !dial_guard.contains(peer_id) {
                                                dial_guard.insert(peer_id.to_string());
                                                drop(dial_guard);
                                                // HELLO originates from the main socket so the
                                                // remote peer replies to the right port.
                                                let frame = create_hello_frame(&id_bytes, &keypair.public);
                                                let _ = socket.send_to(&frame, dial_dest).await;
                                            }
                                        }
                                    }
                                }
                            }

                            // --------------------------------------------------
                            // DATA (0x01): [type(1)][nonce(12)][ciphertext][tag(16)]
                            // --------------------------------------------------
                            0x01 => {
                                let src_str = src.to_string();
                                if let Some(pid) = addr_to_id.lock().await.get(&src_str).cloned() {
                                    let mut pg = peers.lock().await;
                                    if let Some(peer) = pg.get_mut(&pid) {
                                        if let Some(ref mut session) = peer.session {
                                            let data = &buf[1..len];
                                            if let Some(plain) = decrypt(session, data) {
                                                // Bug A fix: strip first 4 bytes (seq) before passing to app
                                                // Matches JS: peer._jitter.push(seq, data) where data = plain.slice(4)
                                                let payload = if plain.len() >= 4 {
                                                    &plain[4..]
                                                } else {
                                                    &plain
                                                };
                                                if let Some(ref cb) = on_data {
                                                    cb(payload, peer);
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            // --------------------------------------------------
                            // PING (0x03): JS sends [F_PING][timestamp_u64be][id_20bytes]
                            // JS expects PONG: [F_PONG][our_id_20bytes]
                            // FIX div-3: we must reply with our full 20-byte ID,
                            // NOT echo the PING payload (which has a different layout).
                            // --------------------------------------------------
                            0x03 => {
                                // Decode our own 40-char hex id back to 20 raw bytes
                                let id_raw = hex::decode(&id).unwrap_or_default();
                                let mut pong = Vec::with_capacity(1 + id_raw.len());
                                pong.push(F_PONG);
                                pong.extend_from_slice(&id_raw);
                                let _ = socket.send_to(&pong, src).await;

                                // Update peer last-seen via addr_to_id lookup
                                let src_str = src.to_string();
                                if let Some(pid) = addr_to_id.lock().await.get(&src_str).cloned() {
                                    if let Some(peer) = peers.lock().await.get_mut(&pid) {
                                        peer.touch(src, None);
                                    }
                                }
                            }

                            // --------------------------------------------------
                            // PONG (0x04): [F_PONG][sender_id_20bytes]
                            // Use the embedded ID to find the peer even if the
                            // reply came from a different port (NAT rebinding).
                            // --------------------------------------------------
                            0x04 => {
                                let src_str = src.to_string();
                                // Try addr first, then fall back to the embedded ID
                                let pid_opt = {
                                    let a2i = addr_to_id.lock().await;
                                    a2i.get(&src_str).cloned()
                                };
                                let pid_opt = if pid_opt.is_some() {
                                    pid_opt
                                } else if len >= 9 {
                                    // 8 bytes of wire ID embedded in PONG from byte 1
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

                            // --------------------------------------------------
                            // GOAWAY (0x0A)
                            // --------------------------------------------------
                            0x0A => {
                                let src_str = src.to_string();
                                if let Some(pid) = addr_to_id.lock().await.remove(&src_str) {
                                    if let Some(mut peer) = peers.lock().await.remove(&pid) {
                                        peer.destroy();
                                        if let Some(ref cb) = on_disconnection { cb(&pid); }
                                    }
                                }
                            }

                            _ => {}
                        }
                    }
                    Ok(Err(_)) => break,
                    Err(_)     => continue, // timeout — loop again
                }
            }
        });

        // =========================================================
        // LAN Multicast
        //
        // FIX div-4: the multicast recv socket is SEPARATE from the
        // main socket. When a LAN announcement arrives, we parse it
        // and send the HELLO through the MAIN socket. This ensures
        // the remote peer replies to our main (random) port, not to
        // the fixed 45678 port that the receive loop never reads.
        //
        // Periodic announcements also go out through the main socket
        // so our local port is consistent in every frame we send.
        // =========================================================

        // --- periodic LAN announcements via main socket ---
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

        // --- multicast receive socket: receive only, forward HELLOs via main socket ---
        let mcast_main_socket = self.socket.clone();
        let mcast_id_bytes    = self.id_bytes;
        let mcast_keypair     = self.keypair.clone();
        let mcast_id          = self.id.clone();
        let mcast_topic       = self.topic_hash.clone();
        let mcast_dialing     = self.dialing.clone();
        let mcast_destroyed   = self.destroyed.clone();

        tokio::spawn(async move {
            let mcast_addr = std::net::Ipv4Addr::new(239, 0, 0, 1);

            let recv_sock = match tokio::net::UdpSocket::bind(
                format!("0.0.0.0:{}", MCAST_PORT)
            ).await {
                Ok(s)  => s,
                Err(_) => return, // port already taken, skip gracefully
            };

            let _ = recv_sock.join_multicast_v4(
                mcast_addr,
                std::net::Ipv4Addr::new(0, 0, 0, 0),
            );

            let mut buf = [0u8; 512];
            loop {
                if *mcast_destroyed.lock().await { break; }

                match timeout(
                    Duration::from_millis(500),
                    recv_sock.recv_from(&mut buf),
                ).await {
                    Ok(Ok((len, _src))) if len > 1 && buf[0] == F_LAN => {
                        if let Ok(msg) = std::str::from_utf8(&buf[1..len]) {
                            let parts: Vec<&str> = msg.split(':').collect();
                            if parts.len() < 3 { continue; }

                            let peer_id    = parts[0];
                            let ip         = parts[1];
                            let port: u16  = parts[2].parse().unwrap_or(0);
                            let their_topic = parts.get(3).copied().unwrap_or("");

                            if peer_id == mcast_id || port == 0 { continue; }

                            // Topic filter
                            if let Some(ref my_topic) = mcast_topic {
                                if !their_topic.is_empty() && their_topic != my_topic {
                                    continue;
                                }
                            }

                            let dest: SocketAddr = match format!("{}:{}", ip, port).parse() {
                                Ok(a)  => a,
                                Err(_) => continue,
                            };

                            // Send HELLO via MAIN socket — replies come back to the
                            // main receive loop, not to this dedicated recv socket.
                            let mut dial_guard = mcast_dialing.lock().await;
                            if !dial_guard.contains(peer_id) {
                                dial_guard.insert(peer_id.to_string());
                                drop(dial_guard);
                                let frame = create_hello_frame(&mcast_id_bytes, &mcast_keypair.public);
                                let _ = mcast_main_socket.send_to(&frame, dest).await;
                            }
                        }
                    }
                    _ => continue,
                }
            }
        });

        // =========================================================
        // STUN — discover external IP:port
        // =========================================================
        let stun_socket    = self.socket.clone();
        let stun_destroyed = self.destroyed.clone();

        tokio::spawn(async move {
            for (host, port) in STUN_HOSTS.iter().take(3) {
                if *stun_destroyed.lock().await { return; }
                if let Some(_ext) = stun_probe(&stun_socket, host, *port).await {
                    if let Some(ref cb) = on_nat { cb(); }
                    break;
                }
                sleep(Duration::from_millis(500)).await;
            }
        });

        // =========================================================
        // HTTP Bootstrap (reqwest, TLS)
        // =========================================================
        self.query_http_bootstrap().await;
    }

    /// Dial a peer directly by sending a HELLO from the main socket.
    pub async fn dial(&self, ip: &str, port: u16) {
        let dest: SocketAddr = match format!("{}:{}", ip, port).parse() {
            Ok(a)  => a,
            Err(_) => return,
        };
        let frame = create_hello_frame(&self.id_bytes, &self.keypair.public);
        let _ = self.socket.send_to(&frame, dest).await;
    }

    /// POST /announce and GET /peers on each HTTP bootstrap server.
    async fn query_http_bootstrap(&self) {
        let id         = self.id.clone();
        let id_bytes   = self.id_bytes;
        let keypair    = self.keypair.clone();
        let local_ip   = self.local_ip.clone();
        let local_port = self.local_port;
        let socket     = self.socket.clone();

        tokio::spawn(async move {
            let client = match reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
            {
                Ok(c)  => c,
                Err(_) => return,
            };

            for server in HARDCODED_HTTP_BOOTSTRAP.iter() {
                let body = serde_json::json!({
                    "id":   id,
                    "ip":   local_ip,
                    "port": local_port,
                });

                let _ = client
                    .post(format!("{}/announce", server))
                    .json(&body)
                    .send()
                    .await;

                if let Ok(resp) = client.get(format!("{}/peers", server)).send().await {
                    if let Ok(list) = resp.json::<Vec<serde_json::Value>>().await {
                        for peer in list.iter().take(30) {
                            if let (Some(pip), Some(pport)) = (
                                peer.get("ip").and_then(|v| v.as_str()),
                                peer.get("port").and_then(|v| v.as_u64()),
                            ) {
                                let frame = create_hello_frame(&id_bytes, &keypair.public);
                                let _ = socket
                                    .send_to(&frame, format!("{}:{}", pip, pport))
                                    .await;
                            }
                        }
                    }
                }
            }
        });
    }
}

// ============================================================================
// STUN probe
// ============================================================================

async fn stun_probe(
    socket: &Arc<tokio::net::UdpSocket>,
    host: &str,
    port: u16,
) -> Option<SocketAddr> {
    use std::net::ToSocketAddrs;

    let stun_addr: SocketAddr = format!("{}:{}", host, port)
        .to_socket_addrs()
        .ok()?
        .next()?;

    // RFC 5389 Binding Request — 20 bytes, no attributes
    let mut req = [0u8; 20];
    req[0] = 0x00; req[1] = 0x01; // type = Binding Request
    req[2] = 0x00; req[3] = 0x00; // length = 0
    req[4] = 0x21; req[5] = 0x12; req[6] = 0xA4; req[7] = 0x42; // magic cookie

    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let txn = COUNTER.fetch_add(1, Ordering::Relaxed);
    for (i, byte) in txn.to_be_bytes().iter().enumerate() {
        req[8 + i] = *byte;
    }

    socket.send_to(&req, stun_addr).await.ok()?;

    let mut buf = [0u8; 512];
    match timeout(Duration::from_millis(1500), socket.recv_from(&mut buf)).await {
        Ok(Ok((len, _))) if len >= 20 && buf[0] == 0x01 && buf[1] == 0x01 => {
            let mut off = 20usize;
            while off + 4 <= len {
                let attr_type = u16::from_be_bytes([buf[off], buf[off + 1]]);
                let attr_len  = u16::from_be_bytes([buf[off + 2], buf[off + 3]]) as usize;

                if attr_type == 0x0020 && attr_len >= 8 && off + 11 <= len {
                    let port = u16::from_be_bytes([buf[off + 5], buf[off + 6]]) ^ 0x2112;
                    let ip   = [
                        buf[off + 7]  ^ 0x21,
                        buf[off + 8]  ^ 0x12,
                        buf[off + 9]  ^ 0xA4,
                        buf[off + 10] ^ 0x42,
                    ];
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
    async fn test_topic_hash_matches_js() {
        // JS: sha1(hex::encode(topic)).slice(0,12)
        // Verify with a known topic bytes sequence
        let mut swarm = Swarm::new().await;
        swarm.join(b"test-topic", false, false);
        let hash = swarm.topic_hash.unwrap();
        assert_eq!(hash.len(), 12, "topic_hash must be 12 hex chars (6 bytes)");
    }

    #[tokio::test]
    async fn test_swarm_destroy() {
        let mut swarm = Swarm::new().await;
        swarm.destroy().await;
    }
}