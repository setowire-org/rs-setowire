//! Peer module - per-peer state management
//!
//! Handles:
//! - Session encryption state
//! - Send/receive queues
//! - Congestion control
//! - RTT measurement
//! - Fragmentation

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::constants::{
    CWND_DECAY, CWND_INIT, CWND_MAX, F_DATA, F_FRAG, MAX_ADDRS_PEER, QUEUE_CTRL, QUEUE_DATA,
    RATE_BURST, RATE_PER_SEC, RTT_INIT,
};
use crate::crypto::{decrypt, encrypt, Session};
use crate::framing::FragmentAssembler;
use crate::structs::RingBuffer;



// ============================================================================
// Peer
// ============================================================================

/// Peer connection state
pub struct Peer {
    /// Peer ID (20 bytes hex string)
    pub id: String,
    /// Current remote address
    pub remote_addr: SocketAddr,
    /// Alternative addresses with RTT
    pub addrs: HashMap<SocketAddr, f64>,
    /// Best address (lowest RTT)
    best_addr: SocketAddr,
    /// Last activity time
    pub last_seen: Instant,
    /// Whether connection is open
    pub open: bool,
    /// Whether peer is in mesh
    pub in_mesh: bool,
    /// Time when peer joined mesh
    mesh_time: Instant,
    /// Peer score for mesh selection
    pub score: i32,
    /// Round-trip time estimate
    pub rtt: f64,
    /// Estimated bandwidth (bytes/sec)
    pub bandwidth: f64,
    /// Session encryption state (public for swarm access)
    pub session: Option<Session>,
    /// Their public key (public for swarm access)
    pub their_pub: Option<[u8; 32]>,
    /// Control queue
    ctrl_queue: RingBuffer<Vec<u8>>,
    /// Data queue
    data_queue: RingBuffer<Vec<u8>>,
    /// Whether currently draining
    draining: bool,
    /// Fragment assembler
    fragger: FragmentAssembler,
    /// Jitter buffer for incoming data
    jitter: JitterBufferCallback,
    /// Congestion window
    cwnd: usize,
    /// In-flight packets
    inflight: usize,
    /// Last loss event time
    last_loss: Instant,
    /// Rate limiter tokens
    tokens: f64,
    /// Last rate update time
    last_rate: Instant,
    /// Last ping send time
    last_ping_sent: u64,
    /// Last pong received time
    last_pong: Instant,
    /// Bytes sent in window
    bytes_sent: usize,
    /// Bytes window start
    bytes_window: Instant,
    /// Loss signaled flag
    loss_signaled: bool,
    /// Swarm reference
    swarm: Option<std::sync::Arc<tokio::sync::Mutex<()>>>,
    /// Send sequence number
    send_seq: u32,
}

type JitterBufferCallback = Box<dyn Fn(Vec<u8>) + Send + Sync>;

impl Peer {
    /// Create a new peer
    pub fn new(id: String, addr: SocketAddr) -> Self {
        let mut addrs = HashMap::new();
        addrs.insert(addr, RTT_INIT);

        Peer {
            id,
            remote_addr: addr,
            addrs,
            best_addr: addr,
            last_seen: Instant::now(),
            open: true,
            in_mesh: false,
            mesh_time: Instant::now(),
            score: 0,
            rtt: RTT_INIT,
            bandwidth: 0.0,
            session: None,
            their_pub: None,
            ctrl_queue: RingBuffer::new(QUEUE_CTRL),
            data_queue: RingBuffer::new(QUEUE_DATA),
            draining: false,
            fragger: FragmentAssembler::new(),
            jitter: Box::new(|_| {}),
            cwnd: CWND_INIT,
            inflight: 0,
            last_loss: Instant::now(),
            tokens: RATE_BURST as f64,
            last_rate: Instant::now(),
            last_ping_sent: 0,
            last_pong: Instant::now(),
            bytes_sent: 0,
            bytes_window: Instant::now(),
            loss_signaled: false,
            swarm: None,
            send_seq: 0,
        }
    }

    /// Set jitter buffer callback
    pub fn set_jitter_callback(&mut self, cb: impl Fn(Vec<u8>) + Send + Sync + 'static) {
        self.jitter = Box::new(cb);
    }

    /// Set swarm reference
    pub fn set_swarm(&mut self, swarm: std::sync::Arc<tokio::sync::Mutex<()>>) {
        self.swarm = Some(swarm);
    }

    /// Get current send sequence number
    pub fn send_seq(&self) -> u32 {
        self.send_seq
    }

    /// Increment and return next send sequence number
    pub fn next_send_seq(&mut self) -> u32 {
        let seq = self.send_seq;
        self.send_seq = self.send_seq.wrapping_add(1);
        seq
    }

    /// Write control data (unencrypted)
    pub fn write_ctrl(&mut self, data: Vec<u8>) -> bool {
        if !self.open {
            return false;
        }
        self.ctrl_queue.push(data);
        true
    }

    /// Write application data (encrypted)
    pub fn write(&mut self, data: Vec<u8>) -> bool {
        if !self.open || self.session.is_none() {
            return false;
        }
        self.data_queue.push(data);
        true
    }

    /// Enqueue data for flooding
    pub fn enqueue(&mut self, data: Vec<u8>) {
        let _ = self.write(data);
    }

    /// Drain send queues
    pub fn drain(&mut self) {
        self.draining = true;

        // Drain control queue first
        while let Some(raw) = self.ctrl_queue.shift() {
            self.send_raw(raw);
        }

        // Drain data queue respecting congestion window
        while !self.data_queue.is_empty() && self.inflight < self.cwnd {
            if let Some(raw) = self.data_queue.shift() {
                self.send_encrypted(raw);
            } else {
                break;
            }
        }

        self.draining = false;
    }

    /// Send raw packet
    fn send_raw(&self, _data: Vec<u8>) {
        // In real implementation, this would send via the socket
        // For now, just track the send
    }

    /// Send encrypted packet
    fn send_encrypted(&mut self, plaintext: Vec<u8>) {
        let session = match &mut self.session {
            Some(s) => s,
            None => return,
        };

        // Rate limiting
        let now = Instant::now();
        let delta = now.duration_since(self.last_rate).as_secs_f64();
        self.tokens = (RATE_BURST as f64).min(self.tokens + delta * RATE_PER_SEC as f64);
        self.last_rate = now;

        if self.tokens < 1.0 {
            return;
        }
        self.tokens -= 1.0;

        // Fragment if needed
        if plaintext.len() > 1200 {
            self.send_fragmented(plaintext);
            return;
        }

        // Build frame
        let mut seq_buf = Vec::with_capacity(4 + plaintext.len());
        seq_buf.extend_from_slice(&self.send_seq.to_be_bytes());
        seq_buf.extend_from_slice(&plaintext);
        self.send_seq += 1;

        let ct = encrypt(session, &seq_buf);
        self.inflight += 1;

        let frame_len = ct.len() + 1;
        let mut frame = vec![F_DATA];
        frame.extend(ct);

        self.bytes_sent += frame_len;
        self.send_raw(frame);

        // Track bandwidth
        let now = Instant::now();
        let elapsed = now.duration_since(self.bytes_window).as_secs_f64();
        if elapsed >= 1.0 {
            self.bandwidth = self.bytes_sent as f64 / elapsed;
            self.bytes_sent = 0;
            self.bytes_window = now;
        }
    }

    /// Send fragmented data
    fn send_fragmented(&mut self, _data: Vec<u8>) {
        // Fragmentation handled by framing module
    }

    /// Handle acknowledgment
    pub fn on_ack(&mut self) {
        if self.inflight > 0 {
            self.inflight -= 1;
        }
        if self.cwnd < CWND_MAX {
            self.cwnd = (CWND_MAX as f64).min(self.cwnd as f64 + 1.0) as usize;
        }
    }

    /// Handle packet loss
    pub fn on_loss(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_loss) < Duration::from_secs(1) {
            return;
        }
        self.last_loss = now;
        self.cwnd = ((CWND_DECAY * self.cwnd as f64).max(1.0)) as usize;
        self.inflight = self.cwnd.min(self.inflight);
    }

    /// Update peer address and RTT
    pub fn touch(&mut self, addr: SocketAddr, rtt: Option<f64>) {
        self.last_seen = Instant::now();
        self.last_pong = Instant::now();
        self.loss_signaled = false;

        if let Some(r) = rtt {
            self.addrs.insert(addr, r);

            // Limit addresses
            if self.addrs.len() > MAX_ADDRS_PEER {
                let worst = self
                    .addrs
                    .iter()
                    .max_by(|a, b| a.1.partial_cmp(b.1).unwrap())
                    .map(|(k, _)| *k);
                if let Some(w) = worst {
                    self.addrs.remove(&w);
                }
            }

            // Find best address
            let best = self
                .addrs
                .iter()
                .min_by(|a, b| a.1.partial_cmp(b.1).unwrap())
                .map(|(k, _)| *k);
            if let Some(b) = best {
                self.best_addr = b;
                self.remote_addr = b;
            }
        }
    }

    /// Add an address
    fn _add_addr(&mut self, addr: SocketAddr, rtt: f64) {
        self.addrs.insert(addr, rtt);
    }

    /// Increase score
    pub fn score_up(&mut self, n: i32) {
        self.score = (1000).min(self.score + n);
    }

    /// Decrease score
    pub fn score_down(&mut self, n: i32) {
        self.score = (-1000).max(self.score - n);
    }

    /// Handle incoming data
    pub fn on_data(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        let session = self.session.as_ref()?;

        if data.is_empty() {
            return None;
        }

        // Check for control messages (no encryption)
        if data[0] != F_DATA && data[0] != F_FRAG {
            return Some(data.to_vec());
        }

        // Decrypt
        let plaintext = decrypt(session, data)?;

        // Handle jitter buffer
        if plaintext.len() >= 4 {
            let payload = plaintext[4..].to_vec();
            (self.jitter)(payload);
            None
        } else {
            Some(plaintext)
        }
    }

    /// Handle fragment
    pub fn on_frag(&mut self, frag_id: &[u8], idx: u16, total: u16, data: Vec<u8>) -> Option<Vec<u8>> {
        self.fragger.add(frag_id, idx, total, data)
    }

    /// Set session keys
    pub fn set_session(&mut self, session: Session) {
        self.session = Some(session);
    }

    /// Check if session is active
    pub fn has_session(&self) -> bool {
        self.session.is_some()
    }

    /// Get best address
    pub fn best_addr(&self) -> SocketAddr {
        self.best_addr
    }

    /// Destroy peer connection
    pub fn destroy(&mut self) {
        self.open = false;
        self.fragger.clear();
        self.ctrl_queue.clear();
        self.data_queue.clear();
    }
}

// ============================================================================
// PeerInfo
// ============================================================================

/// Peer connection information
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Peer ID
    pub id: String,
    /// Remote address
    pub address: String,
    /// Port
    pub port: u16,
    /// NAT type
    pub nat: String,
    /// RTT estimate
    pub rtt: f64,
}

impl Peer {
    /// Get peer info
    pub fn info(&self) -> PeerInfo {
        PeerInfo {
            id: self.id.clone(),
            address: self.remote_addr.ip().to_string(),
            port: self.remote_addr.port(),
            nat: "unknown".to_string(),
            rtt: self.rtt,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_creation() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let peer = Peer::new("abcd1234".to_string(), addr);
        assert_eq!(peer.id, "abcd1234");
        assert!(peer.open);
    }

    #[test]
    fn test_score() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let mut peer = Peer::new("test".to_string(), addr);
        peer.score_up(10);
        assert_eq!(peer.score, 10);
        peer.score_down(20);
        assert_eq!(peer.score, -10);
    }
}