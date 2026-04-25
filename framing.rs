//! Framing module - packet fragmentation, jitter buffer, batch UDP sender

use std::collections::HashMap;
use std::time::{Duration, Instant};

use rand::Rng;

use crate::constants::{
    BATCH_INTERVAL, FRAG_DATA_MAX, FRAG_HDR, FRAG_TIMEOUT, F_BATCH,
};

// ============================================================================
// FragmentAssembler
// ============================================================================

/// Fragment entry pending assembly
struct FragEntry {
    total: u16,
    pieces: HashMap<u16, Vec<u8>>,
    timer: Instant,
}

/// Assembles fragmented messages
pub struct FragmentAssembler {
    pending: HashMap<String, FragEntry>,
}

impl FragmentAssembler {
    /// Create a new FragmentAssembler
    pub fn new() -> Self {
        FragmentAssembler {
            pending: HashMap::new(),
        }
    }

    /// Add a fragment and try to assemble
    /// Returns assembled data if complete
    pub fn add(&mut self, frag_id: &[u8], frag_idx: u16, frag_total: u16, data: Vec<u8>) -> Option<Vec<u8>> {
        let key = hex::encode(frag_id);

        let entry = self.pending.entry(key.clone()).or_insert_with(|| {
            let timeout = Instant::now() + Duration::from_millis(FRAG_TIMEOUT);
            FragEntry {
                total: frag_total,
                pieces: HashMap::new(),
                timer: timeout,
            }
        });

        entry.pieces.insert(frag_idx, data);

        // Check if complete
        if entry.pieces.len() == entry.total as usize {
            let mut parts: Vec<Vec<u8>> = (0..entry.total)
                .filter_map(|i| entry.pieces.remove(&i))
                .collect();

            let total_len: usize = parts.iter().map(|p| p.len()).sum();
            let mut result = Vec::with_capacity(total_len);
            for part in parts.drain(..) {
                result.extend(part);
            }

            self.pending.remove(&key);
            Some(result)
        } else {
            None
        }
    }

    /// Clear all pending fragments
    pub fn clear(&mut self) {
        self.pending.clear();
    }
}

impl Default for FragmentAssembler {
    fn default() -> Self {
        Self::new()
    }
}

/// Fragment a payload that exceeds MAX_PAYLOAD
pub fn fragment_payload(payload: &[u8]) -> Option<(Vec<u8>, u16, usize)> {
    if payload.len() <= FRAG_DATA_MAX {
        return None;
    }

    let mut frag_id = [0u8; 8];
    rand::thread_rng().fill(&mut frag_id);

    let total = ((payload.len() + FRAG_DATA_MAX - 1) / FRAG_DATA_MAX) as u16;
    let mut fragments = Vec::with_capacity(total as usize);

    for i in 0..total {
        let start = (i as usize) * FRAG_DATA_MAX;
        let end = std::cmp::min(start + FRAG_DATA_MAX, payload.len());
        let chunk = &payload[start..end];

        let mut hdr = vec![0u8; FRAG_HDR];
        hdr[..8].copy_from_slice(&frag_id);
        hdr[8..10].copy_from_slice(&(i.to_be_bytes()));
        hdr[10..12].copy_from_slice(&(total.to_be_bytes()));
        hdr.extend_from_slice(chunk);

        fragments.push(hdr);
    }

    Some((frag_id.to_vec(), total, fragments.len()))
}

// ============================================================================
// JitterBuffer
// ============================================================================

/// Entry in jitter buffer
struct JitterEntry {
    data: Vec<u8>,
    deliver_at: Instant,
}

/// Jitter buffer for reordering packets by sequence number
pub struct JitterBuffer<F>
where
    F: Fn(Vec<u8>),
{
    buf: HashMap<u32, JitterEntry>,
    next_seq: u32,
    on_deliver: F,
}

impl<F> JitterBuffer<F>
where
    F: Fn(Vec<u8>) + Clone,
{
    /// Create a new JitterBuffer
    pub fn new(on_deliver: F) -> Self {
        JitterBuffer {
            buf: HashMap::new(),
            next_seq: 0,
            on_deliver,
        }
    }

    /// Push a packet with sequence number
    pub fn push(&mut self, seq: u32, data: Vec<u8>) {
        if seq < self.next_seq {
            return; // Old packet, ignore
        }

        if seq == self.next_seq {
            // Immediate delivery
            (self.on_deliver)(data);
            self.next_seq += 1;
            self.flush();
        } else {
            // Buffer for later (with 50ms delay)
            let deliver_at = Instant::now() + Duration::from_millis(50);
            self.buf.insert(
                seq,
                JitterEntry {
                    data,
                    deliver_at,
                },
            );
        }
    }

    /// Flush buffered packets that are ready
    fn flush(&mut self) {
        while let Some(entry) = self.buf.remove(&self.next_seq) {
            (self.on_deliver)(entry.data);
            self.next_seq += 1;
        }
    }

    /// Clear the buffer
    pub fn clear(&mut self) {
        self.buf.clear();
        self.next_seq = 0;
    }
}

// ============================================================================
// BatchSender
// ============================================================================

/// Pending batch entry
struct PendingBatch {
    buffers: Vec<Vec<u8>>,
}

/// Batches multiple UDP packets for efficient sending
pub struct BatchSender {
    pending: HashMap<String, PendingBatch>,
    last_flush: Instant,
}

impl BatchSender {
    /// Create a new BatchSender
    pub fn new() -> Self {
        BatchSender {
            pending: HashMap::new(),
            last_flush: Instant::now(),
        }
    }

    /// Queue a packet for batched sending
    pub fn send(&mut self, ip: &str, port: u16, buf: Vec<u8>, now: Instant) -> Vec<(String, u16, Vec<u8>)> {
        let key = format!("{}:{}", ip, port);

        self.pending
            .entry(key.clone())
            .or_insert_with(|| PendingBatch {
                buffers: Vec::new(),
            })
            .buffers
            .push(buf);

        // Check if we should flush
        if now.duration_since(self.last_flush).as_millis() as u64 >= BATCH_INTERVAL {
            self.flush()
        } else {
            Vec::new()
        }
    }

    /// Force flush all pending batches
    pub fn flush(&mut self) -> Vec<(String, u16, Vec<u8>)> {
        self.last_flush = Instant::now();
        let mut results = Vec::new();

        for (key, batch) in self.pending.drain() {
            let (ip, port) = key.split_once(':').unwrap();
            let port: u16 = port.parse().unwrap();

            if batch.buffers.len() == 1 {
                results.push((ip.to_string(), port, batch.buffers[0].clone()));
            } else {
                // Create batch packet
                let batch_data = create_batch_packet(&batch.buffers);
                results.push((ip.to_string(), port, batch_data));
            }
        }

        results
    }

    /// Destroy the batch sender
    pub fn destroy(&mut self) -> Vec<(String, u16, Vec<u8>)> {
        self.flush()
    }
}

impl Default for BatchSender {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a batch packet from multiple frames
fn create_batch_packet(buffers: &[Vec<u8>]) -> Vec<u8> {
    let mut parts = Vec::with_capacity(buffers.len() * 2 + 10);
    parts.push(F_BATCH);
    parts.push(buffers.len() as u8);

    for buf in buffers {
        let len = (buf.len() as u16).to_be_bytes();
        parts.extend_from_slice(&len);
        parts.extend_from_slice(buf);
    }

    parts
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Compute xor hash for deduplication
pub fn xor_hash(buf: &[u8]) -> String {
    let mut a: u32 = 0x811C9DC5;
    let mut b: u32 = 0x811C9DC5;

    for (i, &byte) in buf.iter().enumerate() {
        if i & 1 == 0 {
            a ^= byte as u32;
            a = a.wrapping_mul(0x01000193);
        } else {
            b ^= byte as u32;
            b = b.wrapping_mul(0x01000193);
        }
    }

    let mut out = vec![0u8; 8];
    out[0..4].copy_from_slice(&a.to_be_bytes());
    out[4..8].copy_from_slice(&b.to_be_bytes());
    hex::encode(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fragment_assembler() {
        let mut asm = FragmentAssembler::new();
        let frag_id = [1u8; 8];

        let part1 = asm.add(&frag_id, 0, 2, vec![1, 2, 3]);
        assert!(part1.is_none());

        let part2 = asm.add(&frag_id, 1, 2, vec![4, 5, 6]);
        assert_eq!(part2, Some(vec![1, 2, 3, 4, 5, 6]));
    }

    #[test]
    fn test_xor_hash() {
        let hash = xor_hash(b"test");
        assert_eq!(hash.len(), 16);
    }
}