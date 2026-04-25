//! Structs module - BloomFilter, LRU, RingBuffer, PayloadCache

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::constants::{BLOOM_BITS, BLOOM_HASHES, BLOOM_ROTATE};

// ============================================================================
// BloomFilter
// ============================================================================

/// Probabilistic bloom filter for duplicate detection
pub struct BloomFilter {
    bits: usize,
    num_hashes: usize,
    cur: Vec<u8>,
    old: Vec<u8>,
    count: usize,
    last_rotate: Instant,
}

impl BloomFilter {
    /// Create a new BloomFilter
    pub fn new(bits: Option<usize>, num_hashes: Option<usize>) -> Self {
        let bits = bits.unwrap_or(BLOOM_BITS);
        let num_hashes = num_hashes.unwrap_or(BLOOM_HASHES);
        let size = (bits + 7) / 8;

        BloomFilter {
            bits,
            num_hashes,
            cur: vec![0u8; size],
            old: vec![0u8; size],
            count: 0,
            last_rotate: Instant::now(),
        }
    }

    fn rotate(&mut self) {
        if self.last_rotate.elapsed() < Duration::from_millis(BLOOM_ROTATE) {
            return;
        }
        self.old = self.cur.clone();
        self.cur = vec![0u8; self.cur.len()];
        self.count = 0;
        self.last_rotate = Instant::now();
    }

    fn positions(&self, key: &[u8]) -> Vec<usize> {
        let mut out = Vec::with_capacity(self.num_hashes);
        for i in 0..self.num_hashes {
            let mut h = (2166136261u32 as usize).wrapping_add(i * 16777619);
            for &byte in key {
                h ^= byte as usize;
                h = h.wrapping_mul(16777619);
            }
            out.push(h % self.bits);
        }
        out
    }

    /// Add a key to the filter
    pub fn add(&mut self, key: &[u8]) {
        self.rotate();
        for pos in self.positions(key) {
            self.cur[pos >> 3] |= 1 << (pos & 7);
        }
        self.count += 1;
    }

    /// Check if a key might exist
    pub fn has(&self, key: &[u8]) -> bool {
        let pos = self.positions(key);
        let in_cur = pos.iter().all(|&p| self.cur[p >> 3] & (1 << (p & 7)) != 0);
        if in_cur {
            return true;
        }
        pos.iter().all(|&p| self.old[p >> 3] & (1 << (p & 7)) != 0)
    }

    /// Check if key was seen, adding it if not
    pub fn seen(&mut self, key: &[u8]) -> bool {
        if self.has(key) {
            return true;
        }
        self.add(key);
        false
    }
}

// ============================================================================
// LRU Cache
// ============================================================================

/// Entry with timestamp
struct Entry<V> {
    value: V,
    timestamp: Instant,
}

/// Least Recently Used cache
pub struct Lru<K, V> {
    map: HashMap<K, Entry<V>>,
    max_size: usize,
    ttl: Option<Duration>,
    access_order: Vec<K>,
}

impl<K: Clone + std::hash::Hash + Eq, V: Clone> Lru<K, V> {
    /// Create a new LRU cache
    pub fn new(max_size: usize, ttl_ms: Option<u64>) -> Self {
        Lru {
            map: HashMap::new(),
            max_size,
            ttl: ttl_ms.map(Duration::from_millis),
            access_order: Vec::new(),
        }
    }

    /// Check if key exists
    pub fn has(&self, key: &K) -> bool {
        self.map.contains_key(key)
    }

    /// Add a key-value pair
    pub fn add(&mut self, key: K, value: V) {
        // Evict old entries if at capacity
        if self.map.len() >= self.max_size {
            if let Some(oldest) = self.access_order.first().cloned() {
                self.map.remove(&oldest);
                self.access_order.remove(0);
            }
        }

        // Check TTL and evict expired entries
        if let Some(ttl) = self.ttl {
            let now = Instant::now();
            let mut removed = 0;
            self.access_order.retain(|k| {
                if let Some(entry) = self.map.get(k) {
                    if now.duration_since(entry.timestamp) > ttl {
                        self.map.remove(k);
                        removed += 1;
                        false
                    } else {
                        true
                    }
                } else {
                    false
                }
            });
        }

        self.map.insert(key.clone(), Entry {
            value,
            timestamp: Instant::now(),
        });
        self.access_order.push(key);
    }

    /// Get a value by key
    pub fn get(&self, key: &K) -> Option<&V> {
        self.map.get(key).map(|e| &e.value)
    }

    /// Check if key was seen, adding placeholder if not
    pub fn seen(&mut self, key: K) -> bool
    where
        V: Default,
    {
        if self.has(&key) {
            return true;
        }
        self.add(key, V::default());
        false
    }

    /// Remove a key
    pub fn delete(&mut self, key: &K) {
        self.map.remove(key);
        self.access_order.retain(|k| k != key);
    }

    /// Number of entries
    pub fn size(&self) -> usize {
        self.map.len()
    }

    /// Iterator over keys
    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.map.keys()
    }

    /// Iterator over key-value pairs
    pub fn entries(&self) -> impl Iterator<Item = (&K, &V)> {
        self.map.iter().map(|(k, e)| (k, &e.value))
    }
}

// ============================================================================
// RingBuffer
// ============================================================================

/// Ring buffer with fixed capacity (power of 2)
pub struct RingBuffer<T> {
    buf: Vec<Option<T>>,
    mask: usize,
    head: usize,
    tail: usize,
}

impl<T: Clone> RingBuffer<T> {
    /// Create a new RingBuffer
    /// Size must be a power of 2
    pub fn new(size: usize) -> Self {
        assert!(size > 0 && (size & (size - 1)) == 0, 
                "RingBuffer size must be a power of 2");
        let buf: Vec<Option<T>> = (0..size).map(|_| None).collect();
        RingBuffer {
            mask: size - 1,
            head: 0,
            tail: 0,
            buf,
        }
    }

    /// Number of elements in buffer
    pub fn len(&self) -> usize {
        (self.tail.wrapping_sub(self.head)) & self.mask
    }

    /// Check if buffer is full
    pub fn is_full(&self) -> bool {
        ((self.tail.wrapping_add(1)) & self.mask) == (self.head & self.mask)
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.head == self.tail
    }

    /// Push an element
    pub fn push(&mut self, item: T) {
        if self.is_full() {
            self.head = (self.head + 1) & self.mask;
        }
        self.buf[self.tail] = Some(item);
        self.tail = (self.tail + 1) & self.mask;
    }

    /// Pop an element
    pub fn shift(&mut self) -> Option<T> {
        if self.is_empty() {
            return None;
        }
        let item = self.buf[self.head].take();
        self.head = (self.head + 1) & self.mask;
        item
    }

    /// Clear the buffer
    pub fn clear(&mut self) {
        self.head = 0;
        self.tail = 0;
        for item in self.buf.iter_mut() {
            *item = None;
        }
    }
}

// ============================================================================
// PayloadCache
// ============================================================================

/// Cache for reassembled message payloads
pub struct PayloadCache<T> {
    keys: Vec<Option<String>>,
    vals: Vec<Option<T>>,
    map: HashMap<String, usize>,
    mask: usize,
    head: usize,
}

impl<T: Clone> PayloadCache<T> {
    /// Create a new PayloadCache
    pub fn new(size: usize) -> Self {
        PayloadCache {
            keys: vec![None; size],
            vals: vec![None; size],
            map: HashMap::new(),
            mask: size - 1,
            head: 0,
        }
    }

    /// Set a message ID with its frame
    pub fn set(&mut self, msg_id: &str, frame: T) {
        let idx = self.head;

        // Evict old entry
        if let Some(ref old_id) = self.keys[idx] {
            self.map.remove(old_id);
        }

        self.keys[idx] = Some(msg_id.to_string());
        self.vals[idx] = Some(frame);
        self.map.insert(msg_id.to_string(), idx);
        self.head = (self.head + 1) & self.mask;
    }

    /// Get a frame by message ID
    pub fn get(&self, msg_id: &str) -> Option<T> {
        self.map.get(msg_id).and_then(|&idx| self.vals[idx].clone())
    }

    /// Check if message ID exists
    pub fn has(&self, msg_id: &str) -> bool {
        self.map.contains_key(msg_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_filter() {
        let mut bf = BloomFilter::new(None, None);
        assert!(!bf.has(b"test"));
        bf.add(b"test");
        assert!(bf.has(b"test"));
    }

    #[test]
    fn test_lru() {
        let mut lru = Lru::new(3, None);
        lru.add("a", 1);
        lru.add("b", 2);
        lru.add("c", 3);
        assert_eq!(lru.get(&"a"), Some(&1));
    }

    #[test]
    fn test_ring_buffer() {
        let mut rb = RingBuffer::new(4);
        assert!(rb.is_empty());
        rb.push(1);
        rb.push(2);
        assert_eq!(rb.len(), 2);
        assert_eq!(rb.shift(), Some(1));
        assert_eq!(rb.shift(), Some(2));
        assert!(rb.is_empty());
    }
}