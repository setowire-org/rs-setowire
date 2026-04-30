//! Setowire - A lightweight, portable P2P networking library built on UDP
//! 
//! No central servers, no brokers — peers find each other and communicate directly.
//! 
//! ## Quick Start
//! 
//! ```rust,ignore
//! use setowire::{Swarm, Peer};
//! use sha2::Digest;
//! 
//! #[tokio::main]
//! async fn main() {
//!     let mut swarm = Swarm::new().await;
//!     
//!     let topic = sha2::Sha256::digest("my-topic");
//!     swarm.join(&topic, true, true);
//!     
//!     swarm.on_connection(Box::new(|peer: &Peer| {
//!         println!("New peer: {}", peer.id);
//!     }));
//!     
//!     // Keep running
//!     tokio::signal::ctrl_c().await.unwrap();
//! }
//! ```

pub mod constants;
pub mod crypto;
pub mod structs;
pub mod framing;
pub mod dht_lib;
pub mod peer;
pub mod swarm;

// Re-export commonly used types
pub use constants::*;
pub use crypto::{generate_x25519, derive_session, encrypt, decrypt, KeyPair, Session};
pub use structs::{BloomFilter, Lru, RingBuffer, PayloadCache};
pub use framing::{FragmentAssembler, JitterBuffer, BatchSender, fragment_payload, xor_hash};
pub use dht_lib::SimpleDht;
pub use peer::{Peer, PeerInfo};
pub use swarm::Swarm;