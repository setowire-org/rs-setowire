//! Crypto module - X25519 key exchange and ChaCha20-Poly1305 encryption
//!
//! Session key derivation uses HKDF-SHA256 with label "p2p-v12-session"
//! Compatible with js-setowire protocol

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use digest::Digest;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::constants::{F_HELLO, F_HELLO_ACK, NONCE_LEN, TAG_LEN};

/// HKDF info label for session key derivation (matches js-setowire)
const SESSION_KEY_INFO: &[u8] = b"p2p-v12-session";

/// X25519 key pair
#[derive(Clone)]
pub struct KeyPair {
    /// Private key (32 bytes)
    pub private: [u8; 32],
    /// Public key (32 bytes)
    pub public: [u8; 32],
}

/// Session state with send/receive keys
#[derive(Clone)]
pub struct Session {
    /// Send encryption key (32 bytes)
    pub send_key: [u8; 32],
    /// Receive encryption key (32 bytes)
    pub recv_key: [u8; 32],
    /// Session ID (used in nonce)
    pub session_id: u32,
    /// Send counter
    pub send_ctr: u64,
}

/// Generate a new X25519 key pair
pub fn generate_x25519(seed: Option<&[u8]>) -> KeyPair {
    match seed {
        Some(seed_bytes) => {
            // Deterministic key generation from seed
            let mut hasher = Sha256::new();
            hasher.update(seed_bytes);
            let hash = hasher.finalize();
            
            let mut private = [0u8; 32];
            private.copy_from_slice(&hash[..32]);
            // Clamp private key
            private[0] &= 248;
            private[31] &= 127;
            private[31] |= 64;

            let secret = StaticSecret::from(private);
            let public = PublicKey::from(&secret);

            KeyPair {
                private,
                public: *public.as_bytes(),
            }
        }
        None => {
            // Random key generation
            let mut private = [0u8; 32];
            rand::random::<u64>();
            let secret = StaticSecret::random_from_rng(rand::thread_rng());
            private.copy_from_slice(secret.as_bytes());

            let public = PublicKey::from(&secret);

            KeyPair {
                private,
                public: *public.as_bytes(),
            }
        }
    }
}

/// Derive session keys from key exchange (matches js-setowire crypto.js)
pub fn derive_session(my_private: &[u8; 32], their_public: &[u8; 32]) -> Session {
    // Perform X25519 key exchange
    let my_secret = StaticSecret::from(*my_private);
    let their_pub = PublicKey::from(*their_public);
    let shared = my_secret.diffie_hellman(&their_pub);

    // HKDF: salt = empty, info = "p2p-v12-session", len = 68 (matches js-setowire)
    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut okm = [0u8; 68];
    hk.expand(SESSION_KEY_INFO, &mut okm).expect("HKDF expand failed");

    let mut send_key = [0u8; 32];
    let mut recv_key = [0u8; 32];
    send_key.copy_from_slice(&okm[..32]);
    recv_key.copy_from_slice(&okm[32..64]);
    
    // Session ID from bytes 64-67 (big-endian u32)
    let session_id_arr: [u8; 4] = [okm[64], okm[65], okm[66], okm[67]];
    let session_id = u32::from_be_bytes(session_id_arr);

    Session {
        send_key,
        recv_key,
        session_id,
        send_ctr: 0,
    }
}

/// Encrypt plaintext with session
pub fn encrypt(session: &mut Session, plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new_from_slice(&session.send_key)
        .expect("valid key size");

    let mut nonce_bytes = [0u8; NONCE_LEN];
    // Write session ID (4 bytes, big-endian)
    nonce_bytes[0] = (session.session_id >> 24) as u8;
    nonce_bytes[1] = (session.session_id >> 16) as u8;
    nonce_bytes[2] = (session.session_id >> 8) as u8;
    nonce_bytes[3] = session.session_id as u8;
    // Write counter (8 bytes, big-endian)
    nonce_bytes[4] = (session.send_ctr >> 56) as u8;
    nonce_bytes[5] = (session.send_ctr >> 48) as u8;
    nonce_bytes[6] = (session.send_ctr >> 40) as u8;
    nonce_bytes[7] = (session.send_ctr >> 32) as u8;
    nonce_bytes[8] = (session.send_ctr >> 24) as u8;
    nonce_bytes[9] = (session.send_ctr >> 16) as u8;
    nonce_bytes[10] = (session.send_ctr >> 8) as u8;
    nonce_bytes[11] = session.send_ctr as u8;

    // Bug C fix: increment AFTER building nonce (matches JS: nonce uses current sendCtr, then ++)
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext).expect("encryption failed");
    session.send_ctr += 1;

    // Prepend nonce to ciphertext
    let mut result = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend(ciphertext);
    result
}

/// Decrypt ciphertext with session
pub fn decrypt(session: &Session, data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < NONCE_LEN + TAG_LEN {
        return None;
    }

    let cipher = ChaCha20Poly1305::new_from_slice(&session.recv_key)
        .ok()?;

    let nonce = Nonce::from_slice(&data[..NONCE_LEN]);
    let ciphertext = &data[NONCE_LEN..];

    match cipher.decrypt(nonce, ciphertext) {
        Ok(plaintext) => Some(plaintext),
        Err(_) => None,
    }
}

/// Parse HELLO/HELLO_ACK frame (matches js-setowire: 41 bytes = 1 + 8 + 32)
/// Returns Some((peer_id_8bytes, public_key)) or None if invalid
pub fn parse_handshake_frame(frame: &[u8]) -> Option<(&[u8; 8], &[u8; 32])> {
    // Validate frame type
    if frame.is_empty() || (frame[0] != F_HELLO && frame[0] != F_HELLO_ACK) {
        return None;
    }
    
    // Validate frame length (1 + 8 + 32 = 41)
    if frame.len() != 1 + 8 + 32 {
        return None;
    }
    
    let peer_id: &[u8; 8] = frame[1..9].try_into().ok()?;
    let public_key: &[u8; 32] = frame[9..41].try_into().ok()?;
    
    Some((peer_id, public_key))
}

/// Create HELLO frame (0xA1) - 41 bytes = 1 + 8 + 32
pub fn create_hello_frame(peer_id: &[u8; 8], public_key: &[u8; 32]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(1 + 8 + 32);
    frame.push(F_HELLO);
    frame.extend_from_slice(peer_id);
    frame.extend_from_slice(public_key);
    frame
}

/// Create HELLO_ACK frame (0xA2) - 41 bytes = 1 + 8 + 32
pub fn create_hello_ack_frame(peer_id: &[u8; 8], public_key: &[u8; 32]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(1 + 8 + 32);
    frame.push(F_HELLO_ACK);
    frame.extend_from_slice(peer_id);
    frame.extend_from_slice(public_key);
    frame
}

/// Derive session keys with peer ID comparison for send/recv key flipping
/// Uses hex string comparison (matches js-setowire: `this._id < pid`)
pub fn derive_session_flipped(
    my_private: &[u8; 32],
    their_public: &[u8; 32],
    my_id: &str,
    their_id: &str,
) -> Session {
    let mut session = derive_session(my_private, their_public);
    
    // Compare hex string IDs lexicographically (matches JS: this._id < pid)
    if their_id < my_id {
        std::mem::swap(&mut session.send_key, &mut session.recv_key);
    }
    
    session
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let keypair = generate_x25519(None);
        assert_eq!(keypair.private.len(), 32);
        assert_eq!(keypair.public.len(), 32);
    }

    #[test]
    fn test_deterministic_key_generation() {
        let seed = b"test_seed_12345678901234567890";
        let key1 = generate_x25519(Some(seed));
        let key2 = generate_x25519(Some(seed));
        assert_eq!(key1.private, key2.private);
        assert_eq!(key1.public, key2.public);
    }

    #[test]
    fn test_encrypt_decrypt() {
        // Para X25519, cada peer usa a chave pública do outro para derivar a sessão
        let keypair1 = generate_x25519(None);
        let keypair2 = generate_x25519(None);

        // Peer 1 deriva sessão
        let mut session1 = derive_session(&keypair1.private, &keypair2.public);
        // Peer 2 deriva sessão
        let session2 = derive_session(&keypair2.private, &keypair1.public);

        // Verificar que as chaves de sessão são consistentes
        assert_eq!(session1.session_id, session2.session_id);

        let plaintext = b"Hello, World!";

        // Peer 1 criptografa
        let ciphertext = encrypt(&mut session1, plaintext);
        
        // No protocolo, as chaves são espelhadas (peer com ID menor usa sendKey primeiro)
        // Aqui simulamos que session2 seria o receptor espelhado
        let mut session2_for_recv = session2.clone();
        
        // Trocar as chaves para simular o espelhamento do protocolo
        let mut recv_session = session2_for_recv;
        std::mem::swap(&mut recv_session.send_key, &mut recv_session.recv_key);
        
        let decrypted = decrypt(&recv_session, &ciphertext);
        assert!(decrypted.is_some(), "Decrypt failed - session keys may not match");
        
        if let Some(decrypted) = decrypted {
            assert_eq!(plaintext.to_vec(), decrypted);
        }
    }
}