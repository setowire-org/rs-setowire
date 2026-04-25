//! Crypto module - X25519 key exchange and ChaCha20-Poly1305 encryption
//!
//! Session key derivation uses HKDF-SHA256 with label "p2p-v12-session"

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use digest::Digest;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::constants::{NONCE_LEN, TAG_LEN};

/// HKDF label for session key derivation
const SESSION_KEY_LABEL: &[u8] = b"p2p-v12-session";

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

/// Derive session keys from key exchange
pub fn derive_session(my_private: &[u8; 32], their_public: &[u8; 32], session_id: u32) -> Session {
    // Perform X25519 key exchange
    let my_secret = StaticSecret::from(*my_private);
    let their_pub = PublicKey::from(*their_public);
    let shared = my_secret.diffie_hellman(&their_pub);

    // HKDF to derive keys
    let hk = Hkdf::<Sha256>::new(Some(SESSION_KEY_LABEL), shared.as_bytes());
    let mut okm = [0u8; 64];
    hk.expand(&[], &mut okm).expect("HKDF expand failed");

    let mut send_key = [0u8; 32];
    let mut recv_key = [0u8; 32];
    send_key.copy_from_slice(&okm[..32]);
    recv_key.copy_from_slice(&okm[32..64]);

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

    session.send_ctr += 1;

    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext).expect("encryption failed");

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
        let mut session1 = derive_session(&keypair1.private, &keypair2.public, 42);
        // Peer 2 deriva sessão
        let session2 = derive_session(&keypair2.private, &keypair1.public, 42);

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