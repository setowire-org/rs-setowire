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

const SESSION_KEY_INFO: &[u8] = b"p2p-v12-session";

/// X25519 key pair
#[derive(Clone)]
pub struct KeyPair {
    pub private: [u8; 32],
    pub public:  [u8; 32],
}

/// Session encryption state
#[derive(Clone)]
pub struct Session {
    pub send_key:   [u8; 32],
    pub recv_key:   [u8; 32],
    pub session_id: u32,
    pub send_ctr:   u64,
}

/// Generate a new X25519 key pair
pub fn generate_x25519(seed: Option<&[u8]>) -> KeyPair {
    match seed {
        Some(seed_bytes) => {
            let mut hasher = Sha256::new();
            hasher.update(seed_bytes);
            let hash = hasher.finalize();
            let mut private = [0u8; 32];
            private.copy_from_slice(&hash[..32]);
            private[0] &= 248;
            private[31] &= 127;
            private[31] |= 64;
            let secret = StaticSecret::from(private);
            let public  = PublicKey::from(&secret);
            KeyPair { private, public: *public.as_bytes() }
        }
        None => {
            let secret  = StaticSecret::random_from_rng(rand::thread_rng());
            let private = *secret.as_bytes();
            let public  = PublicKey::from(&secret);
            KeyPair { private, public: *public.as_bytes() }
        }
    }
}

/// Derive session keys from X25519 DH + HKDF-SHA256
pub fn derive_session(my_private: &[u8; 32], their_public: &[u8; 32]) -> Session {
    let my_secret  = StaticSecret::from(*my_private);
    let their_pub  = PublicKey::from(*their_public);
    let shared     = my_secret.diffie_hellman(&their_pub);

    let hk  = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut okm = [0u8; 68];
    hk.expand(SESSION_KEY_INFO, &mut okm).expect("HKDF expand failed");

    let mut send_key = [0u8; 32];
    let mut recv_key = [0u8; 32];
    send_key.copy_from_slice(&okm[..32]);
    recv_key.copy_from_slice(&okm[32..64]);
    let session_id = u32::from_be_bytes([okm[64], okm[65], okm[66], okm[67]]);

    Session { send_key, recv_key, session_id, send_ctr: 0 }
}

/// Encrypt plaintext using session send_key
pub fn encrypt(session: &mut Session, plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new_from_slice(&session.send_key)
        .expect("valid key size");

    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes[0]  = (session.session_id >> 24) as u8;
    nonce_bytes[1]  = (session.session_id >> 16) as u8;
    nonce_bytes[2]  = (session.session_id >>  8) as u8;
    nonce_bytes[3]  =  session.session_id        as u8;
    nonce_bytes[4]  = (session.send_ctr >> 56) as u8;
    nonce_bytes[5]  = (session.send_ctr >> 48) as u8;
    nonce_bytes[6]  = (session.send_ctr >> 40) as u8;
    nonce_bytes[7]  = (session.send_ctr >> 32) as u8;
    nonce_bytes[8]  = (session.send_ctr >> 24) as u8;
    nonce_bytes[9]  = (session.send_ctr >> 16) as u8;
    nonce_bytes[10] = (session.send_ctr >>  8) as u8;
    nonce_bytes[11] =  session.send_ctr        as u8;

    let nonce      = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext).expect("encryption failed");
    session.send_ctr += 1;

    let mut result = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend(ciphertext);
    result
}

/// Decrypt ciphertext using session recv_key
pub fn decrypt(session: &Session, data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < NONCE_LEN + TAG_LEN { return None; }
    let cipher = ChaCha20Poly1305::new_from_slice(&session.recv_key).ok()?;
    let nonce      = Nonce::from_slice(&data[..NONCE_LEN]);
    let ciphertext = &data[NONCE_LEN..];
    cipher.decrypt(nonce, ciphertext).ok()
}

/// Parse HELLO / HELLO_ACK frame → (peer_id_8b, pub_key_32b)
pub fn parse_handshake_frame(frame: &[u8]) -> Option<(&[u8; 8], &[u8; 32])> {
    if frame.is_empty() || (frame[0] != F_HELLO && frame[0] != F_HELLO_ACK) { return None; }
    if frame.len() != 41 { return None; }  // 1 + 8 + 32 = 41 (JS compatibility)
    let peer_id:    &[u8; 8]  = frame[1..9].try_into().ok()?;
    let public_key: &[u8; 32] = frame[9..41].try_into().ok()?;
    Some((peer_id, public_key))
}

pub fn create_hello_frame(peer_id: &[u8; 8], public_key: &[u8; 32]) -> Vec<u8> {
    let mut f = Vec::with_capacity(41);
    f.push(F_HELLO);
    f.extend_from_slice(peer_id);
    f.extend_from_slice(public_key);
    f
}

pub fn create_hello_ack_frame(peer_id: &[u8; 8], public_key: &[u8; 32]) -> Vec<u8> {
    let mut f = Vec::with_capacity(41);
    f.push(F_HELLO_ACK);
    f.extend_from_slice(peer_id);
    f.extend_from_slice(public_key);
    f
}

/// Derive session com key-flip correto.
///
/// Espelha o JS:
///   iAmLo = this._id < pid      (this._id = 40-char, pid = 16-char wire id)
///   if (iAmLo) { sess.sendKey = okm[0..32];  sess.recvKey = okm[32..64] }
///   else       { sess.sendKey = okm[32..64]; sess.recvKey = okm[0..32]  }
///
/// Logo: quem tem my_id < their_id NÃO faz swap (usa as chaves como derivadas).
///       Quem tem my_id >= their_id FAZ o swap.
pub fn derive_session_flipped(
    my_private:  &[u8; 32],
    their_public: &[u8; 32],
    my_id:   &str,
    their_id: &str,
) -> Session {
    let mut session = derive_session(my_private, their_public);

    // FIX #1: swap quando EU sou o maior (not iAmLo)
    if my_id >= their_id {
        std::mem::swap(&mut session.send_key, &mut session.recv_key);
    }

    session
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let kp = generate_x25519(None);
        assert_eq!(kp.private.len(), 32);
        assert_eq!(kp.public.len(), 32);
    }

    #[test]
    fn test_deterministic_key_generation() {
        let seed = b"test_seed_12345678901234567890";
        let k1 = generate_x25519(Some(seed));
        let k2 = generate_x25519(Some(seed));
        assert_eq!(k1.private, k2.private);
        assert_eq!(k1.public,  k2.public);
    }

    /// Teste de round-trip correto simulando dois peers A e B.
    ///
    /// O peer com ID lexicograficamente MENOR não faz swap:
    ///   send_key = okm[0..32], recv_key = okm[32..64]
    /// O peer MAIOR faz swap:
    ///   send_key = okm[32..64], recv_key = okm[0..32]
    ///
    /// Portanto:
    ///   A.send_key == B.recv_key   (quando A é o menor)
    ///   B.send_key == A.recv_key
    #[test]
    fn test_round_trip_symmetric() {
        let kp_a = generate_x25519(None);
        let kp_b = generate_x25519(None);

        // IDs fictícios — garantir que id_a < id_b para simplificar
        let id_a = "aaaa000000000000";  // 16 chars (wire id do HELLO)
        let id_b = "ffff000000000000";

        // A deriva sessão com a chave pública de B
        let mut sess_a = derive_session_flipped(&kp_a.private, &kp_b.public, id_a, id_b);
        // B deriva sessão com a chave pública de A
        let     sess_b = derive_session_flipped(&kp_b.private, &kp_a.public, id_b, id_a);

        // id_a < id_b → A não faz swap → A.send = okm[0..32]
        // id_b > id_a → B faz swap     → B.recv = okm[0..32]  ✓
        assert_eq!(sess_a.send_key, sess_b.recv_key,
            "A.send_key deve ser igual a B.recv_key");
        assert_eq!(sess_b.send_key, sess_a.recv_key,
            "B.send_key deve ser igual a A.recv_key");

        // A cifra, B decifra
        let plain = b"hello interop";
        let ct = encrypt(&mut sess_a, plain);
        let dec = decrypt(&sess_b, &ct);
        assert_eq!(dec.as_deref(), Some(plain.as_ref()), "B deve decifrar o que A cifrou");

        // B cifra, A decifra
        let mut sess_b_mut = sess_b;
        let ct2 = encrypt(&mut sess_b_mut, plain);
        let dec2 = decrypt(&sess_a, &ct2);
        assert_eq!(dec2.as_deref(), Some(plain.as_ref()), "A deve decifrar o que B cifrou");
    }

    #[test]
    fn test_session_ids_match() {
        let kp_a = generate_x25519(None);
        let kp_b = generate_x25519(None);
        let s_a = derive_session(&kp_a.private, &kp_b.public);
        let s_b = derive_session(&kp_b.private, &kp_a.public);
        assert_eq!(s_a.session_id, s_b.session_id, "session_id deve ser idêntico nos dois lados");
    }
}