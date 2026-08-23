//! Chiffrement au repos : AES-256-GCM authentifié.
//!
//! Utilisé pour : secrets TOTP, codes de récupération, clés publiques des
//! passkeys (payload sérialisé), détails sensibles des logs de sécurité.
//! Format stocké : base64(nonce_12_octets || ciphertext || tag_16_octets).
//! La clé est dérivée en SHA-256 depuis `ENCRYPTION_KEY`.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct Encryptor {
    cipher: Aes256Gcm,
}

impl std::fmt::Debug for Encryptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Encryptor(aes-256-gcm)")
    }
}

impl Encryptor {
    pub fn new(secret: &str) -> Self {
        let key = Sha256::digest(secret.as_bytes());
        Self {
            cipher: Aes256Gcm::new(aes_gcm::aead::generic_array::GenericArray::from_slice(&key)),
        }
    }

    pub fn encrypt(&self, plaintext: &str) -> anyhow::Result<String> {
        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let ct = self.cipher.encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_bytes())?;
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        Ok(B64.encode(out))
    }

    pub fn decrypt(&self, blob: &str) -> anyhow::Result<String> {
        let raw = B64.decode(blob)?;
        if raw.len() < 13 {
            anyhow::bail!("encrypted blob too short");
        }
        let (nonce, ct) = raw.split_at(12);
        let pt = self.cipher.decrypt(Nonce::from_slice(nonce), ct)?;
        Ok(String::from_utf8(pt)?)
    }
}
