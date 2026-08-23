//! Génération de tokens aléatoires et hashage HMAC-SHA256 (stockage DB).

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Token opaque 48 octets, encodé hexadécimal (96 chars).
pub fn secure_token() -> String {
    let mut bytes = [0u8; 48];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Hash HMAC-SHA256(pepper, value) — les tokens sensibles ne sont JAMAIS
/// stockés en clair en base, seul ce hash l'est.
pub fn hmac_hash(pepper: &str, value: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(pepper.as_bytes())
        .expect("hmac accepts any key length");
    mac.update(value.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Code de récupération MFA : format XXXX-XXXX (alphabet non ambigu).
pub fn recovery_code() -> String {
    const ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";
    let mut rng = rand::thread_rng();
    let core: String = (0..8)
        .map(|_| {
            let i = rng.next_u32() as usize % ALPHABET.len();
            ALPHABET[i] as char
        })
        .collect();
    format!("{}-{}", &core[..4], &core[4..])
}
