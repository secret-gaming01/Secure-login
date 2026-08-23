//! Hashage de mots de passe : Argon2id + salt unique + pepper global.
//!
//! - Algorithme : Argon2id v19 (params par défaut OWASP : m=19 MiB, t=2, p=1)
//! - Salt : généré aléatoirement pour chaque utilisateur, intégré au PHC string
//! - Pepper : secret global (env `PASSWORD_PEPPER`) concaténé AVANT le hash ;
//!   il n'est JAMAIS stocké en base, une fuite DB seule ne permet pas le crack.

use argon2::password_hash::{rand_core::OsRng, SaltString};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};

/// Génère un salt aléatoire (colonne dédiée, aussi présent dans le PHC).
pub fn generate_salt() -> String {
    SaltString::generate(&mut OsRng).to_string()
}

/// Hash un mot de passe (pepper inclus). Retourne (phc_string, salt).
pub fn hash_password(password: &str, pepper: &str) -> anyhow::Result<(String, String)> {
    let salt = SaltString::generate(&mut OsRng);
    let salt_col = salt.to_string();
    let peppered = format!("{}{}", password, pepper);
    let phc = Argon2::default()
        .hash_password(peppered.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("argon2 hash error: {e}"))?
        .to_string();
    Ok((phc, salt_col))
}

/// Vérifie un mot de passe contre son hash PHC (constant-time interne).
pub fn verify_password(password: &str, pepper: &str, phc: &str) -> bool {
    let parsed = match PasswordHash::new(phc) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let peppered = format!("{}{}", password, pepper);
    Argon2::default()
        .verify_password(peppered.as_bytes(), &parsed)
        .is_ok()
}

/// Brûle du CPU (hash factice) pour égaliser le temps de réponse quand
/// l'utilisateur n'existe pas — anti énumération par timing.
pub fn timing_equalizer() {
    let _ = hash_password("timing-equalizer-dummy", "x");
}
