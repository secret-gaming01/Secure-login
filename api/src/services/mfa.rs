//! MFA / 2FA : TOTP (RFC 6238, compatible Google Authenticator/Authy)
//! + codes de recuperation a usage unique.
//!
//! Le secret TOTP et les hashes des codes de recuperation sont chiffres
//! AES-256-GCM au repos. Implementation TOTP native (HMAC-SHA1) avec
//! fenetrage anti-derive (+/- 30 s).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde_json::json;
use sha1::Sha1;

use crate::crypto::tokens::{hmac_hash, recovery_code};
use crate::error::{AppError, AppResult};
use crate::models::MfaRow;
use crate::q_exec;
use crate::q_fetch_optional;
use crate::state::AppState;

const STEP_SECS: i64 = 30;
const DIGITS: u32 = 6;
const WINDOW_STEPS: i64 = 1;

type HmacSha1 = Hmac<Sha1>;

// ---------------------------------------------------------------------------
// RFC 4231 / 6238 minimal
// ---------------------------------------------------------------------------

fn hotp(key: &[u8], counter: u64) -> String {
    let mut mac = HmacSha1::new_from_slice(key).expect("hmac accepts any key");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let bin = ((digest[offset] as u32 & 0x7f) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | (digest[offset + 3] as u32);
    format!("{:06}", bin % 10u32.pow(DIGITS))
}

fn totp_code(key: &[u8], unix_time: i64) -> String {
    let counter = unix_time.div_euclid(STEP_SECS) as u64;
    hotp(key, counter)
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a_b, b_b) = (a.as_bytes(), b.as_bytes());
    if a_b.len() != b_b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a_b.len() {
        diff |= a_b[i] ^ b_b[i];
    }
    diff == 0
}

/// Verifie un code TOTP avec fenetre de tolerance.
pub fn verify_totp_code(secret_hex: &str, code: &str) -> bool {
    let key = match hex::decode(secret_hex) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let now = chrono::Utc::now().timestamp();
    for delta in -WINDOW_STEPS..=WINDOW_STEPS {
        let expected = totp_code(&key, now + delta * STEP_SECS);
        if constant_time_eq(expected.as_str(), code.trim()) {
            return true;
        }
    }
    false
}

/// Encode base32 RFC 4648 (alphabet standard, sans padding).
pub fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for &byte in data {
        buffer = (buffer << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

// ---------------------------------------------------------------------------
// Service MFA
// ---------------------------------------------------------------------------

async fn get_row(state: &AppState, user_id: &str) -> AppResult<Option<MfaRow>> {
    q_fetch_optional!(
        &state.db,
        MfaRow,
        "SELECT * FROM mfa WHERE user_id = $1",
        user_id.to_string()
    )
    .await
}

pub async fn is_enabled(state: &AppState, user_id: &str) -> AppResult<bool> {
    match get_row(state, user_id).await? {
        Some(r) => Ok(r.enabled),
        None => Ok(false),
    }
}

/// Genere un nouveau secret TOTP (non actif jusqu'a confirmation).
pub async fn setup(state: &AppState, user_id: &str, email: &str) -> AppResult<(String, String)> {
    use rand::RngCore;
    let mut secret = [0u8; 20];
    rand::rngs::OsRng.fill_bytes(&mut secret);

    let secret_b32 = base32_encode(&secret);
    let otpauth_url = format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={}&period={}",
        state.cfg.mfa_issuer,
        email,
        secret_b32,
        state.cfg.mfa_issuer,
        DIGITS,
        STEP_SECS
    );

    let enc_secret = state.enc.encrypt(&hex::encode(secret))?;
    let now = crate::util::now();

    q_exec!(
        &state.db,
        "INSERT INTO mfa (user_id, secret_enc, enabled, recovery_codes_enc, confirmed_at, created_at)
         VALUES ($1, $2, FALSE, NULL, NULL, $3)
         ON CONFLICT (user_id) DO UPDATE SET secret_enc = EXCLUDED.secret_enc,
             enabled = FALSE, recovery_codes_enc = NULL, confirmed_at = NULL",
        user_id.to_string(),
        enc_secret,
        now
    )
    .await?;

    Ok((otpauth_url, secret_b32))
}

fn load_recovery_hashes(state: &AppState, row: &MfaRow) -> AppResult<Vec<String>> {
    match &row.recovery_codes_enc {
        Some(enc) => {
            let plain = state.enc.decrypt(enc)?;
            let arr: Vec<String> = serde_json::from_str(&plain)?;
            Ok(arr)
        }
        None => Ok(vec![]),
    }
}

fn save_recovery_hashes(state: &AppState, user_id: &str, hashes: &[String]) -> AppResult<()> {
    let enc = state.enc.encrypt(&serde_json::to_string(hashes)?)?;
    q_exec!(
        &state.db,
        "UPDATE mfa SET recovery_codes_enc = $2 WHERE user_id = $1",
        user_id.to_string(),
        enc
    )
    .await?;
    Ok(())
}

/// Confirme l'activation MFA avec un code valide ; genere les codes de
/// recuperation (retournes EN CLAIR une seule fois).
pub async fn confirm(
    state: &AppState,
    user_id: &str,
    code: &str,
) -> AppResult<Vec<String>> {
    let row = get_row(state, user_id)
        .await?
        .ok_or_else(|| AppError::validation("MFA not initialized"))?;
    if row.enabled {
        return Err(AppError::Conflict("MFA already enabled".into()));
    }

    let secret_hex = state.enc.decrypt(&row.secret_enc)?;
    if !verify_totp_code(&secret_hex, code) {
        return Err(AppError::validation("Invalid verification code"));
    }

    // Codes de recuperation : stockes en HMAC, retournes en clair une fois
    let codes: Vec<String> = (0..8).map(|_| recovery_code()).collect();
    let hashes: Vec<String> = codes
        .iter()
        .map(|c| hmac_hash(&state.cfg.password_pepper, c))
        .collect();
    save_recovery_hashes(state, user_id, &hashes).await?;

    let now = crate::util::now();
    q_exec!(
        &state.db,
        "UPDATE mfa SET enabled = TRUE, confirmed_at = $2 WHERE user_id = $1",
        user_id.to_string(),
        now
    )
    .await?;

    audit::log_event(
        state,
        Some(user_id),
        audit::events::MFA_ENABLED,
        audit::SEV_INFO,
        None,
        None,
        Some(json!({ "recovery_codes": 8 })),
    )
    .await;

    Ok(codes)
}

pub enum MfaChallengeOutcome {
    TotpOk,
    RecoveryUsed,
}

/// Verifie un challenge MFA pendant la connexion.
pub async fn verify_challenge(
    state: &AppState,
    user_id: &str,
    code: &str,
) -> AppResult<MfaChallengeOutcome> {
    let row = get_row(state, user_id)
        .await?
        .filter(|r| r.enabled)
        .ok_or_else(|| AppError::Unauthorized)?;

    let secret_hex = state.enc.decrypt(&row.secret_enc)?;
    if verify_totp_code(&secret_hex, code) {
        return Ok(MfaChallengeOutcome::TotpOk);
    }

    // Sinon : tentative de code de recuperation
    let mut hashes = load_recovery_hashes(state, &row).await?;
    let candidate = hmac_hash(&state.cfg.password_pepper, code.trim());
    if let Some(pos) = hashes.iter().position(|h| h == &candidate) {
        hashes.remove(pos);
        save_recovery_hashes(state, user_id, &hashes).await?;
        return Ok(MfaChallengeOutcome::RecoveryUsed);
    }

    Err(AppError::Unauthorized)
}
