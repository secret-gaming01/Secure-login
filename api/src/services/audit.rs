//! Journal de sécurité — détails chiffrés AES-256-GCM au repos.

use serde_json::Value;

use crate::q_exec;
use crate::state::AppState;

pub const SEV_INFO: &str = "info";
pub const SEV_WARN: &str = "warn";
pub const SEV_CRITICAL: &str = "critical";

/// Événements standards
pub mod events {
    pub const REGISTER: &str = "register";
    pub const LOGIN_SUCCESS: &str = "login_success";
    pub const LOGIN_FAILED: &str = "login_failed";
    pub const LOGIN_LOCKED: &str = "login_locked";
    pub const LOGOUT: &str = "logout";
    pub const LOGOUT_ALL: &str = "logout_all";
    pub const EMAIL_VERIFIED: &str = "email_verified";
    pub const PASSWORD_CHANGED: &str = "password_changed";
    pub const PASSWORD_RESET: &str = "password_reset";
    pub const EMAIL_CHANGED: &str = "email_changed";
    pub const ACCOUNT_DELETED: &str = "account_deleted";
    pub const MFA_ENABLED: &str = "mfa_enabled";
    pub const MFA_CHALLENGE_OK: &str = "mfa_challenge_ok";
    pub const MFA_CHALLENGE_FAILED: &str = "mfa_challenge_failed";
    pub const PASSKEY_ADDED: &str = "passkey_added";
    pub const PASSKEY_LOGIN: &str = "passkey_login";
    pub const REFRESH_ROTATED: &str = "refresh_rotated";
    pub const REFRESH_REUSE_DETECTED: &str = "refresh_reuse_detected";
    pub const UNUSUAL_LOGIN_COUNTRY: &str = "unusual_login_country";
    pub const UNUSUAL_LOGIN_DEVICE: &str = "unusual_login_device";
    pub const IP_BLOCKED: &str = "ip_blocked";
}

/// Enregistre un événement (ne fait jamais échouer la requête appelante).
pub async fn log_event(
    state: &AppState,
    user_id: Option<&str>,
    event: &str,
    severity: &str,
    ip: Option<&str>,
    country: Option<&str>,
    details: Option<Value>,
) {
    let id = uuid::Uuid::new_v4().to_string();
    let now = crate::util::now();
    let details_enc = match details {
        Some(v) => state.enc.encrypt(&v.to_string()).ok(),
        None => None,
    };
    let result = q_exec!(
        &state.db,
        "INSERT INTO security_logs (id, user_id, event, severity, ip, country, details_enc, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        id,
        user_id.map(|s| s.to_string()),
        event.to_string(),
        severity.to_string(),
        ip.map(|s| s.to_string()),
        country.map(|s| s.to_string()),
        details_enc,
        now
    )
    .await;
    if let Err(e) = result {
        tracing::warn!("security_logs insert failed: {e}");
    }
}
