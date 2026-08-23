//! Structures SQL mappÃ©es via sqlx::FromRow â€” compatibles PG & SQLite.

use chrono::{DateTime, Utc};
use sqlx::FromRow;

#[derive(Debug, Clone, FromRow, serde::Serialize)]
pub struct User {
    pub id: String,
    pub email: String,
    pub password_hash: Option<String>,
    pub salt: String,
    pub email_verified: bool,
    pub role: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub last_login_at: Option<DateTime<Utc>>,
    pub last_login_ip: Option<String>,
    pub last_login_country: Option<String>,
    pub last_login_device: Option<String>,
}

#[derive(Debug, Clone, FromRow, serde::Serialize)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub refresh_hash: String,
    pub device: Option<String>,
    pub fingerprint: Option<String>,
    pub ip: Option<String>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
}

#[derive(Debug, Clone, FromRow, serde::Serialize)]
pub struct TokenRow {
    pub id: String,
    pub user_id: Option<String>,
    pub kind: String,
    pub value_hash: String,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub meta: Option<String>,
}

#[derive(Debug, Clone, FromRow, serde::Serialize)]
pub struct BlockedIp {
    pub id: String,
    pub ip: String,
    pub mode: String,
    pub reason: Option<String>,
    pub created_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, FromRow, serde::Serialize)]
pub struct PasskeyRow {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub credential_id: String,
    pub public_key_enc: String,
    pub counter: i64,
    pub transports: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, FromRow, serde::Serialize)]
pub struct MfaRow {
    pub user_id: String,
    pub secret_enc: String,
    pub enabled: bool,
    pub recovery_codes_enc: Option<String>,
    pub confirmed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, serde::Serialize)]
pub struct SecurityLog {
    pub id: String,
    pub user_id: Option<String>,
    pub event: String,
    pub severity: String,
    pub ip: Option<String>,
    pub country: Option<String>,
    pub details_enc: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, serde::Serialize)]
pub struct LoginAttempt {
    pub id: String,
    pub email: Option<String>,
    pub ip: Option<String>,
    pub success: bool,
    pub created_at: DateTime<Utc>,
}
