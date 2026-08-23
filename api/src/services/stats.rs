//! Statistiques, logs (dechiffres pour l'admin) et configuration runtime.

use serde_json::{json, Value};
use sqlx::FromRow;

use crate::error::AppResult;
use crate::models::SecurityLog;
use crate::q_fetch_all;
use crate::q_scalar;
use crate::state::AppState;

#[derive(Debug, FromRow)]
struct OnlyCreated {
    created_at: chrono::DateTime<chrono::Utc>,
}

/// Serie d'activite journaliere : connexions OK / echecs / inscriptions.
pub async fn activity(state: &AppState, days: i64) -> AppResult<Value> {
    let since = crate::util::now() - chrono::Duration::days(days.max(1).min(90));

    #[derive(FromRow)]
    struct AttemptRow {
        success: bool,
        created_at: chrono::DateTime<chrono::Utc>,
    }
    let attempts: Vec<AttemptRow> = q_fetch_all!(&state.db, AttemptRow,
        "SELECT success, created_at FROM login_attempts WHERE created_at > $1", since).await?;

    let registrations: Vec<OnlyCreated> = q_fetch_all!(&state.db, OnlyCreated,
        "SELECT created_at FROM users WHERE deleted_at IS NULL AND created_at > $1", since).await?;

    let mut buckets: std::collections::BTreeMap<String, [i64; 3]> = Default::default();
    for a in &attempts {
        let day = a.created_at.date_naive().to_string();
        let b = buckets.entry(day).or_insert([0, 0, 0]);
        if a.success { b[0] += 1 } else { b[1] += 1 }
    }
    for r in &registrations {
        let day = r.created_at.date_naive().to_string();
        buckets.entry(day).or_insert([0, 0, 0])[2] += 1;
    }

    let rows: Vec<Value> = buckets
        .into_iter()
        .map(|(day, v)| json!({ "day": day, "logins": v[0], "failures": v[1], "registrations": v[2] }))
        .collect();

    Ok(json!({ "days": rows }))
}

pub async fn overview(state: &AppState) -> AppResult<Value> {
    let users = q_scalar!(&state.db,
        "SELECT COUNT(*) FROM users WHERE deleted_at IS NULL").await?;
    let cutoff = crate::util::now() - chrono::Duration::hours(24);
    let sessions = q_scalar!(&state.db,
        "SELECT COUNT(*) FROM sessions WHERE revoked = FALSE AND expires_at > $1", cutoff).await?;
    let blocked = q_scalar!(&state.db,
        "SELECT COUNT(*) FROM blocked_ips WHERE mode = 'blacklist'").await?;
    let fails24h = q_scalar!(&state.db,
        "SELECT COUNT(*) FROM login_attempts WHERE success = FALSE AND created_at > $1", cutoff).await?;

    Ok(json!({
        "users": users,
        "active_sessions": sessions,
        "blocked_ips": blocked,
        "failed_logins_24h": fails24h,
    }))
}

/// Logs de securite ; les details chiffres sont dechiffres cote admin.
pub async fn logs(state: &AppState, limit: i64, offset: i64) -> AppResult<Vec<Value>> {
    let rows: Vec<SecurityLog> = q_fetch_all!(&state.db, SecurityLog,
        "SELECT * FROM security_logs ORDER BY created_at DESC LIMIT $1 OFFSET $2",
        limit.min(500), offset).await?;

    Ok(rows
        .into_iter()
        .map(|r| {
            let details = r
                .details_enc
                .as_deref()
                .and_then(|enc| state.enc.decrypt(enc).ok())
                .and_then(|plain| serde_json::from_str::<Value>(&plain).ok());
            json!({
                "id": r.id,
                "user_id": r.user_id,
                "event": r.event,
                "severity": r.severity,
                "ip": r.ip,
                "country": r.country,
                "details": details.unwrap_or(Value::Null),
                "created_at": r.created_at,
            })
        })
        .collect())
}

// ---------------------------------------------------------------------------
// Configuration runtime (dashboard)
// ---------------------------------------------------------------------------

pub fn config_get(state: &AppState) -> Value {
    let s = state.settings.read().unwrap();
    json!({
        "max_failed_logins": s.max_failed_logins,
        "lockout_base_secs": s.lockout_base_secs,
        "suspicious_fail_threshold": s.suspicious_fail_threshold,
        "double_account_min": s.double_account_min,
        "rate_limit_per_min": s.rate_limit_per_min,
        "geo_enabled": state.cfg.geo_enabled,
        "captcha_configured": crate::services::captcha::is_configured(state),
        "access_token_ttl_secs": state.cfg.access_token_ttl_secs,
        "refresh_token_ttl_secs": state.cfg.refresh_token_ttl_secs,
    })
}

pub fn config_update(
    state: &AppState,
    body: &serde_json::Value,
) {
    let mut s = state.settings.write().unwrap();
    if let Some(v) = body.get("max_failed_logins").and_then(|v| v.as_u64()) {
        s.max_failed_logins = v.clamp(1, 100) as u32;
    }
    if let Some(v) = body.get("lockout_base_secs").and_then(|v| v.as_u64()) {
        s.lockout_base_secs = v.clamp(60, 86400);
    }
    if let Some(v) = body.get("suspicious_fail_threshold").and_then(|v| v.as_u64()) {
        s.suspicious_fail_threshold = v.clamp(3, 10000) as u32;
    }
    if let Some(v) = body.get("double_account_min").and_then(|v| v.as_i64()) {
        s.double_account_min = v.clamp(2, 100);
    }
    if let Some(v) = body.get("rate_limit_per_min").and_then(|v| v.as_u64()) {
        s.rate_limit_per_min = v.clamp(10, 100000) as u32;
    }
}
