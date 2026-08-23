//! Sessions : device + IP tracking, rotation des refresh tokens,
//! révocation individuelle / globale.

use chrono::{DateTime, Utc};
use sqlx::FromRow;

use crate::db::Db;
use crate::error::AppResult;
use crate::models::Session;
use crate::q_exec;
use crate::q_fetch_all;
use crate::q_fetch_optional;

#[derive(Debug, FromRow, serde::Serialize)]
pub struct AdminSession {
    pub id: String,
    pub user_id: String,
    pub email: String,
    pub device: Option<String>,
    pub ip: Option<String>,
    pub country: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
}

pub async fn create_session(
    db: &Db,
    id: &str,
    user_id: &str,
    refresh_hash: &str,
    device: &str,
    fingerprint: &str,
    ip: &str,
    country: Option<&str>,
    city: Option<&str>,
    ttl_secs: i64,
) -> AppResult<()> {
    let now: DateTime<Utc> = crate::util::now();
    let expires = now + chrono::Duration::seconds(ttl_secs);
    q_exec!(
        db,
        "INSERT INTO sessions (id, user_id, refresh_hash, device, fingerprint, ip, country, city, created_at, last_seen_at, expires_at, revoked)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, FALSE)",
        id.to_string(),
        user_id.to_string(),
        refresh_hash.to_string(),
        device.to_string(),
        fingerprint.to_string(),
        ip.to_string(),
        country.map(|s| s.to_string()),
        city.map(|s| s.to_string()),
        now,
        now,
        expires
    )
    .await?;
    Ok(())
}

pub async fn find_by_refresh_hash(db: &Db, hash: &str) -> AppResult<Option<Session>> {
    q_fetch_optional!(
        db,
        Session,
        "SELECT * FROM sessions WHERE refresh_hash = $1 LIMIT 1",
        hash.to_string()
    )
    .await
}

/// Rotation du refresh token. Détecte la réutilisation (replay) :
/// un refresh déjà consommé qui revient => compromission probable.
pub enum RotateOutcome {
    Rotated(Box<Session>),
    Invalid,
    /// Refresh déjà utilisé une fois → on révoque TOUTES les sessions.
    ReuseDetected(String),
}

pub async fn rotate_refresh(db: &Db, presented_hash: &str, new_hash: &str, ttl_secs: i64) -> AppResult<RotateOutcome> {
    let session = match find_by_refresh_hash(db, presented_hash).await? {
        Some(s) => s,
        None => return Ok(RotateOutcome::Invalid),
    };

    if session.revoked || session.expires_at < crate::util::now() {
        return Ok(RotateOutcome::Invalid);
    }

    // Le refresh a-t-il déjà été remplacé ? (il existe une trace "rotated")
    let already_rotated = was_refresh_rotated(db, presented_hash).await?;
    if already_rotated {
        revoke_all_for_user(db, &session.user_id).await?;
        return Ok(RotateOutcome::ReuseDetected(session.user_id));
    }

    let now: DateTime<Utc> = crate::util::now();
    let expires = now + chrono::Duration::seconds(ttl_secs);
    q_exec!(
        db,
        "UPDATE sessions SET refresh_hash = $2, last_seen_at = $3, expires_at = $4 WHERE id = $1",
        session.id.clone(),
        new_hash.to_string(),
        now,
        expires
    )
    .await?;

    // Trace anti-replay : l'ancien refresh ne doit plus jamais être accepté
    let tid = uuid::Uuid::new_v4().to_string();
    q_exec!(
        db,
        "INSERT INTO tokens (id, user_id, kind, value_hash, expires_at, used_at, created_at)
         VALUES ($1, $2, 'refresh_rotated', $3, $4, $5, $6)",
        tid,
        session.user_id.clone(),
        presented_hash.to_string(),
        expires,
        now,
        now
    )
    .await?;

    Ok(RotateOutcome::Rotated(Box::new(session)))
}

async fn was_refresh_rotated(db: &Db, hash: &str) -> AppResult<bool> {
    #[derive(FromRow)]
    struct One {
        #[allow(dead_code)]
        id: String,
    }
    let r = q_fetch_optional!(
        db,
        One,
        "SELECT id FROM tokens WHERE value_hash = $1 AND kind = 'refresh_rotated' LIMIT 1",
        hash.to_string()
    )
    .await?;
    Ok(r.is_some())
}

pub async fn revoke_session(db: &Db, sid: &str) -> AppResult<bool> {
    let before = count_active(db, sid).await?;
    let now: DateTime<Utc> = crate::util::now();
    q_exec!(
        db,
        "UPDATE sessions SET revoked = TRUE WHERE id = $1 AND revoked = FALSE AND expires_at > $2",
        sid.to_string(),
        now
    )
    .await?;
    Ok(before > 0)
}

async fn count_active(db: &Db, sid: &str) -> AppResult<i64> {
    #[derive(FromRow)]
    struct C {
        c: i64,
    }
    let row = q_fetch_optional!(
        db,
        C,
        "SELECT COUNT(*) AS c FROM sessions WHERE id = $1 AND revoked = FALSE",
        sid.to_string()
    )
    .await?;
    Ok(row.map(|r| r.c).unwrap_or(0))
}

pub async fn revoke_all_for_user(db: &Db, user_id: &str) -> AppResult<u64> {
    let active = active_session_count(db, user_id).await?;
    q_exec!(
        db,
        "UPDATE sessions SET revoked = TRUE WHERE user_id = $1 AND revoked = FALSE",
        user_id.to_string()
    )
    .await?;
    Ok(active as u64)
}

pub async fn active_session_count(db: &Db, user_id: &str) -> AppResult<i64> {
    #[derive(FromRow)]
    struct C {
        c: i64,
    }
    let now: DateTime<Utc> = crate::util::now();
    let row = q_fetch_optional!(
        db,
        C,
        "SELECT COUNT(*) AS c FROM sessions WHERE user_id = $1 AND revoked = FALSE AND expires_at > $2",
        user_id.to_string(),
        now
    )
    .await?;
    Ok(row.map(|r| r.c).unwrap_or(0))
}

pub async fn list_user_sessions(db: &Db, user_id: &str) -> AppResult<Vec<Session>> {
    q_fetch_all!(
        db,
        Session,
        "SELECT * FROM sessions WHERE user_id = $1 ORDER BY last_seen_at DESC LIMIT 100",
        user_id.to_string()
    )
    .await
}

pub async fn list_admin_sessions(db: &Db, limit: i64, offset: i64) -> AppResult<Vec<AdminSession>> {
    q_fetch_all!(
        db,
        AdminSession,
        "SELECT s.id, s.user_id, u.email, s.device, s.ip, s.country, s.created_at, s.last_seen_at, s.expires_at, s.revoked
         FROM sessions s JOIN users u ON u.id = s.user_id
         WHERE s.revoked = FALSE AND s.expires_at > $3
         ORDER BY s.last_seen_at DESC
         LIMIT $1 OFFSET $2",
        limit,
        offset,
        crate::util::now()
    )
    .await
}

pub async fn touch(db: &Db, sid: &str) -> AppResult<()> {
    let now: DateTime<Utc> = crate::util::now();
    q_exec!(
        db,
        "UPDATE sessions SET last_seen_at = $2 WHERE id = $1",
        sid.to_string(),
        now
    )
    .await?;
    Ok(())
}
