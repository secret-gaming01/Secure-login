//! Tokens d'action (vérif email, reset password) + blacklist de jti.

use chrono::{DateTime, Utc};

use crate::crypto::tokens::{hmac_hash, secure_token};
use crate::db::Db;
use crate::error::{AppError, AppResult};
use crate::models::TokenRow;
use crate::q_exec;
use crate::q_fetch_optional;
use crate::util::{now, plus_secs};

/// Émet un token d'action : la valeur claire n'existe QUE côté client,
/// seul son hash HMAC est stocké.
pub async fn issue_action_token(
    db: &Db,
    pepper: &str,
    user_id: &str,
    kind: &str,
    ttl_secs: i64,
    meta: Option<&str>,
) -> AppResult<String> {
    let plain = secure_token();
    let hash = hmac_hash(pepper, &plain);
    let id = uuid::Uuid::new_v4().to_string();
    let created = now();
    let expires = plus_secs(ttl_secs);
    q_exec!(
        db,
        "INSERT INTO tokens (id, user_id, kind, value_hash, expires_at, used_at, created_at, meta)
         VALUES ($1, $2, $3, $4, $5, NULL, $6, $7)",
        id,
        user_id.to_string(),
        kind.to_string(),
        hash,
        expires,
        created,
        meta.map(|s| s.to_string())
    )
    .await?;
    Ok(plain)
}

/// Consomme un token d'action (usage unique). Retourne le user_id cible.
pub async fn consume_action_token(
    db: &Db,
    pepper: &str,
    plain: &str,
    kind: &str,
) -> AppResult<String> {
    let hash = hmac_hash(pepper, plain);
    let row = q_fetch_optional!(
        db,
        TokenRow,
        "SELECT * FROM tokens WHERE value_hash = $1 AND kind = $2 LIMIT 1",
        hash.clone(),
        kind.to_string()
    )
    .await?
    .ok_or_else(|| AppError::validation("Invalid or expired token"))?;

    if row.used_at.is_some() || row.expires_at < now() {
        return Err(AppError::validation("Invalid or expired token"));
    }

    let used: DateTime<Utc> = now();
    q_exec!(
        db,
        "UPDATE tokens SET used_at = $2 WHERE id = $1",
        row.id.clone(),
        used
    )
    .await?;

    Ok(row.user_id.unwrap_or_default())
}

/// Blackliste un jti (logout, logout-all, compromission).
pub async fn blacklist_jti(db: &Db, jti: &str, expires_at: DateTime<Utc>) -> AppResult<()> {
    let id = jti.to_string();
    let created = now();
    q_exec!(
        db,
        "INSERT INTO revoked_jti (jti, expires_at, created_at) VALUES ($1, $2, $3)",
        id,
        expires_at,
        created
    )
    .await?;
    Ok(())
}

pub async fn is_jti_revoked(db: &Db, jti: &str) -> AppResult<bool> {
    #[derive(sqlx::FromRow)]
    struct One {
        #[allow(dead_code)]
        jti: String,
    }
    let r = q_fetch_optional!(
        db,
        One,
        "SELECT jti FROM revoked_jti WHERE jti = $1 AND expires_at > $2 LIMIT 1",
        jti.to_string(),
        now()
    )
    .await?;
    Ok(r.is_some())
}
