//! Agrégations admin : IP suspectes et doubles comptes sur une même IP.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::FromRow;

use crate::db::Db;
use crate::error::AppResult;
use crate::models::{BlockedIp, LoginAttempt};
use crate::q_exec;
use crate::q_fetch_all;
use crate::q_fetch_optional;
use crate::state::AppState;

pub async fn list_blocked(db: &Db) -> AppResult<Vec<BlockedIp>> {
    q_fetch_all!(db, BlockedIp,
        "SELECT * FROM blocked_ips ORDER BY created_at DESC LIMIT 500")
        .await
}

pub async fn upsert_block(
    db: &Db,
    id: &str,
    ip: &str,
    mode: &str,
    reason: Option<&str>,
    created_by: &str,
    expires_at: Option<DateTime<Utc>>,
) -> AppResult<()> {
    let now = crate::util::now();
    q_exec!(db,
        "INSERT INTO blocked_ips (id, ip, mode, reason, created_by, created_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (ip) DO UPDATE SET mode = EXCLUDED.mode, reason = EXCLUDED.reason,
             created_by = EXCLUDED.created_by, created_at = EXCLUDED.created_at,
             expires_at = EXCLUDED.expires_at",
        id.to_string(), ip.to_string(), mode.to_string(),
        reason.map(|s| s.to_string()), created_by.to_string(),
        now, expires_at)
        .await?;
    Ok(())
}

pub async fn delete_block(db: &Db, ip: &str) -> AppResult<bool> {
    let found = !list_blocked(db).await?.iter().all(|b| b.ip != ip);
    if found {
        q_exec!(db, "DELETE FROM blocked_ips WHERE ip = $1", ip.to_string()).await?;
    }
    Ok(found)
}

#[derive(Debug, FromRow)]
struct DoubleUser {
    id: String,
    email: String,
    last_login_ip: Option<String>,
}

/// IP suspectes : echecs de login agreges sur 24 h.
pub async fn suspicious_ips(state: &AppState) -> AppResult<Value> {
    let cutoff = crate::util::now() - chrono::Duration::hours(24);
    let attempts: Vec<LoginAttempt> = q_fetch_all!(&state.db, LoginAttempt,
        "SELECT * FROM login_attempts WHERE created_at > $1", cutoff).await?;

    let mut agg: BTreeMap<String, (i64, i64)> = BTreeMap::new();
    for a in &attempts {
        if let Some(ip) = a.ip.clone() {
            let e = agg.entry(ip).or_insert((0, 0));
            e.1 += 1;
            if !a.success {
                e.0 += 1;
            }
        }
    }

    let threshold = state.settings.read().unwrap().suspicious_fail_threshold as i64;
    let blacklisted: Vec<String> = list_blocked(&state.db)
        .await?
        .iter()
        .filter(|b| b.mode == "blacklist")
        .map(|b| b.ip.clone())
        .collect();

    let mut rows: Vec<Value> = agg
        .into_iter()
        .filter(|(_, (fails, _))| *fails >= threshold)
        .map(|(ip, (fails, total))| json!({
            "ip": ip,
            "failed_logins_24h": fails,
            "total_attempts_24h": total,
            "blacklisted": blacklisted.contains(&ip),
        }))
        .collect();
    rows.sort_by_key(|r| -r["failed_logins_24h"].as_i64().unwrap_or(0));

    Ok(json!({ "threshold": threshold, "ips": rows.into_iter().take(200).collect::<Vec<_>>() }))
}

/// Doubles comptes : plusieurs users avec la meme derniere IP de login.
pub async fn double_accounts(state: &AppState) -> AppResult<Value> {
    let min = state.settings.read().unwrap().double_account_min;
    let users: Vec<DoubleUser> = q_fetch_all!(&state.db, DoubleUser,
        "SELECT id, email, last_login_ip FROM users
         WHERE deleted_at IS NULL AND last_login_ip IS NOT NULL")
        .await?;

    let mut groups: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    for u in users {
        if let Some(ip) = u.last_login_ip {
            groups.entry(ip).or_default().push((u.id, u.email));
        }
    }

    let rows: Vec<Value> = groups
        .into_iter()
        .filter(|(_, accs)| accs.len() as i64 >= min)
        .map(|(ip, accs)| json!({
            "ip": ip,
            "count": accs.len(),
            "accounts": accs.into_iter()
                .map(|(id, email)| json!({ "id": id, "email": email }))
                .collect::<Vec<_>>(),
        }))
        .collect();

    Ok(json!({ "min_accounts": min, "groups": rows }))
}
