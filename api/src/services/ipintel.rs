//! Renseignement IP : blacklist/whitelist + géolocalisation approximative
//! (service gratuit ip-api.com, mis en cache 1 h en mémoire).

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::db::Db;
use crate::error::AppResult;
use crate::q_fetch_optional;
use crate::state::AppState;

#[derive(Debug, FromRow)]
struct ModeRow {
    mode: String,
}

/// Retourne Some("blacklist"|"whitelist") si l'IP a une entrée active.
pub async fn ip_mode(db: &Db, ip: &str) -> AppResult<Option<String>> {
    let now: DateTime<Utc> = crate::util::now();
    let row = q_fetch_optional!(
        db,
        ModeRow,
        "SELECT mode FROM blocked_ips WHERE ip = $1 AND (expires_at IS NULL OR expires_at > $2) LIMIT 1",
        ip.to_string(),
        now
    )
    .await?;
    Ok(row.map(|r| r.mode))
}

fn is_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.octets()[0] == 100 && v4.octets()[1] == 64 // CGNAT
                || v4.is_broadcast()
                || v4.is_unspecified()
        }
        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

#[derive(serde::Deserialize)]
struct IpApiResp {
    status: String,
    #[serde(default)]
    country: String,
    #[serde(default)]
    city: String,
}

/// Géolocalisation approximative avec cache mémoire (TTL 1 h).
pub async fn geo_lookup(state: &AppState, ip: &str) -> Option<(String, String)> {
    if !state.cfg.geo_enabled {
        return None;
    }
    let parsed: IpAddr = ip.parse().ok()?;
    if is_private(&parsed) {
        return Some(("Local".into(), "Local network".into()));
    }

    if let Some((c, city, at)) = state.geo_cache.lock().unwrap().get(ip).cloned() {
        if at.elapsed() < Duration::from_secs(3600) {
            return Some((c, city));
        }
    }

    let url = format!("http://ip-api.com/json/{}?fields=status,country,city", ip);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .ok()?;
    let resp: IpApiResp = client.get(url).send().await.ok()?.json().await.ok()?;
    if resp.status != "success" {
        return None;
    }
    state
        .geo_cache
        .lock()
        .unwrap()
        .insert(ip.to_string(), (resp.country.clone(), resp.city.clone(), Instant::now()));
    Some((resp.country, resp.city))
}
