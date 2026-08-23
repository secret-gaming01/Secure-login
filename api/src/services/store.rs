//! Stockage d'etat partage : memoire (mono-instance) ou Redis (multi-instance).
//!
//! Utilise pour :
//!   - le rate-limit global (fenetre fixe atomique)
//!   - les etats WebAuthn (challenges enregistrement/authentification)
//!
//! Selection automatique : si `REDIS_URL` est defini, Redis est utilise ;
//! sinon fallback memoire. Aucune dependance C (crate redis pure Rust).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use redis::AsyncCommands;

const RL_PREFIX: &str = "rl";
const WA_REG_PREFIX: &str = "wa:reg:";
const WA_AUTH_PREFIX: &str = "wa:auth:";

#[derive(Clone)]
pub enum Store {
    Memory(MemoryBackend),
    Redis(redis::aio::MultiplexedConnection),
}

#[derive(Default)]
pub struct MemoryBackend {
    /// cle -> (compteur, debut de fenetre)
    rl: Mutex<HashMap<String, (u64, Instant)>>,
    /// cle -> (valeur, expiration)
    kv: Mutex<HashMap<String, (String, Instant)>>,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Store::Memory(_) => write!(f, "Store::Memory"),
            Store::Redis(_) => write!(f, "Store::Redis"),
        }
    }
}

impl Store {
    /// Construit le store selon REDIS_URL (test de connexion au demarrage).
    pub async fn from_env() -> Store {
        match std::env::var("REDIS_URL") {
            Ok(url) if !url.trim().is_empty() => match redis::Client::open(url) {
                Ok(client) => match client.get_multiplexed_tokio_connection().await {
                    Ok(con) => {
                        tracing::info!("store: Redis actif (multi-instance)");
                        return Store::Redis(con);
                    }
                    Err(e) => tracing::error!("store: connexion Redis impossible ({e})"),
                },
                Err(e) => tracing::error!("store: REDIS_URL invalide ({e})"),
            },
            _ => {}
        }
        tracing::info!("store: memoire locale (mono-instance)");
        Store::Memory(MemoryBackend::default())
    }

    /// Fenetre fixe atomique : true = requete autorisee sous le plafond.
    pub async fn rl_hit(&self, key: &str, cap: u32, window_secs: u64) -> bool {
        let full = format!("{RL_PREFIX}:{key}");
        match self {
            Store::Memory(m) => {
                let mut map = m.rl.lock().unwrap();
                let now = Instant::now();
                let entry = map.entry(full).or_insert((0, now));
                if now.duration_since(entry.1) >= Duration::from_secs(window_secs) {
                    *entry = (0, now);
                }
                entry.0 += 1;
                entry.0 <= cap as u64
            }
            Store::Redis(mut con) => {
                let res: Result<(i64,), _> =
                    redis::pipe()
                        .atomic()
                        .incr(&full, 1i64)
                        .expire(&full, window_secs as i64)
                        .ignore()
                        .query_async(&mut con)
                        .await;
                match res {
                    Ok((n,)) => n <= cap as i64,
                    Err(e) => {
                        // fail-open documente : une panne Redis ne doit pas
                        // couper l'authentification ; le log alerte l'operateur
                        tracing::error!("store: rl redis indisponible ({e}), autorise");
                        true
                    }
                }
            }
        }
    }

    pub async fn kv_put(&self, key: &str, value: &str, ttl_secs: i64) {
        match self {
            Store::Memory(m) => {
                m.kv.lock().unwrap().insert(
                    key.to_string(),
                    (value.to_string(), Instant::now() + Duration::from_secs(ttl_secs as u64)),
                );
            }
            Store::Redis(mut con) => {
                let _: Result<(), _> = con
                    .set_ex(key, value, std::time::Duration::from_secs(ttl_secs as u64))
                    .await;
            }
        }
    }

    pub async fn kv_get(&self, key: &str) -> Option<String> {
        match self {
            Store::Memory(m) => {
                let mut map = m.kv.lock().unwrap();
                let keep = |e: &(String, Instant)| e.1 > Instant::now();
                if !map.get(key).map(keep).unwrap_or(false) {
                    map.remove(key);
                    return None;
                }
                map.get(key).map(|e| e.0.clone())
            }
            Store::Redis(mut con) => {
                let v: Option<String> = con.get(key).await.unwrap_or(None);
                v
            }
        }
    }

    /// Lecture destructive (usage unique).
    pub async fn kv_take(&self, key: &str) -> Option<String> {
        match self {
            Store::Memory(m) => {
                let mut map = m.kv.lock().unwrap();
                let expired = map.get(key).map(|e| e.1 <= Instant::now()).unwrap_or(true);
                if expired {
                    map.remove(key);
                    return None;
                }
                map.remove(key).map(|e| e.0)
            }
            Store::Redis(mut con) => match redis::cmd("GETDEL").arg(key).query_async::<Option<String>>(&mut con).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!("store: getdel ({e})");
                    None
                }
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Clefs WebAuthn partagees
// ---------------------------------------------------------------------------

pub fn wa_reg_key(user_id: &str) -> String {
    format!("{WA_REG_PREFIX}{user_id}")
}

pub fn wa_auth_key(challenge_id: &str) -> String {
    format!("{WA_AUTH_PREFIX}{challenge_id}")
}
