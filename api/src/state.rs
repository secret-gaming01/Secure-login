//! Ãƒâ€°tat applicatif partagÃƒÂ© (Arc).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use crate::config::Config;
use crate::crypto::encrypt::Encryptor;
use crate::crypto::jwt::JwtKeys;
use crate::db::Db;

#[cfg(feature = "webauthn")]
use webauthn_rs::prelude::{Webauthn, WebauthnBuilder};

#[cfg(feature = "webauthn")]
pub type WebAuthnInstance = Webauthn;
#[cfg(not(feature = "webauthn"))]
pub type WebAuthnInstance = ();

pub type GeoCache = Arc<Mutex<HashMap<String, (String, String, Instant)>>>;
pub type SharedStore = crate::services::store::Store;

/// ParamÃƒÂ¨tres runtime modifiables depuis le dashboard (page configuration).
#[derive(Debug, Clone)]
pub struct RuntimeSettingsInner {
    pub max_failed_logins: u32,
    pub lockout_base_secs: u64,
    pub suspicious_fail_threshold: u32,
    pub double_account_min: i64,
    pub rate_limit_per_min: u32,
}

impl Default for RuntimeSettingsInner {
    fn default() -> Self {
        Self {
            max_failed_logins: 5,
            lockout_base_secs: 900,
            suspicious_fail_threshold: 10,
            double_account_min: 2,
            rate_limit_per_min: 240,
        }
    }
}

pub type RuntimeSettings = Arc<RwLock<RuntimeSettingsInner>>;

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub cfg: Config,
    pub enc: Encryptor,
    pub jwt: JwtKeys,
    pub webauthn: WebAuthnInstance,
    pub geo_cache: GeoCache,
    pub store: SharedStore,

    pub settings: RuntimeSettings,
    pub mailer: crate::services::mailer::Mailer,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("db", &self.db)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "webauthn")]
pub fn build_webauthn(cfg: &Config) -> anyhow::Result<WebAuthnInstance> {
    let origin = url::Url::parse(&cfg.rp_origin)?;
    let builder = WebauthnBuilder::new(&cfg.rp_id, &origin)?;
    Ok(builder.build()?)
}

#[cfg(not(feature = "webauthn"))]
pub fn build_webauthn(_cfg: &Config) -> anyhow::Result<WebAuthnInstance> {
    Ok(())
}

/// Scopes dÃƒÂ©rivÃƒÂ©s du rÃƒÂ´le (modÃƒÂ¨le RBAC simple et vÃƒÂ©rifiable cÃƒÂ´tÃƒÂ© API).
pub fn scopes_for_role(role: &str) -> Vec<&'static str> {
    match role {
        "owner" => vec![
            "profile.read",
            "profile.write",
            "sessions.manage",
            "mfa.manage",
            "passkeys.manage",
            "users.read",
            "users.write",
            "users.delete",
            "ips.read",
            "ips.write",
            "logs.read",
            "sessions.admin",
            "stats.read",
            "config.read",
            "config.write",
        ],
        "admin" => vec![
            "profile.read",
            "profile.write",
            "sessions.manage",
            "mfa.manage",
            "passkeys.manage",
            "users.read",
            "users.write",
            "ips.read",
            "ips.write",
            "logs.read",
            "sessions.admin",
            "stats.read",
            "config.read",
        ],
        _ => vec![
            "profile.read",
            "profile.write",
            "sessions.manage",
            "mfa.manage",
            "passkeys.manage",
        ],
    }
}
