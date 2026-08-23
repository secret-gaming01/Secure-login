//! Flux de connexion : anti-bruteforce persistant, captcha adaptatif,
//! détection de connexions inhabituelles (pays/device), création de session.

use serde_json::json;

use axum::http::HeaderMap;

use crate::crypto::{
    hash as pw,
    jwt::{Claims, TYPE_ACCESS, TYPE_MFA_PENDING},
    tokens as tok,
};
use crate::error::{AppError, AppResult};
use crate::extract::{header_str, AuthCtx};
use crate::models::User;
use crate::q_fetch_all;
use crate::services::{audit, captcha, ipintel, sessions, tokens_svc, users};
use crate::state::{scopes_for_role, AppState};
use crate::util::{device_label, fingerprint, now};

#[derive(Debug, serde::Serialize)]
pub struct LoginSuccess {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub user: serde_json::Value,
}

/// Tente une connexion complète (mot de passe déjà vérifié par l'appelant).
pub async fn complete_login(
    state: &AppState,
    user: &User,
    ip: &str,
    user_agent: &str,
    accept_language: &str,
) -> AppResult<LoginSuccess> {
    let device = device_label(user_agent);
    let fp = fingerprint(user_agent, accept_language);
    let geo = ipintel::geo_lookup(state, ip).await;
    let country = geo.as_ref().map(|g| g.0.clone());
    let city = geo.as_ref().map(|g| g.1.clone());

    // --- Détection de connexions inhabituelles ---
    detect_unusual(state, &user.id, &fp, country.as_deref()).await;

    // --- Création session + tokens ---
    let refresh_plain = tok::secure_token();
    let refresh_hash = tok::hmac_hash(&state.cfg.password_pepper, &refresh_plain);
    let sid = uuid::Uuid::new_v4().to_string();

    crate::services::sessions::create_session(
        &state.db,
        &sid,
        &user.id,
        &refresh_hash,
        &device,
        &fp,
        ip,
        country.as_deref().or(user.last_login_country.as_deref()),
        city.as_deref(),
        state.cfg.refresh_token_ttl_secs,
    )
    .await?;

    let access = issue_access_token(state, &user.id, &user.role, Some(&sid))?;

    crate::services::sessions::touch_login(&state.db, &user.id, ip, country.as_deref(), &device)
        .await?;
    record_attempt(state, Some(&user.email), ip, true).await;
    audit::log_event(
        state,
        Some(&user.id),
        audit::events::LOGIN_SUCCESS,
        audit::SEV_INFO,
        Some(ip),
        country.as_deref(),
        Some(json!({ "device": device })),
    )
    .await;

    Ok(LoginSuccess {
        access_token: access.0,
        refresh_token: refresh_plain,
        token_type: "Bearer".into(),
        expires_in: access.1,
        user: public_user(user),
    })
}

/// Signe un access token HS512 court.
pub fn issue_access_token(
    state: &AppState,
    user_id: &str,
    role: &str,
    sid: Option<&str>,
) -> AppResult<(String, i64)> {
    let ttl = state.cfg.access_token_ttl_secs;
    let nowts = chrono::Utc::now();
    let claims = Claims {
        sub: user_id.to_string(),
        sid: sid.map(|s| s.to_string()),
        role: role.to_string(),
        scopes: scopes_for_role(role).iter().map(|s| s.to_string()).collect(),
        jti: uuid::Uuid::new_v4().to_string(),
        typ: TYPE_ACCESS.into(),
        iat: nowts.timestamp(),
        exp: (nowts + chrono::Duration::seconds(ttl)).timestamp(),
        iss: String::new(), // rempli par JwtKeys::sign
        aud: String::new(),
    };
    let token = state
        .jwt
        .sign(claims)
        .map_err(|e| AppError::internal(format!("jwt sign: {e}")))?;
    Ok((token, ttl))
}

pub fn public_user(u: &User) -> serde_json::Value {
    json!({
        "id": u.id,
        "email": u.email,
        "role": u.role,
        "email_verified": u.email_verified,
        "created_at": u.created_at,
        "last_login_at": u.last_login_at,
    })
}

// ---------------------------------------------------------------------------
// Anti-bruteforce persistant
// ---------------------------------------------------------------------------

pub async fn record_attempt(state: &AppState, email: Option<&str>, ip: &str, success: bool) {
    let id = uuid::Uuid::new_v4().to_string();
    let created = now();
    let _ = crate::q_exec!(
        &state.db,
        "INSERT INTO login_attempts (id, email, ip, success, created_at) VALUES ($1, $2, $3, $4, $5)",
        id,
        email.map(|s| s.to_string()),
        ip.to_string(),
        success,
        created
    )
    .await;
}

async fn failures_since(state: &AppState, column: &str, key: &str, cutoff: chrono::DateTime<chrono::Utc>) -> AppResult<i64> {
    // column est une constante compile-time ("ip" / "email") — pas d'injection
    let sql = format!(
        "SELECT COUNT(*) FROM login_attempts WHERE {column} = $1 AND success = FALSE AND created_at > $2"
    );
    let n = crate::q_scalar!(&state.db, sql.as_str(), key.to_string(), cutoff).await?;
    Ok(n)
}

async fn last_failure_time(state: &AppState, column: &str, key: &str) -> AppResult<Option<chrono::DateTime<chrono::Utc>>> {
    #[derive(sqlx::FromRow)]
    struct Row {
        created_at: chrono::DateTime<chrono::Utc>,
    }
    let sql = format!(
        "SELECT created_at FROM login_attempts WHERE {column} = $1 AND success = FALSE ORDER BY created_at DESC LIMIT 1"
    );
    Ok(q_fetch_all!(&state.db, Row, sql.as_str(), key.to_string())
        .await?
        .into_iter()
        .next()
        .map(|r| r.created_at))
}

/// Vérifie le verrouillage bruteforce pour une identité (email ou IP).
/// Retourne Err(RateLimited) si cooldown actif.
pub async fn enforce_lockout(state: &AppState, email: Option<&str>, ip: &str) -> AppResult<()> {
    let settings = state.settings.read().unwrap().clone();
    let window_end = now() - chrono::Duration::minutes(15);

    for (col, key) in [("email", email), ("ip", Some(ip))] {
        let key = match key {
            Some(k) => k,
            None => continue,
        };
        let fails = failures_since(state, col, key, window_end).await?;
        if fails < settings.max_failed_logins as i64 {
            continue;
        }
        // Cooldown exponentiel : base * 2^(excès), cap 24 h
        let excess = (fails - settings.max_failed_logins as i64).min(6);
        let mut cooldown = settings.lockout_base_secs as f64 * 2f64.powi(excess as i32);
        if cooldown > 86_400.0 {
            cooldown = 86_400.0;
        }
        if let Some(last) = last_failure_time(state, col, key).await? {
            let unlock_at = last + chrono::Duration::seconds(cooldown as i64);
            if now() < unlock_at {
                let remaining = (unlock_at - now()).num_seconds().max(1);
                audit::log_event(
                    state,
                    None,
                    audit::events::LOGIN_LOCKED,
                    audit::SEV_WARN,
                    Some(ip),
                    None,
                    Some(json!({ "identity": key, "field": col, "remaining_secs": remaining })),
                )
                .await;
                return Err(AppError::RateLimited(format!(
                    "Too many failed attempts. Retry in ~{remaining}s"
                )));
            }
        }
    }
    Ok(())
}

/// Exige un captcha si configuré et si ≥ 3 échecs récents sur l'IP.
pub async fn enforce_captcha(state: &AppState, ip: &str, provided: Option<&str>) -> AppResult<()> {
    if !captcha::is_configured(state) {
        return Ok(());
    }
    let recent = failures_since(state, "ip", ip, now() - chrono::Duration::minutes(15)).await?;
    if recent >= 3 {
        captcha::verify(state, provided, ip).await?;
    }
    Ok(())
}

fn timing_equalize(user_exists: bool) {
    if !user_exists {
        pw::timing_equalizer();
    }
}

/// Vérifie mot de passe avec égalisation de timing.
pub async fn verify_credentials(state: &AppState, email: &str, password: &str) -> AppResult<User> {
    let user = crate::services::users::find_by_email(&state.db, email)
        .await?
        .filter(|u| u.password_hash.is_some());

    match &user {
        Some(u) => {
            let ok = pw::verify_password(password, &state.cfg.password_pepper, u.password_hash.as_deref().unwrap_or(""));
            if !ok {
                return Err(AppError::Unauthorized);
            }
        }
        None => {
            timing_equalize(false);
            return Err(AppError::Unauthorized);
        }
    }

    Ok(user.unwrap())
}

async fn detect_unusual(state: &AppState, user_id: &str, fp: &str, country: Option<&str>) {
    let sessions = crate::services::sessions::list_user_sessions(&state.db, user_id)
        .await
        .unwrap_or_default();

    let known_countries: Vec<String> =
        sessions.iter().filter_map(|s| s.country.clone()).collect();
    let known_fps: Vec<String> =
        sessions.iter().filter_map(|s| s.fingerprint.clone()).collect();

    if let Some(c) = country {
        if !known_countries.is_empty() && !known_countries.contains(&c.to_string()) {
            audit::log_event(
                state,
                Some(user_id),
                audit::events::UNUSUAL_LOGIN_COUNTRY,
                audit::SEV_WARN,
                None,
                Some(c),
                Some(json!({ "known": known_countries.len() })),
            )
            .await;
        }
    }
    if !known_fps.is_empty() && !known_fps.iter().any(|f| f == fp) {
        audit::log_event(
            state,
            Some(user_id),
            audit::events::UNUSUAL_LOGIN_DEVICE,
            audit::SEV_INFO,
            None,
            country,
            Some(json!({ "new_fingerprint": fp })),
        )
        .await;
    }
}

// ---------------------------------------------------------------------------
// Garde d'authentification + tokens MFA pending
// ---------------------------------------------------------------------------

/// Extrait et valide le JWT access du header Authorization.
/// Verifie : signature HS512, type, expiration, jti non blacklist,
/// utilisateur existant (non supprime).
pub async fn require_auth(state: &AppState, headers: &HeaderMap) -> AppResult<(AuthCtx, User)> {
    let token = header_str(headers, "authorization")
        .and_then(|v| v.strip_prefix("Bearer ").map(|s| s.trim().to_string()))
        .filter(|t| !t.is_empty())
        .ok_or(AppError::Unauthorized)?;

    let claims = state.jwt.verify(&token).map_err(|_| AppError::Unauthorized)?;
    if claims.typ != TYPE_ACCESS {
        return Err(AppError::Unauthorized);
    }
    if tokens_svc::is_jti_revoked(&state.db, &claims.jti).await? {
        return Err(AppError::Unauthorized);
    }

    let user = users::require_user(&state.db, &claims.sub).await?;

    if let Some(sid) = &claims.sid {
        let _ = sessions::touch(&state.db, sid).await;
    }

    Ok((
        AuthCtx {
            user_id: claims.sub,
            role: claims.role,
            scopes: claims.scopes,
            sid: claims.sid,
            jti: claims.jti,
        },
        user,
    ))
}

/// Token court (5 min) autorisant la finalisation d'un login MFA.
pub fn issue_mfa_pending(state: &AppState, user_id: &str) -> AppResult<String> {
    let ttl: i64 = 300;
    let nowts = chrono::Utc::now();
    let claims = Claims {
        sub: user_id.to_string(),
        sid: None,
        role: "user".into(),
        scopes: vec![],
        jti: uuid::Uuid::new_v4().to_string(),
        typ: TYPE_MFA_PENDING.into(),
        iat: nowts.timestamp(),
        exp: (nowts + chrono::Duration::seconds(ttl)).timestamp(),
        iss: String::new(),
        aud: String::new(),
    };
    state
        .jwt
        .sign(claims)
        .map_err(|e| AppError::internal(format!("jwt sign: {e}")))
}
