//! Routes /auth : login (+MFA), refresh rotation, logout, logout-all.

use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;

use crate::crypto::jwt::TYPE_MFA_PENDING;
use crate::error::{AppError, AppResult};
use crate::extract::{client_ip, header_str};
use crate::services::{audit, auth_flow, mfa, sessions, tokens_svc};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/login", post(login))
        .route("/auth/mfa/enable", post(mfa_enable))
        .route("/auth/mfa/verify", post(mfa_verify))
        .route("/auth/token/refresh", post(token_refresh))
        .route("/auth/logout", post(logout))
        .route("/auth/logout-all", post(logout_all))
}

#[derive(Deserialize)]
struct LoginReq {
    email: String,
    password: String,
    #[serde(default)]
    captcha_token: Option<String>,
}

async fn login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<LoginReq>,
) -> AppResult<Json<serde_json::Value>> {
    let ip = client_ip(&headers, addr, state.cfg.trust_proxy);
    let email = body.email.trim().to_lowercase();

    auth_flow::enforce_lockout(&state, Some(&email), &ip).await?;
    auth_flow::enforce_captcha(&state, &ip, body.captcha_token.as_deref()).await?;

    let user = match auth_flow::verify_credentials(&state, &email, &body.password).await {
        Ok(u) => u,
        Err(_) => {
            auth_flow::record_attempt(&state, Some(&email), &ip, false).await;
            audit::log_event(
                &state,
                None,
                audit::events::LOGIN_FAILED,
                audit::SEV_WARN,
                Some(&ip),
                None,
                Some(json!({ "email_domain": email.split('@').nth(1).unwrap_or("?") })),
            )
            .await;
            return Err(AppError::Unauthorized);
        }
    };

    // MFA actif ? -> challenge intermediaire (token 5 min)
    if mfa::is_enabled(&state, &user.id).await? {
        let mfa_token = auth_flow::issue_mfa_pending(&state, &user.id)?;
        return Ok(Json(json!({ "mfa_required": true, "mfa_token": mfa_token })));
    }

    let ua = header_str(&headers, "user-agent").unwrap_or("");
    let lang = header_str(&headers, "accept-language").unwrap_or("");
    let success = auth_flow::complete_login(&state, &user, &ip, ua, lang).await?;
    Ok(Json(serde_json::to_value(success)?))
}

// --- MFA -------------------------------------------------------------------

async fn mfa_enable(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let (ctx, user) = auth_flow::require_auth(&state, &headers).await?;
    ctx.require_scope("mfa.manage")?;
    let (url, secret_b32) = mfa::setup(&state, &ctx.user_id, &user.email).await?;
    Ok(Json(json!({
        "otpauth_url": url,
        "secret": secret_b32,
        "issuer": state.cfg.mfa_issuer,
    })))
}

#[derive(Deserialize)]
struct MfaVerifyReq {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    mfa_token: Option<String>,
}

/// Double usage :
/// - Avec Authorization (session active) : confirme l'ACTIVATION du MFA.
/// - Avec mfa_token (login en cours)     : finalise la CONNEXION.
async fn mfa_verify(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<MfaVerifyReq>,
) -> AppResult<Json<serde_json::Value>> {
    let ip = client_ip(&headers, addr, state.cfg.trust_proxy);
    let code = body.code.clone().unwrap_or_default();

    if headers.contains_key("authorization") {
        let (ctx, _user) = auth_flow::require_auth(&state, &headers).await?;
        ctx.require_scope("mfa.manage")?;
        let codes = mfa::confirm(&state, &ctx.user_id, &code).await?;
        return Ok(Json(json!({
            "enabled": true,
            "recovery_codes": codes,
            "note": "Store these recovery codes safely, they are shown only once.",
        })));
    }

    let raw = body.mfa_token.as_deref().ok_or(AppError::Unauthorized)?;
    let claims = state.jwt.verify(raw).map_err(|_| AppError::Unauthorized)?;
    if claims.typ != TYPE_MFA_PENDING {
        return Err(AppError::Unauthorized);
    }

    match mfa::verify_challenge(&state, &claims.sub, &code).await {
        Ok(_) => {
            let user = crate::services::users::require_user(&state.db, &claims.sub).await?;
            audit::log_event(
                &state,
                Some(&user.id),
                audit::events::MFA_CHALLENGE_OK,
                audit::SEV_INFO,
                Some(&ip),
                None,
                None,
            )
            .await;
            let ua = header_str(&headers, "user-agent").unwrap_or("");
            let lang = header_str(&headers, "accept-language").unwrap_or("");
            let success = auth_flow::complete_login(&state, &user, &ip, ua, lang).await?;
            Ok(Json(serde_json::to_value(success)?))
        }
        Err(_) => {
            audit::log_event(
                &state,
                Some(&claims.sub),
                audit::events::MFA_CHALLENGE_FAILED,
                audit::SEV_WARN,
                Some(&ip),
                None,
                None,
            )
            .await;
            Err(AppError::Unauthorized)
        }
    }
}

// --- Refresh / logout --------------------------------------------------------

#[derive(Deserialize)]
struct RefreshReq {
    refresh_token: String,
}

/// Rotation automatique + detection de reutilisation (replay).
async fn token_refresh(
    State(state): State<AppState>,
    Json(body): Json<RefreshReq>,
) -> AppResult<Json<serde_json::Value>> {
    use sessions::RotateOutcome;

    let presented = tok_hmac(&state, &body.refresh_token);
    let new_refresh = crate::crypto::tokens::secure_token();
    let new_hash = tok_hmac(&state, &new_refresh);

    match sessions::rotate_refresh(&state.db, &presented, &new_hash, state.cfg.refresh_token_ttl_secs)
        .await?
    {
        RotateOutcome::Rotated(s) => {
            let user = crate::services::users::require_user(&state.db, &s.user_id).await?;
            let (access, expires_in) =
                auth_flow::issue_access_token(&state, &user.id, &user.role, Some(&s.id))?;
            Ok(Json(json!({
                "access_token": access,
                "refresh_token": new_refresh,
                "token_type": "Bearer",
                "expires_in": expires_in,
            })))
        }
        RotateOutcome::ReuseDetected(user_id) => {
            audit::log_event(
                &state,
                Some(&user_id),
                audit::events::REFRESH_REUSE_DETECTED,
                audit::SEV_CRITICAL,
                None,
                None,
                None,
            )
            .await;
            Err(AppError::Unauthorized)
        }
        RotateOutcome::Invalid => Err(AppError::Unauthorized),
    }
}

fn tok_hmac(state: &AppState, value: &str) -> String {
    crate::crypto::tokens::hmac_hash(&state.cfg.password_pepper, value)
}

/// Deconnexion de la session courante (blackliste le jti du JWT).
async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let (ctx, _u) = auth_flow::require_auth(&state, &headers).await?;
    if let Some(sid) = &ctx.sid {
        let _ = sessions::revoke_session(&state.db, sid).await;
    }
    let exp = chrono::Utc::now() + chrono::Duration::seconds(900);
    let _ = tokens_svc::blacklist_jti(&state.db, &ctx.jti, exp).await;
    audit::log_event(&state, Some(&ctx.user_id), audit::events::LOGOUT, audit::SEV_INFO, None, None, None).await;
    Ok(Json(json!({ "logged_out": true })))
}

/// Deconnexion globale : toutes les sessions revoquees.
async fn logout_all(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let (ctx, _u) = auth_flow::require_auth(&state, &headers).await?;
    let n = sessions::revoke_all_for_user(&state.db, &ctx.user_id).await?;
    let exp = chrono::Utc::now() + chrono::Duration::seconds(900);
    let _ = tokens_svc::blacklist_jti(&state.db, &ctx.jti, exp).await;
    audit::log_event(
        &state,
        Some(&ctx.user_id),
        audit::events::LOGOUT_ALL,
        audit::SEV_INFO,
        None,
        None,
        Some(json!({ "revoked_sessions": n })),
    )
    .await;
    Ok(Json(json!({ "logged_out": true, "revoked_sessions": n })))
}
