//! Routes /auth : profil, sessions, mot de passe, email, suppression, CSRF.

use axum::extract::{ConnectInfo, Path, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::{delete, get};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;

use crate::error::{AppError, AppResult};
use crate::extract::client_ip;
use crate::services::{audit, auth_flow, mailer, mfa, sessions, tokens_svc};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/me", get(me))
        .route("/auth/csrf", get(csrf))
        .route("/auth/sessions", get(list_sessions))
        .route("/auth/sessions/:id", delete(revoke_session))
        .route("/auth/change-password", axum::routing::post(change_password))
        .route("/auth/forgot-password", post(forgot_password))
        .route("/auth/reset-password", post(reset_password))
        .route("/auth/change-email", post(change_email))
        .route("/auth/account", delete(delete_account))
}

async fn me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let (ctx, user) = auth_flow::require_auth(&state, &headers).await?;
    let mfa_on = mfa::is_enabled(&state, &ctx.user_id).await?;
    Ok(Json(json!({
        "user": auth_flow::public_user(&user),
        "scopes": ctx.scopes,
        "mfa_enabled": mfa_on,
        "session_id": ctx.sid,
    })))
}

/// Double-submit CSRF : cookie lisible + header X-CSRF-Token identique.
async fn csrf() -> impl axum::response::IntoResponse {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    let token = hex::encode(b);
    let cookie = format!("csrf={}; Path=/; SameSite=Lax", token);

    let mut resp = Json(json!({ "csrf_token": token })).into_response();
    if let Ok(v) = axum::http::HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(axum::http::header::SET_COOKIE, v);
    }
    resp
}

async fn list_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let (ctx, _u) = auth_flow::require_auth(&state, &headers).await?;
    ctx.require_scope("sessions.manage")?;
    let rows = sessions::list_user_sessions(&state.db, &ctx.user_id).await?;
    let now = crate::util::now();
    let list: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|s| {
            json!({
                "id": s.id,
                "device": s.device,
                "ip": s.ip,
                "country": s.country,
                "city": s.city,
                "created_at": s.created_at,
                "last_seen_at": s.last_seen_at,
                "expires_at": s.expires_at,
                "revoked": s.revoked,
                "current": ctx.sid.as_deref() == Some(s.id.as_str()),
                "active": !s.revoked && s.expires_at > now,
            })
        })
        .collect();
    Ok(Json(json!({ "sessions": list })))
}

async fn revoke_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let (ctx, _u) = auth_flow::require_auth(&state, &headers).await?;
    ctx.require_scope("sessions.manage")?;
    let owned = sessions::list_user_sessions(&state.db, &ctx.user_id)
        .await?
        .iter()
        .any(|s| s.id == id);
    if !owned {
        return Err(AppError::NotFound("Session not found".into()));
    }
    sessions::revoke_session(&state.db, &id).await?;
    Ok(Json(json!({ "revoked": true })))
}

#[derive(Deserialize)]
struct ChangePasswordReq {
    current_password: String,
    new_password: String,
}

async fn change_password(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<ChangePasswordReq>,
) -> AppResult<Json<serde_json::Value>> {
    let ip = client_ip(&headers, addr, state.cfg.trust_proxy);
    let (ctx, user) = auth_flow::require_auth(&state, &headers).await?;
    ctx.require_scope("profile.write")?;

    let phc = user.password_hash.clone().ok_or(AppError::Forbidden)?;
    if !crate::crypto::hash::verify_password(
        &body.current_password,
        &state.cfg.password_pepper,
        &phc,
    ) {
        return Err(AppError::Unauthorized);
    }
    crate::util::validate_password(&body.new_password).map_err(AppError::validation)?;

    let (new_phc, salt) =
        crate::crypto::hash::hash_password(&body.new_password, &state.cfg.password_pepper)
            .map_err(|e| AppError::internal(format!("hash: {e}")))?;
    crate::services::users::set_credentials(&state.db, &ctx.user_id, Some(&new_phc), &salt).await?;

    // Revoque les AUTRES sessions (celle-ci reste active)
    for s in sessions::list_user_sessions(&state.db, &ctx.user_id).await? {
        if Some(s.id.as_str()) != ctx.sid.as_deref() {
            let _ = sessions::revoke_session(&state.db, &s.id).await;
        }
    }

    audit::log_event(
        &state,
        Some(&ctx.user_id),
        audit::events::PASSWORD_CHANGED,
        audit::SEV_INFO,
        Some(&ip),
        None,
        None,
    )
    .await;
    Ok(Json(json!({ "changed": true })))
}

#[derive(Deserialize)]
struct EmailOnlyReq {
    email: String,
}

async fn forgot_password(
    State(state): State<AppState>,
    Json(body): Json<EmailOnlyReq>,
) -> AppResult<Json<serde_json::Value>> {
    if let Some(user) = crate::services::users::find_by_email(&state.db, body.email.trim()).await?
    {
        let token = tokens_svc::issue_action_token(
            &state.db,
            &state.cfg.password_pepper,
            &user.id,
            "pw_reset",
            3600,
            None,
        )
        .await?;
        mailer::send_link(
            &state.cfg,
            &user.email,
            "password reset",
            &format!("{}/reset-password?token={}", state.cfg.base_url, token),
        );
    }
    Ok(Json(json!({
        "message": "If the account exists, a reset link has been sent."
    })))
}

#[derive(Deserialize)]
struct ResetPasswordReq {
    token: String,
    new_password: String,
}

async fn reset_password(
    State(state): State<AppState>,
    Json(body): Json<ResetPasswordReq>,
) -> AppResult<Json<serde_json::Value>> {
    crate::util::validate_password(&body.new_password).map_err(AppError::validation)?;
    let user_id = tokens_svc::consume_action_token(
        &state.db,
        &state.cfg.password_pepper,
        &body.token,
        "pw_reset",
    )
    .await?;

    let (phc, salt) =
        crate::crypto::hash::hash_password(&body.new_password, &state.cfg.password_pepper)
            .map_err(|e| AppError::internal(format!("hash: {e}")))?;
    crate::services::users::set_credentials(&state.db, &user_id, Some(&phc), &salt).await?;
    sessions::revoke_all_for_user(&state.db, &user_id).await?;

    audit::log_event(
        &state,
        Some(&user_id),
        audit::events::PASSWORD_RESET,
        audit::SEV_WARN,
        None,
        None,
        None,
    )
    .await;
    Ok(Json(json!({ "reset": true })))
}

#[derive(Deserialize)]
struct ChangeEmailReq {
    password: String,
    new_email: String,
}

async fn change_email(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ChangeEmailReq>,
) -> AppResult<Json<serde_json::Value>> {
    let (ctx, user) = auth_flow::require_auth(&state, &headers).await?;
    ctx.require_scope("profile.write")?;

    let phc = user.password_hash.clone().ok_or(AppError::Forbidden)?;
    if !crate::crypto::hash::verify_password(&body.password, &state.cfg.password_pepper, &phc) {
        return Err(AppError::Unauthorized);
    }
    let new_email = body.new_email.trim().to_lowercase();
    if !crate::util::is_valid_email(&new_email) {
        return Err(AppError::validation("Invalid email address"));
    }

    crate::services::users::set_email(&state.db, &ctx.user_id, &new_email).await?;

    let token = tokens_svc::issue_action_token(
        &state.db,
        &state.cfg.password_pepper,
        &ctx.user_id,
        "email_verify",
        86400,
        None,
    )
    .await?;
    mailer::send_link(
        &state.cfg,
        &new_email,
        "email verification",
        &format!("{}/verify-email?token={}", state.cfg.base_url, token),
    );

    audit::log_event(
        &state,
        Some(&ctx.user_id),
        audit::events::EMAIL_CHANGED,
        audit::SEV_WARN,
        None,
        None,
        None,
    )
    .await;
    Ok(Json(json!({ "changed": true, "verify_new_email": true })))
}

#[derive(Deserialize)]
struct DeleteAccountReq {
    password: String,
}

async fn delete_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<DeleteAccountReq>,
) -> AppResult<Json<serde_json::Value>> {
    let (ctx, user) = auth_flow::require_auth(&state, &headers).await?;
    let phc = user.password_hash.clone().ok_or(AppError::Forbidden)?;
    if !crate::crypto::hash::verify_password(&body.password, &state.cfg.password_pepper, &phc) {
        return Err(AppError::Unauthorized);
    }

    crate::services::users::soft_delete(&state.db, &ctx.user_id).await?;
    sessions::revoke_all_for_user(&state.db, &ctx.user_id).await?;

    audit::log_event(
        &state,
        Some(&ctx.user_id),
        audit::events::ACCOUNT_DELETED,
        audit::SEV_CRITICAL,
        None,
        None,
        None,
    )
    .await;
    Ok(Json(json!({ "deleted": true })))
}
