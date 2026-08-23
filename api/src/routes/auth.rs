//! Routes /auth : register + verification email + health.

use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;

use crate::error::{AppError, AppResult};
use crate::extract::client_ip;
use crate::services::{audit, auth_flow, mailer, tokens_svc, users};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/register", post(register))
        .route("/auth/verify-email", post(verify_email))
        .route("/auth/resend-verification", post(resend_verification))
        .route("/health", get(health))
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok",
        "service": "secure-login",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

#[derive(Deserialize)]
struct RegisterReq {
    email: String,
    password: String,
}

async fn register(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<RegisterReq>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    let ip = client_ip(&headers, addr, state.cfg.trust_proxy);
    let email = body.email.trim().to_lowercase();

    if !crate::util::is_valid_email(&email) {
        return Err(AppError::validation("Invalid email address"));
    }
    crate::util::validate_password(&body.password).map_err(AppError::validation)?;

    let id = uuid::Uuid::new_v4().to_string();
    let (phc, salt) = crate::crypto::hash::hash_password(&body.password, &state.cfg.password_pepper)
        .map_err(|e| AppError::internal(format!("hash: {e}")))?;

    users::create_user(&state.db, &id, &email, Some(&phc), &salt, "user").await?;

    // Token de verification email (24 h, hash stocke, usage unique)
    let token = tokens_svc::issue_action_token(
        &state.db,
        &state.cfg.password_pepper,
        &id,
        "email_verify",
        86400,
        None,
    )
    .await?;
    mailer::send_link(
        &state.cfg,
        &email,
        "email verification",
        &format!("{}/verify-email?token={}", state.cfg.base_url, token),
    );

    audit::log_event(
        &state,
        Some(&id),
        audit::events::REGISTER,
        audit::SEV_INFO,
        Some(&ip),
        None,
        None,
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "user_id": id,
            "message": "Account created. Check your email to verify your address.",
        })),
    ))
}

#[derive(Deserialize)]
struct TokenOnlyReq {
    token: String,
}

async fn verify_email(
    State(state): State<AppState>,
    Json(body): Json<TokenOnlyReq>,
) -> AppResult<Json<serde_json::Value>> {
    let user_id = tokens_svc::consume_action_token(
        &state.db,
        &state.cfg.password_pepper,
        &body.token,
        "email_verify",
    )
    .await?;
    users::mark_email_verified(&state.db, &user_id).await?;
    audit::log_event(
        &state,
        Some(&user_id),
        audit::events::EMAIL_VERIFIED,
        audit::SEV_INFO,
        None,
        None,
        None,
    )
    .await;
    Ok(Json(json!({ "verified": true })))
}

#[derive(Deserialize)]
struct EmailOnlyReq {
    email: String,
}

async fn resend_verification(
    State(state): State<AppState>,
    Json(body): Json<EmailOnlyReq>,
) -> AppResult<Json<serde_json::Value>> {
    if let Some(user) = users::find_by_email(&state.db, body.email.trim()).await? {
        if !user.email_verified {
            let token = tokens_svc::issue_action_token(
                &state.db,
                &state.cfg.password_pepper,
                &user.id,
                "email_verify",
                86400,
                None,
            )
            .await?;
            mailer::send_link(
                &state.cfg,
                &user.email,
                "email verification",
                &format!("{}/verify-email?token={}", state.cfg.base_url, token),
            );
        }
    }
    Ok(Json(json!({
        "message": "If the account exists, a verification email has been sent."
    })))
}
