//! Routes /auth passkeys : enregistrement + authentification WebAuthn.

use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::SocketAddr;
use webauthn_rs::prelude::{
    PublicKeyCredential, RegisterPublicKeyCredential,
};

use crate::error::{AppError, AppResult};
use crate::extract::client_ip;
use crate::services::{auth_flow, passkeys};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/passkey/register/options", post(passkey_register_options))
        .route("/auth/passkey/register", post(passkey_register))
        .route("/auth/passkey/login/options", post(passkey_login_options))
        .route("/auth/passkey/login", post(passkey_login))
}

#[derive(Deserialize)]
struct PasskeyRegFinishReq {
    #[serde(default)]
    name: Option<String>,
    response: RegisterPublicKeyCredential,
}

async fn passkey_register_options(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let (ctx, user) = auth_flow::require_auth(&state, &headers).await?;
    ctx.require_scope("passkeys.manage")?;
    let ccr = passkeys::registration_options(&state, &ctx.user_id, &user.email).await?;
    Ok(Json(serde_json::to_value(ccr)?))
}

async fn passkey_register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<PasskeyRegFinishReq>,
) -> AppResult<Json<Value>> {
    let (ctx, _user) = auth_flow::require_auth(&state, &headers).await?;
    ctx.require_scope("passkeys.manage")?;
    let name = body.name.as_deref().unwrap_or("Passkey");
    let id = passkeys::registration_finish(&state, &ctx.user_id, name, &body.response).await?;
    Ok(Json(json!({ "id": id, "registered": true })))
}

#[derive(Deserialize)]
struct PasskeyLoginOptionsReq {
    email: String,
}

async fn passkey_login_options(
    State(state): State<AppState>,
    Json(body): Json<PasskeyLoginOptionsReq>,
) -> AppResult<Json<Value>> {
    let (challenge_id, rcr) =
        passkeys::authentication_options(&state, Some(body.email.trim())).await?;
    Ok(Json(json!({
        "challenge_id": challenge_id,
        "publicKey": serde_json::to_value(rcr)?,
    })))
}

#[derive(Deserialize)]
struct PasskeyLoginFinishReq {
    challenge_id: String,
    response: PublicKeyCredential,
}

async fn passkey_login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<PasskeyLoginFinishReq>,
) -> AppResult<Json<Value>> {
    let ip = client_ip(&headers, addr, state.cfg.trust_proxy);
    let (user_id, _cred) =
        passkeys::authentication_finish(&state, &body.challenge_id, &body.response).await?;

    let user = crate::services::users::require_user(&state.db, &user_id).await?;
    let ua = crate::extract::header_str(&headers, "user-agent").unwrap_or("");
    let lang = crate::extract::header_str(&headers, "accept-language").unwrap_or("");
    let success = auth_flow::complete_login(&state, &user, &ip, ua, lang).await?;
    Ok(Json(serde_json::to_value(success)?))
}
