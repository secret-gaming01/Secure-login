//! Routes /admin : gestion utilisateurs, IPs, sessions, logs, stats, config.

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;

use crate::error::{AppError, AppResult};
use crate::extract::AuthCtx;
use crate::services::{
    adminsvc, audit, auth_flow, sessions, stats, tokens_svc,
};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/admin/users", get(list_users))
        .route("/admin/users/:id", delete(delete_user))
        .route("/admin/block-ip", post(block_ip))
        .route("/admin/block-ip/:ip", delete(unblock_ip))
        .route("/admin/blocked-ips", get(list_blocked))
        .route("/admin/suspicious-ips", get(suspicious_ips))
        .route("/admin/double-accounts", get(double_accounts))
        .route("/admin/sessions", get(list_sessions_admin))
        .route("/admin/sessions/:id", delete(revoke_session_admin))
        .route("/admin/logs", get(logs))
        .route("/admin/stats/activity", get(activity))
        .route("/admin/overview", get(overview))
        .route("/admin/config", get(get_config))
        .route("/admin/config", post(update_config))
}

async fn guard(state: &AppState, headers: &HeaderMap, scope: &str) -> AppResult<AuthCtx> {
    let (ctx, _user) = auth_flow::require_auth(state, headers).await?;
    ctx.require_scope(scope)?;
    Ok(ctx)
}

async fn list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> AppResult<Json<serde_json::Value>> {
    let _ctx = guard(&state, &headers, "users.read").await?;
    let limit = q.get("limit").and_then(|v| v.parse::<i64>().ok()).unwrap_or(50).min(200);
    let offset = q.get("offset").and_then(|v| v.parse::<i64>().ok()).unwrap_or(0);
    let search = q.get("q").map(|s| s.trim().to_string()).filter(|s| !s.is_empty());

    let total = crate::services::users::count_users(&state.db, search.as_deref()).await?;
    let rows = crate::services::users::list_users(&state.db, limit, offset, search.as_deref()).await?;
    Ok(Json(json!({ "total": total, "limit": limit, "offset": offset, "users": rows })))
}

async fn delete_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let ctx = guard(&state, &headers, "users.delete").await?; // owner only
    if id == ctx.user_id {
        return Err(AppError::validation("Cannot delete your own account here"));
    }
    crate::services::users::soft_delete(&state.db, &id).await?;
    sessions::revoke_all_for_user(&state.db, &id).await?;
    audit::log_event(
        &state,
        Some(&ctx.user_id),
        audit::events::ACCOUNT_DELETED,
        audit::SEV_CRITICAL,
        None,
        None,
        Some(json!({ "target": id })),
    )
    .await;
    Ok(Json(json!({ "deleted": true })))
}

#[derive(Deserialize)]
struct BlockIpReq {
    ip: String,
    /// blacklist | whitelist
    mode: String,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    expires_in_minutes: Option<i64>,
}

async fn block_ip(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<BlockIpReq>,
) -> AppResult<Json<serde_json::Value>> {
    let ctx = guard(&state, &headers, "ips.write").await?;
    let ip = body.ip.trim();
    if ip.parse::<std::net::IpAddr>().is_err() {
        return Err(AppError::validation("Invalid IP address"));
    }
    if body.mode != "blacklist" && body.mode != "whitelist" {
        return Err(AppError::validation("mode must be 'blacklist' or 'whitelist'"));
    }
    let expires = body
        .expires_in_minutes
        .map(|m| crate::util::now() + chrono::Duration::minutes(m));

    adminsvc::upsert_block(
        &state.db,
        &uuid::Uuid::new_v4().to_string(),
        ip,
        &body.mode,
        body.reason.as_deref().map(crate::util::sanitize),
        &ctx.user_id,
        expires,
    )
    .await?;

    audit::log_event(
        &state,
        Some(&ctx.user_id),
        audit::events::IP_BLOCKED,
        audit::SEV_WARN,
        None,
        None,
        Some(json!({ "ip": ip, "mode": body.mode })),
    )
    .await;
    Ok(Json(json!({ "blocked": true, "ip": ip, "mode": body.mode })))
}

async fn unblock_ip(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(ip): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let _ctx = guard(&state, &headers, "ips.write").await?;
    let removed = adminsvc::delete_block(&state.db, ip.trim()).await?;
    Ok(Json(json!({ "removed": removed })))
}

async fn list_blocked(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let _ctx = guard(&state, &headers, "ips.read").await?;
    let rows = adminsvc::list_blocked(&state.db).await?;
    Ok(Json(json!({ "blocked_ips": rows })))
}

async fn suspicious_ips(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let _ctx = guard(&state, &headers, "ips.read").await?;
    Ok(Json(adminsvc::suspicious_ips(&state).await?))
}

async fn double_accounts(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let _ctx = guard(&state, &headers, "ips.read").await?;
    Ok(Json(adminsvc::double_accounts(&state).await?))
}

async fn list_sessions_admin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> AppResult<Json<serde_json::Value>> {
    let _ctx = guard(&state, &headers, "sessions.admin").await?;
    let limit = q.get("limit").and_then(|v| v.parse::<i64>().ok()).unwrap_or(100).min(500);
    let offset = q.get("offset").and_then(|v| v.parse::<i64>().ok()).unwrap_or(0);
    let rows = sessions::list_admin_sessions(&state.db, limit, offset).await?;
    Ok(Json(json!({ "sessions": rows })))
}

async fn revoke_session_admin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let ctx = guard(&state, &headers, "sessions.admin").await?;
    let revoked = sessions::revoke_session(&state.db, &id).await?;
    if revoked {
        audit::log_event(
            &state,
            Some(&ctx.user_id),
            "session_revoked_admin",
            audit::SEV_WARN,
            None,
            None,
            Some(json!({ "session": id })),
        )
        .await;
    }
    Ok(Json(json!({ "revoked": revoked })))
}

async fn logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> AppResult<Json<serde_json::Value>> {
    let _ctx = guard(&state, &headers, "logs.read").await?;
    let limit = q.get("limit").and_then(|v| v.parse::<i64>().ok()).unwrap_or(100).min(500);
    let offset = q.get("offset").and_then(|v| v.parse::<i64>().ok()).unwrap_or(0);
    let rows = stats::logs(&state, limit, offset).await?;
    Ok(Json(json!({ "logs": rows })))
}

async fn activity(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> AppResult<Json<serde_json::Value>> {
    let _ctx = guard(&state, &headers, "stats.read").await?;
    let days = q.get("days").and_then(|v| v.parse::<i64>().ok()).unwrap_or(14);
    Ok(Json(stats::activity(&state, days).await?))
}

async fn overview(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let _ctx = guard(&state, &headers, "stats.read").await?;
    Ok(Json(stats::overview(&state).await?))
}

async fn get_config(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let _ctx = guard(&state, &headers, "config.read").await?;
    Ok(Json(stats::config_get(&state)))
}

async fn update_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> AppResult<Json<serde_json::Value>> {
    let _ctx = guard(&state, &headers, "config.write").await?;
    stats::config_update(&state, &body);
    Ok(Json(stats::config_get(&state)))
}
