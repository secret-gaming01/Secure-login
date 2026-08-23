//! Middlewares HTTP : en-têtes de sécurité, pare-feu IP (blacklist/whitelist),
//! rate limiting global et protection CSRF (double-submit pour navigateurs).

use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use std::net::SocketAddr;

use crate::extract::client_ip;
use crate::state::AppState;

/// Ajoute les en-têtes de sécurité à chaque réponse.
pub async fn security_headers(_req: Request<axum::body::Body>, next: Next) -> Response {
    let mut resp = next.run(_req).await;
    let h = resp.headers_mut();
    h.insert("X-Content-Type-Options", "nosniff".parse().unwrap());
    h.insert("X-Frame-Options", "DENY".parse().unwrap());
    h.insert("Referrer-Policy", "no-referrer".parse().unwrap());
    h.insert(
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=()".parse().unwrap(),
    );
    h.insert(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
            .parse()
            .unwrap(),
    );
    resp
}

fn is_mutating(method: &Method) -> bool {
    matches!(*method, Method::POST | Method::PUT | Method::PATCH | Method::DELETE)
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get("cookie")?.to_str().ok()?;
    for pair in raw.split(';') {
        let mut it = pair.trim().splitn(2, '=');
        if let (Some(k), Some(v)) = (it.next(), it.next()) {
            if k == name {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Pare-feu applicatif :
/// 1. Whitelist IP → contournement des limites
/// 2. Blacklist IP → 403 immédiat
/// 3. Rate limit global par fenêtre glissante en mémoire
/// 4. CSRF : si la requête vient d'un navigateur (header Origin/Referer
///    présent) sur une route mutante, exige le couple Cookie csrf +
///    header X-CSRF-Token identique (double-submit).
pub async fn network_guard(
    axum::extract::State(state): axum::extract::State<AppState>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    // /health toujours accessible
    if req.uri().path().starts_with("/health") {
        return next.run(req).await;
    }

    let addr = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0)
        .expect("ConnectInfo missing — use into_make_service_with_connect_info");
    let ip = client_ip(req.headers(), addr, state.cfg.trust_proxy);

    // --- IP intelligence ---
    match crate::services::ipintel::ip_mode(&state.db, &ip).await {
        Ok(Some(mode)) => {
            if mode == "whitelist" {
                // bypass complet des limites
            } else {
                return (
                    StatusCode::FORBIDDEN,
                    axum::Json(json!({"error": "Your IP address is blocked"})),
                )
                    .into_response();
            }
        }
        Ok(None) => {}
        Err(e) => {
            tracing::error!("ip check failed: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"error": "Internal server error"})),
            )
                .into_response();
        }
    }

    // --- CSRF double-submit (navigateurs uniquement) ---
    let headers = req.headers().clone();
    if is_mutating(req.method())
        && (headers.contains_key("origin") || headers.contains_key("referer"))
    {
        let cookie = cookie_value(&headers, "csrf");
        let header = crate::extract::header_str(&headers, "x-csrf-token").map(|s| s.to_string());
        match (cookie, header) {
            (Some(c), Some(h)) if !c.is_empty() && c == h => {}
            _ => {
                return (
                    StatusCode::FORBIDDEN,
                    axum::Json(json!({"error": "CSRF token missing or invalid"})),
                )
                    .into_response();
            }
        }
    }

    // --- Rate limit global (fenetre fixe partagee memoire ou Redis) ---
    let cap = state.settings.read().unwrap().rate_limit_per_min;
    if cap > 0 {
        let allowed = state.store.rl_hit(&ip, cap, 60).await;
        if !allowed {
            tracing::warn!("rate limited ip={}", ip);
            return (
                StatusCode::TOO_MANY_REQUESTS,
                axum::Json(json!({"error": "Too many requests"})),
            )
                .into_response();
        }
    }

    next.run(req).await
}
