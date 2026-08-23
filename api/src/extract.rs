//! Extraction d'informations de requête : IP client, contexte authentifié.

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use std::net::SocketAddr;

use crate::error::AppError;

/// Détermine l'IP réelle du client.
/// Si `TRUST_PROXY=true`, lit X-Forwarded-For (premier hop) puis X-Real-IP.
pub fn client_ip(headers: &HeaderMap, addr: SocketAddr, trust_proxy: bool) -> String {
    if trust_proxy {
        if let Some(xff) = header_str(headers, "x-forwarded-for") {
            if let Some(first) = xff.split(',').next() {
                let ip = first.trim();
                if !ip.is_empty() {
                    return ip.to_string();
                }
            }
        }
        if let Some(xri) = header_str(headers, "x-real-ip") {
            let ip = xri.trim();
            if !ip.is_empty() {
                return ip.to_string();
            }
        }
    }
    addr.ip().to_string()
}

pub fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// Contexte d'un utilisateur authentifié (issu du JWT access).
#[derive(Debug, Clone)]
pub struct AuthCtx {
    pub user_id: String,
    pub role: String,
    pub scopes: Vec<String>,
    pub sid: Option<String>,
    pub jti: String,
}

impl AuthCtx {
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }

    pub fn require_scope(&self, scope: &str) -> Result<(), AppError> {
        if self.has_scope(scope) {
            Ok(())
        } else {
            Err(AppError::Forbidden)
        }
    }
}

/// Réponse 401 standardisée pour les helpers d'auth.
pub fn unauthorized_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": "Unauthorized"})),
    )
        .into_response()
}
