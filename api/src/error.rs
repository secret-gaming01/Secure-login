use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    Validation(String),

    #[error("unauthorized")]
    Unauthorized,

    #[error("forbidden")]
    Forbidden,

    #[error("{0}")]
    NotFound(String),

    #[error("{0}")]
    Conflict(String),

    #[error("{0}")]
    RateLimited(String),

    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),

    #[error("{0}")]
    Internal(String),
}

impl AppError {
    pub fn validation(msg: impl Into<String>) -> Self {
        AppError::Validation(msg.into())
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        tracing::error!("internal error: {}", msg);
        AppError::Internal(msg.into())
    }
    pub fn forbidden_msg(msg: impl Into<String>) -> Self {
        tracing::warn!("forbidden: {}", msg.as_ref());
        AppError::Forbidden
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::Validation(m) => (StatusCode::BAD_REQUEST, m.clone()),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized".into()),
            AppError::Forbidden => (StatusCode::FORBIDDEN, "Forbidden".into()),
            AppError::NotFound(m) => (StatusCode::NOT_FOUND, m.clone()),
            AppError::Conflict(m) => (StatusCode::CONFLICT, m.clone()),
            AppError::RateLimited(m) => (StatusCode::TOO_MANY_REQUESTS, m.clone()),
            AppError::Sqlx(e) => {
                tracing::error!("database error: {e}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
            }
            AppError::Internal(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
            }
        };

        let mut resp = (status, Json(json!({ "error": message }))).into_response();
        if let AppError::RateLimited(_) = self {
            if let Ok(v) = "60".parse() {
                resp.headers_mut().insert("Retry-After", axum::http::HeaderValue::from(v));
            }
        }
        resp
    }
}

pub type AppResult<T> = Result<T, AppError>;
