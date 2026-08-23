//! Secure-login — systeme d'authentification universel ultra-securise.
//!
//! Backend Rust / Axum / SQLx (PostgreSQL + SQLite).

mod config;
mod crypto;
mod db;
mod error;
mod extract;
mod middleware;
mod models;
mod routes;
mod services;
mod state;
mod util;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::middleware;
use axum::response::Redirect;
use axum::routing::get;
use axum::Router;
use tower_http::cors::{Any, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;

use crate::state::{AppState, RuntimeSettingsInner};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cfg = config::Config::from_env();
    let port = cfg.port;

    // Base de donnees + migrations
    let db = db::Db::connect(&cfg.database_url).await?;
    tracing::info!("database connected");
    db.migrate().await?;
    tracing::info!("migrations applied");

    // Creation du premier owner si OWNER_EMAIL est defini et base vide
    services::bootstrap::bootstrap_owner(&state).await;

    let settings = Arc::new(std::sync::RwLock::new(RuntimeSettingsInner {
        max_failed_logins: std::env::var("MAX_FAILED_LOGINS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5),
        lockout_base_secs: std::env::var("LOCKOUT_BASE_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(900),
        suspicious_fail_threshold: std::env::var("SUSPICIOUS_FAIL_THRESHOLD")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10),
        double_account_min: std::env::var("DOUBLE_ACCOUNT_MIN")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(2),
        rate_limit_per_min: std::env::var("RATE_LIMIT_PER_MIN")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(240),
    }));

    let state = AppState {
        db,
        enc: crypto::encrypt::Encryptor::new(&cfg.encryption_key),
        jwt: crypto::jwt::JwtKeys::new(&cfg.jwt_secret),
        geo_cache: Default::default(),
        rl: Default::default(),
        settings: settings.clone(),
        cfg: cfg.clone(),
        mailer: services::mailer::Mailer::from_env(),
        #[cfg(feature = "webauthn")]
        webauthn: state::build_webauthn(&cfg)?,
        #[cfg(feature = "webauthn")]
        wa_reg: Default::default(),
        #[cfg(feature = "webauthn")]
        wa_auth: Default::default(),
    };

    // CORS
    let cors = if cfg.cors_origins.iter().any(|o| o == "*") {
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any)
    } else {
        use tower_http::cors::AllowOrigin;
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(
                cfg.cors_origins.iter().filter_map(|o| o.parse().ok()),
            ))
            .allow_methods([
                axum::http::Method::GET,
                axum::http::Method::POST,
                axum::http::Method::PUT,
                axum::http::Method::PATCH,
                axum::http::Method::DELETE,
            ])
            .allow_headers([
                axum::http::header::AUTHORIZATION,
                axum::http::header::CONTENT_TYPE,
                "X-CSRF-Token".parse().unwrap(),
            ])
    };

    let api = Router::new()
        .merge(routes::auth::router())
        .merge(routes::login::router())
        .merge(routes::account::router())
        .merge(routes::admin::router());

    #[cfg(feature = "webauthn")]
    let api = api.merge(routes::passkeys::router());

    let app = Router::new()
        .route("/", get(|| async { Redirect::temporary("/dashboard/") }))
        .nest_service(
            "/dashboard",
            ServeDir::new("dashboard").fallback(ServeFile::new("dashboard/index.html")),
        )
        .merge(api)
        .layer(RequestBodyLimitLayer::max(1_048_576)) // 1 Mo
        .layer(middleware::from_fn(middleware::security_headers))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            middleware::network_guard,
        ))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("secure-auth-api listening on http://{}", addr);
    tracing::info!("dashboard: http://{}:{}/dashboard/", "localhost", port);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;

    Ok(())
}
