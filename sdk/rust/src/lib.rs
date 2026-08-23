//! Secure-Login SDK — Rust.
//!
//! ```no_run
//! use secure_login_sdk::SecureAuthClient;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = SecureAuthClient::new("http://localhost:8080");
//!     let result = client.login("user@example.com", "Str0ngPassw0rd!").await?;
//!     if result.get("mfa_required") == Some(&serde_json::json!(true)) {
//!         let mfa_token = result["mfa_token"].as_str().unwrap();
//!         client.login_mfa(mfa_token, "123456").await?;
//!     }
//!     println!("{:?}", client.get_current_user().await?);
//!     Ok(())
//! }
//! ```

use serde_json::{json, Value};

#[derive(Debug, thiserror::Error)]
pub enum SdkError {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("api error ({status}): {message}")]
    Api { status: u16, message: String },
}

#[derive(Clone)]
pub struct SecureAuthClient {
    http: reqwest::Client,
    base_url: String,
    access_token: std::sync::RwLock<Option<String>>,
    refresh_token: std::sync::RwLock<Option<String>>,
}

impl SecureAuthClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
            access_token: std::sync::RwLock::new(None),
            refresh_token: std::sync::RwLock::new(None),
        }
    }

    pub fn set_tokens(&self, access: impl Into<String>, refresh: Option<String>) {
        *self.access_token.write().unwrap() = Some(access.into());
        if let Some(r) = refresh {
            *self.refresh_token.write().unwrap() = Some(r);
        }
    }

    pub fn access_token(&self) -> Option<String> {
        self.access_token.read().unwrap().clone()
    }

    async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
        authed: bool,
    ) -> Result<Value, SdkError> {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.http.request(method, &url).json(&body.unwrap_or(Value::Null));
        if authed {
            if let Some(tok) = self.access_token() {
                req = req.bearer_auth(tok);
            }
        }
        let resp = req.send().await?;
        let status = resp.status().as_u16();
        let data: Value = resp.json().await.unwrap_or(Value::Null);
        if !(200..300).contains(&status) {
            let message = data["error"].as_str().unwrap_or("unknown").to_string();
            return Err(SdkError::Api { status, message });
        }
        Ok(data)
    }

    // ------------------------------------------------------------ core API

    /// Cree un compte.
    pub async fn register(&self, email: &str, password: &str) -> Result<Value, SdkError> {
        self.request(
            reqwest::Method::POST,
            "/auth/register",
            Some(json!({ "email": email, "password": password })),
            false,
        )
        .await
    }

    /// Connexion (si MFA : renvoie mfa_required + mfa_token).
    pub async fn login(&self, email: &str, password: &str) -> Result<Value, SdkError> {
        let r = self
            .request(
                reqwest::Method::POST,
                "/auth/login",
                Some(json!({ "email": email, "password": password })),
                false,
            )
            .await?;
        if let Some(t) = r["access_token"].as_str() {
            self.set_tokens(t, r["refresh_token"].as_str().map(String::from));
        }
        Ok(r)
    }

    /// Finalise une connexion MFA.
    pub async fn login_mfa(&self, mfa_token: &str, code: &str) -> Result<Value, SdkError> {
        let r = self
            .request(
                reqwest::Method::POST,
                "/auth/mfa/verify",
                Some(json!({ "mfa_token": mfa_token, "code": code })),
                false,
            )
            .await?;
        if let Some(t) = r["access_token"].as_str() {
            self.set_tokens(t, r["refresh_token"].as_str().map(String::from));
        }
        Ok(r)
    }

    /// Rotation du refresh token.
    pub async fn refresh_token(&self) -> Result<Value, SdkError> {
        let current = self.refresh_token.read().unwrap().clone()
            .ok_or(SdkError::Api { status: 401, message: "No refresh token".into() })?;
        let r = self
            .request(
                reqwest::Method::POST,
                "/auth/token/refresh",
                Some(json!({ "refresh_token": current })),
                false,
            )
            .await?;
        if let Some(t) = r["access_token"].as_str() {
            self.set_tokens(t, r["refresh_token"].as_str().map(String::from));
        }
        Ok(r)
    }

    /// Profil courant (+ scopes, mfa_enabled).
    pub async fn get_current_user(&self) -> Result<Value, SdkError> {
        self.request(reqwest::Method::GET, "/auth/me", None, true).await
    }

    /// Deconnexion de la session courante.
    pub async fn logout(&self) -> Result<Value, SdkError> {
        let r = self.request(reqwest::Method::POST, "/auth/logout", Some(json!({})), true).await;
        *self.access_token.write().unwrap() = None;
        *self.refresh_token.write().unwrap() = None;
        r
    }

    /// True si le scope fait partie des permissions courantes.
    pub async fn check_permission(&self, scope: &str) -> Result<bool, SdkError> {
        match self.get_current_user().await {
            Ok(me) => Ok(me["scopes"].as_array().map(|a| a.iter().any(|s| s.as_str() == Some(scope))).unwrap_or(false)),
            Err(_) => Ok(false),
        }
    }

    // ---------------------------------------------------------------- bonus

    pub async fn logout_all(&self) -> Result<Value, SdkError> {
        self.request(reqwest::Method::POST, "/auth/logout-all", Some(json!({})), true).await
    }

    pub async fn enable_mfa(&self) -> Result<Value, SdkError> {
        self.request(reqwest::Method::POST, "/auth/mfa/enable", None, true).await
    }

    pub async fn admin_suspicious_ips(&self) -> Result<Value, SdkError> {
        self.request(reqwest::Method::GET, "/admin/suspicious-ips", None, true).await
    }

    pub async fn admin_double_accounts(&self) -> Result<Value, SdkError> {
        self.request(reqwest::Method::GET, "/admin/double-accounts", None, true).await
    }
}
