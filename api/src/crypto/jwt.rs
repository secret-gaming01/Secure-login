//! JWT HS512 — access tokens courts + tokens "mfa_pending".
//!
//! Chaque token contient : sub (user id), sid (session), role, scopes,
//! jti (id unique, blacklistable), typ, iat, exp. La validation vérifie
//! signature, émetteur, audience et expiration (leeway 30 s).

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

pub const TYPE_ACCESS: &str = "access";
pub const TYPE_MFA_PENDING: &str = "mfa";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    pub role: String,
    pub scopes: Vec<String>,
    pub jti: String,
    pub typ: String,
    pub iat: i64,
    pub exp: i64,
    pub iss: String,
    pub aud: String,
}

#[derive(Clone)]
pub struct JwtKeys {
    encoding: EncodingKey,
    decoding: DecodingKey,
    issuer: String,
    audience: String,
}

impl std::fmt::Debug for JwtKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "JwtKeys(hs512)")
    }
}

impl JwtKeys {
    pub fn new(secret: &str) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret.as_bytes()),
            decoding: DecodingKey::from_secret(secret.as_bytes()),
            issuer: "secure-login".into(),
            audience: "secure-login-clients".into(),
        }
    }

    pub fn sign(&self, mut claims: Claims) -> Result<String, jsonwebtoken::errors::Error> {
        claims.iss = self.issuer.clone();
        claims.aud = self.audience.clone();
        encode(&Header::new(Algorithm::HS512), &claims, &self.encoding)
    }

    pub fn verify(&self, token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
        let mut validation = Validation::new(Algorithm::HS512);
        validation.leeway = 30;
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        decode(token, &self.decoding, &validation).map(|data| data.claims)
    }
}
