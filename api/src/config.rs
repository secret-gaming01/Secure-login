use std::env;

#[derive(Clone, Debug)]
pub struct Config {
    pub port: u16,
    pub base_url: String,
    pub database_url: String,

    pub jwt_secret: String,
    pub encryption_key: String,
    pub password_pepper: String,

    pub access_token_ttl_secs: i64,
    pub refresh_token_ttl_secs: i64,

    pub rp_id: String,
    pub rp_name: String,
    pub rp_origin: String,

    pub trust_proxy: bool,
    pub cors_origins: Vec<String>,

    pub geo_enabled: bool,
    pub captcha_provider: Option<String>,
    pub captcha_secret: Option<String>,
    pub captcha_site_key: Option<String>,

    pub mfa_issuer: String,
}

fn var(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

fn var_opt(key: &str) -> Option<String> {
    match env::var(key) {
        Ok(v) if !v.trim().is_empty() => Some(v),
        _ => None,
    }
}

impl Config {
    pub fn from_env() -> Self {
        let cors_origins: Vec<String> = var("CORS_ORIGINS", "*")
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        Config {
            port: var("PORT", "8080").parse().unwrap_or(8080),
            base_url: var("BASE_URL", "http://localhost:8080").trim_end_matches('/').to_string(),
            database_url: var(
                "DATABASE_URL",
                "sqlite://./secure-login.db",
            ),
            jwt_secret: var(
                "JWT_SECRET",
                "insecure-dev-jwt-secret-change-me-change-me-change-me-32+chars",
            ),
            encryption_key: var("ENCRYPTION_KEY", "insecure-dev-encryption-key"),
            password_pepper: var("PASSWORD_PEPPER", "insecure-dev-pepper"),
            access_token_ttl_secs: var("ACCESS_TOKEN_TTL_SECS", "900").parse().unwrap_or(900),
            refresh_token_ttl_secs: var("REFRESH_TOKEN_TTL_SECS", "2592000")
                .parse()
                .unwrap_or(2_592_000),
            rp_id: var("RP_ID", "localhost"),
            rp_name: var("RP_NAME", "Secure Login"),
            rp_origin: var("RP_ORIGIN", "http://localhost:8080"),
            trust_proxy: var("TRUST_PROXY", "false").eq_ignore_ascii_case("true"),
            cors_origins,
            geo_enabled: var("GEO_ENABLED", "true").eq_ignore_ascii_case("true"),
            captcha_provider: var_opt("CAPTCHA_PROVIDER"),
            captcha_secret: var_opt("CAPTCHA_SECRET"),
            captcha_site_key: var_opt("CAPTCHA_SITE_KEY"),
            mfa_issuer: var("MFA_ISSUER", "SecureLogin"),
        }
    }
}
