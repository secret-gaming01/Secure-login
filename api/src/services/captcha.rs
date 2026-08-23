//! Captcha optionnel — vérification serveur à serveur.
//! Providers supportés : Cloudflare Turnstile, hCaptcha, reCAPTCHA v2.

use std::collections::HashMap;

use crate::error::{AppError, AppResult};
use crate::state::AppState;

pub fn is_configured(state: &AppState) -> bool {
    state.cfg.captcha_provider.is_some() && state.cfg.captcha_secret.is_some()
}

/// Vérifie un captcha si configuré. `token` = réponse client
/// (h-captcha-response / g-recaptcha-response / cf-turnstile-response).
pub async fn verify(
    state: &AppState,
    token: Option<&str>,
    ip: &str,
) -> AppResult<()> {
    let (provider, secret) = match (&state.cfg.captcha_provider, &state.cfg.captcha_secret) {
        (Some(p), Some(s)) => (p.clone(), s.clone()),
        _ => return Ok(()), // captcha désactivé
    };
    let token = token.filter(|t| !t.trim().is_empty()).ok_or_else(|| {
        AppError::validation("Captcha required")
    })?;

    let url = match provider.as_str() {
        "turnstile" => "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        "hcaptcha" => "https://api.hcaptcha.com/siteverify",
        "recaptcha" => "https://www.google.com/recaptcha/api/siteverify",
        other => return Err(AppError::validation(format!("Unknown captcha provider: {other}"))),
    };

    let mut form = HashMap::new();
    form.insert("secret", secret);
    form.insert("response", token.to_string());
    form.insert("remoteip", ip.to_string());

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;
    let resp: serde_json::Value = client.post(url).form(&form).send().await?.json().await?;

    if resp.get("success").and_then(|b| b.as_bool()).unwrap_or(false) {
        Ok(())
    } else {
        Err(AppError::validation("Captcha verification failed"))
    }
}
