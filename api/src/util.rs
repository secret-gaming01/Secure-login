//! Utilitaires divers : temps, validation, sanitisation XSS, device.

use chrono::{DateTime, Duration, Utc};

pub fn now() -> DateTime<Utc> {
    Utc::now()
}

pub fn plus_secs(secs: i64) -> DateTime<Utc> {
    Utc::now() + Duration::seconds(secs)
}

/// Validation d'email simple mais stricte (longueur + structure).
pub fn is_valid_email(email: &str) -> bool {
    let e = email.trim();
    if e.len() < 5 || e.len() > 254 || !e.contains('@') || e.contains(' ') {
        return false;
    }
    let (local, domain) = match e.split_once('@') {
        Some(v) => v,
        None => return false,
    };
    !local.is_empty()
        && local.len() <= 64
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
}

/// Politique de mot de passe : >= 10 caractères, au moins 3 catégories
/// parmi minuscules / majuscules / chiffres / spéciaux.
pub fn validate_password(pw: &str) -> Result<(), String> {
    if pw.chars().count() < 10 {
        return Err("Password must be at least 10 characters".into());
    }
    if pw.chars().count() > 256 {
        return Err("Password too long".into());
    }
    let mut cats = 0;
    if pw.chars().any(|c| c.is_ascii_lowercase()) { cats += 1; }
    if pw.chars().any(|c| c.is_ascii_uppercase()) { cats += 1; }
    if pw.chars().any(|c| c.is_ascii_digit()) { cats += 1; }
    if pw.chars().any(|c| !c.is_ascii_alphanumeric()) { cats += 1; }
    if cats < 3 {
        return Err("Password needs at least 3 of: lowercase, uppercase, digits, symbols".into());
    }
    Ok(())
}

/// Nettoyage anti-XSS de toute chaîne stockée puis ré-affichée.
pub fn sanitize(input: &str) -> String {
    input
        .chars()
        .filter(|c| !c.is_control())
        .map(|c| match c {
            '<' => '‹',
            '>' => '›',
            '&' => '+',
            _ => c,
        })
        .collect::<String>()
        .trim()
        .chars()
        .take(200)
        .collect()
}

/// Empreinte de device : SHA-256(UA + Accept-Language), tronquée.
pub fn fingerprint(user_agent: &str, accept_language: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(user_agent.as_bytes());
    h.update(b"|");
    h.update(accept_language.as_bytes());
    hex::encode(&h.finalize()[..16])
}

/// Label de device dérivé du User-Agent.
pub fn device_label(user_agent: &str) -> String {
    let ua = user_agent.to_string();
    let os = if ua.contains("Windows") {
        "Windows"
    } else if ua.contains("Android") {
        "Android"
    } else if ua.contains("iPhone") || ua.contains("iPad") {
        "iOS"
    } else if ua.contains("Mac OS") || ua.contains("Macintosh") {
        "macOS"
    } else if ua.contains("Linux") {
        "Linux"
    } else {
        "Unknown OS"
    };
    let browser = if ua.contains("Edg/") {
        "Edge"
    } else if ua.contains("Chrome") && !ua.contains("Chromium") {
        "Chrome"
    } else if ua.contains("Firefox") {
        "Firefox"
    } else if ua.contains("Safari") && !ua.contains("Chrome") {
        "Safari"
    } else if ua.contains("curl") {
        "curl"
    } else {
        "Unknown"
    };
    sanitize(&format!("{browser} on {os}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_validation() {
        assert!(is_valid_email("user@example.com"));
        assert!(!is_valid_email("no-at-sign"));
        assert!(!is_valid_email("a@b"));
        assert!(!is_valid_email("user name@example.com"));
    }

    #[test]
    fn password_policy() {
        assert!(validate_password("Str0ngPassw0rd!").is_ok());
        assert!(validate_password("short1A!").is_err());
        assert!(validate_password("alllowercaseonly").is_err());
    }

    #[test]
    fn sanitize_strips_html() {
        assert_eq!(sanitize("<script>alert(1)</script>"), "‹script›alert(1)‹/script›");
        assert!(sanitize(&"x".repeat(500)).chars().count() <= 200);
    }
}
