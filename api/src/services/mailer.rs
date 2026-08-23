//! Envoi d'emails (mode console par défaut).
//!
//! En mode `console`, les liens de vérification/reset sont affichés dans les
//! logs serveur — pratique en dev et pour les tests. Le branchement SMTP est
//! un point d'extension documenté dans docs/DEPLOYMENT.md.

use crate::config::Config;

pub fn send_link(cfg: &Config, to: &str, kind: &str, link: &str) {
    match cfg_email_mode(cfg).as_str() {
        "smtp" => {
            // Non implémenté volontairement (voir LIMITATIONS du README) :
            // brancher lettre ou un provider HTTP API ici.
            tracing::info!("[mailer:smtp-unavailable] to={} kind={} link={}", to, kind, link);
        }
        _ => {
            tracing::info!(
                "[mailer:console] to={} | {} link: {}",
                to,
                kind,
                link
            );
        }
    }
}

fn cfg_email_mode(_cfg: &Config) -> String {
    std::env::var("EMAIL_MODE").unwrap_or_else(|_| "console".into())
}
