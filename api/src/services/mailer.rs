//! Envoi d'emails : mode `console` (dev) ou `smtp` reel (lettre + rustls).
//!
//! Configuration (env) :
//!   EMAIL_MODE=console|smtp   SMTP_HOST=smtp.exemple.com   SMTP_PORT=465
//!   SMTP_SECURE=implicit|starttls|none        SMTP_USER / SMTP_PASS
//!   EMAIL_FROM="Secure-Login <no-reply@exemple.com>"
//!
//! L'envoi est non bloquant (spawn_blocking) et n'interrompt jamais la
//! requete appelante : les erreurs sont journalisees.

use lettre::message::{header::ContentType, Mailbox};
use lettre::{Message, SmtpTransport, Transport};

#[derive(Clone)]
enum Mode {
    Console,
    Smtp(SmtpTransport),
}

#[derive(Clone)]
pub struct Mailer {
    mode: Mode,
    from: String,
}

fn env(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) if !v.trim().is_empty() => Some(v.trim().to_string()),
        _ => None,
    }
}

impl Mailer {
    pub fn from_env() -> Self {
        let from = env("EMAIL_FROM").unwrap_or_else(|| "Secure-Login <no-reply@localhost>".into());
        let mode = match env("EMAIL_MODE").as_deref() {
            Some("smtp") => match Self::build_transport() {
                Ok(t) => {
                    tracing::info!("mailer: SMTP actif");
                    Mode::Smtp(t)
                }
                Err(e) => {
                    tracing::error!("mailer: transport SMTP indisponible ({e}) -> console");
                    Mode::Console
                }
            },
            _ => Mode::Console,
        };
        Self { mode, from }
    }

    fn build_transport() -> Result<SmtpTransport, String> {
        let host = env("SMTP_HOST").ok_or("SMTP_HOST manquant")?;
        let port: u16 = env("SMTP_PORT").and_then(|p| p.parse().ok()).unwrap_or(465);
        let secure = env("SMTP_SECURE").unwrap_or_else(|| "implicit".into());

        let mut builder = match secure.as_str() {
            "starttls" => SmtpTransport::starttls_relay(&host).map_err(|e| e.to_string())?,
            "none" => Ok(SmtpTransport::builder_dangerous(&host)),
            _ => SmtpTransport::relay(&host).map_err(|e| e.to_string())?,
        }
        .map_err(|e: String| format!("tls smtp: {e}"))?;

        builder = builder.port(port);
        if let (Some(u), Some(p)) = (env("SMTP_USER"), env("SMTP_PASS")) {
            builder =
                builder.credentials(lettre::transport::smtp::authentication::Credentials::new(u, p));
        }
        Ok(builder.build())
    }

    /// Envoie un lien d'action. Fire-and-forget : ne bloque pas la requete.
    pub fn send_link(&self, to: &str, kind: &str, link: &str) {
        let subject = match kind {
            k if k.contains("verification") => "[Secure-Login] Verifiez votre adresse email",
            k if k.contains("reset") => "[Secure-Login] Reinitialisation de votre mot de passe",
            other => "[Secure-Login] Notification de securite",
        };
        let body = format!(
            "<html><body style=\"font-family:sans-serif\">\
<h2>{subject}</h2>\
<p>Cliquez sur le lien ci-dessous (valable 1 a 24 h selon le type d'action) :</p>\
<p><a href=\"{link}\">{link}</a></p>\
<p style=\"color:#888\">Si vous n'etes pas a l'origine de cette demande, ignorez ce message.</p>\
</body></html>"
        );

        match &self.mode {
            Mode::Console => {
                tracing::info!("[mailer:console] to={to} | {kind} link: {link}");
            }
            Mode::Smtp(transport) => {
                let from: Mailbox = match self.from.parse() {
                    Ok(f) => f,
                    Err(e) => {
                        tracing::error!("[mailer:smtp] EMAIL_FROM invalide ({self.from}): {e}");
                        return;
                    }
                };
                let to_mbx: Mailbox = match to.parse() {
                    Ok(f) => f,
                    Err(e) => {
                        tracing::error!("[mailer:smtp] destinataire invalide ({to}): {e}");
                        return;
                    }
                };
                let mail = match Message::builder()
                    .from(from)
                    .to(to_mbx)
                    .subject(subject)
                    .singlepart(ContentType::TEXT_HTML, body)
                {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::error!("[mailer:smtp] construction du message: {e}");
                        return;
                    }
                };

                let transport = transport.clone();
                let to = to.to_string();
                let kind = kind.to_string();
                tokio::spawn(async move {
                    match tokio::task::spawn_blocking(move || transport.send(&mail)).await {
                        Ok(Ok(_)) => tracing::info!("[mailer:smtp] envoye a {to} ({kind})"),
                        Ok(Err(e)) => tracing::error!("[mailer:smtp] echec vers {to}: {e}"),
                        Err(e) => tracing::error!("[mailer:smtp] task panic: {e}"),
                    }
                });
            }
        }
    }
}
