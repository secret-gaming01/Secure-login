//! Amorcage : creation automatique du PREMIER compte owner.
//!
//! Si la variable `OWNER_EMAIL` est definie ET que la table users est vide,
//! un compte owner est cree avec un mot de passe aleatoire affiche UNE FOIS
//! dans les logs serveur. Apres le premier demarrage, cette routine ne fait
//! plus rien (aucune re-attribution possible).

use rand::RngCore;

use crate::crypto::{hash as pw, tokens};
use crate::error::AppError;
use crate::q_exec;
use crate::q_scalar;
use crate::services::users;
use crate::state::AppState;

pub async fn bootstrap_owner(state: &AppState) {
    let email = match std::env::var("OWNER_EMAIL") {
        Ok(e) if !e.trim().is_empty() => e.trim().to_lowercase(),
        _ => return,
    };
    if !crate::util::is_valid_email(&email) {
        tracing::warn!("OWNER_EMAIL invalide, bootstrap ignore");
        return;
    }

    let existing = q_scalar!(&state.db, "SELECT COUNT(*) FROM users")
        .await
        .unwrap_or(0);
    if existing > 0 {
        tracing::info!(
            "bootstrap: des utilisateurs existent deja, OWNER_EMAIL ignore"
        );
        return;
    }

    // Mot de passe temporaire aleatoire 32 caracteres
    let mut raw = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    let password = hex::encode(raw);

    let id = uuid::Uuid::new_v4().to_string();
    let (phc, salt) = match pw::hash_password(&password, &state.cfg.password_pepper) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("bootstrap: hash impossible: {e}");
            return;
        }
    };

    if let Err(AppError::Conflict(_)) =
        users::create_user(&state.db, &id, &email, Some(&phc), &salt, "owner").await
    {
        tracing::warn!("bootstrap: email deja present, ignore");
        return;
    }
    if let Err(e) =
        q_exec!(&state.db, "UPDATE users SET email_verified = TRUE WHERE id = $1", id.clone())
            .await
    {
        tracing::warn!("bootstrap: verification auto echouee: {e}");
    }

    crate::services::audit::log_event(
        state,
        Some(&id),
        crate::services::audit::events::REGISTER,
        crate::services::audit::SEV_CRITICAL,
        None,
        None,
        Some(serde_json::json!({ "bootstrap": true, "role": "owner" })),
    )
    .await;

    tokens::hmac_hash(&state.cfg.password_pepper, &password); // warm-up constant-time

    tracing::warn!(
        "\n==============================================\n\
         BOOTSTRAP OWNER CREE (premier demarrage)\n\
         Email    : {}\n\
         Password : {}\n\
         >>> CHANGEZ CE MOT DE PASSE IMMEDIATEMENT <<<\n\
         ==============================================",
        email,
        password
    );
}
