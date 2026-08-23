//! Passkeys / WebAuthn : authentification sans mot de passe (FIDO2).
//!
//! Les credentials (structure `Passkey` serialisee) sont chiffres
//! AES-256-GCM au repos. Les challenges d'enregistrement/authentification
//! sont conserves en memoire 10 min max (store partagé requis en multi-instance).

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use serde_json::json;
use webauthn_rs::prelude::*;

use crate::error::{AppError, AppResult};
use crate::models::PasskeyRow;
use crate::q_exec;
use crate::q_fetch_all;
use crate::q_fetch_optional;
use crate::services::audit;
use crate::state::AppState;
use std::time::{Duration, Instant};

const STATE_TTL: Duration = Duration::from_secs(600);

async fn user_passkeys(state: &AppState, user_id: &str) -> AppResult<Vec<Passkey>> {
    let rows: Vec<PasskeyRow> = q_fetch_all!(
        &state.db,
        PasskeyRow,
        "SELECT * FROM passkeys WHERE user_id = $1",
        user_id.to_string()
    )
    .await?;
    rows.iter()
        .map(|r| {
            let plain = state.enc.decrypt(&r.public_key_enc)?;
            Ok(serde_json::from_str::<Passkey>(&plain)?)
        })
        .collect::<Result<Vec<_>, anyhow::Error>>()
        .map_err(|e| AppError::internal(format!("passkey decode: {e}")))
}

fn cleanup(map: &mut std::collections::HashMap<String, (impl Clone, Instant)>) {
    map.retain(|_, (_, at)| at.elapsed() < STATE_TTL);
}

// ---------------------------------------------------------------------------
// Enregistrement
// ---------------------------------------------------------------------------

pub async fn registration_options(
    state: &AppState,
    user_id: &str,
    email: &str,
) -> AppResult<CreationChallengeResponse> {
    let uuid = uuid::Uuid::parse_str(user_id)
        .map_err(|_| AppError::validation("invalid user id"))?;
    let exclude: Option<Vec<CredentialID>> = None; // contrainte UNIQUE en base suffit

    let (ccr, reg_state) = state
        .webauthn
        .start_passkey_registration(uuid, email, Some(email), exclude)
        .map_err(|e| AppError::internal(format!("webauthn start_reg: {e}")))?;

    let mut map = state.wa_reg.lock().unwrap();
    cleanup(&mut map);
    map.insert(user_id.to_string(), (reg_state, Instant::now()));
    Ok(ccr)
}

pub async fn registration_finish(
    state: &AppState,
    user_id: &str,
    name: &str,
    resp: &RegisterPublicKeyCredential,
) -> AppResult<String> {
    let reg_state = state
        .wa_reg
        .lock()
        .unwrap()
        .remove(user_id)
        .filter(|(_, at)| at.elapsed() < STATE_TTL)
        .map(|(s, _)| s)
        .ok_or_else(|| AppError::validation("No pending passkey registration"))?;

    let passkey = state
        .webauthn
        .finish_passkey_registration(&reg_state, resp)
        .map_err(|e| AppError::validation(format!("Invalid attestation: {e}")))?;

    let cred_b64 = B64URL.encode(&passkey.cred_id.0);
    let serialized =
        serde_json::to_string(&passkey).map_err(|e| AppError::internal(format!("serde: {e}")))?;
    let enc = state.enc.encrypt(&serialized)?;

    let id = uuid::Uuid::new_v4().to_string();
    let now = crate::util::now();
    q_exec!(
        &state.db,
        "INSERT INTO passkeys (id, user_id, name, credential_id, public_key_enc, counter, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
        id.clone(),
        user_id.to_string(),
        crate::util::sanitize(name),
        cred_b64,
        enc,
        passkey.counter as i64,
        now
    )
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(ref dbe) if dbe.is_unique_violation() => {
            AppError::Conflict("Passkey already registered".into())
        }
        other => other.into(),
    })?;

    audit::log_event(
        state,
        Some(user_id),
        audit::events::PASSKEY_ADDED,
        audit::SEV_INFO,
        None,
        None,
        Some(json!({ "name": name })),
    )
    .await;

    Ok(id)
}

// ---------------------------------------------------------------------------
// Authentification
// ---------------------------------------------------------------------------

pub async fn authentication_options(
    state: &AppState,
    email: Option<&str>,
) -> AppResult<(String, RequestChallengeResponse)> {
    let creds: Vec<Passkey> = match email {
        Some(e) => match crate::services::users::find_by_email(&state.db, e).await? {
            Some(u) => user_passkeys(state, &u.id).await?,
            None => {
                // anti-enumeration : message identique
                return Err(AppError::Unauthorized);
            }
        },
        None => return Err(AppError::validation("email required")),
    };

    if creds.is_empty() {
        return Err(AppError::Unauthorized);
    }

    let (rcr, auth_state) = state
        .webauthn
        .start_passkey_authentication(&creds)
        .map_err(|e| AppError::internal(format!("webauthn start_auth: {e}")))?;

    let challenge_id = hex::encode({
        use rand::RngCore;
        let mut b = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut b);
        b
    });

    let mut map = state.wa_auth.lock().unwrap();
    cleanup(&mut map);
    map.insert(challenge_id.clone(), (auth_state, Instant::now()));
    Ok((challenge_id, rcr))
}

pub async fn authentication_finish(
    state: &AppState,
    challenge_id: &str,
    resp: &PublicKeyCredential,
) -> AppResult<(String, String)> {
    let auth_state = state
        .wa_auth
        .lock()
        .unwrap()
        .remove(challenge_id)
        .filter(|(_, at)| at.elapsed() < STATE_TTL)
        .map(|(s, _)| s)
        .ok_or_else(|| AppError::validation("No pending passkey authentication"))?;

    let (_passkey, _result) = state
        .webauthn
        .finish_passkey_authentication(&auth_state, resp)
        .map_err(|e| AppError::validation(format!("Invalid assertion: {e}")))?;

    let cred_b64 = B64URL.encode(&_passkey.cred_id.0);

    #[derive(sqlx::FromRow)]
    struct Row {
        id: String,
        user_id: String,
    }
    let row = q_fetch_optional!(
        &state.db,
        Row,
        "SELECT id, user_id FROM passkeys WHERE credential_id = $1",
        cred_b64.clone()
    )
    .await?
    .ok_or_else(|| AppError::Unauthorized)?;

    let now = crate::util::now();
    q_exec!(
        &state.db,
        "UPDATE passkeys SET counter = $2, last_used_at = $3 WHERE id = $1",
        row.id.clone(),
        _passkey.counter as i64,
        now
    )
    .await?;

    audit::log_event(
        state,
        Some(&row.user_id),
        audit::events::PASSKEY_LOGIN,
        audit::SEV_INFO,
        None,
        None,
        Some(json!({ "credential": cred_b64 })),
    )
    .await;

    Ok((row.user_id, row.id))
}
