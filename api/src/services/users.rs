//! Utilisateurs : CRUD, recherche, cycle de vie.

use chrono::{DateTime, Utc};
use sqlx::FromRow;

use crate::db::Db;
use crate::error::{AppError, AppResult};
use crate::models::User;
use crate::q_exec;
use crate::q_fetch_all;
use crate::q_fetch_optional;
use crate::q_scalar;

#[derive(Debug, FromRow, serde::Serialize)]
pub struct UserListItem {
    pub id: String,
    pub email: String,
    pub role: String,
    pub email_verified: bool,
    pub created_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
    pub last_login_ip: Option<String>,
}

pub async fn create_user(
    db: &Db,
    id: &str,
    email: &str,
    password_hash: Option<&str>,
    salt: &str,
    role: &str,
) -> AppResult<()> {
    let now: DateTime<Utc> = crate::util::now();
    q_exec!(
        db,
        "INSERT INTO users (id, email, password_hash, salt, email_verified, role, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        id.to_string(),
        email.to_string(),
        password_hash.map(|s| s.to_string()),
        salt.to_string(),
        false,
        role.to_string(),
        now,
        now
    )
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(ref dbe) if dbe.is_unique_violation() => {
            AppError::Conflict("Email already registered".into())
        }
        other => other.into(),
    })
}

pub async fn find_by_email(db: &Db, email: &str) -> AppResult<Option<User>> {
    q_fetch_optional!(
        db,
        User,
        "SELECT * FROM users WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL",
        email.to_string()
    )
    .await
}

pub async fn get_user(db: &Db, id: &str) -> AppResult<Option<User>> {
    q_fetch_optional!(
        db,
        User,
        "SELECT * FROM users WHERE id = $1 AND deleted_at IS NULL",
        id.to_string()
    )
    .await
}

pub async fn require_user(db: &Db, id: &str) -> AppResult<User> {
    get_user(db, id)
        .await?
        .ok_or_else(|| AppError::Unauthorized)
}

pub async fn set_credentials(db: &Db, id: &str, phc: Option<&str>, salt: &str) -> AppResult<()> {
    let now: DateTime<Utc> = crate::util::now();
    q_exec!(
        db,
        "UPDATE users SET password_hash = $2, salt = $3, updated_at = $4 WHERE id = $1",
        id.to_string(),
        phc.map(|s| s.to_string()),
        salt.to_string(),
        now
    )
    .await?;
    Ok(())
}

pub async fn mark_email_verified(db: &Db, id: &str) -> AppResult<()> {
    let now: DateTime<Utc> = crate::util::now();
    q_exec!(
        db,
        "UPDATE users SET email_verified = TRUE, updated_at = $2 WHERE id = $1",
        id.to_string(),
        now
    )
    .await?;
    Ok(())
}

pub async fn set_email(db: &Db, id: &str, new_email: &str) -> AppResult<()> {
    let now: DateTime<Utc> = crate::util::now();
    q_exec!(
        db,
        "UPDATE users SET email = $2, email_verified = FALSE, updated_at = $3 WHERE id = $1",
        id.to_string(),
        new_email.to_string(),
        now
    )
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(ref dbe) if dbe.is_unique_violation() => {
            AppError::Conflict("Email already in use".into())
        }
        other => other.into(),
    })?;
    Ok(())
}

pub async fn soft_delete(db: &Db, id: &str) -> AppResult<()> {
    let now: DateTime<Utc> = crate::util::now();
    let anon = format!("deleted-{}@invalid.local", uuid::Uuid::new_v4().simple());
    q_exec!(
        db,
        "UPDATE users SET deleted_at = $2, email = $3, updated_at = $4 WHERE id = $1",
        id.to_string(),
        now,
        anon,
        now
    )
    .await?;
    Ok(())
}

pub async fn touch_login(
    db: &Db,
    id: &str,
    ip: &str,
    country: Option<&str>,
    device: &str,
) -> AppResult<()> {
    let now: DateTime<Utc> = crate::util::now();
    q_exec!(
        db,
        "UPDATE users SET last_login_at = $2, last_login_ip = $3, last_login_country = $4, last_login_device = $5, updated_at = $6 WHERE id = $1",
        id.to_string(),
        now,
        ip.to_string(),
        country.map(|s| s.to_string()),
        device.to_string(),
        now
    )
    .await?;
    Ok(())
}

pub async fn list_users(
    db: &Db,
    limit: i64,
    offset: i64,
    search: Option<&str>,
) -> AppResult<Vec<UserListItem>> {
    let term = format!("%{}%", search.unwrap_or("").to_lowercase());
    q_fetch_all!(
        db,
        UserListItem,
        "SELECT id, email, role, email_verified, created_at, last_login_at, last_login_ip
         FROM users
         WHERE deleted_at IS NULL AND LOWER(email) LIKE LOWER($3)
         ORDER BY created_at DESC
         LIMIT $1 OFFSET $2",
        limit,
        offset,
        term.clone()
    )
    .await
}

pub async fn count_users(db: &Db, search: Option<&str>) -> AppResult<i64> {
    let term = format!("%{}%", search.unwrap_or("").to_lowercase());
    q_scalar!(
        db,
        "SELECT COUNT(*) FROM users WHERE deleted_at IS NULL AND LOWER(email) LIKE LOWER($1)",
        term.clone()
    )
    .await
}
