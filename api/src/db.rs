//! Abstraction dual-backend PostgreSQL / SQLite.
//!
//! Toutes les requêtes sont écrites en placeholders `$N` (PostgreSQL) et
//! convertis en `?` pour SQLite à l'exécution. Les macros ci-dessous
//! dispatchent vers le bon driver tout en gardant un binding de types fort
//! (`String`, `i64`, `bool`, `DateTime<Utc>` et leurs `Option`), supportés
//! nativement par les deux backends via les features sqlx `chrono`/`uuid`.

use sqlx::{
    postgres::PgPoolOptions,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
    PgPool, SqlitePool,
};
use std::str::FromStr;
use std::time::Duration;

#[derive(Clone)]
pub enum Db {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

impl std::fmt::Debug for Db {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Db::Postgres(_) => write!(f, "Db::Postgres"),
            Db::Sqlite(_) => write!(f, "Db::Sqlite"),
        }
    }
}

/// Convertit les placeholders `$N` en `?` (dialecte SQLite).
pub fn sqlite_sql(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let mut chars = sql.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '$' && chars.peek().map(|d| d.is_ascii_digit()).unwrap_or(false) {
            out.push('?');
            while let Some(d) = chars.peek() {
                if d.is_ascii_digit() {
                    chars.next();
                } else {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

impl Db {
    pub async fn connect(url: &str) -> anyhow::Result<Db> {
        if url.starts_with("postgres://") || url.starts_with("postgresql://") {
            let pool = PgPoolOptions::new()
                .max_connections(10)
                .acquire_timeout(Duration::from_secs(10))
                .connect(url)
                .await?;
            Ok(Db::Postgres(pool))
        } else {
            let opts = SqliteConnectOptions::from_str(url)?
                .create_if_missing(true)
                .journal_mode(SqliteJournalMode::Wal);
            let pool = SqlitePoolOptions::new()
                .max_connections(10)
                .acquire_timeout(Duration::from_secs(10))
                .connect_with(opts)
                .await?;
            Ok(Db::Sqlite(pool))
        }
    }

    pub async fn migrate(&self) -> anyhow::Result<()> {
        match self {
            Db::Postgres(p) => {
                sqlx::migrate!("migrations/postgres").run(p).await?;
            }
            Db::Sqlite(p) => {
                sqlx::migrate!("migrations/sqlite").run(p).await?;
            }
        }
        Ok(())
    }
}

/// Exécute une requête sans résultat : Result<(), sqlx::Error>
#[macro_export]
macro_rules! q_exec {
    ($db:expr, $sql:expr $(, $arg:expr)* $(,)?) => {
        match $db {
            $crate::db::Db::Postgres(p) => {
                sqlx::query($sql)$(.bind($arg))*.execute(p).await.map(|_| ())
            }
            $crate::db::Db::Sqlite(p) => {
                let __sql = $crate::db::sqlite_sql($sql);
                sqlx::query(__sql.as_str())$(.bind($arg))*.execute(p).await.map(|_| ())
            }
        }
    };
}

/// Récupère toutes les lignes mappées sur T : FromRow.
#[macro_export]
macro_rules! q_fetch_all {
    ($db:expr, $ty:ty, $sql:expr $(, $arg:expr)* $(,)?) => {
        match $db {
            $crate::db::Db::Postgres(p) => {
                sqlx::query_as::<_, $ty>($sql)$(.bind($arg))*.fetch_all(p).await
            }
            $crate::db::Db::Sqlite(p) => {
                let __sql = $crate::db::sqlite_sql($sql);
                sqlx::query_as::<_, $ty>(__sql.as_str())$(.bind($arg))*.fetch_all(p).await
            }
        }
    };
}

/// Récupère au plus une ligne mappée sur T : FromRow.
#[macro_export]
macro_rules! q_fetch_optional {
    ($db:expr, $ty:ty, $sql:expr $(, $arg:expr)* $(,)?) => {
        match $db {
            $crate::db::Db::Postgres(p) => {
                sqlx::query_as::<_, $ty>($sql)$(.bind($arg))*.fetch_optional(p).await
            }
            $crate::db::Db::Sqlite(p) => {
                let __sql = $crate::db::sqlite_sql($sql);
                sqlx::query_as::<_, $ty>(__sql.as_str())$(.bind($arg))*.fetch_optional(p).await
            }
        }
    };
}

/// Récupère exactement une ligne mappée sur T : FromRow.
#[macro_export]
macro_rules! q_fetch_one {
    ($db:expr, $ty:ty, $sql:expr $(, $arg:expr)* $(,)?) => {
        match $db {
            $crate::db::Db::Postgres(p) => {
                sqlx::query_as::<_, $ty>($sql)$(.bind($arg))*.fetch_one(p).await
            }
            $crate::db::Db::Sqlite(p) => {
                let __sql = $crate::db::sqlite_sql($sql);
                sqlx::query_as::<_, $ty>(__sql.as_str())$(.bind($arg))*.fetch_one(p).await
            }
        }
    };
}

/// Récupère un scalaire i64 (COUNT, SUM...).
#[macro_export]
macro_rules! q_scalar {
    ($db:expr, $sql:expr $(, $arg:expr)* $(,)?) => {
        match $db {
            $crate::db::Db::Postgres(p) => {
                sqlx::query($sql)$(.bind($arg))*
                    .fetch_one(p)
                    .await
                    .and_then(|r| r.try_get::<i64, usize>(0))
            }
            $crate::db::Db::Sqlite(p) => {
                let __sql = $crate::db::sqlite_sql($sql);
                sqlx::query(__sql.as_str())$(.bind($arg))*
                    .fetch_one(p)
                    .await
                    .and_then(|r| r.try_get::<i64, usize>(0))
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::sqlite_sql;

    #[test]
    fn converts_placeholders() {
        assert_eq!(
            sqlite_sql("SELECT * FROM t WHERE a = $1 AND b = $2"),
            "SELECT * FROM t WHERE a = ? AND b = ?"
        );
        assert_eq!(sqlite_sql("INSERT INTO t VALUES ($1, $10)"), "INSERT INTO t VALUES (?, ?)");
        assert_eq!(sqlite_sql("SELECT $1"), "SELECT ?");
        assert_eq!(sqlite_sql("price is 5$"), "price is 5$");
    }
}
