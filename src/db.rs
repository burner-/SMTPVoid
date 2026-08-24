use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use anyhow::{anyhow, Result};
use rusqlite::{params, Connection, OptionalExtension};

use crate::config::now_unix;
use crate::mailstore::ConnKind;

/// Thin synchronous wrapper around SQLite. Queries are tiny; the connection is
/// shared behind a mutex. Expensive work (argon2) happens outside of this module.
pub struct Db {
    conn: Mutex<Connection>,
}

#[derive(Debug, Clone)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub is_admin: bool,
}

#[derive(Debug, Clone)]
pub struct SmtpCredential {
    pub id: i64,
    pub username: String,
    /// The password itself, in the clear, for the dashboard to show.
    pub password: String,
    pub created_at: i64,
    pub total_messages: i64,
    pub last_used_at: Option<i64>,
}

/// Minimal data needed to verify an SMTP AUTH attempt.
#[derive(Debug, Clone)]
pub struct CredAuth {
    pub id: i64,
    pub user_id: i64,
    pub username: String,
    pub password: String,
}

/// Per-user statistics row for the admin view. Never contains message content.
#[derive(Debug, Clone)]
pub struct AdminUserRow {
    pub id: i64,
    pub username: String,
    pub is_admin: bool,
    pub created_at: i64,
    pub cred_count: i64,
    pub total_messages: i64,
    pub total_bytes: i64,
    pub count_plaintext: i64,
    pub count_starttls: i64,
    pub count_tls: i64,
    pub last_message_at: Option<i64>,
}

#[derive(Debug, Clone, Default)]
pub struct GlobalStats {
    pub total_users: i64,
    pub total_credentials: i64,
    pub total_messages: i64,
    pub total_bytes: i64,
    pub count_plaintext: i64,
    pub count_starttls: i64,
    pub count_tls: i64,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    total_messages INTEGER NOT NULL DEFAULT 0,
    total_bytes INTEGER NOT NULL DEFAULT 0,
    count_plaintext INTEGER NOT NULL DEFAULT 0,
    count_starttls INTEGER NOT NULL DEFAULT 0,
    count_tls INTEGER NOT NULL DEFAULT 0,
    last_message_at INTEGER
);
-- An SMTP credential can only push mail into a virtual mailbox that is never
-- delivered anywhere, so its password is kept in the clear and the dashboard
-- shows it whenever the owner asks. Account passwords are a different matter
-- and stay hashed, in users.password_hash above.
CREATE TABLE IF NOT EXISTS smtp_credentials (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    total_messages INTEGER NOT NULL DEFAULT 0,
    last_used_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_creds_user ON smtp_credentials(user_id);
CREATE TABLE IF NOT EXISTS global_stats (
    key TEXT PRIMARY KEY,
    value INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
";

impl Db {
    pub fn open(path: &Path) -> Result<Db> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(SCHEMA)?;
        migrate_credential_passwords(&conn)?;
        Ok(Db { conn: Mutex::new(conn) })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().expect("db mutex poisoned")
    }

    // ---- settings ----

    /// Read every stored settings row. Missing keys are the caller's problem
    /// (see [`crate::settings::Settings::from_pairs`], which fills in defaults).
    pub fn load_settings(&self) -> Result<HashMap<String, String>> {
        let conn = self.lock();
        let mut stmt = conn.prepare("SELECT key, value FROM settings")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        let mut map = HashMap::new();
        for row in rows {
            let (k, v) = row?;
            map.insert(k, v);
        }
        Ok(map)
    }

    /// Persist settings rows atomically: either the whole set lands or none does.
    pub fn save_settings(&self, pairs: &[(&str, String)]) -> Result<()> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        for (key, value) in pairs {
            tx.execute(
                "INSERT INTO settings (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = ?2",
                params![key, value],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    // ---- users ----

    pub fn create_user(&self, username: &str, password_hash: &str, is_admin: bool) -> Result<i64> {
        let conn = self.lock();
        let res = conn.execute(
            "INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![username, password_hash, is_admin as i64, now_unix()],
        );
        match res {
            Ok(_) => Ok(conn.last_insert_rowid()),
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Err(anyhow!("username is already taken"))
            }
            Err(e) => Err(e.into()),
        }
    }

    pub fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        let conn = self.lock();
        let user = conn
            .query_row(
                "SELECT id, username, password_hash, is_admin FROM users WHERE username = ?1",
                params![username],
                |r| {
                    Ok(User {
                        id: r.get(0)?,
                        username: r.get(1)?,
                        password_hash: r.get(2)?,
                        is_admin: r.get::<_, i64>(3)? != 0,
                    })
                },
            )
            .optional()?;
        Ok(user)
    }

    pub fn get_user_by_id(&self, id: i64) -> Result<Option<User>> {
        let conn = self.lock();
        let user = conn
            .query_row(
                "SELECT id, username, password_hash, is_admin FROM users WHERE id = ?1",
                params![id],
                |r| {
                    Ok(User {
                        id: r.get(0)?,
                        username: r.get(1)?,
                        password_hash: r.get(2)?,
                        is_admin: r.get::<_, i64>(3)? != 0,
                    })
                },
            )
            .optional()?;
        Ok(user)
    }

    /// Replace a user's web password. Returns false when the row is gone.
    pub fn set_password(&self, user_id: i64, password_hash: &str) -> Result<bool> {
        let conn = self.lock();
        let n = conn.execute(
            "UPDATE users SET password_hash = ?2 WHERE id = ?1",
            params![user_id, password_hash],
        )?;
        Ok(n > 0)
    }

    /// Grant or revoke admin rights.
    pub fn set_admin(&self, user_id: i64, is_admin: bool) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "UPDATE users SET is_admin = ?2 WHERE id = ?1",
            params![user_id, is_admin as i64],
        )?;
        Ok(())
    }

    pub fn admin_exists(&self) -> Result<bool> {
        let conn = self.lock();
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM users WHERE is_admin = 1", [], |r| r.get(0))?;
        Ok(n > 0)
    }

    pub fn delete_user(&self, id: i64) -> Result<()> {
        let conn = self.lock();
        conn.execute("DELETE FROM users WHERE id = ?1", params![id])?;
        Ok(())
    }

    // ---- SMTP credentials ----

    pub fn create_credential(&self, user_id: i64, username: &str, password: &str) -> Result<i64> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO smtp_credentials (user_id, username, password, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![user_id, username, password, now_unix()],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn count_credentials(&self, user_id: i64) -> Result<i64> {
        let conn = self.lock();
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM smtp_credentials WHERE user_id = ?1",
            params![user_id],
            |r| r.get(0),
        )?;
        Ok(n)
    }

    pub fn list_credentials(&self, user_id: i64) -> Result<Vec<SmtpCredential>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT id, username, password, created_at, total_messages, last_used_at
             FROM smtp_credentials WHERE user_id = ?1 ORDER BY created_at ASC",
        )?;
        let rows = stmt
            .query_map(params![user_id], |r| {
                Ok(SmtpCredential {
                    id: r.get(0)?,
                    username: r.get(1)?,
                    password: r.get(2)?,
                    created_at: r.get(3)?,
                    total_messages: r.get(4)?,
                    last_used_at: r.get(5)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Delete a credential, but only if it belongs to the given user.
    pub fn delete_credential(&self, user_id: i64, cred_id: i64) -> Result<bool> {
        let conn = self.lock();
        let n = conn.execute(
            "DELETE FROM smtp_credentials WHERE id = ?1 AND user_id = ?2",
            params![cred_id, user_id],
        )?;
        Ok(n > 0)
    }

    pub fn get_credential_for_auth(&self, username: &str) -> Result<Option<CredAuth>> {
        let conn = self.lock();
        let cred = conn
            .query_row(
                "SELECT id, user_id, username, password FROM smtp_credentials WHERE username = ?1",
                params![username],
                |r| {
                    Ok(CredAuth {
                        id: r.get(0)?,
                        user_id: r.get(1)?,
                        username: r.get(2)?,
                        password: r.get(3)?,
                    })
                },
            )
            .optional()?;
        Ok(cred)
    }

    // ---- statistics ----

    /// Record an accepted message into the persistent counters.
    pub fn record_message(&self, user_id: i64, cred_id: i64, size: i64, kind: ConnKind) -> Result<()> {
        let col = match kind {
            ConnKind::Plaintext => "count_plaintext",
            ConnKind::StartTls => "count_starttls",
            ConnKind::ImplicitTls => "count_tls",
        };
        let now = now_unix();
        let conn = self.lock();
        conn.execute(
            &format!(
                "UPDATE users SET total_messages = total_messages + 1, total_bytes = total_bytes + ?1,
                 {col} = {col} + 1, last_message_at = ?2 WHERE id = ?3"
            ),
            params![size, now, user_id],
        )?;
        conn.execute(
            "UPDATE smtp_credentials SET total_messages = total_messages + 1, last_used_at = ?1 WHERE id = ?2",
            params![now, cred_id],
        )?;
        for (key, delta) in [
            ("total_messages", 1),
            ("total_bytes", size),
            (col, 1),
        ] {
            conn.execute(
                "INSERT INTO global_stats (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = value + ?2",
                params![key, delta],
            )?;
        }
        Ok(())
    }

    pub fn list_users_admin(&self) -> Result<Vec<AdminUserRow>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT u.id, u.username, u.is_admin, u.created_at,
                    (SELECT COUNT(*) FROM smtp_credentials c WHERE c.user_id = u.id),
                    u.total_messages, u.total_bytes,
                    u.count_plaintext, u.count_starttls, u.count_tls, u.last_message_at
             FROM users u ORDER BY u.created_at ASC",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(AdminUserRow {
                    id: r.get(0)?,
                    username: r.get(1)?,
                    is_admin: r.get::<_, i64>(2)? != 0,
                    created_at: r.get(3)?,
                    cred_count: r.get(4)?,
                    total_messages: r.get(5)?,
                    total_bytes: r.get(6)?,
                    count_plaintext: r.get(7)?,
                    count_starttls: r.get(8)?,
                    count_tls: r.get(9)?,
                    last_message_at: r.get(10)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn global_stats(&self) -> Result<GlobalStats> {
        let conn = self.lock();
        let mut stats = GlobalStats::default();
        stats.total_users = conn.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?;
        stats.total_credentials =
            conn.query_row("SELECT COUNT(*) FROM smtp_credentials", [], |r| r.get(0))?;
        let mut stmt = conn.prepare("SELECT key, value FROM global_stats")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
        for row in rows {
            let (key, value) = row?;
            match key.as_str() {
                "total_messages" => stats.total_messages = value,
                "total_bytes" => stats.total_bytes = value,
                "count_plaintext" => stats.count_plaintext = value,
                "count_starttls" => stats.count_starttls = value,
                "count_tls" => stats.count_tls = value,
                _ => {}
            }
        }
        Ok(stats)
    }
}

/// Credential passwords used to be stored only as an argon2 hash, so the
/// dashboard could show one exactly once. They live in the clear now, and a
/// hash cannot be turned back into the password it came from, so an older
/// database has its credentials removed rather than carrying rows the UI could
/// never show. Users make new ones from the dashboard; nothing else is touched.
fn migrate_credential_passwords(conn: &Connection) -> Result<()> {
    let has_column = conn
        .prepare("SELECT 1 FROM pragma_table_info('smtp_credentials') WHERE name = 'password'")?
        .exists([])?;
    if has_column {
        return Ok(());
    }
    let dropped: i64 =
        conn.query_row("SELECT COUNT(*) FROM smtp_credentials", [], |r| r.get(0))?;
    conn.execute_batch(
        "BEGIN;
         DROP TABLE smtp_credentials;
         CREATE TABLE smtp_credentials (
             id INTEGER PRIMARY KEY,
             user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
             username TEXT NOT NULL UNIQUE,
             password TEXT NOT NULL,
             created_at INTEGER NOT NULL,
             total_messages INTEGER NOT NULL DEFAULT 0,
             last_used_at INTEGER
         );
         CREATE INDEX IF NOT EXISTS idx_creds_user ON smtp_credentials(user_id);
         COMMIT;",
    )?;
    if dropped > 0 {
        tracing::warn!(
            "removed {dropped} SMTP credential(s) that only had a hashed password; their owners create new ones from the dashboard"
        );
    }
    Ok(())
}
