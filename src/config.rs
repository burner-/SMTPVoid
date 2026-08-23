use std::path::PathBuf;

/// The only configuration that still comes from the environment.
///
/// Everything else is a [`crate::settings::Settings`] row in the database,
/// editable at `/admin/settings`. These two cannot be: the database that holds
/// the settings lives in `data_dir`, and if a bad `http_addr` were persisted
/// there would be no way back into the UI to fix it.
#[derive(Debug, Clone)]
pub struct BootConfig {
    /// Directory for the SQLite database, TLS material, ACME state and the
    /// admin setup token.
    pub data_dir: PathBuf,
    /// Address the plaintext web UI listens on. Always bound, never restarted.
    pub http_addr: String,
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| default.to_string())
}

impl BootConfig {
    pub fn from_env() -> Self {
        BootConfig {
            data_dir: PathBuf::from(env_or("SMTPVOID_DATA_DIR", "./data")),
            http_addr: env_or("SMTPVOID_HTTP_ADDR", "0.0.0.0:8080"),
        }
    }
}

/// Current unix time in seconds.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Format a unix timestamp as "YYYY-MM-DD HH:MM:SS UTC".
pub fn fmt_ts(ts: i64) -> String {
    match time::OffsetDateTime::from_unix_timestamp(ts) {
        Ok(dt) => match dt.format(&time::format_description::well_known::Rfc3339) {
            Ok(s) => s.replace('T', " ").replace('Z', " UTC"),
            Err(_) => ts.to_string(),
        },
        Err(_) => ts.to_string(),
    }
}

/// Human-readable duration like "42m 10s".
pub fn fmt_duration(mut secs: i64) -> String {
    if secs < 0 {
        secs = 0;
    }
    let d = secs / 86_400;
    let h = (secs % 86_400) / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if d > 0 {
        format!("{d}d {h}h")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}

/// Human-readable byte size.
pub fn fmt_bytes(b: i64) -> String {
    const KB: f64 = 1024.0;
    let b = b as f64;
    if b >= KB * KB * KB {
        format!("{:.1} GiB", b / (KB * KB * KB))
    } else if b >= KB * KB {
        format!("{:.1} MiB", b / (KB * KB))
    } else if b >= KB {
        format!("{:.1} KiB", b / KB)
    } else {
        format!("{} B", b as i64)
    }
}
