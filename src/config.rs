use std::path::PathBuf;

/// Runtime configuration, read from environment variables with sane defaults.
#[derive(Debug, Clone)]
pub struct Config {
    /// Directory for the SQLite database, TLS material and the admin setup token.
    pub data_dir: PathBuf,
    /// Address the web UI listens on.
    pub http_addr: String,
    /// Address of the plaintext SMTP listener (also offers STARTTLS).
    pub smtp_addr: String,
    /// Address of the implicit-TLS SMTP listener (SMTPS).
    pub smtps_addr: String,
    /// Hostname used in the SMTP banner and the self-signed certificate.
    pub hostname: String,
    /// How long received messages are kept before they vanish.
    pub retention_secs: u64,
    /// Maximum number of messages kept per mailbox (oldest evicted first).
    pub mailbox_cap: usize,
    /// Maximum accepted message size in bytes (advertised via SIZE).
    pub max_message_size: usize,
    /// Maximum SMTP credentials per user account.
    pub max_credentials_per_user: i64,
    /// Set the Secure flag on session cookies (enable behind HTTPS).
    pub cookie_secure: bool,
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| default.to_string())
}

impl Config {
    pub fn from_env() -> Self {
        Config {
            data_dir: PathBuf::from(env_or("SMTPVOID_DATA_DIR", "./data")),
            http_addr: env_or("SMTPVOID_HTTP_ADDR", "0.0.0.0:8080"),
            smtp_addr: env_or("SMTPVOID_SMTP_ADDR", "0.0.0.0:2525"),
            smtps_addr: env_or("SMTPVOID_SMTPS_ADDR", "0.0.0.0:4650"),
            hostname: env_or("SMTPVOID_HOSTNAME", "smtpvoid.local"),
            retention_secs: env_or("SMTPVOID_RETENTION_SECS", "3600").parse().unwrap_or(3600),
            mailbox_cap: env_or("SMTPVOID_MAILBOX_CAP", "100").parse().unwrap_or(100),
            max_message_size: env_or("SMTPVOID_MAX_MESSAGE_SIZE", "1048576").parse().unwrap_or(1_048_576),
            max_credentials_per_user: env_or("SMTPVOID_MAX_CREDENTIALS", "20").parse().unwrap_or(20),
            cookie_secure: env_or("SMTPVOID_COOKIE_SECURE", "0") == "1",
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
