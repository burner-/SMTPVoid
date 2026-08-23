use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use rustls::ServerConfig;

use crate::config::{now_unix, Config};
use crate::db::Db;
use crate::mailstore::MailStore;

/// A logged-in web session.
#[derive(Debug, Clone)]
pub struct WebSession {
    pub user_id: i64,
    pub expires_at: i64,
}

pub const SESSION_TTL_SECS: i64 = 7 * 24 * 3600;

/// Everything shared between the web UI and the SMTP listeners.
pub struct AppState {
    pub cfg: Config,
    pub db: Db,
    pub mail: MailStore,
    pub tls: Arc<ServerConfig>,
    /// Web sessions: token -> session. In-memory only; restart logs everyone out.
    pub sessions: Mutex<HashMap<String, WebSession>>,
    /// One-time reveal of freshly created SMTP credentials, keyed by session token.
    pub reveals: Mutex<HashMap<String, (String, String)>>,
    /// Admin bootstrap token; None once an admin account exists.
    pub setup_token: Mutex<Option<String>>,
    /// Registration throttle: ip -> (window start, count in window).
    pub reg_throttle: Mutex<HashMap<IpAddr, (i64, u32)>>,
    pub started_at: i64,
}

impl AppState {
    /// Look up a live web session, refreshing its expiry.
    pub fn session_user_id(&self, token: &str) -> Option<i64> {
        let now = now_unix();
        let mut sessions = self.sessions.lock().expect("sessions mutex poisoned");
        sessions.retain(|_, s| s.expires_at > now);
        let s = sessions.get_mut(token)?;
        s.expires_at = now + SESSION_TTL_SECS;
        Some(s.user_id)
    }

    /// Allow at most 10 registrations per IP per hour.
    pub fn allow_registration(&self, ip: IpAddr) -> bool {
        let now = now_unix();
        let mut map = self.reg_throttle.lock().expect("throttle mutex poisoned");
        map.retain(|_, (start, _)| now - *start < 3600);
        let entry = map.entry(ip).or_insert((now, 0));
        if entry.1 >= 10 {
            return false;
        }
        entry.1 += 1;
        true
    }
}
