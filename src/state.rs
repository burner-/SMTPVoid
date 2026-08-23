use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};

use rustls::ServerConfig;

use crate::acme::Acme;
use crate::config::{now_unix, BootConfig};
use crate::db::Db;
use crate::listeners::Listeners;
use crate::mailstore::MailStore;
use crate::settings::Settings;
use crate::tls::CertStore;

/// A logged-in web session.
#[derive(Debug, Clone)]
pub struct WebSession {
    pub user_id: i64,
    pub expires_at: i64,
}

pub const SESSION_TTL_SECS: i64 = 7 * 24 * 3600;

/// Everything shared between the web UI, the SMTP listeners and the ACME manager.
pub struct AppState {
    /// The two values that still come from the environment.
    pub boot: BootConfig,
    /// Live settings. Swapped wholesale when an admin saves the settings form;
    /// readers take a snapshot so a save cannot change values mid-operation.
    settings: RwLock<Arc<Settings>>,
    pub db: Db,
    pub mail: MailStore,
    /// The swappable certificate behind every TLS listener.
    pub certs: Arc<CertStore>,
    /// Built once over `certs`; never needs replacing when the cert changes.
    pub tls: Arc<ServerConfig>,
    pub acme: Acme,
    pub listeners: Listeners,
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
    /// A snapshot of the current settings. Cheap: this clones an `Arc`.
    pub fn settings(&self) -> Arc<Settings> {
        self.settings.read().expect("settings lock poisoned").clone()
    }

    /// Replace the settings and apply the parts that other components cache.
    /// Listener changes are handled separately by [`crate::listeners::reconcile`].
    pub fn set_settings(&self, new: Settings) {
        self.mail.set_limits(new.retention_secs, new.mailbox_cap);
        *self.settings.write().expect("settings lock poisoned") = Arc::new(new);
    }

    pub fn new(
        boot: BootConfig,
        settings: Settings,
        db: Db,
        certs: Arc<CertStore>,
        tls: Arc<ServerConfig>,
        setup_token: Option<String>,
    ) -> AppState {
        let mail = MailStore::new(settings.retention_secs, settings.mailbox_cap);
        let acme = Acme::new(&boot.data_dir);
        AppState {
            boot,
            settings: RwLock::new(Arc::new(settings)),
            db,
            mail,
            certs,
            tls,
            acme,
            listeners: Listeners::default(),
            sessions: Mutex::new(HashMap::new()),
            reveals: Mutex::new(HashMap::new()),
            setup_token: Mutex::new(setup_token),
            reg_throttle: Mutex::new(HashMap::new()),
            started_at: now_unix(),
        }
    }

    /// Look up a live web session, refreshing its expiry.
    pub fn session_user_id(&self, token: &str) -> Option<i64> {
        let now = now_unix();
        let mut sessions = self.sessions.lock().expect("sessions mutex poisoned");
        sessions.retain(|_, s| s.expires_at > now);
        let s = sessions.get_mut(token)?;
        s.expires_at = now + SESSION_TTL_SECS;
        Some(s.user_id)
    }

    /// Enforce the configured per-IP hourly registration limit.
    pub fn allow_registration(&self, ip: IpAddr) -> bool {
        let limit = self.settings().registrations_per_hour;
        let now = now_unix();
        let mut map = self.reg_throttle.lock().expect("throttle mutex poisoned");
        map.retain(|_, (start, _)| now - *start < 3600);
        let entry = map.entry(ip).or_insert((now, 0));
        if entry.1 >= limit {
            return false;
        }
        entry.1 += 1;
        true
    }
}
