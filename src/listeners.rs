//! Supervisor for the listeners whose addresses are configurable at runtime.
//!
//! The plaintext web UI is deliberately not managed here — it is bound once at
//! startup from [`crate::config::BootConfig`] and never moves, so a bad setting
//! can never lock the admin out of the UI that fixes it.
//!
//! [`reconcile`] is idempotent: it compares the running addresses against the
//! current settings and only touches what actually changed. A new address is
//! bound *before* the old listener is dropped, so a port that is already taken
//! leaves the previous listener serving instead of killing it for nothing.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use crate::state::AppState;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    Smtp,
    Smtps,
    Https,
    AcmeHttp,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Smtp => "SMTP (plaintext + STARTTLS)",
            Kind::Smtps => "SMTPS (implicit TLS)",
            Kind::Https => "HTTPS web UI",
            Kind::AcmeHttp => "ACME HTTP-01 challenge",
        }
    }
}

struct Running {
    addr: String,
    handle: JoinHandle<()>,
}

#[derive(Default)]
pub struct Listeners {
    slots: Mutex<HashMap<Kind, Running>>,
}

impl Listeners {
    /// Addresses currently being served, for display in the admin UI.
    pub async fn active(&self) -> Vec<(Kind, String)> {
        let slots = self.slots.lock().await;
        let mut out: Vec<(Kind, String)> = slots.iter().map(|(k, r)| (*k, r.addr.clone())).collect();
        out.sort_by_key(|(k, _)| format!("{k:?}"));
        out
    }
}

/// Bring the running listeners in line with the current settings.
/// Returns one message per listener that could not be started.
pub async fn reconcile(state: &Arc<AppState>) -> Vec<String> {
    let settings = state.settings();
    // An empty address means "this listener should not be running".
    let desired = [
        (Kind::Smtp, settings.smtp_addr.clone()),
        (Kind::Smtps, settings.smtps_addr.clone()),
        (Kind::Https, settings.https_addr.clone()),
        (
            Kind::AcmeHttp,
            if settings.acme_enabled { settings.acme_http_addr.clone() } else { String::new() },
        ),
    ];

    let mut errors = Vec::new();
    let mut slots = state.listeners.slots.lock().await;

    for (kind, addr) in desired {
        match slots.get(&kind) {
            Some(running) if running.addr == addr => continue,
            _ => {}
        }

        if addr.is_empty() {
            if let Some(old) = slots.remove(&kind) {
                old.handle.abort();
                tracing::info!("{} listener on {} stopped", kind.label(), old.addr);
            }
            continue;
        }

        let listener = match TcpListener::bind(&addr).await {
            Ok(l) => l,
            Err(e) => {
                let msg = format!("cannot bind {} to {addr}: {e}{}", kind.label(), bind_hint(&addr, &e));
                tracing::error!("{msg}");
                if let Some(old) = slots.get(&kind) {
                    errors.push(format!("{msg} (still serving on {})", old.addr));
                } else {
                    errors.push(msg);
                }
                continue;
            }
        };

        if let Some(old) = slots.remove(&kind) {
            old.handle.abort();
            tracing::info!("{} listener moving from {} to {addr}", kind.label(), old.addr);
        }

        let handle = spawn(kind, state.clone(), listener);
        tracing::info!("{} listening on {addr}", kind.label());
        slots.insert(kind, Running { addr, handle });
    }

    errors
}

/// The default SMTP ports are privileged, so "permission denied" is the single
/// most likely bind failure. Say what to do about it rather than just the errno.
fn bind_hint(addr: &str, e: &std::io::Error) -> String {
    let privileged = addr
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .is_some_and(|p| p < 1024);
    if privileged && e.kind() == std::io::ErrorKind::PermissionDenied {
        " (ports below 1024 need CAP_NET_BIND_SERVICE, a port redirect, \
          or a higher port set at /admin/settings)"
            .to_string()
    } else {
        String::new()
    }
}

fn spawn(kind: Kind, state: Arc<AppState>, listener: TcpListener) -> JoinHandle<()> {
    match kind {
        Kind::Smtp => tokio::spawn(crate::smtp::accept_plain(state, listener)),
        Kind::Smtps => tokio::spawn(crate::smtp::accept_implicit_tls(state, listener)),
        Kind::Https => tokio::spawn(serve_https(state, listener)),
        Kind::AcmeHttp => tokio::spawn(serve_acme_challenge(state, listener)),
    }
}

async fn serve_https(state: Arc<AppState>, listener: TcpListener) {
    if let Err(e) = crate::web::serve_https(state, listener).await {
        tracing::error!("HTTPS listener stopped: {e:#}");
    }
}

/// A listener that answers nothing but ACME HTTP-01 challenges. Deliberately
/// minimal: it usually runs on port 80 facing the open internet.
async fn serve_acme_challenge(state: Arc<AppState>, listener: TcpListener) {
    let app = crate::acme::challenge_router(state);
    if let Err(e) = axum::serve(listener, app).await {
        tracing::error!("ACME challenge listener stopped: {e:#}");
    }
}
