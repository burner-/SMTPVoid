//! Let's Encrypt / ACME certificate provisioning over the HTTP-01 challenge.
//!
//! A background manager wakes up periodically (and on demand from the admin
//! UI) and renews the certificate whenever it is missing, does not cover the
//! configured domains, or is close to expiry. Challenge responses are served
//! from a dedicated listener — usually `0.0.0.0:80` — so the web UI can stay
//! on whatever port it likes.
//!
//! Everything is written into `<data_dir>/acme/`: the account key/credentials
//! and nothing else. The issued certificate lands in the normal TLS directory
//! and is picked up by [`crate::tls::CertStore`] without a restart.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::Router;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use serde::{Deserialize, Serialize};

use crate::config::now_unix;
use crate::settings::Settings;
use crate::state::AppState;

/// How often the manager re-checks the certificate on its own.
const CHECK_INTERVAL: Duration = Duration::from_secs(6 * 3600);

/// Let's Encrypt validation can take a while under load; the library default
/// of 30 seconds gives up far too early.
fn retry_policy() -> RetryPolicy {
    RetryPolicy::default()
        .initial_delay(Duration::from_secs(1))
        .timeout(Duration::from_secs(180))
}

/// What the admin UI reports about certificate provisioning.
#[derive(Debug, Clone, Default)]
pub struct AcmeStatus {
    pub running: bool,
    pub last_attempt: Option<i64>,
    pub last_success: Option<i64>,
    pub last_error: Option<String>,
    /// Progress line while an order is in flight, e.g. "validating 2 domains".
    pub stage: Option<String>,
}

/// ACME state shared between the manager task, the challenge listener and the UI.
pub struct Acme {
    dir: PathBuf,
    /// HTTP-01 responses: challenge token -> key authorization.
    challenges: Mutex<HashMap<String, String>>,
    status: Mutex<AcmeStatus>,
    /// Nudged by the admin UI to run a check immediately.
    trigger: tokio::sync::Notify,
}

impl Acme {
    pub fn new(data_dir: &std::path::Path) -> Acme {
        Acme {
            dir: data_dir.join("acme"),
            challenges: Mutex::new(HashMap::new()),
            status: Mutex::new(AcmeStatus::default()),
            trigger: tokio::sync::Notify::new(),
        }
    }

    pub fn status(&self) -> AcmeStatus {
        self.status.lock().expect("acme status poisoned").clone()
    }

    fn update<F: FnOnce(&mut AcmeStatus)>(&self, f: F) {
        f(&mut self.status.lock().expect("acme status poisoned"));
    }

    /// Ask the manager to check (and renew if needed) right now.
    pub fn request_renewal(&self) {
        self.trigger.notify_one();
    }

    fn challenge_response(&self, token: &str) -> Option<String> {
        self.challenges.lock().expect("acme challenges poisoned").get(token).cloned()
    }

    fn put_challenge(&self, token: String, key_auth: String) {
        self.challenges.lock().expect("acme challenges poisoned").insert(token, key_auth);
    }

    fn clear_challenges(&self) {
        self.challenges.lock().expect("acme challenges poisoned").clear();
    }

    fn account_path(&self) -> PathBuf {
        self.dir.join("account.json")
    }
}

/// The account credentials plus the directory they belong to. Switching
/// between staging and production must not reuse an account key.
#[derive(Serialize, Deserialize)]
struct StoredAccount {
    directory: String,
    credentials: AccountCredentials,
}

// ---- challenge endpoint ----

/// Router serving `/.well-known/acme-challenge/{token}`.
///
/// Mounted both on the dedicated challenge listener and on the main web UI, so
/// a reverse-proxy setup that forwards `/.well-known/` also works.
pub fn challenge_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/.well-known/acme-challenge/{token}", get(serve_challenge))
        .with_state(state)
}

async fn serve_challenge(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
) -> impl axum::response::IntoResponse {
    match state.acme.challenge_response(&token) {
        Some(key_auth) => {
            tracing::debug!("served ACME HTTP-01 challenge for token {token}");
            (StatusCode::OK, [("content-type", "text/plain")], key_auth)
        }
        None => (
            StatusCode::NOT_FOUND,
            [("content-type", "text/plain")],
            "not found".to_string(),
        ),
    }
}

// ---- manager ----

/// Run the renewal loop until the process exits.
pub fn spawn_manager(state: Arc<AppState>) {
    tokio::spawn(async move {
        loop {
            if let Err(e) = check_and_renew(&state, false).await {
                tracing::warn!("ACME check failed: {e:#}");
            }
            tokio::select! {
                _ = state.acme.trigger.notified() => {
                    tracing::info!("ACME renewal requested from the admin UI");
                }
                _ = tokio::time::sleep(CHECK_INTERVAL) => {}
            }
        }
    });
}

/// Renew if needed. With `force`, renew even when the current certificate
/// would still be fine.
pub async fn check_and_renew(state: &Arc<AppState>, force: bool) -> Result<()> {
    let settings = state.settings();
    if !settings.acme_enabled {
        return Ok(());
    }
    if settings.acme_domains.is_empty() {
        return Err(anyhow!("Let's Encrypt is enabled but no domains are configured"));
    }

    if !force {
        if let Some(info) = state.certs.info() {
            let remaining = info.not_after - now_unix();
            let renew_at = settings.acme_renew_before_days * 86_400;
            if info.source == crate::tls::CertSource::Acme
                && info.covers(&settings.acme_domains)
                && remaining > renew_at
            {
                tracing::debug!(
                    "ACME certificate still good for {}",
                    crate::config::fmt_duration(remaining)
                );
                return Ok(());
            }
        }
    }

    // One order at a time: a second run would race on the challenge map.
    let already_running = {
        let mut status = state.acme.status.lock().expect("acme status poisoned");
        if status.running {
            true
        } else {
            status.running = true;
            status.last_attempt = Some(now_unix());
            status.stage = Some("starting".to_string());
            false
        }
    };
    if already_running {
        tracing::info!("ACME order already in progress; skipping this check");
        return Ok(());
    }

    let result = obtain(state, &settings).await;
    state.acme.clear_challenges();
    state.acme.update(|s| {
        s.running = false;
        s.stage = None;
        match &result {
            Ok(()) => {
                s.last_success = Some(now_unix());
                s.last_error = None;
            }
            Err(e) => s.last_error = Some(format!("{e:#}")),
        }
    });
    result
}

async fn obtain(state: &Arc<AppState>, settings: &Settings) -> Result<()> {
    let domains = &settings.acme_domains;
    tracing::info!(
        "requesting certificate for [{}] from {}",
        domains.join(", "),
        settings.acme_directory
    );

    state.acme.update(|s| s.stage = Some("authenticating with the CA".into()));
    let account = load_or_create_account(state, settings).await?;

    let identifiers: Vec<Identifier> = domains.iter().cloned().map(Identifier::Dns).collect();
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .context("creating ACME order")?;

    state.acme.update(|s| s.stage = Some(format!("preparing {} challenge(s)", domains.len())));
    let mut prepared = 0usize;
    {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result.context("fetching authorization")?;
            match authz.status {
                AuthorizationStatus::Pending => {}
                // Already validated within the CA's caching window.
                AuthorizationStatus::Valid => continue,
                other => return Err(anyhow!("authorization is in unusable state {other:?}")),
            }
            let mut challenge = authz.challenge(ChallengeType::Http01).ok_or_else(|| {
                anyhow!("the CA did not offer an HTTP-01 challenge for this order")
            })?;
            let token = challenge.token.clone();
            let key_auth = challenge.key_authorization().as_str().to_string();
            state.acme.put_challenge(token.clone(), key_auth);
            challenge
                .set_ready()
                .await
                .context("telling the CA the challenge is ready")?;
            prepared += 1;
        }
    }
    tracing::info!("{prepared} HTTP-01 challenge(s) published on {}", settings.acme_http_addr);

    state.acme.update(|s| s.stage = Some("waiting for the CA to validate".into()));
    let status = order
        .poll_ready(&retry_policy())
        .await
        .context("waiting for the order to become ready")?;
    if status != OrderStatus::Ready {
        return Err(anyhow!(
            "the CA did not validate the domains (order status {status:?}); \
             check that port {} is reachable from the internet for {}",
            port_of(&settings.acme_http_addr),
            domains.join(", ")
        ));
    }

    state.acme.update(|s| s.stage = Some("finalizing and downloading".into()));
    let key_pem = order.finalize().await.context("finalizing the order")?;
    let cert_pem = order
        .poll_certificate(&retry_policy())
        .await
        .context("downloading the certificate")?;

    state
        .certs
        .install_pem(&cert_pem, &key_pem)
        .context("installing the issued certificate")?;
    tracing::info!("ACME certificate for [{}] is now live", domains.join(", "));
    Ok(())
}

async fn load_or_create_account(state: &Arc<AppState>, settings: &Settings) -> Result<Account> {
    let path = state.acme.account_path();
    if let Ok(raw) = std::fs::read_to_string(&path) {
        match serde_json::from_str::<StoredAccount>(&raw) {
            Ok(stored) if stored.directory == settings.acme_directory => {
                return Account::builder()
                    .context("building ACME HTTP client")?
                    .from_credentials(stored.credentials)
                    .await
                    .context("restoring the stored ACME account");
            }
            Ok(_) => tracing::info!(
                "ACME directory changed; registering a new account with {}",
                settings.acme_directory
            ),
            Err(e) => tracing::warn!("stored ACME account is unreadable ({e}); registering a new one"),
        }
    }

    let contact_uri = if settings.acme_contact_email.is_empty() {
        Vec::new()
    } else {
        vec![format!("mailto:{}", settings.acme_contact_email)]
    };
    let contact: Vec<&str> = contact_uri.iter().map(String::as_str).collect();

    let (account, credentials) = Account::builder()
        .context("building ACME HTTP client")?
        .create(
            &NewAccount {
                contact: &contact,
                terms_of_service_agreed: settings.acme_tos_agreed,
                only_return_existing: false,
            },
            settings.acme_directory.clone(),
            None,
        )
        .await
        .context("registering an ACME account")?;

    std::fs::create_dir_all(&state.acme.dir)
        .with_context(|| format!("creating {}", state.acme.dir.display()))?;
    let stored = StoredAccount {
        directory: settings.acme_directory.clone(),
        credentials,
    };
    let json = serde_json::to_string_pretty(&stored).context("serializing ACME account")?;
    write_private(&path, &json)?;
    tracing::info!("registered a new ACME account, stored in {}", path.display());
    Ok(account)
}

fn port_of(addr: &str) -> &str {
    addr.rsplit_once(':').map(|(_, p)| p).unwrap_or("80")
}

fn write_private(path: &std::path::Path, contents: &str) -> Result<()> {
    std::fs::write(path, contents).with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("restricting permissions on {}", path.display()))?;
    }
    Ok(())
}
