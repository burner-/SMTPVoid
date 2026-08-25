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
use crate::settings::{Settings, LETSENCRYPT_STAGING};
use crate::state::AppState;
use crate::tls::{CertInfo, CertSource};

/// How often the manager re-checks the certificate on its own.
const CHECK_INTERVAL: Duration = Duration::from_secs(6 * 3600);

/// Let's Encrypt issues at most five certificates per exact set of identifiers
/// per 168 hours, and running into that locks the domain out for days. The
/// manager stops at four so a genuine emergency still has one left, and keeps
/// its own record of what it ordered: the CA's counter is invisible from here.
const ISSUE_WINDOW: i64 = 168 * 3600;
const ISSUE_WINDOW_CAP: usize = 4;
/// A successful issuance also puts ordering on hold for a while, which is what
/// stops a misjudged renewal check from ordering on every pass.
const MIN_REISSUE: i64 = 24 * 3600;
/// The admin UI's renew button may cut that short, but not to nothing.
const MIN_REISSUE_FORCED: i64 = 3600;
/// After a failure, retry sooner than the periodic sweep - six hours is a long
/// time to sit on a typo - but never fast enough to trip the CA's separate
/// limit on failed validations (five per hostname per hour).
const RETRY_MIN: Duration = Duration::from_secs(15 * 60);

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
    /// Why ordering is being withheld right now, if it is. Not an error: the
    /// certificate in place is fine, or the CA's rate limit is close.
    pub hold: Option<String>,
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

    fn ledger_path(&self) -> PathBuf {
        self.dir.join("issued.json")
    }

    /// When certificates were last issued for `identifiers` from `directory`,
    /// oldest first, within the CA's rate-limit window. An unreadable ledger
    /// reads as empty: it may cost one extra order, never a stuck renewal.
    fn recent_issuances(&self, directory: &str, identifiers: &[String], now: i64) -> Vec<i64> {
        let ledger = match std::fs::read_to_string(self.ledger_path()) {
            Ok(raw) => serde_json::from_str::<Ledger>(&raw).unwrap_or_default(),
            Err(_) => Ledger::default(),
        };
        let mut times: Vec<i64> = ledger
            .issued
            .into_iter()
            .filter(|i| {
                i.directory == directory
                    && same_identifiers(&i.identifiers, identifiers)
                    && now - i.at < ISSUE_WINDOW
            })
            .map(|i| i.at)
            .collect();
        times.sort_unstable();
        times
    }

    /// Record an issuance, dropping whatever has aged out of the window.
    fn record_issuance(&self, directory: &str, identifiers: &[String], now: i64) {
        let mut ledger = match std::fs::read_to_string(self.ledger_path()) {
            Ok(raw) => serde_json::from_str::<Ledger>(&raw).unwrap_or_default(),
            Err(_) => Ledger::default(),
        };
        ledger.issued.retain(|i| now - i.at < ISSUE_WINDOW);
        ledger.issued.push(Issuance {
            at: now,
            directory: directory.to_string(),
            identifiers: identifiers.to_vec(),
        });
        if let Err(e) = std::fs::create_dir_all(&self.dir)
            .and_then(|()| serde_json::to_string_pretty(&ledger).map_err(std::io::Error::other))
            .and_then(|json| std::fs::write(self.ledger_path(), json))
        {
            // Not fatal, but it means the next check cannot see this order.
            tracing::warn!("could not record the issuance in {}: {e}", self.ledger_path().display());
        }
    }
}

/// One issued certificate, as remembered locally.
#[derive(Clone, Serialize, Deserialize)]
struct Issuance {
    at: i64,
    directory: String,
    identifiers: Vec<String>,
}

#[derive(Default, Serialize, Deserialize)]
struct Ledger {
    issued: Vec<Issuance>,
}

/// The CA counts its limit per *exact set* of identifiers, so order and case
/// do not matter here either.
fn same_identifiers(a: &[String], b: &[String]) -> bool {
    let norm = |v: &[String]| {
        let mut v: Vec<String> = v.iter().map(|s| s.to_ascii_lowercase()).collect();
        v.sort();
        v.dedup();
        v
    };
    norm(a) == norm(b)
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
        let mut failures: u32 = 0;
        loop {
            match check_and_renew(&state, false).await {
                Ok(()) => failures = 0,
                Err(e) => {
                    failures = failures.saturating_add(1);
                    tracing::warn!("ACME check failed (attempt {failures}): {e:#}");
                }
            }
            let wait = if failures == 0 { CHECK_INTERVAL } else { retry_delay(failures) };
            tokio::select! {
                _ = state.acme.trigger.notified() => {
                    tracing::info!("ACME renewal requested from the admin UI");
                    failures = 0;
                }
                _ = tokio::time::sleep(wait) => {}
            }
        }
    });
}

/// How long to wait before retrying after `failures` consecutive failures:
/// 15 minutes, doubling, up to the periodic interval.
fn retry_delay(failures: u32) -> Duration {
    let steps = failures.clamp(1, 5) - 1;
    let secs = RETRY_MIN.as_secs().saturating_mul(1u64 << steps);
    Duration::from_secs(secs.min(CHECK_INTERVAL.as_secs()))
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

    let now = now_unix();
    if !force {
        if let Some(info) = state.certs.info() {
            if certificate_still_good(&info, &settings, now) {
                tracing::debug!(
                    "ACME certificate still good for {}",
                    crate::config::fmt_duration(info.not_after - now)
                );
                return Ok(());
            }
        }
    }

    // Whatever the certificate looks like, the CA's limit is the hard one, and
    // it is invisible from here - so the local record of past orders decides.
    let recent = state.acme.recent_issuances(&settings.acme_directory, &settings.acme_domains, now);
    let cap = if settings.acme_directory == LETSENCRYPT_STAGING {
        // Staging allows thousands a week; capping it would only get in the way
        // of exactly the testing it exists for.
        usize::MAX
    } else {
        ISSUE_WINDOW_CAP
    };
    if let Err(reason) = issue_allowed(&recent, now, force, cap) {
        tracing::warn!("not ordering a certificate: {reason}");
        state.acme.update(|s| s.hold = Some(reason));
        return Ok(());
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
    if result.is_ok() {
        state
            .acme
            .record_issuance(&settings.acme_directory, &settings.acme_domains, now_unix());
    }
    state.acme.update(|s| {
        s.running = false;
        s.stage = None;
        match &result {
            Ok(()) => {
                s.last_success = Some(now_unix());
                s.last_error = None;
                s.hold = None;
            }
            Err(e) => s.last_error = Some(format!("{e:#}")),
        }
    });
    result
}

/// Whether the certificate in hand still satisfies the configuration: it came
/// from the ACME environment now configured, covers every configured domain,
/// and is not yet inside its renewal window.
fn certificate_still_good(info: &CertInfo, settings: &Settings, now: i64) -> bool {
    let expected = if settings.acme_directory == LETSENCRYPT_STAGING {
        CertSource::AcmeStaging
    } else {
        CertSource::Acme
    };
    info.source == expected
        && info.covers(&settings.acme_domains)
        && info.not_after - now > renew_threshold_secs(info, settings.acme_renew_before_days)
}

/// How much life may remain before renewing: the configured window, but never
/// more than a third of the certificate's own lifetime. Without that cap a
/// six-day certificate sits permanently inside a thirty-day window, and every
/// single check orders another one - which is how a week's worth of the CA's
/// rate limit disappears in a day.
fn renew_threshold_secs(info: &CertInfo, configured_days: i64) -> i64 {
    (configured_days.max(0) * 86_400).min(info.lifetime_secs() / 3)
}

/// Whether another order may start, given when certificates were last issued
/// for this exact identifier set. `Err` carries the reason, for the log and the
/// certificate panel.
fn issue_allowed(recent: &[i64], now: i64, force: bool, cap: usize) -> Result<(), String> {
    if recent.len() >= cap {
        let oldest = recent[recent.len() - cap];
        return Err(format!(
            "{} certificates were already issued for these domains in the last {}; the CA allows five per week, so ordering waits until {}",
            recent.len(),
            crate::config::fmt_duration(ISSUE_WINDOW),
            crate::config::fmt_ts(oldest + ISSUE_WINDOW),
        ));
    }
    let min_gap = if force { MIN_REISSUE_FORCED } else { MIN_REISSUE };
    if let Some(last) = recent.last() {
        let since = now - last;
        if since < min_gap {
            return Err(format!(
                "a certificate for these domains was issued {} ago; the next order waits until {}",
                crate::config::fmt_duration(since),
                crate::config::fmt_ts(last + min_gap),
            ));
        }
    }
    Ok(())
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

    let source = if settings.acme_directory == LETSENCRYPT_STAGING {
        CertSource::AcmeStaging
    } else {
        CertSource::Acme
    };
    state
        .certs
        .install_known_pem(&cert_pem, &key_pem, source)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::LETSENCRYPT_PRODUCTION;

    const DAY: i64 = 86_400;

    fn cert(source: CertSource, names: &[&str], issued_ago: i64, lifetime: i64) -> CertInfo {
        let now = 1_700_000_000;
        CertInfo {
            source,
            issuer: "test".into(),
            names: names.iter().map(|n| n.to_string()).collect(),
            not_before: now - issued_ago,
            not_after: now - issued_ago + lifetime,
        }
    }

    fn settings(directory: &str, domains: &[&str], renew_days: i64) -> Settings {
        Settings {
            acme_enabled: true,
            acme_directory: directory.to_string(),
            acme_domains: domains.iter().map(|d| d.to_string()).collect(),
            acme_renew_before_days: renew_days,
            ..Default::default()
        }
    }

    #[test]
    fn a_fresh_production_certificate_is_left_alone() {
        let s = settings(LETSENCRYPT_PRODUCTION, &["mail.test"], 30);
        let info = cert(CertSource::Acme, &["mail.test"], DAY, 90 * DAY);
        assert!(certificate_still_good(&info, &s, 1_700_000_000));
    }

    #[test]
    fn a_certificate_inside_its_renewal_window_is_replaced() {
        let s = settings(LETSENCRYPT_PRODUCTION, &["mail.test"], 30);
        let info = cert(CertSource::Acme, &["mail.test"], 65 * DAY, 90 * DAY);
        assert!(!certificate_still_good(&info, &s, 1_700_000_000));
    }

    #[test]
    fn a_short_lived_certificate_does_not_sit_in_its_own_window() {
        // Six days of life against a thirty-day window: without the cap this
        // is renewed on every check, which is what burned the rate limit.
        let s = settings(LETSENCRYPT_PRODUCTION, &["mail.test"], 30);
        let fresh = cert(CertSource::Acme, &["mail.test"], 3600, 6 * DAY);
        assert!(certificate_still_good(&fresh, &s, 1_700_000_000));
        assert_eq!(renew_threshold_secs(&fresh, 30), 2 * DAY);
        let old = cert(CertSource::Acme, &["mail.test"], 5 * DAY, 6 * DAY);
        assert!(!certificate_still_good(&old, &s, 1_700_000_000));
    }

    #[test]
    fn a_staging_certificate_does_not_satisfy_production() {
        let prod = settings(LETSENCRYPT_PRODUCTION, &["mail.test"], 30);
        let staging_cert = cert(CertSource::AcmeStaging, &["mail.test"], DAY, 90 * DAY);
        assert!(!certificate_still_good(&staging_cert, &prod, 1_700_000_000));

        let staging = settings(LETSENCRYPT_STAGING, &["mail.test"], 30);
        assert!(certificate_still_good(&staging_cert, &staging, 1_700_000_000));
        // ...and the other way round: a production certificate while testing.
        let prod_cert = cert(CertSource::Acme, &["mail.test"], DAY, 90 * DAY);
        assert!(!certificate_still_good(&prod_cert, &staging, 1_700_000_000));
    }

    #[test]
    fn a_missing_domain_forces_a_new_certificate() {
        let s = settings(LETSENCRYPT_PRODUCTION, &["mail.test", "smtp.test"], 30);
        let info = cert(CertSource::Acme, &["mail.test"], DAY, 90 * DAY);
        assert!(!certificate_still_good(&info, &s, 1_700_000_000));
    }

    #[test]
    fn ordering_waits_after_a_recent_issuance() {
        let now = 1_700_000_000;
        let recent = [now - 3 * 3600];
        assert!(issue_allowed(&recent, now, false, ISSUE_WINDOW_CAP).is_err());
        // The admin UI may cut the wait short, but not below an hour.
        assert!(issue_allowed(&recent, now, true, ISSUE_WINDOW_CAP).is_ok());
        assert!(issue_allowed(&[now - 60], now, true, ISSUE_WINDOW_CAP).is_err());
        assert!(issue_allowed(&[now - 2 * DAY], now, false, ISSUE_WINDOW_CAP).is_ok());
        assert!(issue_allowed(&[], now, false, ISSUE_WINDOW_CAP).is_ok());
    }

    #[test]
    fn the_weekly_cap_stops_short_of_the_ca_limit() {
        let now = 1_700_000_000;
        let four: Vec<i64> = (1..=4).map(|d| now - d * DAY).rev().collect();
        let err = issue_allowed(&four, now, true, ISSUE_WINDOW_CAP).unwrap_err();
        assert!(err.contains("five per week"), "{err}");
        // Staging has no meaningful limit, so nothing is withheld there.
        assert!(issue_allowed(&four, now, false, usize::MAX).is_ok());
        // One order aged out of the window: room again.
        let three: Vec<i64> = (1..=3).map(|d| now - d * DAY).rev().collect();
        assert!(issue_allowed(&three, now, true, ISSUE_WINDOW_CAP).is_ok());
    }

    #[test]
    fn identifier_sets_ignore_order_and_case() {
        let a = ["Mail.Test".to_string(), "smtp.test".to_string()];
        let b = ["smtp.test".to_string(), "mail.test".to_string()];
        assert!(same_identifiers(&a, &b));
        assert!(!same_identifiers(&a, &["mail.test".to_string()]));
    }

    #[test]
    fn failures_back_off_up_to_the_check_interval() {
        assert_eq!(retry_delay(1), RETRY_MIN);
        assert_eq!(retry_delay(2), Duration::from_secs(30 * 60));
        assert_eq!(retry_delay(4), Duration::from_secs(2 * 3600));
        assert_eq!(retry_delay(9), Duration::from_secs(4 * 3600));
        assert!(retry_delay(50) <= CHECK_INTERVAL);
    }
}
