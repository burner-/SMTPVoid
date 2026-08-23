//! SMTPVoid — an SMTP black hole for testing mail submission.
//!
//! Accepts mail over plaintext, STARTTLS and implicit-TLS SMTP into per-user
//! in-memory mailboxes. Messages expire after a configurable retention period
//! and are never delivered, relayed or written to disk.
//!
//! Apart from the data directory and the web UI's bind address, everything is
//! configured from the admin UI at `/admin/settings` and stored in SQLite.

mod acme;
mod config;
mod db;
mod listeners;
mod mailstore;
mod settings;
mod smtp;
mod state;
mod tls;
mod web;

use std::sync::Arc;

use anyhow::{Context, Result};
use rand::distributions::{Alphanumeric, DistString};

use crate::config::BootConfig;
use crate::db::Db;
use crate::settings::Settings;
use crate::state::AppState;
use crate::tls::CertStore;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    let boot = BootConfig::from_env();
    std::fs::create_dir_all(&boot.data_dir)
        .with_context(|| format!("cannot create data dir {}", boot.data_dir.display()))?;

    let db = Db::open(&boot.data_dir.join("smtpvoid.db")).context("opening database")?;

    // Settings live in the database. On first run we write the defaults out so
    // the admin form shows explicit rows rather than implicit fallbacks.
    let stored = db.load_settings().context("reading settings")?;
    let first_run = stored.is_empty();
    let settings = Settings::from_pairs(&stored);
    if first_run {
        db.save_settings(&settings.to_pairs()).context("seeding default settings")?;
        tracing::info!("no settings stored yet - seeded defaults, edit them at /admin/settings");
    }
    if let Err(e) = settings.validate() {
        // Not fatal: the admin needs the UI up in order to fix it.
        tracing::warn!("stored settings are questionable ({e}); fix them at /admin/settings");
    }

    let certs = CertStore::new(&boot.data_dir).context("preparing the TLS directory")?;
    certs
        .load_or_generate(&settings.cert_names())
        .context("preparing TLS")?;
    let tls = tls::server_config(certs.clone());

    // Admin bootstrap: keep a setup token around until an admin account exists.
    let setup_token = if db.admin_exists()? {
        None
    } else {
        let token_file = boot.data_dir.join("admin_setup_token");
        let token = match std::fs::read_to_string(&token_file) {
            Ok(t) if !t.trim().is_empty() => t.trim().to_string(),
            _ => {
                let t = Alphanumeric.sample_string(&mut rand::thread_rng(), 40);
                std::fs::write(&token_file, &t).context("writing admin setup token")?;
                t
            }
        };
        tracing::info!("no admin account yet - create one at /setup");
        tracing::info!("admin setup token: {token}");
        tracing::info!("(also stored in {})", token_file.display());
        Some(token)
    };

    let state = Arc::new(AppState::new(boot, settings, db, certs, tls, setup_token));

    smtp::spawn_sweeper(state.clone());
    acme::spawn_manager(state.clone());

    for problem in listeners::reconcile(&state).await {
        tracing::error!("{problem} - fix it at /admin/settings");
    }

    let settings = state.settings();
    tracing::info!(
        "SMTPVoid up: retention {}s, mailbox cap {}, max message size {} bytes",
        settings.retention_secs,
        settings.mailbox_cap,
        settings.max_message_size
    );

    web::serve(state).await.context("running web server")
}
