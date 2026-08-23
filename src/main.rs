//! SMTPVoid — an SMTP black hole for testing mail submission.
//!
//! Accepts mail over plaintext, STARTTLS and implicit-TLS SMTP into per-user
//! in-memory mailboxes. Messages expire after a configurable retention period
//! and are never delivered, relayed or written to disk.

mod config;
mod db;
mod mailstore;
mod smtp;
mod state;
mod tls;
mod web;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use rand::distributions::{Alphanumeric, DistString};

use crate::config::{now_unix, Config};
use crate::db::Db;
use crate::mailstore::MailStore;
use crate::state::AppState;

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

    let cfg = Config::from_env();
    std::fs::create_dir_all(&cfg.data_dir)
        .with_context(|| format!("cannot create data dir {}", cfg.data_dir.display()))?;

    let db = Db::open(&cfg.data_dir.join("smtpvoid.db")).context("opening database")?;
    let mail = MailStore::new(Duration::from_secs(cfg.retention_secs), cfg.mailbox_cap);
    let tls = tls::load_or_generate(&cfg.data_dir, &cfg.hostname).context("preparing TLS")?;

    // Admin bootstrap: keep a setup token around until an admin account exists.
    let setup_token = if db.admin_exists()? {
        None
    } else {
        let token_file = cfg.data_dir.join("admin_setup_token");
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

    let state = Arc::new(AppState {
        cfg: cfg.clone(),
        db,
        mail,
        tls,
        sessions: Mutex::new(HashMap::new()),
        reveals: Mutex::new(HashMap::new()),
        setup_token: Mutex::new(setup_token),
        reg_throttle: Mutex::new(HashMap::new()),
        started_at: now_unix(),
    });

    smtp::spawn_sweeper(state.clone());
    smtp::run(state.clone()).await.context("starting SMTP listeners")?;

    tracing::info!(
        "SMTPVoid up: retention {}s, mailbox cap {}, max message size {} bytes",
        cfg.retention_secs,
        cfg.mailbox_cap,
        cfg.max_message_size
    );

    web::serve(state).await.context("running web server")
}
