//! Web management UI: registration, login, SMTP credential management,
//! the virtual mailbox, admin statistics and first-run admin setup.

mod html;
mod tls_listener;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use anyhow::Result;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::serve::ListenerExt;
use axum::{Form, Router};
use rand::distributions::{Alphanumeric, DistString};
use serde::Deserialize;
use tokio::net::TcpListener;

use crate::config::now_unix;
use crate::db::User;
use crate::settings::{mib_as_bytes, parse_domains, Settings};
use crate::state::{AppState, WebSession, SESSION_TTL_SECS};
use crate::web::tls_listener::TlsListener;

const SESSION_COOKIE: &str = "svsession";

// ---- password hashing ----

pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("hashing failed: {e}"))?;
    Ok(hash.to_string())
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// A throwaway hash used to equalize timing when the username does not exist.
pub fn dummy_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| hash_password("smtpvoid-timing-dummy").expect("argon2 works"))
}

// ---- small helpers ----

fn percent_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn redirect_ok(path: &str, msg: &str) -> Response {
    Redirect::to(&format!("{path}?msg={}", percent_encode(msg))).into_response()
}

fn redirect_err(path: &str, msg: &str) -> Response {
    Redirect::to(&format!("{path}?err={}", percent_encode(msg))).into_response()
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookies = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in cookies.split(';') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix(name) {
            if let Some(v) = v.strip_prefix('=') {
                return Some(v.to_string());
            }
        }
    }
    None
}

fn session_token(headers: &HeaderMap) -> Option<String> {
    cookie_value(headers, SESSION_COOKIE)
}

fn current_user(state: &AppState, headers: &HeaderMap) -> Option<User> {
    let token = session_token(headers)?;
    let user_id = state.session_user_id(&token)?;
    state.db.get_user_by_id(user_id).ok().flatten()
}

fn new_session(state: &AppState, user_id: i64) -> (String, String) {
    let token = Alphanumeric.sample_string(&mut rand::thread_rng(), 43);
    state
        .sessions
        .lock()
        .expect("sessions mutex poisoned")
        .insert(
            token.clone(),
            WebSession { user_id, expires_at: now_unix() + SESSION_TTL_SECS },
        );
    let secure = if state.settings().cookie_secure { "; Secure" } else { "" };
    let cookie = format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL_SECS}{secure}"
    );
    (token, cookie)
}

fn valid_username(s: &str) -> bool {
    (3..=32).contains(&s.len())
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn flash<'a>(q: &'a HashMap<String, String>) -> (Option<&'a str>, Option<&'a str>) {
    (q.get("msg").map(String::as_str), q.get("err").map(String::as_str))
}

// ---- routing ----

/// The full application router, shared by the HTTP and HTTPS listeners.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/register", get(register_form).post(register))
        .route("/login", get(login_form).post(login))
        .route("/logout", post(logout))
        .route("/dashboard", get(dashboard))
        .route("/credentials/create", post(cred_create))
        .route("/credentials/{id}/delete", post(cred_delete))
        .route("/mail/{id}", get(mail_view))
        .route("/mail/{id}/raw", get(mail_raw))
        .route("/mail/{id}/delete", post(mail_delete))
        .route("/mailbox/clear", post(mailbox_clear))
        .route("/account", get(account_view))
        .route("/account/password", post(account_password))
        .route("/setup", get(setup_form).post(setup_submit))
        .route("/admin", get(admin_view))
        .route("/admin/users/{id}/delete", post(admin_delete_user))
        .route("/admin/settings", get(settings_view).post(settings_save))
        .route("/admin/tls/renew", post(tls_renew))
        .route("/admin/tls/self-signed", post(tls_self_signed))
        .with_state(state.clone())
        // Also answer ACME challenges here, for deployments that proxy
        // /.well-known/ to the web UI instead of exposing the port-80 listener.
        .merge(crate::acme::challenge_router(state))
}

/// The plaintext web UI. Bound once from [`crate::config::BootConfig`] and
/// never moved, so a bad setting cannot cut off access to the settings form.
pub async fn serve(state: Arc<AppState>) -> Result<()> {
    let listener = TcpListener::bind(&state.boot.http_addr).await?;
    tracing::info!("web UI listening on http://{}", state.boot.http_addr);
    let app = router(state).into_make_service_with_connect_info::<SocketAddr>();
    axum::serve(listener, app).await?;
    Ok(())
}

/// The optional HTTPS web UI, using the same certificate as the SMTP listeners.
pub async fn serve_https(state: Arc<AppState>, listener: TcpListener) -> Result<()> {
    let acceptor = tokio_rustls::TlsAcceptor::from(state.tls.clone());
    // The no-op `tap_io` is load-bearing: axum only implements `Connected`
    // (which is what makes `ConnectInfo<SocketAddr>` work) for `TcpListener`
    // and for any `TapIo` wrapper, not for arbitrary custom listeners.
    let listener = TlsListener::new(listener, acceptor)?.tap_io(|_| {});
    let app = router(state).into_make_service_with_connect_info::<SocketAddr>();
    axum::serve(listener, app).await?;
    Ok(())
}

// ---- public pages ----

async fn index(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let settings = state.settings();
    let body = html::index_page(
        &settings.endpoint(&settings.smtp_addr),
        &settings.endpoint(&settings.smtps_addr),
        settings.retention_secs as i64,
        settings.registration_open,
    );
    let nav = match current_user(&state, &headers) {
        Some(u) => html::layout("SMTP testing sink", html::Nav::User(&u), None, None, &body),
        None => html::layout("SMTP testing sink", html::Nav::Anonymous, None, None, &body),
    };
    Html(nav).into_response()
}

async fn register_form(
    State(state): State<Arc<AppState>>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if !state.settings().registration_open {
        return redirect_err("/login", "Registration is closed on this server");
    }
    let (ok, err) = flash(&q);
    let body = html::auth_page("Create account", "/register", "Create account", "");
    Html(html::layout("Create account", html::Nav::Anonymous, ok, err, &body)).into_response()
}

#[derive(Deserialize)]
struct AuthForm {
    username: String,
    password: String,
}

async fn register(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Form(form): Form<AuthForm>,
) -> Response {
    if !state.settings().registration_open {
        return redirect_err("/login", "Registration is closed on this server");
    }
    let username = form.username.trim().to_string();
    if !valid_username(&username) {
        return redirect_err(
            "/register",
            "Username must be 3-32 characters: letters, digits, _ or -",
        );
    }
    if form.password.len() < 8 || form.password.len() > 128 {
        return redirect_err("/register", "Password must be 8-128 characters");
    }
    if !state.allow_registration(peer.ip()) {
        return redirect_err("/register", "Too many registrations from your address; try again later");
    }
    let hash = match tokio::task::spawn_blocking(move || hash_password(&form.password)).await {
        Ok(Ok(h)) => h,
        _ => return redirect_err("/register", "Internal error, please try again"),
    };
    match state.db.create_user(&username, &hash, false) {
        Ok(user_id) => {
            tracing::info!("new user registered: {username} (id {user_id})");
            let (_, cookie) = new_session(&state, user_id);
            (
                [(header::SET_COOKIE, cookie)],
                Redirect::to("/dashboard?msg=Welcome%20to%20SMTPVoid"),
            )
                .into_response()
        }
        Err(e) => redirect_err("/register", &e.to_string()),
    }
}

async fn login_form(Query(q): Query<HashMap<String, String>>) -> Response {
    let (ok, err) = flash(&q);
    let body = html::auth_page("Sign in", "/login", "Sign in", "");
    Html(html::layout("Sign in", html::Nav::Anonymous, ok, err, &body)).into_response()
}

async fn login(State(state): State<Arc<AppState>>, Form(form): Form<AuthForm>) -> Response {
    let username = form.username.trim().to_string();
    let user = match state.db.get_user_by_username(&username) {
        Ok(u) => u,
        Err(_) => return redirect_err("/login", "Internal error, please try again"),
    };
    let password = form.password;
    let verified: Option<User> = tokio::task::spawn_blocking(move || match user {
        Some(u) if verify_password(&password, &u.password_hash) => Some(u),
        Some(_) => None,
        None => {
            verify_password(&password, dummy_hash());
            None
        }
    })
    .await
    .ok()
    .flatten();

    match verified {
        Some(u) => {
            let (_, cookie) = new_session(&state, u.id);
            ([(header::SET_COOKIE, cookie)], Redirect::to("/dashboard")).into_response()
        }
        None => redirect_err("/login", "Invalid username or password"),
    }
}

async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(token) = session_token(&headers) {
        state.sessions.lock().expect("sessions mutex poisoned").remove(&token);
    }
    let clear = format!("{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
    ([(header::SET_COOKIE, clear)], Redirect::to("/")).into_response()
}

// ---- user pages ----

async fn dashboard(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let user = match current_user(&state, &headers) {
        Some(u) => u,
        None => return Redirect::to("/login").into_response(),
    };
    let creds = state.db.list_credentials(user.id).unwrap_or_default();
    let emails = state.mail.list(user.id);
    let (ok, err) = flash(&q);
    let settings = state.settings();
    let body = html::dashboard_page(
        &user,
        &creds,
        &emails,
        &settings.endpoint(&settings.smtp_addr),
        &settings.endpoint(&settings.smtps_addr),
        &settings.hostname,
        settings.retention_secs as i64,
    );
    Html(html::layout("Dashboard", html::Nav::User(&user), ok, err, &body)).into_response()
}

async fn cred_create(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let user = match current_user(&state, &headers) {
        Some(u) => u,
        None => return Redirect::to("/login").into_response(),
    };
    let count = state.db.count_credentials(user.id).unwrap_or(0);
    if count >= state.settings().max_credentials_per_user {
        return redirect_err("/dashboard", "Credential limit reached");
    }
    let (cred_user, cred_pass) = {
        let mut rng = rand::thread_rng();
        (
            format!("sv_{}", Alphanumeric.sample_string(&mut rng, 10).to_lowercase()),
            Alphanumeric.sample_string(&mut rng, 24),
        )
    };
    if let Err(e) = state.db.create_credential(user.id, &cred_user, &cred_pass) {
        tracing::warn!("credential creation failed: {e:#}");
        return redirect_err("/dashboard", "Could not create credential, please try again");
    }
    redirect_ok("/dashboard", &format!("SMTP credential {cred_user} created"))
}

async fn cred_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    let user = match current_user(&state, &headers) {
        Some(u) => u,
        None => return Redirect::to("/login").into_response(),
    };
    match state.db.delete_credential(user.id, id) {
        Ok(true) => redirect_ok("/dashboard", "SMTP credential deleted"),
        _ => redirect_err("/dashboard", "Credential not found"),
    }
}

async fn mail_view(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let user = match current_user(&state, &headers) {
        Some(u) => u,
        None => return Redirect::to("/login").into_response(),
    };
    match state.mail.get(user.id, &id) {
        Some(email) => {
            let body = html::mail_page(&email);
            Html(html::layout(&email.subject, html::Nav::User(&user), None, None, &body))
                .into_response()
        }
        None => redirect_err("/dashboard", "Message not found (it may have expired)"),
    }
}

async fn mail_raw(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let user = match current_user(&state, &headers) {
        Some(u) => u,
        None => return Redirect::to("/login").into_response(),
    };
    match state.mail.get(user.id, &id) {
        Some(email) => (
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            email.raw.clone(),
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "message not found").into_response(),
    }
}

async fn mail_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let user = match current_user(&state, &headers) {
        Some(u) => u,
        None => return Redirect::to("/login").into_response(),
    };
    if state.mail.delete(user.id, &id) {
        redirect_ok("/dashboard", "Message deleted")
    } else {
        redirect_err("/dashboard", "Message not found")
    }
}

async fn mailbox_clear(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let user = match current_user(&state, &headers) {
        Some(u) => u,
        None => return Redirect::to("/login").into_response(),
    };
    state.mail.clear(user.id);
    redirect_ok("/dashboard", "Mailbox emptied")
}

/// The signed-in user's own account page, linked from the username in the
/// header.
async fn account_view(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let user = match current_user(&state, &headers) {
        Some(u) => u,
        None => return Redirect::to("/login").into_response(),
    };
    let (ok, err) = flash(&q);
    let body = html::account_page(&user);
    Html(html::layout("Account", html::Nav::User(&user), ok, err, &body)).into_response()
}

#[derive(Deserialize)]
struct PasswordForm {
    current_password: String,
    new_password: String,
    confirm_password: String,
}

/// Change the signed-in user's web password. SMTP credentials are separate
/// rows with their own passwords and are deliberately left alone.
async fn account_password(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<PasswordForm>,
) -> Response {
    let user = match current_user(&state, &headers) {
        Some(u) => u,
        None => return Redirect::to("/login").into_response(),
    };
    if form.new_password != form.confirm_password {
        return redirect_err("/account", "The two new passwords do not match");
    }
    if form.new_password.len() < 8 || form.new_password.len() > 128 {
        return redirect_err("/account", "Password must be 8-128 characters");
    }
    if form.new_password == form.current_password {
        return redirect_err("/account", "The new password is the same as the old one");
    }
    // Two argon2 operations - verifying the old password and hashing the new
    // one - so both go to the blocking pool, like every other hash here.
    let stored = user.password_hash.clone();
    let current = form.current_password;
    let new = form.new_password;
    let hashed = tokio::task::spawn_blocking(move || {
        verify_password(&current, &stored).then(|| hash_password(&new))
    })
    .await;
    let hashed = match hashed {
        Ok(Some(Ok(h))) => h,
        Ok(None) => return redirect_err("/account", "Current password is not correct"),
        _ => return redirect_err("/account", "Internal error, please try again"),
    };
    match state.db.set_password(user.id, &hashed) {
        Ok(true) => {
            // Every other session was opened with the old password; end them,
            // but keep this one so the change does not sign the user out.
            state.drop_user_sessions(user.id, session_token(&headers).as_deref());
            tracing::info!("password changed for user '{}' (id {})", user.username, user.id);
            redirect_ok("/account", "Password changed")
        }
        Ok(false) => redirect_err("/account", "Account no longer exists"),
        Err(e) => {
            tracing::warn!("password change failed for user id {}: {e:#}", user.id);
            redirect_err("/account", "Could not change the password, please try again")
        }
    }
}

// ---- admin setup ----

async fn setup_form(
    State(state): State<Arc<AppState>>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if state.setup_token.lock().expect("setup mutex poisoned").is_none() {
        return redirect_err("/login", "Admin account is already configured");
    }
    let (ok, err) = flash(&q);
    Html(html::layout("Admin setup", html::Nav::Anonymous, ok, err, &html::setup_page()))
        .into_response()
}

#[derive(Deserialize)]
struct SetupForm {
    token: String,
    username: String,
    password: String,
}

async fn setup_submit(State(state): State<Arc<AppState>>, Form(form): Form<SetupForm>) -> Response {
    let expected = state.setup_token.lock().expect("setup mutex poisoned").clone();
    let expected = match expected {
        Some(t) => t,
        None => return redirect_err("/login", "Admin account is already configured"),
    };
    // Length-constant comparison is overkill here, but avoid trivial mismatch leaks.
    let supplied = form.token.trim();
    let matches = supplied.len() == expected.len()
        && supplied
            .bytes()
            .zip(expected.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0;
    if !matches {
        return redirect_err("/setup", "Invalid setup token");
    }
    let username = form.username.trim().to_string();
    if !valid_username(&username) {
        return redirect_err("/setup", "Username must be 3-32 characters: letters, digits, _ or -");
    }
    if form.password.len() < 8 || form.password.len() > 128 {
        return redirect_err("/setup", "Password must be 8-128 characters");
    }
    let hash = match tokio::task::spawn_blocking(move || hash_password(&form.password)).await {
        Ok(Ok(h)) => h,
        _ => return redirect_err("/setup", "Internal error, please try again"),
    };
    match state.db.create_user(&username, &hash, true) {
        Ok(_) => {
            *state.setup_token.lock().expect("setup mutex poisoned") = None;
            let token_file = state.boot.data_dir.join("admin_setup_token");
            if let Err(e) = std::fs::remove_file(&token_file) {
                tracing::warn!("could not remove setup token file: {e}");
            }
            tracing::info!("admin account '{username}' created; setup token invalidated");
            redirect_ok("/login", "Admin account created - you can sign in now")
        }
        Err(e) => redirect_err("/setup", &e.to_string()),
    }
}

// ---- admin pages ----

/// Resolve the signed-in admin, or the response to send instead.
// The `Err` variant is a whole `Response`, which clippy considers large. Boxing
// it would only add an allocation on a path that returns the value immediately.
#[allow(clippy::result_large_err)]
fn require_admin(state: &AppState, headers: &HeaderMap) -> Result<User, Response> {
    match current_user(state, headers) {
        Some(u) if u.is_admin => Ok(u),
        Some(_) => Err((StatusCode::FORBIDDEN, "admin only").into_response()),
        None => Err(Redirect::to("/login").into_response()),
    }
}

async fn admin_view(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let user = match require_admin(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let stats = state.db.global_stats().unwrap_or_default();
    let users = state.db.list_users_admin().unwrap_or_default();
    let usage = state.mail.usage();
    let (ok, err) = flash(&q);
    let body = html::admin_page(
        &stats,
        &users,
        &usage,
        state.started_at,
        state.settings().retention_secs as i64,
    );
    Html(html::layout("Admin", html::Nav::User(&user), ok, err, &body)).into_response()
}

async fn admin_delete_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    let user = match require_admin(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let target = match state.db.get_user_by_id(id) {
        Ok(Some(t)) => t,
        _ => return redirect_err("/admin", "User not found"),
    };
    if target.is_admin || target.id == user.id {
        return redirect_err("/admin", "Admin accounts cannot be deleted from the UI");
    }
    if let Err(e) = state.db.delete_user(id) {
        tracing::warn!("user deletion failed: {e:#}");
        return redirect_err("/admin", "Deletion failed");
    }
    state.mail.clear(id);
    state
        .sessions
        .lock()
        .expect("sessions mutex poisoned")
        .retain(|_, s| s.user_id != id);
    tracing::info!("admin {} deleted user {} ({})", user.username, target.username, id);
    redirect_ok("/admin", "User deleted")
}

// ---- admin settings ----

async fn settings_view(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let user = match require_admin(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let (ok, err) = flash(&q);
    let body = html::settings_page(
        &state.settings(),
        &state.boot,
        state.certs.info(),
        &state.acme.status(),
        &state.listeners.active().await,
    );
    Html(html::layout("Settings", html::Nav::User(&user), ok, err, &body)).into_response()
}

/// Every field arrives as a string; unchecked checkboxes are simply absent.
#[derive(Deserialize)]
struct SettingsForm {
    hostname: String,
    smtp_addr: String,
    smtps_addr: String,
    https_addr: String,
    retention_secs: String,
    mailbox_cap: String,
    max_message_size: String,
    max_credentials_per_user: String,
    cookie_secure: Option<String>,
    registration_open: Option<String>,
    registrations_per_hour: String,
    acme_enabled: Option<String>,
    acme_directory: String,
    acme_contact_email: String,
    acme_domains: String,
    acme_http_addr: String,
    acme_tos_agreed: Option<String>,
    acme_renew_before_days: String,
}

fn parse_num<T: std::str::FromStr>(label: &str, raw: &str) -> Result<T, String> {
    raw.trim()
        .parse::<T>()
        .map_err(|_| format!("{label} must be a whole number"))
}

impl SettingsForm {
    fn into_settings(self) -> Result<Settings, String> {
        Ok(Settings {
            hostname: self.hostname.trim().to_ascii_lowercase(),
            smtp_addr: self.smtp_addr.trim().to_string(),
            smtps_addr: self.smtps_addr.trim().to_string(),
            https_addr: self.https_addr.trim().to_string(),
            retention_secs: parse_num("Retention", &self.retention_secs)?,
            mailbox_cap: parse_num("Mailbox capacity", &self.mailbox_cap)?,
            // The form field is in MiB; everything else here works in bytes.
            max_message_size: mib_as_bytes(&self.max_message_size)
                .ok_or("Max message size must be a number of mebibytes")?,
            max_credentials_per_user: parse_num(
                "Credentials per user",
                &self.max_credentials_per_user,
            )?,
            cookie_secure: self.cookie_secure.is_some(),
            registration_open: self.registration_open.is_some(),
            registrations_per_hour: parse_num(
                "Registrations per hour",
                &self.registrations_per_hour,
            )?,
            acme_enabled: self.acme_enabled.is_some(),
            acme_directory: self.acme_directory.trim().to_string(),
            acme_contact_email: self.acme_contact_email.trim().to_string(),
            acme_domains: parse_domains(&self.acme_domains),
            acme_http_addr: self.acme_http_addr.trim().to_string(),
            acme_tos_agreed: self.acme_tos_agreed.is_some(),
            acme_renew_before_days: parse_num("Renewal window", &self.acme_renew_before_days)?,
        })
    }
}

async fn settings_save(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<SettingsForm>,
) -> Response {
    let user = match require_admin(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };

    let new = match form.into_settings() {
        Ok(s) => s,
        Err(e) => return redirect_err("/admin/settings", &e),
    };
    if let Err(e) = new.validate() {
        return redirect_err("/admin/settings", &e);
    }

    let old = state.settings();
    if *old == new {
        return redirect_ok("/admin/settings", "No changes to save");
    }
    if let Err(e) = state.db.save_settings(&new.to_pairs()) {
        tracing::error!("saving settings failed: {e:#}");
        return redirect_err("/admin/settings", "Could not write the settings to the database");
    }
    state.set_settings(new.clone());
    tracing::info!("admin {} updated the settings", user.username);

    let mut notes: Vec<String> = Vec::new();

    // A self-signed certificate names the SMTP hostname, so it has to be
    // reissued when that changes. A real certificate is left alone.
    let self_signed = state
        .certs
        .info()
        .is_some_and(|i| i.source == crate::tls::CertSource::SelfSigned);
    if self_signed && !new.acme_enabled && new.hostname != old.hostname {
        match state.certs.generate_self_signed(&new.cert_names()) {
            Ok(()) => notes.push(format!("reissued the self-signed certificate for {}", new.hostname)),
            Err(e) => {
                tracing::error!("regenerating the self-signed certificate failed: {e:#}");
                notes.push("could not reissue the self-signed certificate".to_string());
            }
        }
    }

    let problems = crate::listeners::reconcile(&state).await;

    // Ask for a certificate as soon as ACME is switched on or retargeted.
    let acme_changed = new.acme_enabled
        && (!old.acme_enabled
            || old.acme_domains != new.acme_domains
            || old.acme_directory != new.acme_directory);
    if acme_changed {
        state.acme.request_renewal();
        notes.push("requesting a certificate from the CA in the background".to_string());
    }

    if !problems.is_empty() {
        return redirect_err("/admin/settings", &format!("Saved, but: {}", problems.join("; ")));
    }
    let msg = if notes.is_empty() {
        "Settings saved and applied".to_string()
    } else {
        format!("Settings saved - {}", notes.join("; "))
    };
    redirect_ok("/admin/settings", &msg)
}

async fn tls_renew(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let user = match require_admin(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    if !state.settings().acme_enabled {
        return redirect_err("/admin/settings", "Enable Let's Encrypt first");
    }
    tracing::info!("admin {} requested a certificate renewal", user.username);
    // The order takes minutes; run it in the background and let the admin
    // watch the status panel rather than holding the request open.
    let bg = state.clone();
    tokio::spawn(async move {
        if let Err(e) = crate::acme::check_and_renew(&bg, true).await {
            tracing::warn!("manual ACME renewal failed: {e:#}");
        }
    });
    redirect_ok(
        "/admin/settings",
        "Certificate order started - reload this page to follow it",
    )
}

async fn tls_self_signed(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let user = match require_admin(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let settings = state.settings();
    match state.certs.generate_self_signed(&settings.cert_names()) {
        Ok(()) => {
            tracing::info!("admin {} regenerated the self-signed certificate", user.username);
            redirect_ok("/admin/settings", "Self-signed certificate regenerated")
        }
        Err(e) => {
            tracing::error!("self-signed certificate generation failed: {e:#}");
            redirect_err("/admin/settings", "Could not generate a self-signed certificate")
        }
    }
}
