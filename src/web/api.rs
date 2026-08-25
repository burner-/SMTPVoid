//! A small read-only REST API over the virtual mailbox, meant for end-to-end
//! tests: send a message through SMTP, then poll `/api/latest` until the
//! assertion holds. Every endpoint is a GET, answers JSON, and authenticates
//! with the per-account token shown on the dashboard.
//!
//! Nothing here can change a mailbox; the API only reads. Deleting mail stays a
//! session-authenticated action in the web UI.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::db::User;
use crate::mailstore::StoredEmail;
use crate::state::AppState;

/// Header carrying the token when `Authorization: Bearer` is inconvenient.
const TOKEN_HEADER: &str = "x-api-token";

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api", get(index))
        .route("/api/list", get(list))
        .route("/api/latest", get(latest))
        .route("/api/get/{id}", get(get_one))
        .with_state(state)
}

// ---- authentication ----

fn presented_token(headers: &HeaderMap) -> Option<String> {
    if let Some(raw) = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        let raw = raw.trim();
        // Case-insensitive scheme, as required by RFC 7235.
        if raw.len() > 7 && raw[..7].eq_ignore_ascii_case("bearer ") {
            return Some(raw[7..].trim().to_string());
        }
    }
    headers
        .get(TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Resolve the token holder, or the error response to send instead.
// The `Err` variant is a whole `Response`, which clippy considers large; the
// caller returns it immediately, so boxing would only add an allocation.
#[allow(clippy::result_large_err)]
fn require_token(state: &AppState, headers: &HeaderMap) -> Result<User, Response> {
    let token = presented_token(headers).ok_or_else(|| {
        fail(
            StatusCode::UNAUTHORIZED,
            "missing API token: send it as 'Authorization: Bearer <token>' or 'X-API-Token: <token>'",
        )
    })?;
    match state.db.get_user_by_api_token(&token) {
        Ok(Some(user)) => Ok(user),
        Ok(None) => Err(fail(StatusCode::UNAUTHORIZED, "unknown API token")),
        Err(e) => {
            tracing::warn!("API token lookup failed: {e:#}");
            Err(fail(StatusCode::INTERNAL_SERVER_ERROR, "token lookup failed"))
        }
    }
}

fn fail(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

// ---- filtering ----

/// Every filter is an optional case-insensitive substring match, so a test can
/// wait for its own message without knowing anything else about the mailbox.
#[derive(Debug, Default, Deserialize)]
struct Filter {
    /// Matches any envelope recipient.
    to: Option<String>,
    /// Matches the envelope sender or the From header.
    from: Option<String>,
    subject: Option<String>,
    /// Only meaningful for `/api/list`; the newest N messages are returned.
    limit: Option<usize>,
}

fn contains(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

impl Filter {
    fn matches(&self, e: &StoredEmail) -> bool {
        if let Some(to) = &self.to {
            if !e.rcpt_to.iter().any(|r| contains(r, to)) {
                return false;
            }
        }
        if let Some(from) = &self.from {
            if !contains(&e.mail_from, from) && !contains(&e.from_header, from) {
                return false;
            }
        }
        if let Some(subject) = &self.subject {
            if !contains(&e.subject, subject) {
                return false;
            }
        }
        true
    }
}

// ---- JSON shapes ----

/// The fields every listing entry carries. `/api/get` and `/api/latest` return
/// the same object with the message content added, so a test can move from a
/// listing to a body without learning a second shape.
fn summary(e: &StoredEmail) -> Value {
    json!({
        "id": e.id,
        "subject": e.subject,
        "from": e.from_header,
        "mail_from": e.mail_from,
        "rcpt_to": e.rcpt_to,
        "size": e.raw.len(),
        "received_at": e.received_at,
        "expires_at": e.expires_at,
        "credential": e.cred_username,
        "connection": {
            "security": e.conn.kind.api_name(),
            "tls_version": e.conn.tls_version,
            "tls_cipher": e.conn.tls_cipher,
            "peer": e.conn.peer_addr,
            "helo": e.conn.helo,
            "esmtp": e.conn.esmtp,
            "auth": e.conn.auth_mechanism,
        },
    })
}

fn full(e: &StoredEmail) -> Value {
    let mut out = summary(e);
    let parsed = mail_parser::MessageParser::default().parse(&e.raw[..]);
    let (text, html, attachments) = match &parsed {
        Some(msg) => {
            use mail_parser::MimeHeaders;
            let attachments: Vec<Value> = msg
                .attachments()
                .map(|part| {
                    let content_type = part.content_type().map(|ct| match ct.subtype() {
                        Some(sub) => format!("{}/{}", ct.ctype(), sub),
                        None => ct.ctype().to_string(),
                    });
                    json!({
                        "filename": part.attachment_name(),
                        "content_type": content_type,
                        "size": part.len(),
                    })
                })
                .collect();
            // Deliberately the parts as they arrived, rather than
            // `body_text`/`body_html`, which invent the missing half of the
            // pair by converting the other one. A test asserting that its
            // mail carries no HTML should not be told that it does.
            let text = msg
                .text_bodies()
                .find(|p| !p.is_text_html())
                .and_then(|p| p.text_contents())
                .map(str::to_string);
            let html = msg
                .html_bodies()
                .find(|p| p.is_text_html())
                .and_then(|p| p.text_contents())
                .map(str::to_string);
            (text, html, attachments)
        }
        None => (None, None, Vec::new()),
    };

    if let Some(obj) = out.as_object_mut() {
        obj.insert("parsed".into(), json!(parsed.is_some()));
        obj.insert("text".into(), json!(text));
        obj.insert("html".into(), json!(html));
        obj.insert("attachments".into(), json!(attachments));
        obj.insert("headers".into(), json!(raw_headers(&e.raw)));
        // Lossy on purpose: a test that sends deliberately broken bytes should
        // still get a response it can look at rather than a 500.
        obj.insert("raw".into(), json!(String::from_utf8_lossy(&e.raw)));
    }
    out
}

/// The header block exactly as it arrived, unfolded into name/value pairs.
/// Duplicates are kept in order, which an object keyed by name could not do.
fn raw_headers(raw: &[u8]) -> Vec<Value> {
    let text = String::from_utf8_lossy(raw);
    let block = text.split("\r\n\r\n").next().unwrap_or("");
    let mut out: Vec<Value> = Vec::new();
    let mut name = String::new();
    let mut value = String::new();
    let mut started = false;
    for line in block.split("\r\n") {
        if line.starts_with(' ') || line.starts_with('\t') {
            // A folded continuation belongs to the header above it.
            if started {
                value.push(' ');
                value.push_str(line.trim());
            }
            continue;
        }
        if started {
            out.push(json!({ "name": name, "value": value.trim() }));
            started = false;
        }
        if let Some((n, v)) = line.split_once(':') {
            name = n.trim().to_string();
            value = v.trim().to_string();
            started = true;
        }
    }
    if started {
        out.push(json!({ "name": name, "value": value.trim() }));
    }
    out
}

// ---- endpoints ----

/// A description of the API itself, so that hitting `/api` with a browser is
/// not a dead end. This is the one endpoint that needs no token.
async fn index() -> Response {
    Json(json!({
        "service": "SMTPVoid mail API",
        "authentication": "Authorization: Bearer <token>, or X-API-Token: <token>",
        "endpoints": {
            "GET /api/list": "message summaries, newest first (filters: to, from, subject, limit)",
            "GET /api/latest": "the newest message with its content (filters: to, from, subject)",
            "GET /api/get/{id}": "one message with its content",
        },
    }))
    .into_response()
}

async fn list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(filter): Query<Filter>,
) -> Response {
    let user = match require_token(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let all = state.mail.list(user.id);
    let matched: Vec<_> = all.iter().filter(|e| filter.matches(e)).collect();
    let total = matched.len();
    let messages: Vec<Value> = matched
        .into_iter()
        .take(filter.limit.unwrap_or(usize::MAX))
        .map(|e| summary(e))
        .collect();
    Json(json!({
        "count": messages.len(),
        "total": total,
        "messages": messages,
    }))
    .into_response()
}

async fn latest(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(filter): Query<Filter>,
) -> Response {
    let user = match require_token(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    // `MailStore::list` is newest-first, so the first match is the latest one.
    match state.mail.list(user.id).iter().find(|e| filter.matches(e)) {
        Some(email) => Json(full(email)).into_response(),
        None => fail(StatusCode::NOT_FOUND, "no message matches"),
    }
}

async fn get_one(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let user = match require_token(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    match state.mail.get(user.id, &id) {
        Some(email) => Json(full(&email)).into_response(),
        None => fail(StatusCode::NOT_FOUND, "message not found (it may have expired)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mailstore::{ConnKind, ConnectionInfo, MailStore};

    fn conn() -> ConnectionInfo {
        ConnectionInfo {
            kind: ConnKind::StartTls,
            tls_version: Some("TLSv1.3".into()),
            tls_cipher: None,
            peer_addr: "127.0.0.1:1234".into(),
            helo: "test".into(),
            esmtp: true,
            auth_mechanism: "PLAIN".into(),
        }
    }

    fn stored(subject: &str, to: &str) -> Arc<StoredEmail> {
        let store = MailStore::new(3600, 10);
        store.add(
            1,
            "sv_test".into(),
            "sender@example.test".into(),
            vec![to.to_string()],
            format!("Subject: {subject}\r\nFrom: Sender <sender@example.test>\r\nTo: {to}\r\n\r\nhello")
                .into_bytes(),
            conn(),
        )
    }

    fn filter(to: Option<&str>, subject: Option<&str>) -> Filter {
        Filter {
            to: to.map(str::to_string),
            subject: subject.map(str::to_string),
            ..Filter::default()
        }
    }

    #[test]
    fn filters_ignore_case_and_match_substrings() {
        let email = stored("Reset your password", "Alice@Example.test");
        assert!(filter(Some("alice@example.test"), None).matches(&email));
        assert!(filter(None, Some("reset")).matches(&email));
        assert!(filter(Some("ALICE"), Some("PASSWORD")).matches(&email));
        assert!(!filter(Some("bob@example.test"), None).matches(&email));
        assert!(!filter(None, Some("invoice")).matches(&email));
    }

    #[test]
    fn an_empty_filter_matches_everything() {
        assert!(Filter::default().matches(&stored("anything", "someone@example.test")));
    }

    #[test]
    fn an_html_only_message_reports_no_text_body() {
        let store = MailStore::new(3600, 10);
        let email = store.add(
            1,
            "sv_test".into(),
            "sender@example.test".into(),
            vec!["alice@example.test".into()],
            b"Subject: Rich
Content-Type: text/html

<p>hello</p>".to_vec(),
            conn(),
        );
        let json = full(&email);
        assert_eq!(json["html"], "<p>hello</p>");
        assert_eq!(json["text"], Value::Null, "no text part means no text body");
    }

    #[test]
    fn a_message_carries_its_bodies_and_headers() {
        let email = stored("Hello", "alice@example.test");
        let json = full(&email);
        assert_eq!(json["subject"], "Hello");
        assert_eq!(json["text"], "hello");
        assert_eq!(json["html"], Value::Null);
        assert_eq!(json["connection"]["security"], "starttls");
        let headers = json["headers"].as_array().expect("headers are an array");
        assert!(headers
            .iter()
            .any(|h| h["name"] == "Subject" && h["value"] == "Hello"));
    }

    #[test]
    fn folded_headers_are_joined_into_one_value() {
        let raw = b"Subject: one\r\n two\r\nX-Test: a\r\nX-Test: b\r\n\r\nbody";
        let headers = raw_headers(raw);
        assert_eq!(headers[0]["name"], "Subject");
        assert_eq!(headers[0]["value"], "one two");
        // Repeated header names keep both values, in order.
        assert_eq!(headers[1]["value"], "a");
        assert_eq!(headers[2]["value"], "b");
    }

    #[test]
    fn bearer_tokens_are_read_whatever_the_scheme_case() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "BeArEr  tok123 ".parse().unwrap());
        assert_eq!(presented_token(&headers).as_deref(), Some("tok123"));

        let mut headers = HeaderMap::new();
        headers.insert(TOKEN_HEADER, "tok456".parse().unwrap());
        assert_eq!(presented_token(&headers).as_deref(), Some("tok456"));

        assert_eq!(presented_token(&HeaderMap::new()), None);
    }
}
