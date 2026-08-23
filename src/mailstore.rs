use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rand::distributions::{Alphanumeric, DistString};

use crate::config::now_unix;

/// How the message reached the SMTP listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnKind {
    /// Plain TCP, no encryption at any point.
    Plaintext,
    /// Plain TCP upgraded with STARTTLS before submission.
    StartTls,
    /// Implicit TLS from the first byte (SMTPS).
    ImplicitTls,
}

impl ConnKind {
    pub fn label(self) -> &'static str {
        match self {
            ConnKind::Plaintext => "plaintext",
            ConnKind::StartTls => "STARTTLS",
            ConnKind::ImplicitTls => "implicit TLS",
        }
    }
}

/// Connection metadata recorded for every accepted message.
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub kind: ConnKind,
    pub tls_version: Option<String>,
    pub tls_cipher: Option<String>,
    pub peer_addr: String,
    pub helo: String,
    pub esmtp: bool,
    pub auth_mechanism: String,
}

/// One message resting in the void. Only ever lives in memory.
#[derive(Debug, Clone)]
pub struct StoredEmail {
    pub id: String,
    pub cred_username: String,
    pub mail_from: String,
    pub rcpt_to: Vec<String>,
    pub raw: Vec<u8>,
    pub received_at: i64,
    pub expires_at: i64,
    pub conn: ConnectionInfo,
    /// Parsed at ingest time for list views.
    pub subject: String,
    pub from_header: String,
}

/// In-memory, self-expiring mailbox store. Messages are never written to disk
/// and never leave this process.
pub struct MailStore {
    boxes: Mutex<HashMap<i64, VecDeque<Arc<StoredEmail>>>>,
    retention: Duration,
    per_user_cap: usize,
}

impl MailStore {
    pub fn new(retention: Duration, per_user_cap: usize) -> Self {
        MailStore {
            boxes: Mutex::new(HashMap::new()),
            retention,
            per_user_cap,
        }
    }

    /// Store a message, assigning it an id. Evicts the oldest message if the
    /// mailbox is at capacity.
    pub fn add(
        &self,
        user_id: i64,
        cred_username: String,
        mail_from: String,
        rcpt_to: Vec<String>,
        raw: Vec<u8>,
        conn: ConnectionInfo,
    ) -> Arc<StoredEmail> {
        let now = now_unix();
        let (subject, from_header) = parse_summary(&raw);
        let email = Arc::new(StoredEmail {
            id: Alphanumeric.sample_string(&mut rand::thread_rng(), 24),
            cred_username,
            mail_from,
            rcpt_to,
            raw,
            received_at: now,
            expires_at: now + self.retention.as_secs() as i64,
            conn,
            subject,
            from_header,
        });
        let mut boxes = self.boxes.lock().expect("mailstore mutex poisoned");
        let mailbox = boxes.entry(user_id).or_default();
        while mailbox.len() >= self.per_user_cap {
            mailbox.pop_front();
        }
        mailbox.push_back(email.clone());
        email
    }

    /// List a user's messages, newest first, skipping expired ones.
    pub fn list(&self, user_id: i64) -> Vec<Arc<StoredEmail>> {
        let now = now_unix();
        let boxes = self.boxes.lock().expect("mailstore mutex poisoned");
        boxes
            .get(&user_id)
            .map(|q| {
                q.iter()
                    .filter(|e| e.expires_at > now)
                    .rev()
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn get(&self, user_id: i64, id: &str) -> Option<Arc<StoredEmail>> {
        let now = now_unix();
        let boxes = self.boxes.lock().expect("mailstore mutex poisoned");
        boxes
            .get(&user_id)
            .and_then(|q| q.iter().find(|e| e.id == id && e.expires_at > now))
            .cloned()
    }

    pub fn delete(&self, user_id: i64, id: &str) -> bool {
        let mut boxes = self.boxes.lock().expect("mailstore mutex poisoned");
        if let Some(q) = boxes.get_mut(&user_id) {
            let before = q.len();
            q.retain(|e| e.id != id);
            return q.len() != before;
        }
        false
    }

    pub fn clear(&self, user_id: i64) {
        let mut boxes = self.boxes.lock().expect("mailstore mutex poisoned");
        boxes.remove(&user_id);
    }

    /// Drop expired messages. Returns how many were removed.
    pub fn sweep(&self) -> usize {
        let now = now_unix();
        let mut removed = 0;
        let mut boxes = self.boxes.lock().expect("mailstore mutex poisoned");
        boxes.retain(|_, q| {
            let before = q.len();
            q.retain(|e| e.expires_at > now);
            removed += before - q.len();
            !q.is_empty()
        });
        removed
    }

    /// Per-user (message count, byte count) of currently stored mail.
    pub fn usage(&self) -> HashMap<i64, (usize, usize)> {
        let now = now_unix();
        let boxes = self.boxes.lock().expect("mailstore mutex poisoned");
        boxes
            .iter()
            .map(|(uid, q)| {
                let live: Vec<_> = q.iter().filter(|e| e.expires_at > now).collect();
                (*uid, (live.len(), live.iter().map(|e| e.raw.len()).sum()))
            })
            .collect()
    }
}

/// Extract subject and From header for list views; tolerant of garbage input.
fn parse_summary(raw: &[u8]) -> (String, String) {
    let parsed = mail_parser::MessageParser::default().parse(raw);
    match parsed {
        Some(msg) => {
            let subject = msg.subject().unwrap_or("(no subject)").to_string();
            let from = msg
                .from()
                .and_then(|a| a.first())
                .map(|addr| {
                    let email = addr.address().unwrap_or_default();
                    match addr.name() {
                        Some(name) if !name.is_empty() => format!("{name} <{email}>"),
                        _ => email.to_string(),
                    }
                })
                .unwrap_or_else(|| "(unknown sender)".to_string());
            (subject, from)
        }
        None => ("(unparseable message)".to_string(), "(unknown sender)".to_string()),
    }
}
