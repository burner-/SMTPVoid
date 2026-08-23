use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

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
///
/// Retention and capacity are atomics rather than plain fields because an admin
/// can change them from the web UI while mail is being delivered.
pub struct MailStore {
    boxes: Mutex<HashMap<i64, VecDeque<Arc<StoredEmail>>>>,
    retention_secs: AtomicU64,
    per_user_cap: AtomicUsize,
}

impl MailStore {
    pub fn new(retention_secs: u64, per_user_cap: usize) -> Self {
        MailStore {
            boxes: Mutex::new(HashMap::new()),
            retention_secs: AtomicU64::new(retention_secs),
            per_user_cap: AtomicUsize::new(per_user_cap.max(1)),
        }
    }

    pub fn retention_secs(&self) -> u64 {
        self.retention_secs.load(Ordering::Relaxed)
    }

    pub fn per_user_cap(&self) -> usize {
        self.per_user_cap.load(Ordering::Relaxed)
    }

    /// Apply new limits from the admin UI.
    ///
    /// Messages already in the store are re-dated against the new retention, so
    /// a change takes effect immediately in both directions instead of only for
    /// mail that arrives later. A lowered capacity evicts the oldest messages
    /// exactly as delivery would.
    pub fn set_limits(&self, retention_secs: u64, per_user_cap: usize) {
        let per_user_cap = per_user_cap.max(1);
        let previous = self.retention_secs.swap(retention_secs, Ordering::Relaxed);
        self.per_user_cap.store(per_user_cap, Ordering::Relaxed);
        if retention_secs == previous && per_user_cap >= self.longest_mailbox() {
            return; // nothing to re-date, nothing over capacity
        }

        let mut boxes = self.boxes.lock().expect("mailstore mutex poisoned");
        for mailbox in boxes.values_mut() {
            if retention_secs != previous {
                for email in mailbox.iter_mut() {
                    let mut updated = (**email).clone();
                    updated.expires_at = updated.received_at + retention_secs as i64;
                    *email = Arc::new(updated);
                }
            }
            while mailbox.len() > per_user_cap {
                mailbox.pop_front();
            }
        }
    }

    fn longest_mailbox(&self) -> usize {
        self.boxes
            .lock()
            .expect("mailstore mutex poisoned")
            .values()
            .map(VecDeque::len)
            .max()
            .unwrap_or(0)
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
            expires_at: now + self.retention_secs() as i64,
            conn,
            subject,
            from_header,
        });
        let cap = self.per_user_cap();
        let mut boxes = self.boxes.lock().expect("mailstore mutex poisoned");
        let mailbox = boxes.entry(user_id).or_default();
        while mailbox.len() >= cap {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn conn() -> ConnectionInfo {
        ConnectionInfo {
            kind: ConnKind::StartTls,
            tls_version: None,
            tls_cipher: None,
            peer_addr: "127.0.0.1:1234".into(),
            helo: "test".into(),
            esmtp: true,
            auth_mechanism: "PLAIN".into(),
        }
    }

    fn store_with(n: usize, retention: u64, cap: usize) -> MailStore {
        let store = MailStore::new(retention, cap);
        for i in 0..n {
            store.add(
                1,
                "sv_test".into(),
                "from@test".into(),
                vec!["to@test".into()],
                format!("Subject: msg {i}\r\n\r\nbody").into_bytes(),
                conn(),
            );
        }
        store
    }

    #[test]
    fn lowering_capacity_evicts_the_oldest_messages() {
        let store = store_with(5, 3600, 10);
        assert_eq!(store.list(1).len(), 5);

        store.set_limits(3600, 2);
        let kept = store.list(1);
        assert_eq!(kept.len(), 2, "mailbox trimmed to the new cap");
        // list() is newest-first, so the survivors must be the last two added.
        assert_eq!(kept[0].subject, "msg 4");
        assert_eq!(kept[1].subject, "msg 3");
    }

    #[test]
    fn changing_retention_re_dates_stored_messages_both_ways() {
        let store = store_with(1, 3600, 10);
        let original = store.list(1)[0].clone();
        assert_eq!(original.expires_at, original.received_at + 3600);

        store.set_limits(60, 10);
        let shortened = store.list(1)[0].clone();
        assert_eq!(shortened.expires_at, original.received_at + 60);

        store.set_limits(7200, 10);
        let extended = store.list(1)[0].clone();
        assert_eq!(extended.expires_at, original.received_at + 7200);
    }

    #[test]
    fn shortening_retention_can_expire_mail_immediately() {
        let store = store_with(3, 3600, 10);
        // Re-date everything into the past; the sweeper should collect it all.
        store.set_limits(1, 10);
        for email in store.list(1) {
            assert!(email.expires_at <= now_unix() + 1);
        }
    }

    #[test]
    fn new_messages_use_the_updated_limits() {
        let store = store_with(0, 3600, 10);
        store.set_limits(120, 1);
        store.add(1, "sv_test".into(), "f".into(), vec!["t".into()], b"x".to_vec(), conn());
        store.add(1, "sv_test".into(), "f".into(), vec!["t".into()], b"y".to_vec(), conn());

        let kept = store.list(1);
        assert_eq!(kept.len(), 1, "new cap applies to delivery");
        assert_eq!(kept[0].expires_at, kept[0].received_at + 120);
    }

    #[test]
    fn a_zero_capacity_is_clamped_rather_than_dropping_everything() {
        let store = store_with(2, 3600, 10);
        store.set_limits(3600, 0);
        assert_eq!(store.per_user_cap(), 1);
        assert_eq!(store.list(1).len(), 1);
    }
}
