//! Minimal ESMTP server that accepts mail into the void.
//!
//! Two listeners: a plaintext one that also offers STARTTLS, and an
//! implicit-TLS one. Every accepted message is stored in the in-memory
//! mailbox of the authenticated user together with connection metadata
//! (plaintext / STARTTLS / implicit TLS, TLS version, cipher, peer address,
//! AUTH mechanism). Nothing is ever relayed anywhere.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use base64::Engine;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use crate::config::now_unix;
use crate::db::CredAuth;
use crate::mailstore::{ConnKind, ConnectionInfo};
use crate::state::AppState;

const CMD_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_LINE: usize = 8192;
const MAX_RCPT: usize = 50;
const MAX_MESSAGES_PER_CONN: u32 = 100;
const MAX_AUTH_FAILURES: u32 = 5;
const MAX_ERRORS: u32 = 20;

pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

/// Line-oriented reader/writer over a stream that can be swapped out for a
/// TLS-wrapped one mid-session (STARTTLS).
struct LineStream {
    inner: Option<Box<dyn AsyncStream>>,
    buf: Vec<u8>,
}

impl LineStream {
    fn new(stream: Box<dyn AsyncStream>) -> Self {
        LineStream { inner: Some(stream), buf: Vec::new() }
    }

    /// Read one CRLF-terminated line (LF tolerated). None on clean EOF.
    async fn read_line(&mut self) -> Result<Option<String>> {
        loop {
            if let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
                let mut line: Vec<u8> = self.buf.drain(..=pos).collect();
                line.pop(); // \n
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return Ok(Some(String::from_utf8_lossy(&line).into_owned()));
            }
            if self.buf.len() > MAX_LINE {
                anyhow::bail!("line too long");
            }
            let stream = self.inner.as_mut().expect("stream taken");
            let mut chunk = [0u8; 4096];
            let n = tokio::time::timeout(CMD_TIMEOUT, stream.read(&mut chunk)).await??;
            if n == 0 {
                return Ok(None);
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    async fn write_line(&mut self, line: &str) -> Result<()> {
        let stream = self.inner.as_mut().expect("stream taken");
        stream.write_all(line.as_bytes()).await?;
        stream.write_all(b"\r\n").await?;
        stream.flush().await?;
        Ok(())
    }

    /// Replace the underlying transport (STARTTLS). Any buffered plaintext
    /// bytes are discarded per RFC 3207.
    fn upgrade(&mut self, new: Box<dyn AsyncStream>) {
        self.buf.clear();
        self.inner = Some(new);
    }

    fn take(&mut self) -> Box<dyn AsyncStream> {
        self.inner.take().expect("stream taken twice")
    }
}

struct AuthedAs {
    cred_id: i64,
    user_id: i64,
    cred_username: String,
    mechanism: String,
}

struct Session {
    state: Arc<AppState>,
    io: LineStream,
    peer: String,
    /// Offered on the plaintext listener until upgraded.
    starttls: Option<TlsAcceptor>,
    kind: ConnKind,
    tls_version: Option<String>,
    tls_cipher: Option<String>,
    helo: Option<String>,
    esmtp: bool,
    auth: Option<AuthedAs>,
    mail_from: Option<String>,
    rcpt_to: Vec<String>,
    auth_failures: u32,
    errors: u32,
    messages: u32,
}

/// Spawn both SMTP listeners.
pub async fn run(state: Arc<AppState>) -> Result<()> {
    let plain = TcpListener::bind(&state.cfg.smtp_addr).await?;
    let tls = TcpListener::bind(&state.cfg.smtps_addr).await?;
    tracing::info!("SMTP (plaintext + STARTTLS) listening on {}", state.cfg.smtp_addr);
    tracing::info!("SMTPS (implicit TLS) listening on {}", state.cfg.smtps_addr);

    let s1 = state.clone();
    tokio::spawn(async move {
        loop {
            match plain.accept().await {
                Ok((stream, peer)) => {
                    let state = s1.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_plain(state, stream, peer.to_string()).await {
                            tracing::debug!("smtp session {peer}: {e:#}");
                        }
                    });
                }
                Err(e) => tracing::warn!("smtp accept error: {e}"),
            }
        }
    });

    let s2 = state.clone();
    tokio::spawn(async move {
        loop {
            match tls.accept().await {
                Ok((stream, peer)) => {
                    let state = s2.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_implicit_tls(state, stream, peer.to_string()).await {
                            tracing::debug!("smtps session {peer}: {e:#}");
                        }
                    });
                }
                Err(e) => tracing::warn!("smtps accept error: {e}"),
            }
        }
    });

    Ok(())
}

async fn handle_plain(state: Arc<AppState>, stream: TcpStream, peer: String) -> Result<()> {
    let acceptor = TlsAcceptor::from(state.tls.clone());
    let session = Session {
        state,
        io: LineStream::new(Box::new(stream)),
        peer,
        starttls: Some(acceptor),
        kind: ConnKind::Plaintext,
        tls_version: None,
        tls_cipher: None,
        helo: None,
        esmtp: false,
        auth: None,
        mail_from: None,
        rcpt_to: Vec::new(),
        auth_failures: 0,
        errors: 0,
        messages: 0,
    };
    session.run().await
}

async fn handle_implicit_tls(state: Arc<AppState>, stream: TcpStream, peer: String) -> Result<()> {
    let acceptor = TlsAcceptor::from(state.tls.clone());
    let tls_stream = tokio::time::timeout(Duration::from_secs(30), acceptor.accept(stream)).await??;
    let (version, cipher) = tls_params(tls_stream.get_ref().1);
    let session = Session {
        state,
        io: LineStream::new(Box::new(tls_stream)),
        peer,
        starttls: None,
        kind: ConnKind::ImplicitTls,
        tls_version: version,
        tls_cipher: cipher,
        helo: None,
        esmtp: false,
        auth: None,
        mail_from: None,
        rcpt_to: Vec::new(),
        auth_failures: 0,
        errors: 0,
        messages: 0,
    };
    session.run().await
}

fn tls_params(conn: &rustls::ServerConnection) -> (Option<String>, Option<String>) {
    let version = conn.protocol_version().map(|v| format!("{v:?}"));
    let cipher = conn
        .negotiated_cipher_suite()
        .map(|s| format!("{:?}", s.suite()));
    (version, cipher)
}

impl Session {
    async fn run(mut self) -> Result<()> {
        let hostname = self.state.cfg.hostname.clone();
        self.io
            .write_line(&format!(
                "220 {hostname} ESMTP SMTPVoid ready - test sink, nothing is ever delivered"
            ))
            .await?;

        loop {
            let line = match self.io.read_line().await? {
                Some(l) => l,
                None => return Ok(()), // client disconnected
            };
            let (verb, arg) = split_command(&line);
            match verb.as_str() {
                "HELO" => self.cmd_helo(arg, false).await?,
                "EHLO" => self.cmd_helo(arg, true).await?,
                "STARTTLS" => {
                    if self.cmd_starttls().await? {
                        // session continues on the upgraded transport
                    }
                }
                "AUTH" => self.cmd_auth(arg).await?,
                "MAIL" => self.cmd_mail(arg).await?,
                "RCPT" => self.cmd_rcpt(arg).await?,
                "DATA" => self.cmd_data().await?,
                "RSET" => {
                    self.reset_transaction();
                    self.io.write_line("250 2.0.0 OK").await?;
                }
                "NOOP" => self.io.write_line("250 2.0.0 OK").await?,
                "VRFY" => {
                    self.io
                        .write_line("252 2.1.5 Cannot VRFY, but the void accepts everyone")
                        .await?
                }
                "HELP" => {
                    self.io
                        .write_line("214 2.0.0 This is SMTPVoid; messages are stored briefly and never delivered")
                        .await?
                }
                "QUIT" => {
                    self.io
                        .write_line(&format!("221 2.0.0 {hostname} closing connection"))
                        .await?;
                    return Ok(());
                }
                "" => self.syntax_error("500 5.5.2 Empty command").await?,
                _ => self.syntax_error("500 5.5.1 Command not recognized").await?,
            }
            if self.errors >= MAX_ERRORS {
                self.io
                    .write_line("421 4.7.0 Too many errors, closing connection")
                    .await?;
                return Ok(());
            }
            if self.auth_failures >= MAX_AUTH_FAILURES {
                self.io
                    .write_line("421 4.7.0 Too many authentication failures, closing connection")
                    .await?;
                return Ok(());
            }
        }
    }

    async fn syntax_error(&mut self, msg: &str) -> Result<()> {
        self.errors += 1;
        self.io.write_line(msg).await
    }

    fn reset_transaction(&mut self) {
        self.mail_from = None;
        self.rcpt_to.clear();
    }

    async fn cmd_helo(&mut self, arg: &str, esmtp: bool) -> Result<()> {
        let arg = arg.trim();
        if arg.is_empty() {
            return self.syntax_error("501 5.5.4 Hostname required").await;
        }
        self.helo = Some(arg.to_string());
        self.esmtp = esmtp;
        self.reset_transaction();
        let hostname = &self.state.cfg.hostname;
        if !esmtp {
            return self.io.write_line(&format!("250 {hostname} greets {arg}")).await;
        }
        self.io.write_line(&format!("250-{hostname} greets {arg}")).await?;
        self.io.write_line("250-8BITMIME").await?;
        self.io
            .write_line(&format!("250-SIZE {}", self.state.cfg.max_message_size))
            .await?;
        if self.starttls.is_some() {
            self.io.write_line("250-STARTTLS").await?;
        }
        self.io.write_line("250-AUTH PLAIN LOGIN").await?;
        self.io.write_line("250 ENHANCEDSTATUSCODES").await?;
        Ok(())
    }

    async fn cmd_starttls(&mut self) -> Result<bool> {
        let acceptor = match self.starttls.take() {
            Some(a) => a,
            None => {
                self.syntax_error("454 4.7.0 TLS not available").await?;
                return Ok(false);
            }
        };
        self.io.write_line("220 2.0.0 Ready to start TLS").await?;
        let inner = self.io.take();
        let tls_stream =
            tokio::time::timeout(Duration::from_secs(30), acceptor.accept(inner)).await??;
        let (version, cipher) = tls_params(tls_stream.get_ref().1);
        self.io.upgrade(Box::new(tls_stream));
        self.kind = ConnKind::StartTls;
        self.tls_version = version;
        self.tls_cipher = cipher;
        // RFC 3207: back to initial state after the handshake.
        self.helo = None;
        self.esmtp = false;
        self.auth = None;
        self.reset_transaction();
        Ok(true)
    }

    async fn cmd_auth(&mut self, arg: &str) -> Result<()> {
        if self.auth.is_some() {
            return self.syntax_error("503 5.5.1 Already authenticated").await;
        }
        let mut parts = arg.trim().splitn(2, ' ');
        let mech = parts.next().unwrap_or("").to_uppercase();
        let initial = parts.next().map(str::trim).unwrap_or("");
        match mech.as_str() {
            "PLAIN" => {
                let payload = if initial.is_empty() {
                    self.io.write_line("334 ").await?;
                    match self.io.read_line().await? {
                        Some(l) => l,
                        None => return Ok(()),
                    }
                } else {
                    initial.to_string()
                };
                if payload == "*" {
                    return self.syntax_error("501 5.7.0 Authentication aborted").await;
                }
                let decoded = match base64::engine::general_purpose::STANDARD.decode(payload.trim()) {
                    Ok(d) => d,
                    Err(_) => return self.auth_failed("501 5.5.2 Invalid base64").await,
                };
                // authzid NUL authcid NUL password
                let parts: Vec<&[u8]> = decoded.split(|&b| b == 0).collect();
                if parts.len() != 3 {
                    return self.auth_failed("501 5.5.2 Malformed AUTH PLAIN payload").await;
                }
                let username = String::from_utf8_lossy(parts[1]).into_owned();
                let password = String::from_utf8_lossy(parts[2]).into_owned();
                self.try_auth(&username, &password, "PLAIN").await
            }
            "LOGIN" => {
                let username = if initial.is_empty() {
                    self.io.write_line("334 VXNlcm5hbWU6").await?; // "Username:"
                    match self.io.read_line().await? {
                        Some(l) => l,
                        None => return Ok(()),
                    }
                } else {
                    initial.to_string()
                };
                if username.trim() == "*" {
                    return self.syntax_error("501 5.7.0 Authentication aborted").await;
                }
                self.io.write_line("334 UGFzc3dvcmQ6").await?; // "Password:"
                let password = match self.io.read_line().await? {
                    Some(l) => l,
                    None => return Ok(()),
                };
                if password.trim() == "*" {
                    return self.syntax_error("501 5.7.0 Authentication aborted").await;
                }
                let engine = &base64::engine::general_purpose::STANDARD;
                let (u, p) = match (engine.decode(username.trim()), engine.decode(password.trim())) {
                    (Ok(u), Ok(p)) => (
                        String::from_utf8_lossy(&u).into_owned(),
                        String::from_utf8_lossy(&p).into_owned(),
                    ),
                    _ => return self.auth_failed("501 5.5.2 Invalid base64").await,
                };
                self.try_auth(&u, &p, "LOGIN").await
            }
            _ => {
                self.syntax_error("504 5.5.4 Unrecognized authentication type")
                    .await
            }
        }
    }

    async fn auth_failed(&mut self, msg: &str) -> Result<()> {
        self.auth_failures += 1;
        self.errors += 1;
        self.io.write_line(msg).await
    }

    async fn try_auth(&mut self, username: &str, password: &str, mechanism: &str) -> Result<()> {
        let cred = self.state.db.get_credential_for_auth(username)?;
        let password = password.to_string();
        let ok_cred: Option<CredAuth> = tokio::task::spawn_blocking(move || {
            match cred {
                Some(c) => {
                    if crate::web::verify_password(&password, &c.password_hash) {
                        Some(c)
                    } else {
                        None
                    }
                }
                None => {
                    // Constant-ish time: burn an argon2 verification anyway.
                    crate::web::verify_password(&password, crate::web::dummy_hash());
                    None
                }
            }
        })
        .await?;

        match ok_cred {
            Some(c) => {
                self.auth = Some(AuthedAs {
                    cred_id: c.id,
                    user_id: c.user_id,
                    cred_username: c.username,
                    mechanism: mechanism.to_string(),
                });
                self.io
                    .write_line("235 2.7.0 Authentication successful")
                    .await
            }
            None => {
                self.auth_failed("535 5.7.8 Authentication credentials invalid")
                    .await
            }
        }
    }

    async fn cmd_mail(&mut self, arg: &str) -> Result<()> {
        if self.helo.is_none() {
            return self.syntax_error("503 5.5.1 Send HELO/EHLO first").await;
        }
        if self.auth.is_none() {
            return self
                .syntax_error("530 5.7.0 Authentication required (create SMTP credentials in the web UI)")
                .await;
        }
        if self.mail_from.is_some() {
            return self.syntax_error("503 5.5.1 Nested MAIL command").await;
        }
        let upper = arg.trim().to_uppercase();
        if !upper.starts_with("FROM:") {
            return self.syntax_error("501 5.5.4 Syntax: MAIL FROM:<address>").await;
        }
        let rest = &arg.trim()[5..];
        let addr = match extract_angle_addr(rest) {
            Some(a) => a,
            None => return self.syntax_error("501 5.1.7 Bad sender address syntax").await,
        };
        // SIZE parameter, if the client declares one, is checked up front.
        for param in rest.split_whitespace().skip_while(|p| !p.to_uppercase().starts_with("SIZE=")) {
            if let Some(v) = param.to_uppercase().strip_prefix("SIZE=") {
                if let Ok(size) = v.parse::<usize>() {
                    if size > self.state.cfg.max_message_size {
                        return self
                            .syntax_error("552 5.3.4 Message size exceeds fixed maximum")
                            .await;
                    }
                }
                break;
            }
        }
        self.mail_from = Some(addr);
        self.io.write_line("250 2.1.0 Sender OK").await
    }

    async fn cmd_rcpt(&mut self, arg: &str) -> Result<()> {
        if self.mail_from.is_none() {
            return self.syntax_error("503 5.5.1 Need MAIL command first").await;
        }
        let upper = arg.trim().to_uppercase();
        if !upper.starts_with("TO:") {
            return self.syntax_error("501 5.5.4 Syntax: RCPT TO:<address>").await;
        }
        let addr = match extract_angle_addr(&arg.trim()[3..]) {
            Some(a) if !a.is_empty() => a,
            _ => return self.syntax_error("501 5.1.3 Bad recipient address syntax").await,
        };
        if self.rcpt_to.len() >= MAX_RCPT {
            return self.syntax_error("452 4.5.3 Too many recipients").await;
        }
        self.rcpt_to.push(addr);
        // Any address is "deliverable" — into the void.
        self.io.write_line("250 2.1.5 Recipient OK (message will be captured, never delivered)").await
    }

    async fn cmd_data(&mut self) -> Result<()> {
        if self.mail_from.is_none() || self.rcpt_to.is_empty() {
            return self.syntax_error("503 5.5.1 Need MAIL and RCPT first").await;
        }
        if self.messages >= MAX_MESSAGES_PER_CONN {
            return self.syntax_error("452 4.5.3 Too many messages in one connection").await;
        }
        self.io
            .write_line("354 End data with <CR><LF>.<CR><LF>")
            .await?;

        let max = self.state.cfg.max_message_size;
        let mut body: Vec<u8> = Vec::new();
        let mut oversize = false;
        loop {
            let line = match self.io.read_line().await? {
                Some(l) => l,
                None => return Ok(()), // dropped mid-DATA; nothing stored
            };
            if line == "." {
                break;
            }
            // Undo dot-stuffing.
            let content = if let Some(stripped) = line.strip_prefix('.') { stripped } else { &line };
            if body.len() + content.len() + 2 > max {
                oversize = true;
                // keep consuming until the terminator, then reject
                continue;
            }
            body.extend_from_slice(content.as_bytes());
            body.extend_from_slice(b"\r\n");
        }

        if oversize {
            self.reset_transaction();
            return self
                .syntax_error("552 5.3.4 Message size exceeds fixed maximum")
                .await;
        }

        let auth = self.auth.as_ref().expect("checked above");
        let conn = ConnectionInfo {
            kind: self.kind,
            tls_version: self.tls_version.clone(),
            tls_cipher: self.tls_cipher.clone(),
            peer_addr: self.peer.clone(),
            helo: self.helo.clone().unwrap_or_default(),
            esmtp: self.esmtp,
            auth_mechanism: auth.mechanism.clone(),
        };
        let size = body.len() as i64;
        let email = self.state.mail.add(
            auth.user_id,
            auth.cred_username.clone(),
            self.mail_from.clone().unwrap_or_default(),
            std::mem::take(&mut self.rcpt_to),
            body,
            conn,
        );
        if let Err(e) = self
            .state
            .db
            .record_message(auth.user_id, auth.cred_id, size, self.kind)
        {
            tracing::warn!("failed to record message stats: {e:#}");
        }
        self.messages += 1;
        self.mail_from = None;
        tracing::info!(
            "message {} captured for user {} via {} ({})",
            email.id,
            auth.user_id,
            auth.cred_username,
            self.kind.label()
        );
        self.io
            .write_line(&format!(
                "250 2.0.0 OK: captured as {} - it will vanish at {} and is never delivered",
                email.id,
                crate::config::fmt_ts(email.expires_at)
            ))
            .await
    }
}

fn split_command(line: &str) -> (String, &str) {
    let trimmed = line.trim_start();
    match trimmed.find(' ') {
        Some(i) => (trimmed[..i].to_uppercase(), trimmed[i + 1..].trim_start()),
        None => (trimmed.trim_end().to_uppercase(), ""),
    }
}

/// Extract the address from a `<addr>` or bare-address form, ignoring
/// trailing ESMTP parameters. Empty return means the null reverse-path.
fn extract_angle_addr(s: &str) -> Option<String> {
    let s = s.trim();
    if let Some(start) = s.find('<') {
        let end = s[start..].find('>')? + start;
        return Some(s[start + 1..end].trim().to_string());
    }
    // Lenient fallback: first whitespace-separated token.
    let token = s.split_whitespace().next().unwrap_or("");
    if token.is_empty() {
        return None;
    }
    Some(token.to_string())
}

/// Periodically drop expired messages.
pub fn spawn_sweeper(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            let removed = state.mail.sweep();
            if removed > 0 {
                tracing::debug!("swept {removed} expired messages into oblivion at {}", now_unix());
            }
        }
    });
}
