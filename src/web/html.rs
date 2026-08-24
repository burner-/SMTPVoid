//! Hand-rolled server-side HTML rendering. Every piece of user-controlled
//! data must pass through [`esc`] before being embedded.

use std::sync::Arc;

use crate::acme::AcmeStatus;
use crate::config::{fmt_bytes, fmt_duration, fmt_ts, now_unix, BootConfig};
use crate::db::{AdminUserRow, GlobalStats, SmtpCredential, User};
use crate::listeners::Kind as ListenerKind;
use crate::mailstore::{ConnKind, StoredEmail};
use crate::settings::{Settings, LETSENCRYPT_PRODUCTION, LETSENCRYPT_STAGING};
use crate::tls::{CertInfo, CertSource};

/// HTML-escape untrusted text.
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

const CSS: &str = r#"
:root { --bg:#0d1117; --panel:#161b22; --border:#30363d; --text:#e6edf3; --muted:#8b949e;
        --accent:#58a6ff; --green:#3fb950; --amber:#d29922; --red:#f85149; }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--text);
       font:15px/1.5 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }
a { color:var(--accent); text-decoration:none; }
a:hover { text-decoration:underline; }
header { border-bottom:1px solid var(--border); background:var(--panel); }
.hwrap { max-width:1100px; margin:0 auto; padding:12px 20px; display:flex; align-items:center; gap:18px; }
.logo { font-weight:700; font-size:18px; color:var(--text); }
.logo span { color:var(--accent); }
nav { display:flex; gap:14px; margin-left:auto; align-items:center; }
nav .who { color:var(--muted); }
main { max-width:1100px; margin:0 auto; padding:24px 20px 60px; }
h1 { font-size:24px; margin:0 0 6px; }
h2 { font-size:18px; margin:28px 0 10px; }
.sub { color:var(--muted); margin:0 0 20px; }
.panel { background:var(--panel); border:1px solid var(--border); border-radius:8px; padding:18px; margin:14px 0; }
table { width:100%; border-collapse:collapse; font-size:14px; }
th { text-align:left; color:var(--muted); font-weight:600; padding:8px 10px; border-bottom:1px solid var(--border); }
td { padding:8px 10px; border-bottom:1px solid var(--border); vertical-align:top; }
tr:last-child td { border-bottom:none; }
tr.rowlink:hover { background:#1c2129; cursor:pointer; }
.badge { display:inline-block; padding:2px 9px; border-radius:999px; font-size:12px; font-weight:600; white-space:nowrap; }
.b-plain { background:#3d1d20; color:var(--red); border:1px solid #6e2a2f; }
.b-starttls { background:#3a2d12; color:var(--amber); border:1px solid #6b5518; }
.b-tls { background:#12351c; color:var(--green); border:1px solid #1f6b34; }
.b-admin { background:#1a2c47; color:var(--accent); border:1px solid #2a4a75; }
input[type=text], input[type=password] { width:100%; padding:9px 11px; border-radius:6px;
  border:1px solid var(--border); background:var(--bg); color:var(--text); font-size:14px; }
label { display:block; margin:12px 0 4px; color:var(--muted); font-size:13px; }
button, .btn { display:inline-block; margin-top:14px; padding:8px 16px; border-radius:6px; border:1px solid var(--border);
  background:#21262d; color:var(--text); font-size:14px; cursor:pointer; }
button:hover, .btn:hover { background:#30363d; text-decoration:none; }
button.primary { background:#1f6feb; border-color:#1f6feb; color:#fff; }
button.primary:hover { background:#388bfd; }
button.danger { background:transparent; border-color:#6e2a2f; color:var(--red); padding:3px 10px; margin:0; font-size:13px; }
button.danger:hover { background:#3d1d20; }
form.inline { display:inline; }
.flash { border-radius:6px; padding:10px 14px; margin:14px 0; font-size:14px; }
.flash.ok { background:#12351c; border:1px solid #1f6b34; color:var(--green); }
.flash.err { background:#3d1d20; border:1px solid #6e2a2f; color:var(--red); }
.cards { display:grid; grid-template-columns:repeat(auto-fill,minmax(170px,1fr)); gap:12px; margin:14px 0; }
.card { background:var(--panel); border:1px solid var(--border); border-radius:8px; padding:14px; }
.card .num { font-size:24px; font-weight:700; }
.card .lbl { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.05em; }
pre { background:var(--bg); border:1px solid var(--border); border-radius:6px; padding:12px;
      overflow-x:auto; font-size:13px; white-space:pre-wrap; word-break:break-word; }
code { background:#21262d; padding:1px 6px; border-radius:4px; font-size:13px; }
.kv { display:grid; grid-template-columns:190px 1fr; gap:6px 14px; font-size:14px; }
.kv dt { color:var(--muted); }
.kv dd { margin:0; word-break:break-all; }
.reveal { border:1px solid #1f6b34; background:#12351c; border-radius:8px; padding:16px; margin:14px 0; }
.reveal code { font-size:15px; background:#0d1117; }
.muted { color:var(--muted); }
.small { font-size:13px; }
.narrow { max-width:430px; margin:40px auto; }
.grid2 { display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:0 22px; }
.field .hint { color:var(--muted); font-size:12px; margin:4px 0 0; }
.check { display:flex; align-items:flex-start; gap:9px; margin:14px 0 0; }
.check input { margin:3px 0 0; flex:none; }
.check .txt { font-size:14px; }
.check .txt .hint { margin:2px 0 0; }
input[type=number], input[type=email], input[type=url], textarea, select {
  width:100%; padding:9px 11px; border-radius:6px; border:1px solid var(--border);
  background:var(--bg); color:var(--text); font-size:14px; font-family:inherit; }
textarea { resize:vertical; min-height:64px; }
.warn { background:#3a2d12; border:1px solid #6b5518; color:var(--amber);
        border-radius:6px; padding:10px 14px; margin:14px 0; font-size:13px; }
.stack { display:flex; gap:10px; flex-wrap:wrap; align-items:center; }
.stack form { margin:0; }
footer { max-width:1100px; margin:0 auto; padding:20px; color:var(--muted); font-size:13px;
         border-top:1px solid var(--border); }
"#;

/// Navigation context for the layout.
pub enum Nav<'a> {
    Anonymous,
    User(&'a User),
}

pub fn layout(title: &str, nav: Nav, flash_ok: Option<&str>, flash_err: Option<&str>, body: &str) -> String {
    let nav_html = match nav {
        Nav::Anonymous => {
            r#"<nav><a href="/login">Sign in</a><a class="btn" style="margin:0" href="/register">Create account</a></nav>"#.to_string()
        }
        Nav::User(u) => {
            let admin = if u.is_admin {
                r#"<a href="/admin">Admin</a><a href="/admin/settings">Settings</a>"#
            } else {
                ""
            };
            format!(
                r#"<nav><a href="/dashboard">Dashboard</a>{admin}<span class="who">{}</span>
                <form class="inline" method="post" action="/logout"><button style="margin:0;padding:4px 12px">Sign out</button></form></nav>"#,
                esc(&u.username)
            )
        }
    };
    let flash = match (flash_ok, flash_err) {
        (Some(m), _) => format!(r#"<div class="flash ok">{}</div>"#, esc(m)),
        (_, Some(m)) => format!(r#"<div class="flash err">{}</div>"#, esc(m)),
        _ => String::new(),
    };
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} - SMTPVoid</title>
<style>{CSS}</style>
</head>
<body>
<header><div class="hwrap"><a class="logo" href="/">SMTP<span>Void</span></a>{nav_html}</div></header>
<main>{flash}{body}</main>
<footer>SMTPVoid is an SMTP testing sink. Messages are held in memory for a limited time and are <strong>never delivered anywhere</strong>.</footer>
</body>
</html>"#,
        title = esc(title),
    )
}

pub fn badge(kind: ConnKind) -> &'static str {
    match kind {
        ConnKind::Plaintext => r#"<span class="badge b-plain">plaintext</span>"#,
        ConnKind::StartTls => r#"<span class="badge b-starttls">STARTTLS</span>"#,
        ConnKind::ImplicitTls => r#"<span class="badge b-tls">implicit TLS</span>"#,
    }
}

pub fn index_page(
    smtp_addr: &str,
    smtps_addr: &str,
    retention_secs: i64,
    registration_open: bool,
) -> String {
    let actions = if registration_open {
        r#"<p><a class="btn" href="/register">Create an account</a> <a class="btn" href="/login">Sign in</a></p>"#.to_string()
    } else {
        r#"<p><a class="btn" href="/login">Sign in</a></p>
<p class="muted small">Registration is closed on this server; ask an administrator for an account.</p>"#
            .to_string()
    };
    format!(
        r#"<h1>Send email into the void</h1>
<p class="sub">A free SMTP testing sink. Point your application at SMTPVoid, send mail to <em>any</em> address, and watch it arrive in your virtual mailbox instead of the real world.</p>
<div class="panel">
<h2 style="margin-top:0">How it works</h2>
<ol>
<li>Create a free account and generate SMTP credentials.</li>
<li>Configure your application to send mail through this server using those credentials.</li>
<li>Messages to any recipient are captured into your private virtual mailbox.</li>
<li>Each message shows how it arrived: <span class="badge b-plain">plaintext</span> <span class="badge b-starttls">STARTTLS</span> or <span class="badge b-tls">implicit TLS</span>, including TLS version and cipher.</li>
<li>Messages self-destruct after {retention}. Nothing is ever stored on disk or delivered to a real mailbox &mdash; this service cannot be used to send actual email.</li>
</ol>
</div>
<div class="panel">
<h2 style="margin-top:0">Endpoints</h2>
<div class="kv">
<dt>SMTP (plaintext + STARTTLS)</dt><dd><code>{smtp}</code></dd>
<dt>SMTPS (implicit TLS)</dt><dd><code>{smtps}</code></dd>
<dt>Authentication</dt><dd><code>AUTH PLAIN</code> and <code>AUTH LOGIN</code></dd>
</div>
</div>
{actions}"#,
        retention = fmt_duration(retention_secs),
        smtp = esc(smtp_addr),
        smtps = esc(smtps_addr),
    )
}

pub fn auth_page(title: &str, action: &str, submit: &str, extra_field: &str) -> String {
    format!(
        r#"<div class="narrow"><div class="panel">
<h1>{title}</h1>
<form method="post" action="{action}">
{extra_field}
<label for="username">Username</label>
<input type="text" id="username" name="username" required maxlength="32" autocomplete="username">
<label for="password">Password</label>
<input type="password" id="password" name="password" required minlength="8" maxlength="128" autocomplete="current-password">
<button class="primary" type="submit">{submit}</button>
</form>
</div></div>"#,
        title = esc(title),
        action = esc(action),
        submit = esc(submit),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn dashboard_page(
    user: &User,
    creds: &[SmtpCredential],
    emails: &[Arc<StoredEmail>],
    reveal: Option<(String, String)>,
    smtp_addr: &str,
    smtps_addr: &str,
    hostname: &str,
    retention_secs: i64,
) -> String {
    let now = now_unix();
    let mut out = String::new();
    out.push_str(&format!(
        "<h1>Dashboard</h1><p class=\"sub\">Signed in as <strong>{}</strong>. Messages vanish {} after arrival and are never delivered.</p>",
        esc(&user.username),
        fmt_duration(retention_secs)
    ));

    if let Some((cu, cp)) = reveal {
        out.push_str(&format!(
            r#"<div class="reveal">
<strong>New SMTP credential created.</strong> The password is shown only once &mdash; copy it now.
<div class="kv" style="margin-top:10px">
<dt>Server (plaintext/STARTTLS)</dt><dd><code>{smtp}</code></dd>
<dt>Server (implicit TLS)</dt><dd><code>{smtps}</code></dd>
<dt>Hostname</dt><dd><code>{host}</code></dd>
<dt>Username</dt><dd><code>{cu}</code></dd>
<dt>Password</dt><dd><code>{cp}</code></dd>
<dt>Mechanisms</dt><dd><code>AUTH PLAIN</code>, <code>AUTH LOGIN</code></dd>
</div></div>"#,
            smtp = esc(smtp_addr),
            smtps = esc(smtps_addr),
            host = esc(hostname),
            cu = esc(&cu),
            cp = esc(&cp),
        ));
    }

    // SMTP credentials
    out.push_str("<h2>SMTP credentials</h2><div class=\"panel\">");
    if creds.is_empty() {
        out.push_str(r#"<p class="muted">No SMTP credentials yet. Create one to start sending mail into the void.</p>"#);
    } else {
        out.push_str("<table><tr><th>Username</th><th>Created</th><th>Messages received</th><th>Last used</th><th></th></tr>");
        for c in creds {
            out.push_str(&format!(
                r#"<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td>
<td><form class="inline" method="post" action="/credentials/{}/delete" onsubmit="return confirm('Delete this SMTP credential?')"><button class="danger">Delete</button></form></td></tr>"#,
                esc(&c.username),
                fmt_ts(c.created_at),
                c.total_messages,
                c.last_used_at.map(fmt_ts).unwrap_or_else(|| "never".into()),
                c.id,
            ));
        }
        out.push_str("</table>");
    }
    out.push_str(
        r#"<form method="post" action="/credentials/create"><button class="primary">Create SMTP credential</button></form></div>"#,
    );

    // Mailbox
    out.push_str(&format!(
        "<h2>Mailbox <span class=\"muted small\">({} messages)</span></h2><div class=\"panel\">",
        emails.len()
    ));
    if emails.is_empty() {
        out.push_str(r#"<p class="muted">The void is empty. Send a message using your SMTP credentials and it will appear here.</p>"#);
    } else {
        out.push_str("<table><tr><th>Received</th><th>From</th><th>To</th><th>Subject</th><th>Connection</th><th>Size</th><th>Expires in</th></tr>");
        for e in emails {
            let rcpt = if e.rcpt_to.len() > 2 {
                format!("{} (+{} more)", esc(&e.rcpt_to[0]), e.rcpt_to.len() - 1)
            } else {
                esc(&e.rcpt_to.join(", "))
            };
            out.push_str(&format!(
                r#"<tr class="rowlink" onclick="location.href='/mail/{id}'"><td>{}</td><td>{}</td><td>{}</td><td><a href="/mail/{id}">{}</a></td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                fmt_ts(e.received_at),
                esc(&e.from_header),
                rcpt,
                esc(&e.subject),
                badge(e.conn.kind),
                fmt_bytes(e.raw.len() as i64),
                fmt_duration(e.expires_at - now),
                id = esc(&e.id),
            ));
        }
        out.push_str("</table>");
        out.push_str(
            r#"<form method="post" action="/mailbox/clear" onsubmit="return confirm('Delete all messages in your mailbox?')"><button class="danger" style="margin-top:14px">Empty mailbox</button></form>"#,
        );
    }
    out.push_str("</div>");

    // Account
    out.push_str(
        r#"<h2>Account</h2><div class="panel">
<p class="muted small">Changing your sign-in password signs out every other browser. SMTP credentials are separate and keep working.</p>
<form method="post" action="/account/password" style="max-width:420px">
<label for="current_password">Current password</label>
<input type="password" id="current_password" name="current_password" required maxlength="128" autocomplete="current-password">
<label for="new_password">New password</label>
<input type="password" id="new_password" name="new_password" required minlength="8" maxlength="128" autocomplete="new-password">
<label for="confirm_password">New password again</label>
<input type="password" id="confirm_password" name="confirm_password" required minlength="8" maxlength="128" autocomplete="new-password">
<button class="primary">Change password</button>
</form></div>"#,
    );
    out
}

pub fn mail_page(e: &StoredEmail) -> String {
    let now = now_unix();
    let parsed = mail_parser::MessageParser::default().parse(&e.raw[..]);

    let mut meta = String::new();
    meta.push_str(&format!(
        r#"<div class="kv">
<dt>Connection</dt><dd>{badge}</dd>
<dt>TLS version</dt><dd>{tlsv}</dd>
<dt>TLS cipher</dt><dd>{cipher}</dd>
<dt>Client address</dt><dd><code>{peer}</code></dd>
<dt>HELO/EHLO</dt><dd><code>{helo}</code> ({proto})</dd>
<dt>AUTH mechanism</dt><dd><code>{mech}</code></dd>
<dt>SMTP credential</dt><dd><code>{cred}</code></dd>
<dt>Envelope sender</dt><dd><code>{from}</code></dd>
<dt>Envelope recipients</dt><dd>{rcpts}</dd>
<dt>Received</dt><dd>{recv}</dd>
<dt>Vanishes</dt><dd>{exp} (in {expin})</dd>
<dt>Size</dt><dd>{size}</dd>
</div>"#,
        badge = badge(e.conn.kind),
        tlsv = e.conn.tls_version.as_deref().map(esc).unwrap_or_else(|| "none (unencrypted)".into()),
        cipher = e.conn.tls_cipher.as_deref().map(esc).unwrap_or_else(|| "none".into()),
        peer = esc(&e.conn.peer_addr),
        helo = esc(&e.conn.helo),
        proto = if e.conn.esmtp { "ESMTP" } else { "SMTP" },
        mech = esc(&e.conn.auth_mechanism),
        cred = esc(&e.cred_username),
        from = if e.mail_from.is_empty() { "&lt;&gt; (null sender)".to_string() } else { format!("&lt;{}&gt;", esc(&e.mail_from)) },
        rcpts = e.rcpt_to.iter().map(|r| format!("<code>{}</code>", esc(r))).collect::<Vec<_>>().join(" "),
        recv = fmt_ts(e.received_at),
        exp = fmt_ts(e.expires_at),
        expin = fmt_duration(e.expires_at - now),
        size = fmt_bytes(e.raw.len() as i64),
    ));

    // Header block: everything before the first blank line, shown verbatim.
    let raw_str = String::from_utf8_lossy(&e.raw);
    let headers = raw_str
        .split("\r\n\r\n")
        .next()
        .unwrap_or("")
        .to_string();

    let mut bodies = String::new();
    match &parsed {
        Some(msg) => {
            if let Some(text) = msg.body_text(0) {
                bodies.push_str(&format!("<h2>Text body</h2><pre>{}</pre>", esc(&text)));
            }
            if let Some(html) = msg.body_html(0) {
                bodies.push_str(&format!(
                    "<h2>HTML body <span class=\"muted small\">(shown as source, not rendered)</span></h2><pre>{}</pre>",
                    esc(&html)
                ));
            }
            let att = msg.attachment_count();
            if att > 0 {
                bodies.push_str(&format!(
                    "<h2>Attachments</h2><p class=\"muted\">{att} attachment(s) present in the raw message.</p>"
                ));
            }
            if bodies.is_empty() {
                bodies.push_str(r#"<p class="muted">No decodable body parts.</p>"#);
            }
        }
        None => bodies.push_str(r#"<p class="muted">Message could not be parsed; see raw source below.</p>"#),
    }

    format!(
        r#"<p><a href="/dashboard">&larr; Back to mailbox</a></p>
<h1>{subject}</h1>
<p class="sub">From {from}</p>
<div class="panel"><h2 style="margin-top:0">Delivery details</h2>{meta}</div>
<div class="panel">{bodies}
<h2>Headers</h2><pre>{headers}</pre>
<p><a class="btn" href="/mail/{id}/raw">View raw message</a>
<form class="inline" method="post" action="/mail/{id}/delete" onsubmit="return confirm('Delete this message?')"><button class="danger" style="margin-left:8px">Delete now</button></form></p>
</div>"#,
        subject = esc(&e.subject),
        from = esc(&e.from_header),
        headers = esc(&headers),
        id = esc(&e.id),
    )
}

pub fn admin_page(
    stats: &GlobalStats,
    users: &[AdminUserRow],
    usage: &std::collections::HashMap<i64, (usize, usize)>,
    started_at: i64,
    retention_secs: i64,
) -> String {
    let live_msgs: usize = usage.values().map(|(n, _)| n).sum();
    let live_bytes: usize = usage.values().map(|(_, b)| b).sum();
    let mut out = format!(
        r#"<h1>Admin</h1>
<p class="sub">User accounts and statistics. Message contents are private to their owners and not visible here.
Server configuration lives under <a href="/admin/settings">Settings</a>.</p>
<div class="cards">
<div class="card"><div class="num">{users_n}</div><div class="lbl">Users</div></div>
<div class="card"><div class="num">{creds}</div><div class="lbl">SMTP credentials</div></div>
<div class="card"><div class="num">{total}</div><div class="lbl">Messages all-time</div></div>
<div class="card"><div class="num">{live}</div><div class="lbl">Messages in store</div></div>
<div class="card"><div class="num">{livebytes}</div><div class="lbl">Store size</div></div>
<div class="card"><div class="num">{plain}</div><div class="lbl">Plaintext</div></div>
<div class="card"><div class="num">{starttls}</div><div class="lbl">STARTTLS</div></div>
<div class="card"><div class="num">{tls}</div><div class="lbl">Implicit TLS</div></div>
<div class="card"><div class="num">{uptime}</div><div class="lbl">Uptime</div></div>
<div class="card"><div class="num">{retention}</div><div class="lbl">Retention</div></div>
</div>
<h2>Users</h2><div class="panel">
<table><tr><th>User</th><th>Created</th><th>Credentials</th><th>Messages all-time</th><th>In store</th>
<th>Bytes all-time</th><th>Plain / STARTTLS / TLS</th><th>Last message</th><th></th></tr>"#,
        users_n = stats.total_users,
        creds = stats.total_credentials,
        total = stats.total_messages,
        live = live_msgs,
        livebytes = fmt_bytes(live_bytes as i64),
        plain = stats.count_plaintext,
        starttls = stats.count_starttls,
        tls = stats.count_tls,
        uptime = fmt_duration(now_unix() - started_at),
        retention = fmt_duration(retention_secs),
    );
    for u in users {
        let (live_n, live_b) = usage.get(&u.id).copied().unwrap_or((0, 0));
        let admin_badge = if u.is_admin {
            r#" <span class="badge b-admin">admin</span>"#
        } else {
            ""
        };
        let delete = if u.is_admin {
            String::new()
        } else {
            format!(
                r#"<form class="inline" method="post" action="/admin/users/{}/delete" onsubmit="return confirm('Delete user, their credentials and mailbox?')"><button class="danger">Delete</button></form>"#,
                u.id
            )
        };
        out.push_str(&format!(
            "<tr><td><strong>{}</strong>{admin_badge}</td><td>{}</td><td>{}</td><td>{}</td><td>{} ({})</td><td>{}</td><td>{} / {} / {}</td><td>{}</td><td>{delete}</td></tr>",
            esc(&u.username),
            fmt_ts(u.created_at),
            u.cred_count,
            u.total_messages,
            live_n,
            fmt_bytes(live_b as i64),
            fmt_bytes(u.total_bytes),
            u.count_plaintext,
            u.count_starttls,
            u.count_tls,
            u.last_message_at.map(fmt_ts).unwrap_or_else(|| "never".into()),
        ));
    }
    out.push_str("</table></div>");
    out
}

pub fn setup_page() -> String {
    format!(
        r#"<div class="narrow"><div class="panel">
<h1>Admin setup</h1>
<p class="muted small">Enter the setup token generated during installation (see the server log or <code>admin_setup_token</code> in the data directory) to create the administrator account.</p>
<form method="post" action="/setup">
<label for="token">Setup token</label>
<input type="text" id="token" name="token" required autocomplete="off">
<label for="username">Admin username</label>
<input type="text" id="username" name="username" required maxlength="32">
<label for="password">Password</label>
<input type="password" id="password" name="password" required minlength="8" maxlength="128" autocomplete="new-password">
<button class="primary" type="submit">Create admin account</button>
</form>
</div></div>"#
    )
}

// ---- settings ----

fn text_field(id: &str, label: &str, value: &str, hint: &str, kind: &str) -> String {
    format!(
        r#"<div class="field"><label for="{id}">{label}</label>
<input type="{kind}" id="{id}" name="{id}" value="{value}"><p class="hint">{hint}</p></div>"#,
        id = esc(id),
        label = esc(label),
        value = esc(value),
        hint = esc(hint),
        kind = esc(kind),
    )
}

fn num_field(id: &str, label: &str, value: impl std::fmt::Display, hint: &str) -> String {
    format!(
        r#"<div class="field"><label for="{id}">{label}</label>
<input type="number" id="{id}" name="{id}" value="{value}"><p class="hint">{hint}</p></div>"#,
        id = esc(id),
        label = esc(label),
        value = esc(&value.to_string()),
        hint = esc(hint),
    )
}

fn check_field(id: &str, label: &str, checked: bool, hint: &str) -> String {
    format!(
        r#"<label class="check" for="{id}"><input type="checkbox" id="{id}" name="{id}" value="1"{checked}>
<span class="txt">{label}<p class="hint">{hint}</p></span></label>"#,
        id = esc(id),
        label = esc(label),
        hint = esc(hint),
        checked = if checked { " checked" } else { "" },
    )
}

/// The TLS certificate / ACME status panel above the settings form.
fn tls_panel(settings: &Settings, cert: Option<CertInfo>, acme: &AcmeStatus) -> String {
    let mut out = String::from(r#"<h2>TLS certificate</h2><div class="panel">"#);
    match cert {
        Some(info) => {
            let remaining = info.not_after - now_unix();
            let expiry = if remaining <= 0 {
                format!(r#"<span style="color:var(--red)">expired {} ago</span>"#, fmt_duration(-remaining))
            } else if remaining < 14 * 86_400 {
                format!(r#"<span style="color:var(--amber)">{} left</span>"#, fmt_duration(remaining))
            } else {
                format!(r#"<span style="color:var(--green)">{} left</span>"#, fmt_duration(remaining))
            };
            out.push_str(&format!(
                r#"<div class="kv">
<dt>Source</dt><dd>{source}</dd>
<dt>Issuer</dt><dd>{issuer}</dd>
<dt>Valid for</dt><dd>{names}</dd>
<dt>Issued</dt><dd>{issued}</dd>
<dt>Expires</dt><dd>{expires} &mdash; {expiry}</dd>
</div>"#,
                source = esc(info.source.label()),
                issuer = esc(&info.issuer),
                names = esc(&info.names.join(", ")),
                issued = fmt_ts(info.not_before),
                expires = fmt_ts(info.not_after),
                expiry = expiry,
            ));
            if info.source == CertSource::SelfSigned {
                out.push_str(
                    r#"<div class="warn">This is a self-signed certificate. Mail clients will refuse it or warn loudly. Configure Let's Encrypt below for a publicly trusted one.</div>"#,
                );
            }
        }
        None => out.push_str(r#"<p class="muted">No certificate loaded.</p>"#),
    }

    if settings.acme_enabled {
        let mut rows = String::new();
        if acme.running {
            rows.push_str(&format!(
                "<dt>In progress</dt><dd>{}</dd>",
                esc(acme.stage.as_deref().unwrap_or("working"))
            ));
        }
        if let Some(t) = acme.last_attempt {
            rows.push_str(&format!("<dt>Last attempt</dt><dd>{}</dd>", fmt_ts(t)));
        }
        if let Some(t) = acme.last_success {
            rows.push_str(&format!("<dt>Last success</dt><dd>{}</dd>", fmt_ts(t)));
        }
        if let Some(e) = &acme.last_error {
            rows.push_str(&format!(
                r#"<dt>Last error</dt><dd style="color:var(--red)">{}</dd>"#,
                esc(e)
            ));
        }
        if rows.is_empty() {
            rows.push_str(r#"<dt>Status</dt><dd class="muted">no order attempted yet</dd>"#);
        }
        out.push_str(&format!(
            r#"<h2 style="font-size:15px;margin:20px 0 8px">Let's Encrypt</h2><div class="kv">{rows}</div>"#
        ));
    }

    out.push_str(
        r#"<div class="stack" style="margin-top:16px">
<form method="post" action="/admin/tls/renew"><button class="primary">Request / renew certificate now</button></form>
<form method="post" action="/admin/tls/self-signed" onsubmit="return confirm('Replace the current certificate with a freshly generated self-signed one?')"><button>Regenerate self-signed</button></form>
</div></div>"#,
    );
    out
}

pub fn settings_page(
    s: &Settings,
    boot: &BootConfig,
    cert: Option<CertInfo>,
    acme: &AcmeStatus,
    active: &[(ListenerKind, String)],
) -> String {
    let running: Vec<String> = active
        .iter()
        .map(|(k, addr)| format!("<code>{}</code> {}", esc(addr), esc(k.label())))
        .collect();
    let running = if running.is_empty() {
        r#"<span class="muted">none</span>"#.to_string()
    } else {
        running.join(" &middot; ")
    };

    format!(
        r#"<h1>Settings</h1>
<p class="sub">Every setting below is stored in the database and applied without restarting. Listener bind addresses take effect as soon as you save.</p>

{tls}

<h2>Environment</h2><div class="panel">
<p class="muted small" style="margin-top:0">These two are fixed at startup: the database lives in the data directory, and a mistyped web bind address would lock you out of this page.</p>
<div class="kv">
<dt>Data directory</dt><dd><code>{data_dir}</code> <span class="muted">(SMTPVOID_DATA_DIR)</span></dd>
<dt>Web UI bind address (HTTP)</dt><dd><code>{http_addr}</code> <span class="muted">(SMTPVOID_HTTP_ADDR)</span></dd>
<dt>Running listeners</dt><dd>{running}</dd>
</div></div>

<form method="post" action="/admin/settings">

<h2>Identity and listeners</h2><div class="panel">
<div class="grid2">
{hostname}
{https_addr}
{smtp_addr}
{smtps_addr}
</div>
</div>

<h2>Mail behaviour</h2><div class="panel">
<div class="grid2">
{retention}
{cap}
{maxsize}
{maxcreds}
</div>
</div>

<h2>Access</h2><div class="panel">
{registration_open}
{cookie_secure}
<div class="grid2" style="margin-top:14px">
{regs_per_hour}
</div>
</div>

<h2>Let's Encrypt</h2><div class="panel">
<p class="muted small" style="margin-top:0">SMTPVoid answers the HTTP-01 challenge on its own listener, so the challenge port must be reachable from the internet on port 80 for every domain listed. The issued certificate is used by STARTTLS, SMTPS and the HTTPS web UI alike.</p>
{acme_enabled}
{acme_tos}
<div class="grid2" style="margin-top:14px">
{acme_domains}
{acme_http_addr}
{acme_contact}
{acme_renew}
</div>
<div class="field" style="margin-top:14px"><label for="acme_directory">ACME directory URL</label>
<select id="acme_directory" name="acme_directory">
<option value="{le_prod}"{prod_sel}>Let's Encrypt production</option>
<option value="{le_stage}"{stage_sel}>Let's Encrypt staging (untrusted certificates, for testing)</option>
{custom_opt}
</select><p class="hint">Use staging while you get the DNS and firewall right &mdash; production has strict rate limits.</p></div>
</div>

<button class="primary" type="submit">Save settings</button>
</form>"#,
        tls = tls_panel(s, cert, acme),
        data_dir = esc(&boot.data_dir.display().to_string()),
        http_addr = esc(&boot.http_addr),
        running = running,
        hostname = text_field(
            "hostname",
            "SMTP hostname",
            &s.hostname,
            "Announced in the SMTP banner and used for the self-signed certificate.",
            "text",
        ),
        https_addr = text_field(
            "https_addr",
            "HTTPS web UI bind address",
            &s.https_addr,
            "Empty disables HTTPS. Uses the certificate above, e.g. 0.0.0.0:443.",
            "text",
        ),
        smtp_addr = text_field(
            "smtp_addr",
            "SMTP bind address (plaintext + STARTTLS)",
            &s.smtp_addr,
            "Standard ports are 25 and 587; binding below 1024 needs CAP_NET_BIND_SERVICE.",
            "text",
        ),
        smtps_addr = text_field(
            "smtps_addr",
            "SMTPS bind address (implicit TLS)",
            &s.smtps_addr,
            "The standard port is 465.",
            "text",
        ),
        retention = num_field(
            "retention_secs",
            "Retention (seconds)",
            s.retention_secs,
            "How long a captured message survives. Applies to mail already in the store too.",
        ),
        cap = num_field(
            "mailbox_cap",
            "Messages per mailbox",
            s.mailbox_cap,
            "The oldest message is evicted once a mailbox is full.",
        ),
        maxsize = num_field(
            "max_message_size",
            "Max message size (bytes)",
            s.max_message_size,
            "Advertised to clients via the ESMTP SIZE extension.",
        ),
        maxcreds = num_field(
            "max_credentials_per_user",
            "SMTP credentials per user",
            s.max_credentials_per_user,
            "How many credential pairs one account may hold at a time.",
        ),
        registration_open = check_field(
            "registration_open",
            "Open registration",
            s.registration_open,
            "When off, nobody can create an account through the web UI.",
        ),
        cookie_secure = check_field(
            "cookie_secure",
            "Mark session cookies Secure",
            s.cookie_secure,
            "Turn on when the UI is only reachable over HTTPS. With this on, sign-in stops working over plain HTTP.",
        ),
        regs_per_hour = num_field(
            "registrations_per_hour",
            "Registrations per IP per hour",
            s.registrations_per_hour,
            "Throttles account creation from a single client IP address.",
        ),
        acme_enabled = check_field(
            "acme_enabled",
            "Obtain and renew a certificate automatically",
            s.acme_enabled,
            "Renewal is checked every six hours and runs when the certificate is close to expiry.",
        ),
        acme_tos = check_field(
            "acme_tos_agreed",
            "I accept the certificate authority's terms of service",
            s.acme_tos_agreed,
            "Required by the ACME protocol before an account can be registered.",
        ),
        acme_domains = text_field(
            "acme_domains",
            "Domains",
            &s.acme_domains.join(", "),
            "Comma-separated. Each must resolve to this server over the public internet.",
            "text",
        ),
        acme_http_addr = text_field(
            "acme_http_addr",
            "HTTP-01 challenge bind address",
            &s.acme_http_addr,
            "Must be port 80 as seen from the internet; the CA does not follow other ports.",
            "text",
        ),
        acme_contact = text_field(
            "acme_contact_email",
            "Contact email (optional)",
            &s.acme_contact_email,
            "The CA uses it for expiry warnings.",
            "email",
        ),
        acme_renew = num_field(
            "acme_renew_before_days",
            "Renew when days remaining below",
            s.acme_renew_before_days,
            "Let's Encrypt certificates last 90 days; 30 is the usual choice.",
        ),
        le_prod = esc(LETSENCRYPT_PRODUCTION),
        le_stage = esc(LETSENCRYPT_STAGING),
        prod_sel = if s.acme_directory == LETSENCRYPT_PRODUCTION { " selected" } else { "" },
        stage_sel = if s.acme_directory == LETSENCRYPT_STAGING { " selected" } else { "" },
        custom_opt = if s.acme_directory != LETSENCRYPT_PRODUCTION
            && s.acme_directory != LETSENCRYPT_STAGING
        {
            format!(
                r#"<option value="{v}" selected>{v}</option>"#,
                v = esc(&s.acme_directory)
            )
        } else {
            String::new()
        },
    )
}
