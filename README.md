# SMTPVoid

An SMTP black hole for testing mail submission.

SMTPVoid looks and behaves like a real submission server — it speaks ESMTP, supports
`AUTH PLAIN`/`AUTH LOGIN`, and accepts mail for **any** recipient over plaintext,
STARTTLS, or implicit TLS. But every message falls into the void: it is captured into
the sending user's private in-memory mailbox, expires after one hour, and is **never
delivered, relayed, or written to disk**. The service cannot be used for spam.

## Features

- **Open registration** — anyone can create an account through the web UI.
- **SMTP credentials** — each user generates credentials (random username + password,
  shown once) for authenticating SMTP submissions.
- **Virtual mailbox** — captured messages appear in the web UI with parsed headers,
  text/HTML bodies and raw source.
- **Connection transparency** — every message records how it arrived: plaintext,
  STARTTLS, or implicit TLS, plus TLS version, cipher suite, client address,
  HELO/EHLO name and AUTH mechanism.
- **Ephemeral by design** — messages live only in RAM and vanish after the retention
  period (default 1 hour). Restarting the server empties all mailboxes.
- **Admin account** — bootstrapped with a one-time setup token generated at first
  start. Admins see user accounts and statistics (message counts, byte counts,
  connection-type breakdown) but can **never** read anyone's mail.

## Quick start

```bash
cargo build --release
./target/release/smtpvoid
```

On first start the server:

1. Creates the data directory (default `./data`) containing the SQLite database
   (accounts and statistics only — never mail).
2. Generates a self-signed TLS certificate in `data/tls/` (replace `cert.pem` /
   `key.pem` with a real certificate if you have one).
3. Prints an **admin setup token** to the log and stores it in
   `data/admin_setup_token`. Open `http://<host>:8080/setup`, enter the token and
   create the admin account. The token is invalidated immediately afterwards.

## Configuration

Everything is configured through environment variables:

| Variable | Default | Description |
|---|---|---|
| `SMTPVOID_DATA_DIR` | `./data` | SQLite database, TLS material, setup token |
| `SMTPVOID_HTTP_ADDR` | `0.0.0.0:8080` | Web UI listen address |
| `SMTPVOID_SMTP_ADDR` | `0.0.0.0:2525` | SMTP listener (plaintext + STARTTLS) |
| `SMTPVOID_SMTPS_ADDR` | `0.0.0.0:4650` | SMTPS listener (implicit TLS) |
| `SMTPVOID_HOSTNAME` | `smtpvoid.local` | Hostname in the SMTP banner and certificate |
| `SMTPVOID_RETENTION_SECS` | `3600` | How long messages are kept |
| `SMTPVOID_MAILBOX_CAP` | `100` | Max messages per mailbox (oldest evicted) |
| `SMTPVOID_MAX_MESSAGE_SIZE` | `1048576` | Max message size in bytes |
| `SMTPVOID_MAX_CREDENTIALS` | `20` | Max SMTP credentials per user |
| `SMTPVOID_COOKIE_SECURE` | `0` | Set `1` when serving the UI over HTTPS |
| `RUST_LOG` | `info` | Log filter (`tracing_subscriber` syntax) |

To use the standard ports (25/587 plaintext+STARTTLS, 465 implicit TLS) on Linux,
either run behind a load balancer, use `CAP_NET_BIND_SERVICE`
(see [deploy/smtpvoid.service](deploy/smtpvoid.service)), or redirect ports with nftables.

## Deployment (Linux)

A container image and a systemd unit are provided:

```bash
docker build -t smtpvoid .
docker run -d --name smtpvoid \
  -p 8080:8080 -p 2525:2525 -p 4650:4650 \
  -v smtpvoid-data:/data -e SMTPVOID_DATA_DIR=/data \
  -e SMTPVOID_HOSTNAME=smtp.example.test \
  smtpvoid
```

or copy the release binary to a server and install
[deploy/smtpvoid.service](deploy/smtpvoid.service).

The web UI should be placed behind an HTTPS reverse proxy (Caddy, nginx, …) with
`SMTPVOID_COOKIE_SECURE=1` for internet-facing deployments.

## Testing a submission

Anything that speaks SMTP works. For example with `swaks`:

```bash
swaks --server smtp.example.test:2525 --tls \
  --auth-user sv_xxxxxxxxxx --auth-password '...' \
  --from tester@example.test --to anyone@anywhere.example
```

A development smoke-test client is included:

```bash
cargo run --example smoke_client -- plain    localhost:2525 <user> <pass>
cargo run --example smoke_client -- starttls localhost:2525 <user> <pass>
cargo run --example smoke_client -- tls      localhost:4650 <user> <pass>
```

## Security model & abuse resistance

- **No outbound mail, ever.** There is no delivery queue, no relay logic, and no
  outbound SMTP client anywhere in the codebase. Accepted messages go straight into
  an in-memory store and expire.
- Message bodies never touch disk; only counters (message/byte counts per user) are
  persisted for statistics.
- Passwords (accounts and SMTP credentials) are stored as argon2id hashes.
- SMTP requires authentication before `MAIL FROM`; unauthenticated sessions cannot
  submit anything.
- Session cookies are `HttpOnly` + `SameSite=Strict`; registration is rate-limited
  per IP; SMTP sessions disconnect after repeated authentication failures.
- Admins can list users and statistics and delete abusive accounts, but have no
  route to any message content.

For a hardened internet deployment consider adding fail2ban (the log records
authentication failures) and a reverse proxy with rate limiting in front of the web UI.

## License

MIT
