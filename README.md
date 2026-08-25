# SMTPVoid

An SMTP black hole for testing mail submission.
This code is 100% vibecoded so use with your own risk ;) 

SMTPVoid looks and behaves like a real submission server — it speaks ESMTP, supports
`AUTH PLAIN`/`AUTH LOGIN`, and accepts mail for **any** recipient over plaintext,
STARTTLS, or implicit TLS. But every message falls into the void: it is captured into
the sending user's private in-memory mailbox, expires after one hour, and is **never
delivered or relayed**. 

## Features

- **Open registration** — anyone can create an account through the web UI (can be
  closed from the admin settings).
- **SMTP credentials** — each user generates credentials (random username + password)
  for authenticating SMTP submissions. The dashboard keeps showing the password,
  with a copy button next to both halves: a credential can only push mail into its
  owner's void mailbox, so there is nothing to protect it from.
- **Account password** — every user changes their own sign-in password from the
  account page, reached by clicking their username in the header; doing so ends
  their other browser sessions.
  If nobody can sign in any more, `smtpvoid set-password <user>` resets one from
  the command line (the password is read from stdin, never from an argument).
- **Virtual mailbox** — captured messages appear in the web UI with parsed headers,
  text/HTML bodies and raw source.
- **Connection transparency** — every message records how it arrived: plaintext,
  STARTTLS, or implicit TLS, plus TLS version, cipher suite, client address,
  HELO/EHLO name and AUTH mechanism.
- **Read-only mail API** — a token-authenticated `GET` API (`/api/list`,
  `/api/latest`, `/api/get/<id>`) lets an end-to-end test assert on the mail its
  application just sent. The token and its instructions sit on the dashboard,
  behind the (i) next to it. See [Reading the mailbox from a test](#reading-the-mailbox-from-a-test).
- **Ephemeral by design** — messages live only in RAM and vanish after the retention
  period (default 1 hour). Restarting the server empties all mailboxes.
- **Configured from the browser** — hostname, listener addresses, retention, limits
  and TLS all live in the admin UI, not in environment variables. Changes apply
  immediately: listeners move to a new port without restarting the process.
- **Built-in Let's Encrypt** — SMTPVoid can obtain and renew a publicly trusted
  certificate over the ACME HTTP-01 challenge and use it for STARTTLS, SMTPS and
  its own HTTPS web UI. No certbot, no reverse proxy required.
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
   (accounts, settings and statistics only — never mail).
2. Writes the default settings into the database and generates a self-signed TLS
   certificate in `data/tls/`.
3. Prints an **admin setup token** to the log and stores it in
   `data/admin_setup_token`. Open `http://<host>:8080/setup`, enter the token and
   create the admin account. The token is invalidated immediately afterwards.

Then sign in and open **Settings** to configure the server.

## Configuration

Everything is configured at **`/admin/settings`** and stored in the database.
Saving applies changes immediately — including moving the SMTP, SMTPS and HTTPS
listeners to new addresses, which happens without dropping the process.

| Setting | Default | Description |
|---|---|---|
| SMTP hostname | `smtpvoid.local` | Hostname in the SMTP banner, in the self-signed certificate, and in the connection details shown to users |
| SMTP address | `0.0.0.0:587` | Submission listener (plaintext, offers STARTTLS) |
| SMTPS address | `0.0.0.0:465` | Implicit-TLS submission listener |
| HTTPS web UI address | *(empty)* | Serves the UI over TLS with the same certificate; empty disables it |
| Retention | `3600` s | How long messages are kept; re-dates mail already in the store |
| Messages per mailbox | `100` | Oldest evicted past this |
| Max message size | `1` MiB | Advertised via the ESMTP `SIZE` extension; stored in bytes, edited in MiB |
| SMTP credentials per user | `20` | Credential pairs one account may hold |
| Open registration | on | When off, nobody can self-register |
| Session cookie `Secure` | off | Turn on once the UI is HTTPS-only |
| Registrations per IP per hour | `10` | Account-creation throttle |
| Let's Encrypt | off | See below |

Only two things still come from the environment, because the database that holds
the settings lives in one and a mistyped value in the other would lock you out of
the page that fixes it:

| Variable | Default | Description |
|---|---|---|
| `SMTPVOID_DATA_DIR` | `./data` | SQLite database, TLS material, ACME account, setup token |
| `SMTPVOID_HTTP_ADDR` | `0.0.0.0:8080` | Plaintext web UI address; bound at startup and never moved |
| `RUST_LOG` | `info` | Log filter (`tracing_subscriber` syntax) |

### Setting the domain in one place

The domain appears twice in the settings form — as the SMTP hostname and, when
Let's Encrypt is on, in the certificate's domain list. For provisioning there is
a one-shot command that writes both from a single value, so an installer never
has to ask twice:

```bash
smtpvoid set-domain mail.example.com \
  --letsencrypt --agree-tos --email ops@example.com --https-addr 0.0.0.0:443
```

The first domain becomes the SMTP hostname; every domain listed goes on the
certificate. `--letsencrypt` requires `--agree-tos`, because ordering a
certificate accepts the CA's terms of service; `--staging` picks the staging
directory. Without `--letsencrypt` the command just sets the hostname — and
retargets the ACME domains if that was already configured.

It writes the same database rows the settings form writes, works before the
first start, and reissues the self-signed certificate when the name changes. A
running server keeps its cached settings until it is restarted.

### Ports and privileges

SMTPVoid is a *submission* server — it requires `AUTH` before `MAIL FROM` and
never relays — so it defaults to the submission ports from RFC 6409 and RFC 8314:
**587** for STARTTLS and **465** for implicit TLS. Port 25 is for MTA-to-MTA
relay and is deliberately not used.

Both defaults are privileged, as are 80 (ACME) and 443 (HTTPS UI). On Linux give
the process `CAP_NET_BIND_SERVICE` (see
[deploy/smtpvoid.service](deploy/smtpvoid.service)), run behind a load balancer,
or redirect ports with nftables. Without any of those the bind fails, but the
process keeps running and logs what to do — the web UI stays reachable so you can
set unprivileged ports (e.g. `0.0.0.0:2525` and `0.0.0.0:4650`) under Settings.

Changing the defaults only affects fresh installations. An existing deployment
keeps whatever is already stored in its database.

## Let's Encrypt

Enable it under **Settings → Let's Encrypt**: list the domains, accept the CA's
terms, and pick a challenge address (`0.0.0.0:80`).

SMTPVoid runs a dedicated listener that answers nothing but
`/.well-known/acme-challenge/...`, so the web UI can stay on any port. Every
listed domain must resolve to this host and reach that listener **on port 80** —
the CA does not follow redirects to other ports. The same route is also served by
the main web UI, so forwarding `/.well-known/` from an existing reverse proxy
works too.

The issued certificate is written to `data/tls/` and swapped in live: STARTTLS,
SMTPS and the HTTPS UI pick it up on their next connection, with no restart and
no dropped sessions. The settings page shows the current certificate, its expiry
and the result of the last order.

A certificate this server ordered is recorded in `data/tls/issued-by.json`
(source plus serial number), so recognising it later is a lookup rather than a
guess at the issuer's name — Let's Encrypt issues from intermediates called
things like `E5`, `R11` and `YE2`, and a certificate mistaken for someone else's
is a certificate the renewal check replaces every time it runs. For material the
operator installed, the issuer's organisation is what decides.

Renewal is checked every six hours (sooner after a failure, backing off from 15
minutes towards six hours) and runs when the certificate is missing, does not
cover every configured domain, came from a different ACME environment than the
one configured, or has less life left than the renewal window. That window is
the configured number of days, capped at a third of the certificate's own
lifetime — a six-day certificate is not permanently inside a thirty-day window.

Ordering itself is rate-limit aware, because the CA's limit is invisible from
here and hitting it locks the domain out for days:

- Let's Encrypt issues at most **5 certificates per week per exact set of
  domains**. SMTPVoid keeps its own record in `data/acme/issued.json` and stops
  at four, leaving one for an emergency.
- After a successful issuance, ordering is held for 24 hours (1 hour if the
  admin presses *Request / renew certificate now*). A held order is not an
  error; the certificate panel shows why and until when.
- Staging is not capped: it allows thousands a week.

Use the **staging** directory while you get DNS and firewall rules right —
production has strict rate limits and staging issues untrusted certificates that
are otherwise identical. Switching back to production replaces the staging
certificate automatically; the panel marks a staging certificate as untrusted.

Watch out for *Regenerate self-signed* on a working deployment: it replaces the
live certificate, so the next check has to order a new one.

## Deployment (Linux)

### Ubuntu / Debian installer

[install-ubuntu.sh](install-ubuntu.sh) does the whole thing on a fresh Ubuntu or
Debian host: installs the build dependencies and a current Rust toolchain,
builds the release binary, creates the `smtpvoid` system user and
`/var/lib/smtpvoid`, installs the systemd unit, enables it at boot and prints
the admin setup token.

```bash
sudo ./install-ubuntu.sh
```

Give it the domain once and it configures the SMTP hostname, the certificate
and the ACME order for you, so the settings form has nothing domain-shaped left
in it:

```bash
sudo ./install-ubuntu.sh --domain mail.example.com \
  --letsencrypt --agree-tos --email ops@example.com --https
```

Repeat `--domain` to put more names on the certificate.

The same script is the upgrade path. `--pull` fast-forwards the checkout first,
so one command takes a deployment to the latest commit:

```bash
sudo ./install-ubuntu.sh --pull
```

Every run rebuilds, reinstalls the binary and the unit, and restarts the
service, whether or not anything changed — the data directory (database, TLS
material, ACME state) is never touched. The closing summary says which parts
were actually updated, when the service restarted and which revision it was
built from, and it warns if the running process is not the binary that was just
installed.

An upgrade run also keeps the layout it finds: the service user, the web bind
address and the data directory are read back from the installed unit unless the
command line names them again. A bare `--pull` therefore cannot move the service
to a different data directory, which would look like a fresh install to the
server — self-signed certificate, new ACME order and new setup token included.

> **Upgrading past the plaintext-credential change:** SMTP credentials created
> while passwords were hashed cannot be recovered, so the first start after that
> change deletes them and logs how many went. Accounts, settings and statistics
> are untouched; users create new credentials from the dashboard.

`--data-dir`, `--http-addr`, `--user`, `--prefix`, `--binary` (skip the build),
`--acme-staging`, `--open-firewall` and `--no-start` are available too; see
`./install-ubuntu.sh --help`.

### Container

A container image and a systemd unit are also provided:

```bash
docker build -t smtpvoid .
docker run -d --name smtpvoid \
  -p 8080:8080 -p 587:587 -p 465:465 -p 80:80 -p 443:443 \
  -v smtpvoid-data:/data -e SMTPVOID_DATA_DIR=/data \
  smtpvoid
```

Then open `/setup`, create the admin account and set the hostname, listener
addresses and Let's Encrypt options under **Settings**. Publish only the ports
you actually intend to use; 80 and 443 are needed only for ACME and the built-in
HTTPS UI respectively.

The image runs unprivileged, and the binary carries
`cap_net_bind_service`, so the privileged defaults bind without extra flags. If
your runtime drops that capability, publish a remapped port instead (for example
`-p 587:2525`) and set the matching unprivileged address under Settings.

Alternatively copy the release binary to a server and install
[deploy/smtpvoid.service](deploy/smtpvoid.service).

For an internet-facing deployment, either let SMTPVoid terminate TLS itself
(Let's Encrypt + an HTTPS address, then turn on the `Secure` cookie flag), or put
it behind an HTTPS reverse proxy (Caddy, nginx, …) and turn on the `Secure`
cookie flag there.

## Testing a submission

Anything that speaks SMTP works. For example with `swaks`:

```bash
swaks --server smtp.example.test:587 --tls \
  --auth-user sv_xxxxxxxxxx --auth-password '...' \
  --from tester@example.test --to anyone@anywhere.example
```

A development smoke-test client is included (pass whichever ports the server is
actually listening on):

```bash
cargo run --example smoke_client -- plain    localhost:587 <user> <pass>
cargo run --example smoke_client -- starttls localhost:587 <user> <pass>
cargo run --example smoke_client -- tls      localhost:465 <user> <pass>
```

## Reading the mailbox from a test

Every account has a **mail API token**, shown on the dashboard next to the SMTP
server details; the (i) button beside it opens the same instructions in the
browser. Send the token in either header:

```
Authorization: Bearer svapi_xxxxxxxx
X-API-Token: svapi_xxxxxxxx
```

| Request | Answer |
| --- | --- |
| `GET /api/list` | Summaries of every message in the mailbox, newest first: `count`, `total`, `messages`. |
| `GET /api/latest` | The newest message, with its headers, bodies and raw source. |
| `GET /api/get/<id>` | One message by the `id` a listing gave you, in the same shape. |
| `GET /api` | The above as JSON. The only endpoint that needs no token. |

`to`, `from` and `subject` are case-insensitive substring filters accepted by both
`/api/list` and `/api/latest`, and `limit` caps a listing. They let a test wait for
*its own* message instead of whatever arrived last:

```bash
# Wait up to 30 seconds for the message a test just triggered.
for _ in $(seq 30); do
  curl -sf -H "Authorization: Bearer $SMTPVOID_TOKEN"     "https://smtp.example.test/api/latest?to=alice@example.test" && break
  sleep 1
done
```

A single message carries the summary fields plus `text`, `html`, `attachments`,
`headers` (name/value pairs, in arrival order) and `raw`. `text` and `html` are the
parts that were actually in the message, so a mail sent as plain text reports
`"html": null` rather than a conversion of its own text. `connection.security` is
`plaintext`, `starttls` or `tls`, which is enough to assert that the client really
did negotiate encryption.

A missing or unknown token is `401`; a filter that matches nothing, or an id that has
expired, is `404`. Both carry an `error` field. The API only reads — deleting mail
stays in the web UI — and a token sees exactly one mailbox, its owner's. Regenerate
it from the same dialog if it leaks; the old one stops working immediately.

## Security model & abuse resistance

- **No outbound mail, ever.** There is no delivery queue, no relay logic, and no
  outbound SMTP client anywhere in the codebase. Accepted messages go straight into
  an in-memory store and expire.
- Message bodies never touch disk; only counters (message/byte counts per user) are
  persisted for statistics.
- Account passwords are stored as argon2id hashes. SMTP credential passwords are
  stored in the clear on purpose: they are server-generated random strings whose
  only power is to submit mail into the sender's own mailbox, which is never
  delivered or relayed. Leaking one lets somebody clutter that mailbox, nothing
  more.
- SMTP requires authentication before `MAIL FROM`; unauthenticated sessions cannot
  submit anything.
- Session cookies are `HttpOnly` + `SameSite=Strict`; registration is rate-limited
  per IP; SMTP sessions disconnect after repeated authentication failures.
- The mail API token is a server-generated random string that only reads its own
  owner's mailbox, and the API exposes no way to modify anything. It is minted on
  the first dashboard visit and can be replaced from the API dialog, which
  invalidates the previous one at once.
- Admins can list users and statistics and delete abusive accounts, but have no
  route to any message content. The settings and TLS pages are admin-only too.
- The ACME challenge listener serves exactly one route and returns a token only
  for an order this process is currently running. The account key is written with
  owner-only permissions and never leaves the data directory.

For a hardened internet deployment consider adding fail2ban (the log records
authentication failures) and a reverse proxy with rate limiting in front of the web UI.

## License

MIT
