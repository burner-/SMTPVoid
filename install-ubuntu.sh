#!/usr/bin/env bash
# Install SMTPVoid as a systemd service on Ubuntu or Debian.
#
# Installs the build dependencies, builds the release binary from this source
# tree, installs it to /usr/local/bin, creates a system user and data
# directory, installs deploy/smtpvoid.service and enables it at boot.
#
# Re-running the script upgrades an existing installation in place: the binary
# is rebuilt and swapped, the unit refreshed and the service restarted. The
# data directory (database, TLS material, ACME state) is left untouched.
#
#   sudo ./install-ubuntu.sh
#   sudo ./install-ubuntu.sh --pull                 # update to the latest commit
#   sudo ./install-ubuntu.sh --domain mail.example.com --letsencrypt --agree-tos
#   sudo ./install-ubuntu.sh --binary ./target/release/smtpvoid   # skip the build
#
set -euo pipefail

# Kept for the re-exec after --pull updates this file; see below.
ORIGINAL_ARGS=("$@")

SERVICE_USER=smtpvoid
DATA_DIR=/var/lib/smtpvoid
HTTP_ADDR=0.0.0.0:8080
# Whether those three came from the command line. An upgrade run is usually
# just "--pull", and silently resetting them to the defaults would point the
# service at a different data directory - an empty one, so it would generate a
# self-signed certificate and order a new Let's Encrypt one for nothing.
USER_SET=0
DATA_DIR_SET=0
HTTP_ADDR_SET=0
BIN_DIR=/usr/local/bin
UNIT_DIR=/etc/systemd/system
PREBUILT_BINARY=
OPEN_FIREWALL=0
START_SERVICE=1
PULL=0
DOMAINS=
LETSENCRYPT=0
AGREE_TOS=0
ACME_STAGING=0
ACME_EMAIL=
HTTPS_ADDR=

# axum 0.8 and the ACME stack need a newer compiler than Ubuntu 24.04 or Debian
# bookworm ship, so an older distro toolchain is bypassed in favour of rustup.
MIN_RUST=1.82.0

SRC_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
SRC_OWNER=root
RUST_ROOT=/opt/rust

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'USAGE'
Install SMTPVoid as a systemd service on Ubuntu or Debian.

Usage: sudo ./install-ubuntu.sh [options]

Options:
  --domain DOMAIN      the server's domain, given once: it becomes the SMTP
                       hostname, the certificate name and, with --letsencrypt,
                       the domain the certificate is ordered for. Repeat the
                       option to put more names on the certificate.
  --letsencrypt        order a Let's Encrypt certificate for those domains
  --agree-tos          accept the CA's terms of service (required with --letsencrypt)
  --email ADDR         contact address to register with the CA
  --acme-staging       use the Let's Encrypt staging directory while testing
  --https              also serve the web UI over TLS on 0.0.0.0:443
  --user NAME          system account to run as (default: smtpvoid)
  --data-dir PATH      database, TLS material, ACME state (default: /var/lib/smtpvoid)
  --http-addr ADDR     plaintext web UI address (default: 0.0.0.0:8080)
  --prefix DIR         where to install the binary (default: /usr/local/bin)
  --binary PATH        install this prebuilt binary instead of building
  --pull               git pull --ff-only in this source tree before building,
                       so one command updates the service to the latest commit
  --open-firewall      open 8080, 587, 465, 80 and 443 in ufw, if ufw is active
  --no-start           install and enable the unit but do not start it now
  -h, --help           show this help

Example:
  sudo ./install-ubuntu.sh --domain mail.example.com \
       --letsencrypt --agree-tos --email ops@example.com --https

Everything else - listener addresses, retention, limits - is configured in the
web UI at /admin/settings after the first start.
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --domain)         DOMAINS="$DOMAINS ${2:?--domain needs a value}"; shift 2 ;;
        --letsencrypt)    LETSENCRYPT=1; shift ;;
        --agree-tos)      AGREE_TOS=1; shift ;;
        --email)          ACME_EMAIL=${2:?--email needs a value}; shift 2 ;;
        --acme-staging)   ACME_STAGING=1; shift ;;
        --https)          HTTPS_ADDR=0.0.0.0:443; shift ;;
        --user)           SERVICE_USER=${2:?--user needs a value}; USER_SET=1; shift 2 ;;
        --data-dir)       DATA_DIR=${2:?--data-dir needs a value}; DATA_DIR_SET=1; shift 2 ;;
        --http-addr)      HTTP_ADDR=${2:?--http-addr needs a value}; HTTP_ADDR_SET=1; shift 2 ;;
        --prefix)         BIN_DIR=${2:?--prefix needs a value}; shift 2 ;;
        --binary)         PREBUILT_BINARY=${2:?--binary needs a value}; shift 2 ;;
        --pull)           PULL=1; shift ;;
        --open-firewall)  OPEN_FIREWALL=1; shift ;;
        --no-start)       START_SERVICE=0; shift ;;
        -h|--help)        usage; exit 0 ;;
        *)                die "unknown option: $1 (try --help)" ;;
    esac
done

# ---------------------------------------------------------------- preflight

DOMAINS=${DOMAINS# }
if [ -z "$DOMAINS" ]; then
    [ "$LETSENCRYPT" -eq 0 ] || die "--letsencrypt needs --domain"
    [ -z "$ACME_EMAIL" ]     || die "--email needs --domain"
    [ "$ACME_STAGING" -eq 0 ] || die "--acme-staging needs --domain"
    [ -z "$HTTPS_ADDR" ]     || die "--https needs --domain"
fi
if [ "$LETSENCRYPT" -eq 1 ] && [ "$AGREE_TOS" -eq 0 ]; then
    die "--letsencrypt also needs --agree-tos: ordering a certificate accepts the CA's terms of service on your behalf"
fi

[ "$(id -u)" -eq 0 ]            || die "run this as root, e.g. sudo $0"
command -v apt-get >/dev/null   || die "no apt-get - this script targets Ubuntu and Debian"
command -v systemctl >/dev/null || die "no systemctl - this machine does not run systemd"

if [ -r /etc/os-release ]; then
    . /etc/os-release
    say "Installing SMTPVoid on ${PRETTY_NAME:-${ID:-unknown}}"
    case "${ID:-}${ID_LIKE:+ $ID_LIKE}" in
        *ubuntu*|*debian*) ;;
        *) warn "this looks like neither Ubuntu nor Debian - continuing anyway" ;;
    esac
fi

UNIT_TEMPLATE=$SRC_DIR/deploy/smtpvoid.service
[ -f "$UNIT_TEMPLATE" ] || die "missing $UNIT_TEMPLATE - run this script from inside the SMTPVoid source tree"

if [ -n "$PREBUILT_BINARY" ]; then
    [ -x "$PREBUILT_BINARY" ] || die "$PREBUILT_BINARY is not an executable file"
elif [ ! -f "$SRC_DIR/Cargo.toml" ]; then
    die "no Cargo.toml in $SRC_DIR - run this from the SMTPVoid source tree, or pass --binary"
fi

# -------------------------------------------------------------- new sources

# Root pulling into someone else's checkout would leave root-owned objects
# behind, and git refuses the "dubious ownership" case anyway, so the pull runs
# as whoever owns the tree.
git_src() {
    if [ "$SRC_OWNER" = root ]; then
        git -C "$SRC_DIR" "$@"
    else
        runuser -u "$SRC_OWNER" -- git -C "$SRC_DIR" "$@"
    fi
}

if [ "$PULL" -eq 1 ]; then
    command -v git >/dev/null || die "--pull needs git installed"
    [ -d "$SRC_DIR/.git" ] || die "--pull needs $SRC_DIR to be a git checkout"
    SRC_OWNER=$(stat -c %U "$SRC_DIR/.git")
    [ "$SRC_OWNER" = root ] || command -v runuser >/dev/null \
        || die "--pull needs runuser to pull as $SRC_OWNER, who owns $SRC_DIR"

    before=$(git_src rev-parse --short HEAD)
    say "Updating the source tree (git pull --ff-only, as $SRC_OWNER)"
    git_src pull --ff-only
    after=$(git_src rev-parse --short HEAD)
    if [ "$before" = "$after" ]; then
        say "Source already current at $after"
    else
        say "Source $before -> $after"
        # bash reads a script lazily, so the pull may just have rewritten the
        # lines this run has not reached yet. Start over from the new copy.
        # The repeat pull is a no-op, so this can only happen once.
        say "Restarting with the updated installer"
        exec bash "$SRC_DIR/install-ubuntu.sh" ${ORIGINAL_ARGS[@]+"${ORIGINAL_ARGS[@]}"}
    fi
fi

# ------------------------------------------------------------- dependencies

say "Installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
# build-essential: rusqlite bundles SQLite and ring compiles C, so a compiler is
#   needed even though nothing links against system libraries.
# libcap2-bin: setcap, for binding the privileged default ports.
# ca-certificates: the ACME client verifies the CA's own HTTPS chain.
apt-get install -y -qq --no-install-recommends \
    build-essential pkg-config ca-certificates curl libcap2-bin

# ---------------------------------------------------------------- toolchain

version_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }

# The cargo this script installs is a rustup shim, and a shim locates its
# toolchain through RUSTUP_HOME. Without it, /opt/rust/cargo/bin/cargo cannot
# even print its own version - it looks for toolchains under root's home and
# fails - so a later run would skip the toolchain the first run installed.
use_rust_env() {
    case "$1" in
        "$RUST_ROOT"/*) export RUSTUP_HOME=$RUST_ROOT/rustup CARGO_HOME=$RUST_ROOT/cargo ;;
    esac
}

CARGO=

if [ -z "$PREBUILT_BINARY" ]; then
    for candidate in "$RUST_ROOT/cargo/bin/cargo" "$HOME/.cargo/bin/cargo" "$(command -v cargo || true)"; do
        [ -n "$candidate" ] && [ -x "$candidate" ] || continue
        # Probed in a subshell, so the environment follows the candidate
        # instead of leaking into the next one.
        have=$( (use_rust_env "$candidate"; "$candidate" --version) 2>/dev/null | awk '{print $2}' )
        if [ -z "$have" ]; then
            warn "$candidate did not run - skipping it"
            continue
        fi
        if version_ge "$have" "$MIN_RUST"; then
            CARGO=$candidate
            say "Using the Rust toolchain already installed: cargo $have ($candidate)"
            break
        fi
        warn "cargo $have at $candidate is older than $MIN_RUST - skipping it"
    done

    if [ -z "$CARGO" ]; then
        say "Installing the Rust toolchain into $RUST_ROOT (rustup, stable)"
        export RUSTUP_HOME=$RUST_ROOT/rustup CARGO_HOME=$RUST_ROOT/cargo
        mkdir -p "$RUSTUP_HOME" "$CARGO_HOME"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
            | sh -s -- -y --no-modify-path --profile minimal --default-toolchain stable
        CARGO=$CARGO_HOME/bin/cargo
        [ -x "$CARGO" ] || die "rustup finished but $CARGO is missing"
    fi
fi

# -------------------------------------------------------------------- build

BUILT_BINARY=$PREBUILT_BINARY
if [ -z "$BUILT_BINARY" ]; then
    say "Building the release binary with $CARGO (a few minutes on a small VM)"
    # A toolchain outside /opt/rust keeps whatever environment it came with.
    use_rust_env "$CARGO"
    ( cd "$SRC_DIR" && "$CARGO" build --release --locked )
    BUILT_BINARY=$SRC_DIR/target/release/smtpvoid
    [ -x "$BUILT_BINARY" ] || die "the build finished but $BUILT_BINARY is missing"
fi

# ------------------------------------------------------------- user and data

if ! getent group "$SERVICE_USER" >/dev/null; then
    groupadd --system "$SERVICE_USER"
fi
if id -u "$SERVICE_USER" >/dev/null 2>&1; then
    say "System user $SERVICE_USER already exists"
else
    say "Creating system user $SERVICE_USER"
    useradd --system --gid "$SERVICE_USER" --home-dir "$DATA_DIR" \
        --shell /usr/sbin/nologin "$SERVICE_USER"
fi

say "Preparing $DATA_DIR"
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0750 "$DATA_DIR"

# ------------------------------------------------------------------ install

TARGET_BINARY=$BIN_DIR/smtpvoid
install -d "$BIN_DIR"

# A re-run is meant to upgrade, so say plainly whether this one moved anything -
# "nothing happened" and "nothing needed to happen" look identical otherwise.
if cmp -s "$BUILT_BINARY" "$TARGET_BINARY" 2>/dev/null; then
    BINARY_STATE="unchanged"
    say "Binary unchanged - the build produced the same image as the installed one"
else
    BINARY_STATE="updated"
    say "Installing $TARGET_BINARY"
fi
# Write beside the target and rename, so a running instance is never handed a
# half-written file; the restart below picks up the new inode.
install -m 0755 "$BUILT_BINARY" "$TARGET_BINARY.new"
mv -f "$TARGET_BINARY.new" "$TARGET_BINARY"

# 587, 465, 80 and 443 are all privileged and the service runs unprivileged.
# The unit grants CAP_NET_BIND_SERVICE; the file capability additionally covers
# running the binary by hand.
if setcap 'cap_net_bind_service=+ep' "$TARGET_BINARY" 2>/dev/null; then
    say "Granted cap_net_bind_service to $TARGET_BINARY"
else
    warn "setcap failed (unsupported filesystem?) - the unit's AmbientCapabilities still cover the service"
fi

UNIT_FILE=$UNIT_DIR/smtpvoid.service

# An installed unit is the record of how this host was set up, so keep whatever
# it says for anything this run did not mention. Otherwise a bare "--pull"
# would move the service to the default user, port and data directory - and a
# different data directory looks like a fresh install to the server:
# self-signed certificate, new ACME order, new setup token.
unit_value() {
    sed -n "s|^$1||p" "$UNIT_FILE" 2>/dev/null | tail -n1
}
if [ -f "$UNIT_FILE" ]; then
    if [ "$USER_SET" -eq 0 ]; then
        INSTALLED=$(unit_value 'User=')
        [ -z "$INSTALLED" ] || SERVICE_USER=$INSTALLED
    fi
    if [ "$DATA_DIR_SET" -eq 0 ]; then
        INSTALLED=$(unit_value 'Environment=SMTPVOID_DATA_DIR=')
        [ -z "$INSTALLED" ] || DATA_DIR=$INSTALLED
    fi
    if [ "$HTTP_ADDR_SET" -eq 0 ]; then
        INSTALLED=$(unit_value 'Environment=SMTPVOID_HTTP_ADDR=')
        [ -z "$INSTALLED" ] || HTTP_ADDR=$INSTALLED
    fi
    say "Keeping the installed layout: user $SERVICE_USER, data $DATA_DIR, web $HTTP_ADDR"
fi

sed -e "s|^User=.*|User=$SERVICE_USER|" \
    -e "s|^Group=.*|Group=$SERVICE_USER|" \
    -e "s|^ExecStart=.*|ExecStart=$TARGET_BINARY|" \
    -e "s|^Environment=SMTPVOID_DATA_DIR=.*|Environment=SMTPVOID_DATA_DIR=$DATA_DIR|" \
    -e "s|^Environment=SMTPVOID_HTTP_ADDR=.*|Environment=SMTPVOID_HTTP_ADDR=$HTTP_ADDR|" \
    -e "s|^ReadWritePaths=.*|ReadWritePaths=$DATA_DIR|" \
    "$UNIT_TEMPLATE" > "$UNIT_FILE.new"

if cmp -s "$UNIT_FILE.new" "$UNIT_FILE" 2>/dev/null; then
    UNIT_STATE="unchanged"
    say "Unit already up to date at $UNIT_FILE"
    rm -f "$UNIT_FILE.new"
else
    UNIT_STATE="updated"
    say "Installing $UNIT_FILE"
    mv -f "$UNIT_FILE.new" "$UNIT_FILE"
fi
chmod 0644 "$UNIT_FILE"

# Unconditional: cheap, and it also picks up an edit made outside this script.
systemctl daemon-reload

# ---------------------------------------------------------------- the domain

# The admin UI wants the domain in two fields (the SMTP hostname and the
# certificate domains), so the binary has a one-shot command that writes both
# from a single value. It runs as the service user, before the first start, so
# the database it creates is owned correctly and the server comes up already
# knowing its own name.
if [ -n "$DOMAINS" ]; then
    # Deliberately unquoted: --domain may be repeated and collects into one
    # space-separated list, which becomes one argument per domain here.
    # shellcheck disable=SC2086
    set -- $DOMAINS
    if [ "$LETSENCRYPT" -eq 1 ];  then set -- "$@" --letsencrypt --agree-tos; fi
    if [ "$ACME_STAGING" -eq 1 ]; then set -- "$@" --staging; fi
    if [ -n "$ACME_EMAIL" ];      then set -- "$@" --email "$ACME_EMAIL"; fi
    if [ -n "$HTTPS_ADDR" ];      then set -- "$@" --https-addr "$HTTPS_ADDR"; fi

    say "Setting the domain"
    if command -v runuser >/dev/null; then
        runuser -u "$SERVICE_USER" -- \
            env SMTPVOID_DATA_DIR="$DATA_DIR" "$TARGET_BINARY" set-domain "$@"
    else
        env SMTPVOID_DATA_DIR="$DATA_DIR" "$TARGET_BINARY" set-domain "$@"
        chown -R "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR"
    fi
fi

# ----------------------------------------------------------------- firewall

if [ "$OPEN_FIREWALL" -eq 1 ]; then
    if command -v ufw >/dev/null && ufw status 2>/dev/null | head -n1 | grep -q active; then
        say "Opening 8080, 587, 465, 80 and 443 in ufw"
        for port in 8080 587 465 80 443; do ufw allow "$port"/tcp >/dev/null; done
    else
        warn "--open-firewall given but ufw is not installed or not active - skipping"
    fi
fi

# -------------------------------------------------------------------- start

say "Enabling smtpvoid at boot"
systemctl enable smtpvoid >/dev/null

if [ "$START_SERVICE" -eq 0 ]; then
    say "Not starting it now, as requested: sudo systemctl start smtpvoid"
    exit 0
fi

# The restart is what actually puts the new binary and settings into service,
# so it happens on every run, whether or not anything above changed.
if systemctl is-active --quiet smtpvoid; then
    say "Restarting smtpvoid (it was running)"
else
    say "Starting smtpvoid"
fi
systemctl restart smtpvoid

# Give it a moment to bind, seed the database and write the setup token.
for _ in $(seq 20); do
    systemctl is-active --quiet smtpvoid || break
    if [ -s "$DATA_DIR/admin_setup_token" ]; then break; fi
    sleep 0.5
done

if ! systemctl is-active --quiet smtpvoid; then
    warn "smtpvoid failed to start - last log lines:"
    journalctl -u smtpvoid -n 30 --no-pager || true
    exit 1
fi

if [ -n "$DOMAINS" ]; then
    HOST=${DOMAINS%% *}
else
    HOST=$(hostname -I 2>/dev/null | awk '{print $1}')
    [ -n "$HOST" ] || HOST=localhost
fi
PORT=${HTTP_ADDR##*:}

MAIN_PID=$(systemctl show -p MainPID --value smtpvoid 2>/dev/null || echo 0)
SINCE=$(systemctl show -p ActiveEnterTimestamp --value smtpvoid 2>/dev/null || true)

# The symptom of a failed upgrade is a service still running the old image, so
# check what the process actually executes rather than trusting the restart.
if [ "${MAIN_PID:-0}" -gt 0 ] && [ -r "/proc/$MAIN_PID/exe" ]; then
    RUNNING=$(readlink "/proc/$MAIN_PID/exe" || true)
    case "$RUNNING" in
        "$TARGET_BINARY") ;;
        "") ;;
        *) warn "the service is running $RUNNING, not $TARGET_BINARY - check ExecStart in $UNIT_FILE" ;;
    esac
fi

echo
say "SMTPVoid is running."
echo
echo "  Web UI     http://$HOST:$PORT/"
echo "  Data dir   $DATA_DIR"
echo "  Logs       journalctl -u smtpvoid -f"
echo "  Binary     $TARGET_BINARY ($BINARY_STATE)"
echo "  Unit       $UNIT_FILE ($UNIT_STATE)"
echo "  Service    restarted${SINCE:+ at $SINCE}${MAIN_PID:+, pid $MAIN_PID}"
if REV=$(git -C "$SRC_DIR" describe --always --dirty 2>/dev/null); then
    echo "  Built from $REV"
fi
if [ -n "$DOMAINS" ]; then
    echo "  Domain     ${DOMAINS%% *} (SMTP hostname and certificate name)"
fi
if [ "$LETSENCRYPT" -eq 1 ]; then
    echo "  Let's Encrypt is on: the certificate is ordered in the background, and"
    echo "  every domain must resolve to this host and reach port 80. Watch the log,"
    echo "  or the certificate panel under Settings, for the result."
fi
echo

if [ -s "$DATA_DIR/admin_setup_token" ]; then
    echo "  First run: open http://$HOST:$PORT/setup and create the admin account with"
    echo
    echo "      setup token: $(cat "$DATA_DIR/admin_setup_token")"
    echo
    echo "  The token stops working as soon as the admin account exists. Listener"
    echo "  addresses, retention and the rest are under Settings."
else
    echo "  An admin account already exists - sign in and continue at /admin/settings."
fi
echo
