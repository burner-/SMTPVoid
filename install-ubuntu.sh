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
#   sudo ./install-ubuntu.sh --data-dir /srv/smtpvoid --http-addr 127.0.0.1:8080
#   sudo ./install-ubuntu.sh --binary ./target/release/smtpvoid   # skip the build
#
set -euo pipefail

SERVICE_USER=smtpvoid
DATA_DIR=/var/lib/smtpvoid
HTTP_ADDR=0.0.0.0:8080
BIN_DIR=/usr/local/bin
UNIT_DIR=/etc/systemd/system
PREBUILT_BINARY=
OPEN_FIREWALL=0
START_SERVICE=1

# axum 0.8 and the ACME stack need a newer compiler than Ubuntu 24.04 or Debian
# bookworm ship, so an older distro toolchain is bypassed in favour of rustup.
MIN_RUST=1.82.0

SRC_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
RUST_ROOT=/opt/rust

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'USAGE'
Install SMTPVoid as a systemd service on Ubuntu or Debian.

Usage: sudo ./install-ubuntu.sh [options]

Options:
  --user NAME          system account to run as (default: smtpvoid)
  --data-dir PATH      database, TLS material, ACME state (default: /var/lib/smtpvoid)
  --http-addr ADDR     plaintext web UI address (default: 0.0.0.0:8080)
  --prefix DIR         where to install the binary (default: /usr/local/bin)
  --binary PATH        install this prebuilt binary instead of building
  --open-firewall      open 8080, 587, 465, 80 and 443 in ufw, if ufw is active
  --no-start           install and enable the unit but do not start it now
  -h, --help           show this help

Everything else - hostname, listener addresses, retention, Let's Encrypt - is
configured in the web UI at /admin/settings after the first start.
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --user)           SERVICE_USER=${2:?--user needs a value}; shift 2 ;;
        --data-dir)       DATA_DIR=${2:?--data-dir needs a value}; shift 2 ;;
        --http-addr)      HTTP_ADDR=${2:?--http-addr needs a value}; shift 2 ;;
        --prefix)         BIN_DIR=${2:?--prefix needs a value}; shift 2 ;;
        --binary)         PREBUILT_BINARY=${2:?--binary needs a value}; shift 2 ;;
        --open-firewall)  OPEN_FIREWALL=1; shift ;;
        --no-start)       START_SERVICE=0; shift ;;
        -h|--help)        usage; exit 0 ;;
        *)                die "unknown option: $1 (try --help)" ;;
    esac
done

# ---------------------------------------------------------------- preflight

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

CARGO=

if [ -z "$PREBUILT_BINARY" ]; then
    for candidate in "$RUST_ROOT/cargo/bin/cargo" "$HOME/.cargo/bin/cargo" "$(command -v cargo || true)"; do
        [ -n "$candidate" ] && [ -x "$candidate" ] || continue
        have=$("$candidate" --version 2>/dev/null | awk '{print $2}')
        [ -n "$have" ] || continue
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
    say "Building the release binary (a few minutes on a small VM)"
    # RUSTUP_HOME/CARGO_HOME are exported only by the rustup branch above: a
    # toolchain found elsewhere keeps its own, or its shim would look for
    # toolchains in a directory that does not exist.
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
say "Installing $TARGET_BINARY"
install -d "$BIN_DIR"
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

say "Installing $UNIT_DIR/smtpvoid.service"
sed -e "s|^User=.*|User=$SERVICE_USER|" \
    -e "s|^Group=.*|Group=$SERVICE_USER|" \
    -e "s|^ExecStart=.*|ExecStart=$TARGET_BINARY|" \
    -e "s|^Environment=SMTPVOID_DATA_DIR=.*|Environment=SMTPVOID_DATA_DIR=$DATA_DIR|" \
    -e "s|^Environment=SMTPVOID_HTTP_ADDR=.*|Environment=SMTPVOID_HTTP_ADDR=$HTTP_ADDR|" \
    -e "s|^ReadWritePaths=.*|ReadWritePaths=$DATA_DIR|" \
    "$UNIT_TEMPLATE" > "$UNIT_DIR/smtpvoid.service"
chmod 0644 "$UNIT_DIR/smtpvoid.service"

systemctl daemon-reload

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

say "Starting smtpvoid"
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

HOST=$(hostname -I 2>/dev/null | awk '{print $1}')
[ -n "$HOST" ] || HOST=localhost
PORT=${HTTP_ADDR##*:}

echo
say "SMTPVoid is running."
echo
echo "  Web UI     http://$HOST:$PORT/"
echo "  Data dir   $DATA_DIR"
echo "  Logs       journalctl -u smtpvoid -f"
echo

if [ -s "$DATA_DIR/admin_setup_token" ]; then
    echo "  First run: open http://$HOST:$PORT/setup and create the admin account with"
    echo
    echo "      setup token: $(cat "$DATA_DIR/admin_setup_token")"
    echo
    echo "  Then set the hostname, listener addresses and Let's Encrypt options under"
    echo "  Settings. The token stops working as soon as the admin account exists."
else
    echo "  An admin account already exists - sign in and continue at /admin/settings."
fi
echo
