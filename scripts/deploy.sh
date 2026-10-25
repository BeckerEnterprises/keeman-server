#!/usr/bin/env bash
# Builds the release binary, installs it, restarts the service and checks the
# health endpoint. Needs the one-time setup from the README (service user,
# configuration, systemd unit) and the right to restart the unit with sudo.
#
#   KEEMAN_BIN=/opt/keeman/keeman-server \
#   KEEMAN_SERVICE=keeman-api \
#   KEEMAN_HEALTH_URL=http://127.0.0.1:8787/v1/health \
#     scripts/deploy.sh
set -euo pipefail

: "${KEEMAN_BIN:?path of the installed binary, e.g. /opt/keeman/keeman-server}"
: "${KEEMAN_SERVICE:?name of the systemd unit, e.g. keeman-api}"
: "${KEEMAN_HEALTH_URL:?health endpoint, e.g. http://127.0.0.1:8787/v1/health}"

cd "$(dirname "$0")/.."
if [ -n "$(git status --porcelain)" ]; then
  echo "error: uncommitted changes; deploy only committed code" >&2
  exit 1
fi
# shellcheck disable=SC1091
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

if ! systemctl cat "$KEEMAN_SERVICE" >/dev/null 2>&1; then
  echo "error: systemd unit $KEEMAN_SERVICE is not installed (see README)" >&2
  exit 1
fi

cargo build --release --locked
install -m 0755 target/release/keeman-server "$KEEMAN_BIN.new"
mv "$KEEMAN_BIN.new" "$KEEMAN_BIN"
echo "installed $KEEMAN_BIN ($("$KEEMAN_BIN" --version))"

sudo -n systemctl restart "$KEEMAN_SERVICE"
for _ in $(seq 1 30); do
  if curl -fsS --max-time 2 "$KEEMAN_HEALTH_URL" >/dev/null 2>&1; then
    echo "$KEEMAN_SERVICE is healthy"
    exit 0
  fi
  sleep 0.5
done
echo "error: $KEEMAN_HEALTH_URL did not answer 200" >&2
sudo -n systemctl status "$KEEMAN_SERVICE" | cat >&2 || true
exit 1
