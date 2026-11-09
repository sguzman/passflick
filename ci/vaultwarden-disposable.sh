#!/usr/bin/env bash
# Disposable Vaultwarden 1.37.5 + Caddy TLS. Real server, fictional data.
# No real account, machine endpoint, developer credentials or permanent volume.
set -euo pipefail
umask 077
work="$(mktemp -d)"
network="passflick-ci-$GITHUB_RUN_ID"
vault="passflick-vault-$GITHUB_RUN_ID"
proxy="passflick-proxy-$GITHUB_RUN_ID"
cleanup() {
  docker rm -f "$proxy" "$vault" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

mkdir -p "$work/certs"
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
  -keyout "$work/certs/root.key" -out "$work/certs/root.pem" \
  -subj '/CN=Passflick Disposable Test CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes \
  -keyout "$work/certs/server.key" -out "$work/certs/server.csr" \
  -subj '/CN=localhost' >/dev/null 2>&1
cat > "$work/certs/server.ext" <<'EOF'
subjectAltName=DNS:localhost
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EOF
openssl x509 -req -in "$work/certs/server.csr" \
  -CA "$work/certs/root.pem" -CAkey "$work/certs/root.key" \
  -CAcreateserial -out "$work/certs/server.crt" \
  -days 1 -sha256 -extfile "$work/certs/server.ext" >/dev/null 2>&1

cat > "$work/Caddyfile" <<'EOF'
{
    auto_https off
    admin off
}
https://localhost:18443 {
    tls /etc/caddy/certs/server.crt /etc/caddy/certs/server.key
    reverse_proxy http://passflick-vault:80
}
EOF

docker network create "$network" >/dev/null
docker run -d --name "$vault" --network "$network" \
  --network-alias passflick-vault \
  -e DOMAIN=https://localhost:18443 \
  -e SIGNUPS_ALLOWED=true \
  -e SIGNUPS_VERIFY=false \
  -e I_REALLY_WANT_VOLATILE_STORAGE=true \
  -e ROCKET_PORT=80 \
  vaultwarden/server:1.37.5 >/dev/null
docker run -d --name "$proxy" --network "$network" \
  --publish 127.0.0.1:18443:18443 \
  --mount "type=bind,source=$work/Caddyfile,target=/etc/caddy/Caddyfile,readonly" \
  --mount "type=bind,source=$work/certs,target=/etc/caddy/certs,readonly" \
  caddy:2.10.2-alpine >/dev/null

ready=0
for _ in $(seq 1 45); do
  if ! docker inspect "$vault" --format '{{.State.Running}}' 2>/dev/null | grep -qx true; then
    echo 'Disposable Vaultwarden container exited unexpectedly' >&2
    docker inspect "$vault" --format 'Exit: {{.State.ExitCode}}' >&2 || true
    docker logs --tail 60 "$vault" >&2 || true
    exit 1
  fi
  if ! docker inspect "$proxy" --format '{{.State.Running}}' 2>/dev/null | grep -qx true; then
    echo 'Synthetic HTTPS proxy exited unexpectedly' >&2
    docker logs --tail 60 "$proxy" >&2 || true
    exit 1
  fi
  if curl -fsS --max-time 2 --cacert "$work/certs/root.pem" \
      https://localhost:18443/api/config >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 2
done
if [[ "$ready" != 1 ]]; then
  echo 'Disposable HTTPS server did not become healthy' >&2
  curl -sS --max-time 5 --cacert "$work/certs/root.pem" \
    https://localhost:18443/api/config >/dev/null || true
  docker ps --filter name=passflick --format '{{.Names}}: {{.Status}}' >&2
  docker logs --tail 40 "$proxy" >&2 || true
  docker logs --tail 40 "$vault" >&2 || true
  exit 1
fi

cargo build --locked --features vaultwarden-preview
# A real virtual X display is used solely for fictional populated-picker
# tests. No desktop session or user clipboard is mounted into the runner.
PASSFLICK_PREVIEW_BINARY="$(pwd)/target/debug/passflick" \
PASSFLICK_DISPOSABLE_URL=https://localhost:18443/ \
PASSFLICK_DISPOSABLE_CA="$work/certs/root.pem" \
PASSFLICK_CI_DISPOSABLE_PROXY="$proxy" \
PASSFLICK_CI_DISPOSABLE_TLS_CERT="$work/certs/server.crt" \
PASSFLICK_CI_DISPOSABLE_TLS_KEY="$work/certs/server.key" \
  xvfb-run -a cargo test --locked --features vaultwarden-preview bitwarden::live_acceptance::disposable_server_auth_sync_encrypted_offline \
  -- --ignored --nocapture
