#!/bin/bash
# OpnAgent host-side one-time setup. Run on the Linux deploy host:
#   bash deploy/bootstrap.sh
# Checks kernel/Docker prerequisites, extracts the OpenShell sandbox binary
# to the host, builds the sandbox image, and writes deploy/.env for compose.
set -euo pipefail

cd "$(dirname "$0")"
ROOT="$(cd .. && pwd)"
SUPERVISOR_DIR="${OPN_STATE_DIR:-$HOME/openshell}/supervisor"
SUPERVISOR_BIN="$SUPERVISOR_DIR/openshell-sandbox"
OPENSHELL_IMAGE_TAG="${OPENSHELL_IMAGE_TAG:-latest}"

echo "== OpnAgent bootstrap =="

# 1. Kernel >= 6.2 (Landlock ABI 3 required by the OpenShell boundary)
K="$(uname -r)"
MAJ="${K%%.*}"; REST="${K#*.}"; MIN="${REST%%[.-]*}"
if [ "${MAJ:-0}" -lt 6 ] || { [ "${MAJ}" -eq 6 ] && [ "${MIN:-0}" -lt 2 ]; }; then
  echo "ERROR: kernel $K too old. OpenShell sandboxes need >= 6.2 (Landlock ABI 3)."
  exit 1
fi
echo "kernel: $K  OK"

# 2. Docker >= 28.0 and daemon reachable
if ! docker info >/dev/null 2>&1; then
  echo "ERROR: cannot reach the Docker daemon (permissions? is it running?)"
  exit 1
fi
DOCKER_VER="$(docker version --format '{{.Server.Version}}')"
D_MAJOR="${DOCKER_VER%%.*}"
if [ "${D_MAJOR:-0}" -lt 28 ]; then
  echo "ERROR: Docker server $DOCKER_VER found; OpenShell docker driver needs >= 28.0."
  exit 1
fi
echo "docker: $DOCKER_VER  OK"
DOCKER_GID="$(stat -c %g /var/run/docker.sock)"

# 3. Get the openshell-sandbox runtime binary onto the host (bind-mounted
#    into each sandbox container at the SAME absolute path by the gateway).
#    Docs disagree about where the binary lives, so try, in order:
#      a) supervisor / sandbox runtime images — documented path, else search
#      b) the official static musl release tarball (same release as the CLI)
mkdir -p "$SUPERVISOR_DIR"
if [ ! -x "$SUPERVISOR_BIN" ]; then
  docker rm -f opn-tmp-supervisor >/dev/null 2>&1 || true
  ARCH="$(uname -m)"          # x86_64 / aarch64 — matches release artifact names
  case "$ARCH" in x86_64|aarch64) : ;; *) echo "ERROR: unsupported arch $ARCH"; exit 1;; esac

  extract_from_image() {      # $1 = image ref
    docker rm -f opn-tmp-supervisor >/dev/null 2>&1 || true
    docker create --name opn-tmp-supervisor "$1" >/dev/null 2>&1 || return 1
    if docker cp opn-tmp-supervisor:/openshell-sandbox "$SUPERVISOR_BIN" 2>/dev/null; then
      return 0
    fi
    local p
    p="$(docker export opn-tmp-supervisor 2>/dev/null \
         | tar -t 2>/dev/null | grep -E '(^|/)[.]?openshell-sandbox$' | head -1)"
    [ -n "$p" ] || return 1
    p="/${p#./}"; p="/${p#/}"
    echo "  found at $p in $1"
    docker cp "opn-tmp-supervisor:$p" "$SUPERVISOR_BIN"
  }

  got=0
  for img in "ghcr.io/nvidia/openshell/supervisor:${OPENSHELL_IMAGE_TAG}" \
             "ghcr.io/nvidia/openshell/sandbox:${OPENSHELL_IMAGE_TAG}"; do
    echo "trying $img ..."
    if extract_from_image "$img"; then got=1; break; fi
  done
  docker rm -f opn-tmp-supervisor >/dev/null 2>&1 || true

  if [ "$got" -ne 1 ]; then
    echo "images did not carry the binary; downloading release tarball..."
    # Pinned like launcher/Dockerfile's CLI download; bump with the CLI.
    TB="openshell-sandbox-${ARCH}-unknown-linux-musl.tar.gz"
    URL="${OPN_RELEASE_BASE:-https://github.com/NVIDIA/OpenShell/releases/download/v0.1.2/$TB}"
    TMP="$(mktemp -d)"
    curl -fsSL "$URL" -o "$TMP/$TB" && tar -xzf "$TMP/$TB" -C "$TMP" \
      && find "$TMP" -name openshell-sandbox -type f \
           -exec cp {} "$SUPERVISOR_BIN" \; && got=1
    rm -rf "$TMP"
  fi

  if [ "$got" -ne 1 ] || [ ! -s "$SUPERVISOR_BIN" ]; then
    echo "ERROR: could not obtain openshell-sandbox from images or release tarball."
    echo "Manual fallback: locate it yourself, e.g."
    echo "  docker create --name t <image> && docker export t | tar -t | grep -i sandbox; docker rm -f t"
    exit 1
  fi
  chmod +x "$SUPERVISOR_BIN"
fi
file "$SUPERVISOR_BIN" | grep -qi 'executable' || echo "WARN: $SUPERVISOR_BIN does not look like a binary"
echo "supervisor binary: $SUPERVISOR_BIN"

# 3b. Sandbox-protocol JWT keys. The gateway mints the launch-scoped
#     credentials from these; gateways ~0.1.2+ REFUSE docker `sandbox create`
#     without them ("docker sandboxes require launch-scoped gateway
#     authentication"), even with allow_unauthenticated_users=true. The
#     package-managed installer generates this PKI automatically; the
#     container image does not, so we run its own `generate-certs` once.
TLS_DIR="${OPN_STATE_DIR:-$HOME/openshell}/tls"
if [ ! -f "$TLS_DIR/jwt/signing.pem" ]; then
  echo "generating OpenShell PKI (incl. sandbox JWT keys) into $TLS_DIR ..."
  mkdir -p "$TLS_DIR"
  # Newer gateway :latest builds run generate-certs as the image's non-root
  # uid AND chmod their --output-dir first — EPERM when /out is a host dir
  # owned by us (chmod needs ownership; the container is not root). Match
  # ownership when the image USER is numeric (distroless: 65532); otherwise
  # (root / named user) run as root — root can chmod anything, and the
  # alpine pass below still makes the files readable for the gateway.
  GW_IMG="ghcr.io/nvidia/openshell/gateway:${OPENSHELL_IMAGE_TAG}"
  CUSER="$(docker inspect --format '{{.Config.User}}' "$GW_IMG" 2>/dev/null || true)"
  CUID="${CUSER%%:*}"
  RUN_AS=()
  if [[ "$CUID" =~ ^[0-9]+$ ]] && [ "$CUID" != "0" ]; then
    chown "$CUID" "$TLS_DIR" 2>/dev/null || RUN_AS=(--user 0)
  elif [ -n "$CUSER" ] && [[ ! "$CUID" =~ ^[0-9]+$ ]]; then
    RUN_AS=(--user 0)
  fi
  docker run --rm ${RUN_AS[@]+"${RUN_AS[@]}"} -v "$TLS_DIR:/out" "$GW_IMG" \
    generate-certs --output-dir /out --server-san host.openshell.internal
  # Files land owned by the image's uid; make them readable for the gateway
  # container too. Throwaway PKI for a 127.0.0.1-only gateway.
  docker run --rm -v "$TLS_DIR:/d" alpine:3.20 chmod -R a+rX /d
  ls -R "$TLS_DIR"
fi
echo "tls dir: $TLS_DIR"

# 4. Build the sandbox image with the HOST docker engine (OpenShell --from
#    needs the image visible to the same daemon the gateway drives).
echo "building sandbox image..."
docker build -t opnagent-sandbox:latest "$ROOT/sandbox"
# The rebuilt image MUST reach the sandbox: drop the skip-recreate hash so
# the next launcher restart recreates (hermes data rides the automatic
# backup/restore through it).
mkdir -p "$ROOT/backups"
rm -f "$ROOT/backups/applied-spec.json"
echo "sandbox image rebuilt; launcher restart will recreate the sandbox"

# 5. Mirror config/listen.json into compose env. The launcher parses the
#    same file for validation (and refuses a non-loopback bind while
#    users.json is disabled); compose reads the host bind from here, so
#    after editing listen.json rerun this script, then
#    `docker compose -f deploy/docker-compose.yml up -d launcher`.
LISTEN_PAIR="$(python3 - "$ROOT/config/listen.json" <<'PY'
import json, re, sys
host, port = "127.0.0.1", "8000"
try:
    with open(sys.argv[1], encoding="utf-8") as fh:
        raw = json.load(fh)
except FileNotFoundError:
    raw = None
if raw is not None:
    value = str(raw.get("listen_url", "")).strip()
    for scheme in ("http://", "https://"):
        if value.lower().startswith(scheme):
            value = value[len(scheme):]
    m = re.fullmatch(r"(?:(\[[0-9A-Fa-f:.]+\])|([A-Za-z0-9.\-]+))(?::(\d{1,5}))?", value)
    if not m:
        sys.exit(f"{sys.argv[1]}: invalid listen_url {raw.get('listen_url')!r}")
    host = m.group(1) or m.group(2)
    port = m.group(3) or port
    if not 1 <= int(port) <= 65535:
        sys.exit(f"{sys.argv[1]}: port out of range")
print(host, port)
PY
)"
read -r OPN_LISTEN_HOST OPN_LISTEN_PORT <<<"$LISTEN_PAIR"
echo "web entry point bind: $OPN_LISTEN_HOST:$OPN_LISTEN_PORT (from config/listen.json)"

cat > .env <<EOF
OPENSHELL_SUPERVISOR_BIN=$SUPERVISOR_BIN
OPENSHELL_DOCKER_GID=$DOCKER_GID
OPENSHELL_IMAGE_TAG=$OPENSHELL_IMAGE_TAG
OPENSHELL_TLS_DIR=$TLS_DIR
OPN_LISTEN_HOST=$OPN_LISTEN_HOST
OPN_LISTEN_PORT=$OPN_LISTEN_PORT
EOF
echo "wrote $(pwd)/.env"

echo
echo "Next:"
echo "  1. edit $ROOT/config/*.json  (LLM keys, lists, users)"
echo "  2. docker compose -f deploy/docker-compose.yml up -d --build"
echo "  3. browse http://127.0.0.1:8000/status then the login page"
