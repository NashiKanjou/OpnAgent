#!/bin/bash
# OpnAgent sandbox entrypoint (runs as the sandbox main process under
# OpenShell). Starts one opn-shim per LLM_Porting_Map entry, then serves
# hermes-webui (nesquena) on loopback; OpenShell --expose publishes it.
#
# Config arrives via env (no secrets — real keys stay in the gateway):
#   OPN_SHIM_SPEC   base64(JSON array):
#     [{"listen":"127.0.0.1:18001","upstream":"https://api.openai.com/v1",
#       "inner_key":"fake-key-local-0","cred_env":"OPNL_0",
#       "model":"","context_length":0,"catalog_provider":"",
#       "provider":"OpnAgentAPI0"} ...]
#   (model/context_length/catalog_provider/provider feed the config.yaml
#   below; "provider" is the hermes-side provider name, default opn<N>)
#   OPN_DEFAULT_INDEX   which entry hermes uses by default (default 0)
#   HERMES_PORT         web UI port (default 9119)
set -euo pipefail

SHIM_DIR=/opt/opnagent/shim
HERMES_PORT="${HERMES_PORT:-9119}"
LOG_PREFIX="[opnagent]"

log() { echo "$LOG_PREFIX $*"; }

if [ -z "${OPN_SHIM_SPEC:-}" ]; then
  log "ERROR: OPN_SHIM_SPEC not set; launcher must pass the LLM map."
  exit 2
fi

export _SPEC="$(printf '%s' "$OPN_SHIM_SPEC" | base64 -d)"

# Start one shim per mapping entry; wait for each listen port.
mapfile -t LINES < <(python3 - <<'PY'
import json, os
for i, e in enumerate(json.loads(os.environ["_SPEC"])):
    print(f'{e["listen"]}\t{e["upstream"]}\t{e["inner_key"]}\t{e["cred_env"]}'
          f'\t{e.get("provider") or "opn"+str(i)}')
PY
)

i=0
for line in "${LINES[@]}"; do
  IFS=$'\t' read -r listen upstream inner_key cred_env pname <<<"$line"
  log "starting shim #$i: $listen -> $upstream (cred env: $cred_env, hermes provider: $pname)"
  # FAKE inner keys — the real ones live in the gateway. config.yaml below
  # inlines them per provider (the OPN_HERMES_KEY_<N> env stays as a
  # sandbox-side debugging convenience only).
  export "OPN_HERMES_KEY_$i=$inner_key"
  # hermes resolves a NAMED provider's key from <PROVIDER>_API_KEY once it
  # is no longer the default runtime — live deploy: switching to another
  # profile failed with "Provider 'opn0' is set in config.yaml but no API
  # key was found. Set the OPN0_API_KEY environment variable". The inlined
  # config.yaml api_key only answers the default path. Export the env
  # contract here AND mirror it into ~/.hermes/.env below: exporting alone
  # did NOT fix the switch even though webui is exec'd from this shell, so
  # the resolver evidently reads the dotenv file, not the inherited
  # process env (same channel webui uses to pick up API_SERVER_KEY).
  export "${pname^^}_API_KEY=$inner_key"
  python3 "$SHIM_DIR/shim.py" \
    --listen "$listen" --upstream "$upstream" \
    --inner-key "$inner_key" --cred-env "$cred_env" \
    >/tmp/opn-shim-$i.log 2>&1 &
  port="${listen##*:}"
  for _ in $(seq 1 30); do
    if python3 - "$port" <<'PY'
import socket, sys
s = socket.socket(); s.settimeout(0.4)
sys.exit(0 if s.connect_ex(("127.0.0.1", int(sys.argv[1]))) == 0 else 1)
PY
    then break; fi
    sleep 0.3
  done
  i=$((i+1))
done

# (No OPENAI_BASE_URL/OPENAI_API_KEY exports on purpose: those env names are
# the OPENAI provider's credential contract in both hermes' runtime resolver
# and hermes-webui's key management — using them made the shim URL and the
# fake key show up under the "openai" provider. The default mapping is bound
# through its named providers.<name> entry instead; see config.yaml below.)
log "hermes -> default mapping = providers entry #${OPN_DEFAULT_INDEX:-0} (named custom provider)"

# Pre-provision ~/.hermes/config.yaml so the web UI never has to run the
# interactive `hermes model` wizard: every LLM_Porting_Map entry becomes a
# named hermes provider pointed at its shim (fake key via key_env). Users
# switch/select models with the /model chat command; the endpoint wiring
# itself is managed here (this file is regenerated on every sandbox boot,
# so anything set via `hermes model` inside the sandbox does not survive).
mkdir -p "${HOME:-/home/opn}/.hermes"
# Loopback-only secret for the gateway's api_server platform (HTTP API +
# /health that hermes-webui's gateway pill probes). Regenerated per boot;
# the webui process learns it via API_SERVER_KEY (its documented fallback).
export API_SERVER_KEY="$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
if python3 - <<'PY'
import json, os, secrets
from urllib.parse import urlsplit

def s(v):                       # JSON string == valid YAML quoted scalar
    return json.dumps(str(v))

spec = json.loads(os.environ["_SPEC"])
di = int(os.environ.get("OPN_DEFAULT_INDEX", "0"))
d = spec[di]

def base(e):
    u = urlsplit(e["upstream"])
    return f"http://{e['listen']}{u.path.rstrip('/')}"

def pname(i, e):
    # Launcher names these (OpnAgentAPI<N>); the opn<N> fallback keeps an
    # old launcher spec working. Must match the <NAME>_API_KEY export in
    # the shim loop above — that env is how hermes finds a non-default
    # provider's key.
    return str(e.get("provider") or f"opn{i}")

def entry_lines(i, e):
    # Map "protocol":"anthropic" -> hermes' canonical Messages-transport
    # name (hermes_cli/config_providers.py _API_MODE_ALIASES maps
    # "anthropic"/"messages" to anthropic_messages; verified against the
    # pinned HERMES_REF source). The client then POSTs /v1/messages and
    # carries the FAKE key in x-api-key (hermes uses x-api-key for any
    # non-anthropic.com base_url) — opn-shim accepts it there too. Egress
    # is unchanged: Authorization: Bearer <placeholder>, which Anthropic
    # native and most relays also accept.
    proto = str(e.get("protocol") or "openai").strip().lower()
    transport = "anthropic_messages" if proto == "anthropic" \
        else "chat_completions"
    lines = [f"  {pname(i, e)}:",
             f"    api: {s(base(e))}",
             f"    api_key: {s(e['inner_key'])}",
             f"    transport: {transport}"]
    if e.get("model"):
        lines.append(f"    default_model: {s(e['model'])}")
        # EXPLICIT model list, not just the default: an entry without a
        # `models:` map makes the webui settings picker fall back to hermes'
        # built-in static catalog (gpt-5.1-codex et al. — models_catalog_
        # static.py), never the endpoint's real offering. Listing the map's
        # model pins the picker to what the operator actually configured.
        lines.append("    models:")
        lines.append(f"      {s(e['model'])}: {{}}")
    # Both are DOCUMENTED entry keys (hermes_cli/config_providers.py
    # _KNOWN_PROVIDER_KEYS): context_length answers step 0 of the context
    # resolution WITHOUT any network probe and, unlike model.context_length,
    # survives a /model switch to this provider; catalog_provider names the
    # catalogued vendor the endpoint resells so models.dev metadata lookups
    # work (metadata only, never routing).
    if e.get("context_length"):
        lines.append(f"    context_length: {int(e['context_length'])}")
    if e.get("catalog_provider"):
        lines.append(f"    catalog_provider: {s(e['catalog_provider'])}")
    return lines

# api_key is INLINED on purpose: these are the fake inner keys that only
# work against the matching 127.0.0.1 shim; real keys never enter the
# sandbox (the supervisor swaps the placeholder at egress). The default
# mapping binds through its NAMED provider (provider: <name>) rather than the
# bare "custom" class: bare custom + OPENAI_BASE_URL/OPENAI_API_KEY env
# made hermes/webui register the fake key and the shim URL under the
# "openai" provider (those env names are openai's credential contract).
# A named entry keeps key+endpoint under its own provider slug everywhere.
out = ["# generated by OpnAgent entrypoint from LLM_Porting_Map — do not edit",
       "model:",
       f"  provider: {s(pname(di, d))}",
       f"  base_url: {s(base(d))}",
       f"  api_key: {s(d['inner_key'])}"]
if d.get("model"):
    out.append(f"  model: {s(d['model'])}")
# model.context_length = hermes' documented override for the DEFAULT runtime
# (agent reads it before any probe; dropped when the runtime differs from the
# default, which is what the per-entry context_length below covers).
if d.get("context_length"):
    out.append(f"  context_length: {int(d['context_length'])}")
out.append("providers:")
for i, e in enumerate(spec):
    out += entry_lines(i, e)
# api_server platform: without it `gateway run` logs "No messaging platforms
# enabled" and serves no /health — the webui pill then says "Gateway endpoint
# not reachable" (hermes gateway/platforms/api_server.py: DEFAULT 127.0.0.1:
# 8642, host/port/key under platforms.api_server.extra, refuses to start with
# no key). Loopback-only inside the sandbox; only 9119 is exposed.
api_key = os.environ.get("API_SERVER_KEY") or secrets.token_hex(16)
out += ["platforms:",
        "  api_server:",
        "    enabled: true",
        "    gateway_restart_notification: false",
        "    extra:",
        "      host: 127.0.0.1",
        "      port: 8642",
        f"      key: {s(api_key)}"]
path = os.path.expanduser("~/.hermes/config.yaml")
with open(path, "w", encoding="utf-8") as fh:
    fh.write("\n".join(out) + "\n")
# .env carries the api_server secret PLUS one <NAME>_API_KEY line per named
# provider. Those env lines are the contract hermes uses to key a NAMED
# provider once it is not the default runtime — live deploy proved the
# process-env export alone does not reach the resolver (profile switch kept
# failing with "no API key was found. Set the OPNAGENTAPI0_API_KEY
# environment variable" even though webui is exec'd from this shell), while
# the dotenv channel demonstrably works (API_SERVER_KEY arrives this way).
# Values are the FAKE per-shim keys only. Still NO OPENAI_API_KEY /
# OPENAI_BASE_URL in here (or in process env): hermes-webui's key manager
# labels OPENAI_API_KEY as the openai provider's key, and hermes' runtime
# resolver treats a base_url matching OPENAI_BASE_URL as an openai route —
# both leaked our fake key / shim URL into the "openai" provider.
env_lines = [f"API_SERVER_KEY={api_key}"]
for i, e in enumerate(spec):
    env_lines.append(f"{pname(i, e).upper()}_API_KEY={e['inner_key']}")
with open(os.path.expanduser("~/.hermes/.env"), "w", encoding="utf-8") as fh:
    fh.write("\n".join(env_lines) + "\n")
print(f"[opnagent] wrote {path} + .env ({len(spec)} provider(s))")
PY
then :; else log "WARN: could not write ~/.hermes/config.yaml; hermes may ask for 'hermes model'"; fi

# hermes >=0.21 resolves its frontends from env-var overrides:
# HERMES_WEB_DIST (dashboard SPA) and HERMES_TUI_DIR (prebuilt chat TUI
# bundle; _make_tui_argv then takes the node --expose-gc fast path and
# never tries an npm install/download). The image ENVs already point at
# the trees baked by the Dockerfile, but re-export defensively —
# OpenShell does override image ENVs (HOME is the proof).
export HERMES_WEB_DIST="${HERMES_WEB_DIST:-/opt/hermes/hermes_cli/web_dist}"
export HERMES_TUI_DIR="${HERMES_TUI_DIR:-/opt/hermes/ui-tui}"

cd "${HOME:-/home/opn}"
mkdir -p "${HOME:-/home/opn}/workspace"

# Gateway daemon: scheduled cron ticks are driven by the gateway (every 60s),
# NOT by hermes-webui itself (docs/docker.md "Scheduled jobs and the gateway
# daemon") — without it the Tasks panel's jobs never fire ("Run now" works
# because webui runs those in-process). Same command their two-container
# agent service uses (`command: gateway run` on the hermes CLI entrypoint).
# Background child of the webui main process => dies with the sandbox.
# gateway_state.json under ~/.hermes is what webui reads for the pill;
# HERMES_API_URL lets its health probe hit the loopback API.
# The while-kill-loop is deliberate: live deploy caught the gateway taking
# SIGTERM ~5 min in (hermes self-restarts on config.yaml churn expecting a
# systemd-style relaunch; the sandbox reparents orphans to PID 1 = the
# supervisor, which does not respawn). The loop respawns it in 5s — cron
# ticks are 60s apart, so a brief gap is invisible.
( while :; do
    hermes gateway run >>/tmp/opn-gateway.log 2>&1
    echo "[opnagent] gateway exited rc=$?; restarting in 5s" >>/tmp/opn-gateway.log
    sleep 5
  done & )
export HERMES_API_URL="http://127.0.0.1:8642"
log "gateway daemon launching (cron ticker + api_server :8642); log: /tmp/opn-gateway.log"

# Primary web UI: hermes-webui (nesquena) — baked at /opt/hermes-webui by
# the Dockerfile (pure Python, no build step). It runs the hermes agent
# IN-PROCESS reading the ~/.hermes/config.yaml generated above, so the
# shim/fake-key provider wiring is unchanged; /model switches among the
# generated providers. Deps (pyyaml, cryptography) were pip-installed
# into /opt/hermes-venv at image build time — no runtime pip install
# (AUTO_INSTALL stays off; pypi policy untouched).
WEBUI_DIR=/opt/hermes-webui
if [ -f "$WEBUI_DIR/server.py" ]; then
  export HERMES_WEBUI_HOST=127.0.0.1
  export HERMES_WEBUI_PORT="$HERMES_PORT"
  export HERMES_WEBUI_AGENT_DIR=/opt/hermes
  # /opt/hermes is policy read-only — point relative fallback writes here:
  export HERMES_WEBUI_SERVER_CWD="${HOME:-/home/opn}/workspace"
  export HERMES_WEBUI_STATE_DIR="${HOME:-/home/opn}/.hermes/webui"
  export HERMES_WEBUI_DEFAULT_WORKSPACE="${HOME:-/home/opn}/workspace"
  # The launcher rewrites Host to the gateway vhost (that is how OpenShell
  # service routing works), which would trip webui's CSRF Origin-vs-Host
  # check on every browser POST; it forwards the browser's real authority
  # in X-Forwarded-Host, which this flag makes webui accept alongside Host.
  export HERMES_WEBUI_TRUST_FORWARDED_HOST=1
  # No HERMES_WEBUI_PASSWORD: the launcher's users.json login fronts this,
  # and the server only ever binds loopback inside the sandbox.
  log "serving hermes-webui on 127.0.0.1:$HERMES_PORT"
  exec /opt/hermes-venv/bin/python "$WEBUI_DIR/server.py"
fi

# Fallbacks (only reached on an image without hermes-webui baked in):
# the old built-in dashboard, then headless serve.
log "WARN: $WEBUI_DIR/server.py not found; falling back to built-in UI"
if [ -f "$HERMES_WEB_DIST/index.html" ]; then
  DASH_ARGS=(dashboard --host 127.0.0.1 --port "$HERMES_PORT")
  # --skip-build was the 0.19 flag name; 0.21 speaks of "--build-mode
  # skip" instead. Only pass what this hermes actually accepts — the
  # dists are prebuilt either way, the flag just suppresses auto-build
  # attempts (which would hit the policy-read-only checkout).
  if hermes dashboard --help 2>/dev/null | grep -q -- '--skip-build'; then
    DASH_ARGS+=(--skip-build)
  fi
  log "serving hermes dashboard (built-in web UI) on 127.0.0.1:$HERMES_PORT"
  exec hermes "${DASH_ARGS[@]}"
else
  log "web UI dist not found; serving headless gateway on 127.0.0.1:$HERMES_PORT"
  exec hermes serve --host 127.0.0.1 --port "$HERMES_PORT"
fi
