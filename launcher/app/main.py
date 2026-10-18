"""OpnAgent launcher: reads the JSON config set, drives the OpenShell CLI to
create the hermes sandbox, and serves the users.json-gated web entry point.

Runs as its own compose service; talks to the gateway container over the
compose network (TLS-less gRPC is fine there — see README before exposing
anything beyond 127.0.0.1).
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import re
import shutil
import tempfile
import time
import urllib.parse

from datetime import datetime, timezone

from fastapi import (BackgroundTasks, FastAPI, File, Form, HTTPException,
                     Request, UploadFile, WebSocket)
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from . import adminui, auth, hermesfs
from .config import (ConfigError, OpnConfig, UserEntry, _config_dir,
                     F_USERS, load_config)
from .policy import policy_yaml
from .proxy import Reverse
from .providers import hermes_provider_name, profile_yaml, provider_name
from .reload import guard_fingerprint, merge_network

log = logging.getLogger("opnagent")
logging.basicConfig(level=logging.INFO, format="[opnagent] %(message)s")

GATEWAY_URL = os.environ.get("OPN_GATEWAY_URL", "http://gateway:8080")
SANDBOX_NAME = os.environ.get("OPN_SANDBOX_NAME", "opnagent")
SANDBOX_IMAGE = os.environ.get("OPN_SANDBOX_IMAGE", "opnagent-sandbox:latest")
HERMES_PORT = int(os.environ.get("OPN_HERMES_PORT", "9119"))

# --- sandbox-rebuild hermes backup/restore ---------------------------------
# bootstrap() must recreate the sandbox whenever the baked-at-create spec
# changes (OPN_SHIM_SPEC is a create-time env), and `sandbox delete` purges
# the compute AND its workspace — hermes chat history and user files die
# with it. So recreate_sandbox zips the persistent home dirs out over the
# exec channel BEFORE delete and pushes them back after the new sandbox is
# up (same channel the /admin file manager trusts; sandbox upload/download
# are dead — see hermesfs). Staging is the launcher's own /backups bind
# (compose: ../backups:/backups; bootstrap.sh mkdir's it).
BACKUP_DIR = os.environ.get("OPN_BACKUP_DIR", "/backups")
BACKUP_MAX_BYTES = int(os.environ.get("OPN_BACKUP_MAX_BYTES",
                                      str(400 * 1024 * 1024)))
BACKUP_SETS_KEPT = int(os.environ.get("OPN_BACKUP_SETS_KEPT", "5"))
BACKUP_DIRS = (".hermes", "workspace")
# Regenerable trees kept OUT of the backup zip (fnmatch globs, relative to
# each BACKUP_DIRS entry): the live profile cache is the size bomb — one
# real deploy measured 2.0 GB of tool downloads + scratch under
# .hermes/profiles/<p>/cache, versus ~900 MB of real data (SDKs in
# profiles/*/home count as data — re-downloading toolchains over a slow
# link is not "regenerable" in practice). Matched against the entry path
# relative to the zipped dir, a directory match prunes the whole subtree.
# OPN_BACKUP_EXCLUDE (JSON, same shape) overrides for special deployments.
_DEFAULT_BACKUP_EXCLUDE = {
    ".hermes": ["cache", "profiles/*/cache", "profiles/*/home/.cache"],
}
try:
    BACKUP_EXCLUDE = json.loads(
        os.environ.get("OPN_BACKUP_EXCLUDE") or "null") \
        or _DEFAULT_BACKUP_EXCLUDE
except json.JSONDecodeError as exc:
    log.error("OPN_BACKUP_EXCLUDE 不是合法 JSON(%s),改用預設值", exc)
    BACKUP_EXCLUDE = _DEFAULT_BACKUP_EXCLUDE
# Entrypoint-owned files: regenerated on EVERY boot (~/.hermes/.env carries
# the per-boot random API_SERVER_KEY, config.yaml the generated provider
# wiring, gateway_state.json the gateway's live state). Restoring stale
# copies would desync webui/gateway — never clobber them.
RESTORE_SKIP = {".hermes": [".hermes/config.yaml", ".hermes/.env",
                            ".hermes/gateway_state.json"]}

# openapi_url=None too: otherwise the built-in /openapi.json route shadows
# a same-named hermes API behind the catch-all proxy.
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
# fingerprint: guard_fingerprint() of the running config, so /admin/reload
# can reject reloads that also carry restart-required changes.
state: dict = {"cfg": None, "reverse": None, "ready": False, "error": None,
               "fingerprint": None, "last_reload": None,
               # last recreate's hermes backup/restore outcome
               # ({"ok":bool,"set":name,"error"?}) — surfaced on /status
               "hermes_restore": None,
               "reload_lock": asyncio.Lock(),
               # phase/since: what apply_list_reload is doing right now
               # (GET /admin/reload/status surfaces them, so the web
               # console can tell "slow" apart from "wedged")
               "reload_phase": None, "reload_since": None}


# --------------------------------------------------------------------------
# OpenShell CLI helpers
# --------------------------------------------------------------------------

async def run_cli(*args: str, env: dict | None = None, timeout: int = 120,
                  stdin: bytes | None = None):
    proc = await asyncio.create_subprocess_exec(
        "openshell", *args,
        stdin=asyncio.subprocess.PIPE if stdin is not None
        else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        env={**os.environ, **(env or {})})
    try:
        out, err = await asyncio.wait_for(proc.communicate(stdin), timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return 124, "", b"timeout"
    return proc.returncode or 0, out.decode(errors="replace"), err.decode(errors="replace")


def _write_tmp(name: str, content: str) -> str:
    path = os.path.join(tempfile.mkdtemp(prefix="opn-"), name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


def _service_target(url: str) -> tuple[str, str]:
    """Split the CLI-printed service URL into (connect-origin, vhost Host).

    The CLI prints a vhost URL like
    `http://default--opnagent.openshell.localhost:8080/`: the gateway routes
    on the HOST HEADER, and `*.openshell.localhost` is not resolvable from
    the compose net (and `*.localhost` would mean loopback anyway), so we
    dial GATEWAY_URL and pin Host to the printed authority instead.
    """
    m = re.match(r"(https?)://([^/]+)", url)
    if not m:
        raise RuntimeError(f"unparseable service URL: {url!r}")
    authority = m.group(2)
    gw = re.match(r"(https?)://([^/]+)", GATEWAY_URL)
    return f"{gw.group(1)}://{gw.group(2)}", authority


# --------------------------------------------------------------------------
# Bootstrap orchestration
# --------------------------------------------------------------------------

async def wait_gateway() -> None:
    # --local only: the CLI's --remote flag now takes a value (docs example
    # is stale), and locality was never the discriminator for sandbox
    # create anyway — the JWT keys in gateway.toml are.
    rc, out, err = await run_cli("gateway", "add", GATEWAY_URL,
                                 "--name", "opnagent-gw", "--local")
    if rc != 0 and "exist" not in (err + out).lower():
        log.warning("gateway add failed (may already be registered): %s",
                    err.strip()[:300])
    for i in range(60):
        # Short per-call timeout: while the gateway restarts, each status
        # probe should fail fast and LOUDLY (every ~5 tries) — a silent
        # 120 s hang here made deploy debugging impossible once already.
        rc, _, _ = await run_cli("status", timeout=15)
        if rc == 0:
            log.info("gateway reachable")
            return
        if i % 5 == 4:
            log.info("waiting for gateway... (try %d, last rc=%d)", i + 1, rc)
        await asyncio.sleep(2)
    raise RuntimeError("gateway not reachable")


async def ensure_providers(cfg: OpnConfig) -> None:
    for e in cfg.llm_map:
        from .providers import profile_id
        path = _write_tmp(f"profile-{e.index}.yaml", profile_yaml(e))
        rc, _, err = await run_cli("profile", "lint", "-f", path)
        # lint also validates id-vs-existing; re-runs must tolerate it
        # exactly like the import below (state DB persists across deploys).
        if rc != 0 and "already exists" not in (err + "").lower():
            raise RuntimeError(f"profile lint failed #{e.index}: {err[:500]}")
        rc, _, err = await run_cli("profile", "import", "-f", path)
        if rc != 0 and "exists" not in err.lower():
            raise RuntimeError(f"profile import failed #{e.index}: {err[:500]}")
        # --from-existing reads the credential from the CLI process env,
        # keeping the real key out of argv/`ps`.
        rc, _, err = await run_cli(
            "provider", "create", "--name", provider_name(e),
            "--type", profile_id(e), "--from-existing",
            env={e.cred_env: e.key})
        if rc != 0 and "exists" not in err.lower():
            raise RuntimeError(f"provider create failed #{e.index}: {err[:500]}")
        log.info("provider ready: %s -> %s", provider_name(e), e.url)


def _shim_spec(cfg: OpnConfig) -> list[dict]:
    """The OPN_SHIM_SPEC array baked into the sandbox at create (also the
    hash input for skip-recreate — keep it deterministic)."""
    return [{
        "listen": f"127.0.0.1:{e.inner_port}",
        "upstream": e.url,
        "inner_key": e.inner_key,
        "cred_env": e.cred_env,
        # written into ~/.hermes/config.yaml by the sandbox entrypoint
        "model": e.model,
        "context_length": e.context_length,
        "catalog_provider": e.catalog_provider,
        # hermes-side provider name (webui picker); the entrypoint also
        # exports <NAME>_API_KEY so non-default profiles can find the key
        "provider": hermes_provider_name(e),
        # "anthropic" -> entrypoint writes transport: anthropic_messages
        "protocol": e.protocol,
    } for e in cfg.llm_map]


def sandbox_spec_hash(cfg: OpnConfig) -> str:
    """sha256 over everything `sandbox create` bakes: image, shim spec,
    provider set, policy document, exposed port. Identical hash + a
    running sandbox => recreate can be skipped, hermes data untouched.

    The profile DOCUMENTS are hashed too: they are gateway-side state
    attached at create (endpoints + binaries binding), and recreate now
    regenerates them (_regenerate_providers) — hashing their content is
    what makes a generator/config change invalidate the skip-recreate.
    profile_yaml carries no real key (only OPNL_<i> placeholder env
    names), so this adds no secret to the payload.

    The real API keys stay EXCLUDED deliberately: a key edit rotates a
    credential in the gateway store (applied by recreate when it
    happens), it does not change the sandbox's contract with hermes."""
    payload = json.dumps({
        "image": SANDBOX_IMAGE,
        "hermes_port": HERMES_PORT,
        "spec": _shim_spec(cfg),
        "policy": policy_yaml(cfg),
        "providers": [provider_name(e) for e in cfg.llm_map],
        "profiles": [profile_yaml(e) for e in cfg.llm_map],
    }, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()


def _applied_hash() -> str:
    """Hash of the spec the CURRENT sandbox was created from ('' = unknown).
    Lives on the /backups bind so it survives launcher restarts — which is
    the whole point (a restart without a spec change must not recreate)."""
    try:
        with open(os.path.join(BACKUP_DIR, "applied-spec.json"),
                  encoding="utf-8") as fh:
            return str(json.load(fh).get("hash") or "")
    except (OSError, ValueError):
        return ""


def _save_applied_hash(h: str) -> None:
    try:
        os.makedirs(BACKUP_DIR, exist_ok=True)
        with open(os.path.join(BACKUP_DIR, "applied-spec.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"hash": h, "sandbox": SANDBOX_NAME,
                       "time": datetime.now(timezone.utc).isoformat(
                           timespec="seconds")}, fh)
    except OSError as exc:
        # Not fatal — the price is an unnecessary recreate on next restart.
        log.warning("無法寫入 %s/applied-spec.json (%s):下次重啟會多重建一次",
                    BACKUP_DIR, exc)


async def _sandbox_phase() -> str:
    rc, out, _ = await run_cli("sandbox", "get", SANDBOX_NAME, "-o", "json")
    if rc != 0:
        return ""
    try:
        return str(json.loads(out).get("phase", "")).lower()
    except (json.JSONDecodeError, AttributeError):
        return ""


async def _expose_url() -> str:
    """(Re-)assert the exposed port and return its URL. `service expose`
    is an idempotent update and the only place the CLI prints the URL
    (`--detach` create swallows its own output)."""
    rc, out, err = await run_cli("service", "expose",
                                 SANDBOX_NAME, str(HERMES_PORT))
    m = re.search(r"URL:\s*(\S+)", out + "\n" + err)
    if rc != 0 or not m:
        raise RuntimeError(f"service expose failed (rc={rc}): {(err or out)[:500]}")
    return m.group(1)


async def backup_hermes_data() -> str | None:
    """Zip BACKUP_DIRS out of the sandbox home BEFORE the delete.
    Returns the backup-set dir, or None when there is nothing to save
    (no running sandbox / dirs absent). ANY failure while the sandbox
    still exists raises — the caller must then abort the recreate,
    leaving the old sandbox (and its data) intact. Fail-closed: never
    delete what we could not copy out."""
    phase = await _sandbox_phase()
    if phase not in ("running", "ready"):
        if phase:
            log.warning("sandbox phase=%s — 無法 exec 備份;重建將遺失 "
                        "hermes 資料(可先在 /admin 手動匯出)", phase)
        return None
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    set_dir = os.path.join(BACKUP_DIR, f"{SANDBOX_NAME}-{stamp}")
    saved: dict[str, int] = {}
    for d in BACKUP_DIRS:
        script = hermesfs.script_zip_dir(hermesfs.normalize_rel(d), stamp,
                                         BACKUP_MAX_BYTES,
                                         exclude=BACKUP_EXCLUDE.get(d))
        try:
            # deflate of a ~1 GB tree on a VM can pass 180 s; the channel
            # is idempotent here (stale sweep reclaims an orphaned zip).
            res = await _exec_retry(script, tries=3, timeout=600)
        except HTTPException as exc:
            raise RuntimeError(f"hermes 備份失敗({d}):{exc.detail}") from exc
        if res.get("error"):
            if "這不是資料夾" in res["error"]:
                continue                      # absent dir = nothing to save
            raise RuntimeError(f"hermes 備份失敗({d}):{res['error']}")
        data = await _hermes_fetch_bytes(res["zip"], max_bytes=BACKUP_MAX_BYTES)
        os.makedirs(set_dir, exist_ok=True)
        with open(os.path.join(set_dir, f"{d}.zip"), "wb") as fh:
            fh.write(data)
        saved[d] = len(data)
        log.info("hermes backup: %s -> %s (%d bytes)", d, set_dir, len(data))
        try:                                  # tidy the in-sandbox zip
            await _exec_retry(hermesfs.script_delete(res["zip"]))
        except HTTPException:
            pass                              # delete sweeps it anyway
    if not saved:
        return None
    with open(os.path.join(set_dir, "meta.json"), "w",
              encoding="utf-8") as fh:
        json.dump({"stamp": stamp, "dirs": saved,
                   "time": datetime.now(timezone.utc).isoformat(
                       timespec="seconds")}, fh)
    _prune_backup_sets()
    return set_dir


def _prune_backup_sets() -> None:
    """Keep the newest BACKUP_SETS_KEPT sets; names sort chronologically
    ('<sandbox>-YYYYmmdd-HHMMSS'). Only OUR sets are touched."""
    try:
        names = sorted(n for n in os.listdir(BACKUP_DIR)
                       if n.startswith(SANDBOX_NAME + "-")
                       and os.path.isdir(os.path.join(BACKUP_DIR, n)))
    except OSError:
        return
    for n in names[:-BACKUP_SETS_KEPT] if len(names) > BACKUP_SETS_KEPT else []:
        shutil.rmtree(os.path.join(BACKUP_DIR, n), ignore_errors=True)
        log.info("trimmed old hermes backup set %s", n)


async def restore_hermes_data(set_dir: str) -> None:
    """Push the backup zips back into the fresh sandbox home, AFTER the
    entrypoint generated its own config (restore order: entrypoint-owned
    files are in RESTORE_SKIP, everything else lands as it was). Raises
    RuntimeError on any trouble — the set stays on disk for a manual
    retry; bootstrap records the failure instead of dying (the sandbox
    already exists at this point, there is nothing to abort back to)."""
    with open(os.path.join(set_dir, "meta.json"), encoding="utf-8") as fh:
        meta = json.load(fh)
    for d, size in (meta.get("dirs") or {}).items():
        src = os.path.join(set_dir, f"{d}.zip")
        if not os.path.isfile(src) or os.path.getsize(src) != size:
            raise RuntimeError(f"備份遺失/破損:{src}")
        with open(src, "rb") as fh:
            data = fh.read()
        rel_tmp = (f"{hermesfs.UPLOADS_DIR}/opn-restore-"
                   f"{meta.get('stamp', 'x')}-{d.replace('/', '_')}.zip")
        await _sandbox_put_bytes(data, rel_tmp)
        res = await _exec_retry(
            hermesfs.script_unzip(rel_tmp, RESTORE_SKIP.get(d, []),
                                  BACKUP_MAX_BYTES * 8),
            tries=3, timeout=300)
        if res.get("error"):
            raise RuntimeError(f"hermes 還原失敗({d}):{res['error']}")
        log.info("hermes restore: %s (%s files)", d, res.get("n"))
        try:
            await _exec_retry(hermesfs.script_delete(rel_tmp))
        except HTTPException:
            pass


async def _regenerate_providers(cfg: OpnConfig) -> None:
    """Full delete+rebuild of every profile+provider from config/code.

    ensure_providers() is deliberately idempotent (skips existing), which
    pins the gateway-side profile document — endpoint rules AND the
    binaries binding — to whatever the FIRST-EVER `profile import` left:
    the gateway state DB outlives sandbox recreates, so the
    python3.12 -> python3.14 binaries fix never reached live deploys
    (LLM egress kept failing [Errno 13] with a correct base policy).
    Call this where breaking the live attach is safe — right after
    `sandbox delete`. Real keys are re-fed from config through the
    process env (--from-existing), never argv, so the churn costs no
    secrets; a config entry missing its key then fails LOUD (raise),
    because unlike ensure_providers the old provider is already gone."""
    from .providers import profile_id
    for e in cfg.llm_map:
        # Tolerated failures: "not found" is the normal fresh case; a
        # refused delete (still attached somewhere) resurfaces as the
        # import-skip warning below.
        await run_cli("provider", "delete", provider_name(e))
        await run_cli("profile", "delete", profile_id(e))
        path = _write_tmp(f"profile-{e.index}.yaml", profile_yaml(e))
        rc, _, err = await run_cli("profile", "lint", "-f", path)
        if rc != 0:
            raise RuntimeError(f"profile lint failed #{e.index}: {(err or '')[:500]}")
        rc, _, err = await run_cli("profile", "import", "-f", path)
        if rc != 0 and "exists" not in (err or "").lower():
            raise RuntimeError(f"profile import failed #{e.index}: {(err or '')[:500]}")
        if rc != 0:
            log.warning("profile #%s delete was refused/ignored — recreate "
                        "re-attaches the OLD document; check `openshell "
                        "profile get %s` binaries", e.index, profile_id(e))
        rc, _, err = await run_cli(
            "provider", "create", "--name", provider_name(e),
            "--type", profile_id(e), "--from-existing",
            env={e.cred_env: e.key})
        if rc != 0:
            raise RuntimeError(
                f"provider create failed #{e.index}: {(err or '')[:500]} — the "
                "old provider was deleted; fix config and restart the "
                "launcher (ensure_providers will recreate it)")
        log.info("provider regenerated: %s -> %s", provider_name(e), e.url)


async def recreate_sandbox(cfg: OpnConfig) -> str:
    # Backup FIRST: raises out of here (fail-closed) leave the running
    # sandbox untouched — data loss must never ride on a half-done update.
    set_dir = await backup_hermes_data()
    await run_cli("sandbox", "delete", SANDBOX_NAME)  # idempotent
    # Providers/profiles are config-derived documents; regenerate them
    # now that the sandbox (the only live attach) is gone, so code-level
    # changes to profile_yaml actually reach the gateway state DB.
    await _regenerate_providers(cfg)

    spec = _shim_spec(cfg)
    spec_b64 = base64.b64encode(
        json.dumps(spec).encode()).decode()

    policy_path = _write_tmp("policy.yaml", policy_yaml(cfg))
    args = ["sandbox", "create", "--name", SANDBOX_NAME, "--detach",
            "--from", SANDBOX_IMAGE, "--policy", policy_path,
            "--expose", str(HERMES_PORT),
            "--env", f"OPN_SHIM_SPEC={spec_b64}"]
    for e in cfg.llm_map:
        args += ["--provider", provider_name(e)]
    args += ["--", "/opt/opnagent/entrypoint.sh"]

    rc, out, err = await run_cli(*args, timeout=300)
    if rc != 0:
        raise RuntimeError(f"sandbox create failed: {err[:800] or out[:800]}")
    log.info("sandbox created; waiting for Running")

    # `sandbox get -o json` carries phase + conditions but NO service URL —
    # the CLI only ever prints that in create's own stdout at Ready time,
    # which --detach swallows. So: wait on `phase`, fail fast on `error`
    # (surfacing the condition message), then re-run `service expose` for
    # the printed URL (idempotent update, prints `URL: ...`).
    last_raw, phase = "", ""
    for _ in range(150):  # up to ~5 min
        rc, out, _ = await run_cli("sandbox", "get", SANDBOX_NAME, "-o", "json")
        last_raw = out
        if rc == 0:
            try:
                data = json.loads(out)
            except json.JSONDecodeError:
                data = None
            if data:
                phase = str(data.get("phase", "")).lower()
                if phase in ("running", "ready"):
                    break
                if phase == "error":
                    msgs = [f"{c.get('reason')}: {c.get('message')}"
                            for c in data.get("conditions") or []
                            if str(c.get("status")).lower() == "false"]
                    raise RuntimeError(
                        "sandbox entered error phase: "
                        + ("; ".join(msgs) or last_raw[:800]))
        await asyncio.sleep(2)
    if phase not in ("running", "ready"):
        raise RuntimeError(f"sandbox not Running in time; last get output: {last_raw[:600]}")

    # Restore INSIDE the recreate window: the user reaches the web entry
    # point only after state["ready"], so sessions/files land before anyone
    # can start a chat against the empty sandbox. A failure here does NOT
    # abort — the sandbox exists already; keep the set for a manual retry
    # and surface it on /status + logs.
    state["hermes_restore"] = None
    if set_dir:
        try:
            await restore_hermes_data(set_dir)
            state["hermes_restore"] = {"ok": True,
                                       "set": os.path.basename(set_dir)}
        except (RuntimeError, HTTPException) as exc:
            state["hermes_restore"] = {"ok": False,
                                       "set": os.path.basename(set_dir),
                                       "error": str(getattr(exc, "detail", exc))[:400]}
            log.error("hermes 資料還原失敗:%s — 備份保留於 %s,可人工復原",
                      exc, set_dir)

    url = await _expose_url()
    log.info("service URL: %s", url)
    return url


async def bootstrap() -> None:
    cfg = load_config()
    state["cfg"] = cfg
    state["fingerprint"] = guard_fingerprint(cfg)
    for w in cfg.warnings:
        log.warning(w)
    await wait_gateway()
    await ensure_providers(cfg)
    # Skip-recreate: the sandbox is create-immutable (OPN_SHIM_SPEC is a
    # create-time env), but MANY restarts carry no spec change — launcher
    # code updates, compose up, restarts after a lists hot-reload. If the
    # running sandbox was created from exactly this spec, leave it alone:
    # no delete, no backup, no hermes-data window at all.
    desired = sandbox_spec_hash(cfg)
    if (_applied_hash() == desired
            and await _sandbox_phase() in ("running", "ready")):
        log.info("sandbox spec unchanged and running — 跳過重建,"
                 "hermes 資料原地保留")
        service_url = await _expose_url()
    else:
        service_url = await recreate_sandbox(cfg)
    _save_applied_hash(desired)
    origin, vhost = _service_target(service_url)
    state["reverse"] = Reverse(origin, vhost)
    state["ready"] = True
    log.info("web entry point ready -> %s (dial %s, Host: %s)",
             service_url, origin, vhost)


@app.on_event("startup")
async def _startup() -> None:
    # Background, not awaited: sandbox creation can take minutes and
    # uvicorn would refuse ALL connections (including /status) until the
    # startup event returns. /status + 503 pages report progress instead.
    asyncio.create_task(_boot_task())


async def _boot_task() -> None:
    try:
        await bootstrap()
    except (ConfigError, RuntimeError) as exc:
        state["error"] = str(exc)
        log.error("bootstrap failed: %s", exc)
    except Exception as exc:  # noqa: BLE001 — keep /status informative
        state["error"] = f"{type(exc).__name__}: {exc}"
        log.exception("bootstrap crashed")


# --------------------------------------------------------------------------
# Web console (/admin*) — admin-role only, declared before the catch-all
# so they win routing against it
# --------------------------------------------------------------------------

def _lists_summary(cfg: OpnConfig) -> dict:
    def one(nl) -> dict:
        return {"enabled": nl.enabled, "count": len(nl.items)}
    return {"url_whitelist": one(cfg.url_wl), "url_blacklist": one(cfg.url_bl),
            "pkg_whitelist": one(cfg.pkg_wl), "pkg_blacklist": one(cfg.pkg_bl)}


async def apply_list_reload() -> dict:
    """Re-read the config and hot-swap network_policies on the sandbox.

    Raises RuntimeError (with an operator-actionable message) on any
    rejection; on success updates state["cfg"]/fingerprint/last_reload
    and returns the list summary. Publishes reload_phase/since while
    running — the two CLI calls can each burn their full 120 s timeout,
    and the console needs to tell slow from wedged."""
    state["reload_since"] = time.monotonic()
    try:
        state["reload_phase"] = "重讀設定檔"
        try:
            cfg2 = load_config()
        except ConfigError as exc:
            raise RuntimeError(f"config invalid, current policy untouched: {exc}")
        if guard_fingerprint(cfg2) != state["fingerprint"]:
            raise RuntimeError("LLM_Porting_Map / users / listen changed: those "
                               "feed providers, the shim and the host bind, not "
                               "just the sandbox policy — rerun "
                               "`docker compose restart launcher` instead")
        state["reload_phase"] = "policy get --base(上限 120s)"
        rc, out, err = await run_cli("policy", "get", SANDBOX_NAME,
                                     "--base", "--output", "json")
        if rc != 0:
            raise RuntimeError(f"policy get failed, current policy untouched: "
                               f"{(err or out)[:500]}")
        try:
            base = json.loads(out)["policy"]
        except (json.JSONDecodeError, TypeError, KeyError) as exc:
            raise RuntimeError(f"unparseable policy get output ({exc}): "
                               f"{out[:300]}")
        # Keep the untouched base on disk: if the sandbox rejects the new
        # revision while the gateway runs fail_closed, traffic stays blocked
        # until SOME valid policy loads — this file is the one to resubmit.
        backup = _write_tmp("base-policy-backup.json", json.dumps(base))
        merged = _write_tmp("base-policy.json", json.dumps(merge_network(base, cfg2)))
        state["reload_phase"] = "policy set --wait(上限 120s)"
        rc, out, err = await run_cli("policy", "set", SANDBOX_NAME,
                                     "--policy", merged, "--wait", timeout=120)
        if rc != 0:
            raise RuntimeError(
                f"policy set failed (rc={rc}): {(err or out)[:500]} — if the "
                f"sandbox is now blocking traffic (fail_closed), restore in the "
                f"launcher container: openshell policy set {SANDBOX_NAME} "
                f"--policy {backup} --wait")
        state["cfg"] = cfg2
        state["fingerprint"] = guard_fingerprint(cfg2)
        # The live sandbox now carries the reloaded policy too: refresh the
        # stored spec hash so the next restart does not "helpfully" recreate
        # for a difference this reload already applied.
        _save_applied_hash(sandbox_spec_hash(cfg2))
        summary = _lists_summary(cfg2)
        state["last_reload"] = {"time": datetime.now(timezone.utc).isoformat(
                                timespec="seconds"),
                                "lists": summary, "warnings": cfg2.warnings}
        log.info("lists hot-reloaded: %s", summary)
        return summary
    finally:
        state["reload_phase"] = None
        state["reload_since"] = None


@app.get("/admin/reload/status")
async def admin_reload_status(request: Request) -> dict:
    """What a reload is doing right now (the console polls this while a
    save-and-apply is in flight; busy=false means nothing is running)."""
    _admin_gate(request)
    busy = state["reload_lock"].locked()
    since = state["reload_since"]
    return {"busy": busy,
            "phase": state["reload_phase"] if busy else None,
            "elapsed_s": round(time.monotonic() - since, 1)
                        if busy and since is not None else None}


def _admin_gate(request: Request) -> None:
    if not _admin_ok(request):
        raise HTTPException(403, "admin only")


async def _json_body(request: Request) -> dict:
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "expected a JSON object body")
    if not isinstance(body, dict):
        raise HTTPException(400, "expected a JSON object body")
    return body


def _cfg_ready() -> OpnConfig:
    cfg = state["cfg"]
    if cfg is None:
        raise HTTPException(503, "OpnAgent is not ready yet")
    return cfg


@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request) -> Response:
    if not _admin_ok(request):
        # signed-in plain user -> hermes; anonymous -> the login gate
        if _session_user(request) is not None:
            return RedirectResponse("/", status_code=302)
        if state["cfg"] is not None and state["cfg"].users_enabled:
            return RedirectResponse("/login", status_code=302)
        raise HTTPException(403, "admin only")
    return HTMLResponse(adminui.ADMIN_HTML)


@app.post("/admin/reload")
async def admin_reload(request: Request) -> dict:
    _admin_gate(request)
    if not state["ready"]:
        raise HTTPException(503, "OpnAgent is not ready yet")
    if state["reload_lock"].locked():
        raise HTTPException(409, "a reload is already running")
    async with state["reload_lock"]:
        try:
            summary = await apply_list_reload()
        except (RuntimeError, OSError) as exc:
            raise HTTPException(400, str(exc))
    summary["note"] = ("new rules loaded; connections opened under the old "
                       "rules (keep-alive, WebSocket, LLM streams) were "
                       "closed — clients reconnect on the next request")
    return summary


# --- list JSON editor -------------------------------------------------------

@app.get("/admin/lists")
async def admin_lists(request: Request) -> dict:
    _admin_gate(request)
    out = {}
    for name in adminui.LIST_FILES:
        try:
            with open(os.path.join(_config_dir(), name), "r",
                      encoding="utf-8") as fh:
                out[name] = fh.read()
        except FileNotFoundError:
            # absent == disabled; give the editor a valid starting point
            out[name] = json.dumps({"enabled": False, "list": []}, indent=2)
    return out


@app.post("/admin/lists")
async def admin_list_save(request: Request) -> dict:
    """Validate -> atomic write -> hot-apply. A validation failure leaves
    the file untouched (400); a failed APPLY still returns 200 with the
    file saved and the reason, so the edit survives and the operator can
    fix the config and press plain reload."""
    _admin_gate(request)
    body = await _json_body(request)
    name = str(body.get("name") or "")
    content = str(body.get("content") or "")
    try:
        adminui.validate_list_text(name, content)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    # name is one of LIST_FILES (validate_list_text rejects anything else)
    path = os.path.join(_config_dir(), name)
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.replace(tmp, path)  # same fs: in-place swap, no truncated-file window
    except OSError as exc:
        raise HTTPException(500,
                            f"write failed ({exc}); is /config still mounted read-only?")
    if not body.get("apply", True):
        # save-only mode: batch-edit several files, press reload once later
        return {"saved": True, "applied": False,
                "note": "已儲存,尚未套用 — 按【熱更新名單】生效"}
    if state["reload_lock"].locked():
        # refuse fast instead of queueing on the lock: the waiting client
        # would just see a dead button for up to several minutes
        return {"saved": True, "applied": False,
                "error": "另一個熱更新還在跑(看 /admin/reload/status),"
                         "檔案已儲存,請稍後按【熱更新名單】"}
    applied, result, err = True, None, None
    async with state["reload_lock"]:
        try:
            result = await apply_list_reload()
        except (RuntimeError, OSError) as exc:
            applied, err = False, str(exc)
    return {"saved": True, "applied": applied, "result": result, "error": err}


# --- user management (users.json written back + hot-swapped in memory) -----

async def _commit_users(new_users: list[UserEntry]) -> None:
    path = os.path.join(_config_dir(), F_USERS)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            old = fh.read()
    except FileNotFoundError:
        old = ""
    try:
        tmp = path + ".tmp"
        enabled = bool(state["cfg"] and state["cfg"].users_enabled)
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(adminui.users_payload(new_users, enabled),
                                indent=2, ensure_ascii=False))
        os.replace(tmp, path)
        cfg2 = load_config()
    except (ConfigError, OSError) as exc:
        # something else in /config broke under us — undo, change nothing
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(old)
        except OSError:
            pass
        raise HTTPException(400, f"config rejected the change, users.json restored: {exc}")
    state["cfg"] = cfg2
    # sync the guard so a later lists-reload doesn't flag the very user
    # change just applied as restart-required
    state["fingerprint"] = guard_fingerprint(cfg2)
    log.info("users.json updated: %s", [u.username for u in cfg2.users])


def _user_mutation(fn, body: dict) -> list[UserEntry]:
    if state["reload_lock"].locked():
        raise HTTPException(409, "a reload is running, try again after it finishes")
    cfg = _cfg_ready()
    try:
        return fn(cfg.users, str(body.get("username") or ""),
                  str(body.get("passkey") or ""))
    except ValueError as exc:
        raise HTTPException(400, str(exc))


async def _run_user_mutation(request: Request, fn) -> dict:
    _admin_gate(request)
    body = await _json_body(request)
    new_users = _user_mutation(fn, body)
    async with state["reload_lock"]:
        await _commit_users(new_users)
    return {"ok": True}


@app.post("/admin/users/add")
async def admin_users_add(request: Request) -> dict:
    return await _run_user_mutation(request, adminui.user_add)


@app.post("/admin/users/update")
async def admin_users_update(request: Request) -> dict:
    return await _run_user_mutation(request, adminui.user_set_passkey)


@app.post("/admin/users/remove")
async def admin_users_remove(request: Request) -> dict:
    def rm(users, username, _passkey):
        return adminui.user_remove(users, username)
    return await _run_user_mutation(request, rm)


@app.get("/admin/users")
async def admin_users_list(request: Request) -> list:
    _admin_gate(request)
    cfg = _cfg_ready()
    # never carry passkeys (or their hashes) to the browser
    return [{"username": u.username, "role": u.role} for u in cfg.users]


# --- hermes file browser (sandbox home: exec + download via the CLI) -------

# No streaming yet, so cap the read: a runaway download of a huge tree
# would pin launcher memory at whatever the sandbox holds (the cap also
# bounds the zipped folder pulls; env-tunable like the upload cap).
HERMES_DL_MAX_BYTES = int(os.environ.get("OPN_HERMES_DL_MAX_BYTES",
                                         str(100 * 1024 * 1024)))


async def _hermes_exec(script: str, timeout: int = 30,
                       stdin: bytes | None = None) -> dict:
    """Run one hermesfs action script in the sandbox and decode its
    sentinel JSON line. stdin bytes are piped to the COMMAND (the CLI's
    documented input path) — how upload batches ride in: the exec
    channel's per-arg limit and its relay's large-command-string death
    both apply to argv only, not to the pipe. CLI failures
    surface as 400 with the CLI's own stderr — the refdocs lag the
    deployed binary, so the real error text is the debuggable thing
    to show the operator."""
    rc, out, err = await run_cli("sandbox", "exec", "-n", SANDBOX_NAME,
                                 "--", "python3", "-c", script,
                                 timeout=timeout, stdin=stdin)
    if rc == 124:
        raise HTTPException(504, f"sandbox exec 逾時({timeout}s),"
                                 f"沙箱可能未運作")
    if rc != 0:
        raise HTTPException(400, f"sandbox exec 失敗 (rc={rc}): "
                                 f"{(err or out).strip()[:500]}")
    try:
        data = hermesfs.parse_exec_output(out)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    if data.get("error"):
        raise HTTPException(400, str(data["error"]))
    return data


def _hermes_rel(raw) -> str:
    try:
        return hermesfs.normalize_rel(str(raw or ""))
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@app.get("/admin/hermes/ls")
async def admin_hermes_ls(request: Request, path: str = "") -> dict:
    _admin_gate(request)
    rel = _hermes_rel(path)
    return await _hermes_exec(hermesfs.script_ls(rel))


@app.post("/admin/hermes/mkdir")
async def admin_hermes_mkdir(request: Request) -> dict:
    _admin_gate(request)
    body = await _json_body(request)
    rel = _hermes_rel(body.get("path"))
    try:
        script = hermesfs.script_mkdir(rel)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return await _hermes_exec(script)


@app.post("/admin/hermes/delete")
async def admin_hermes_delete(request: Request) -> dict:
    """Deletes recursively (the UI confirms first) — same semantics the
    operator gets from a shell, minus the typos: the path went through
    normalize_rel and the CLI's own working-dir containment."""
    _admin_gate(request)
    body = await _json_body(request)
    rel = _hermes_rel(body.get("path"))
    try:
        script = hermesfs.script_delete(rel)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return await _hermes_exec(script, timeout=60)


HERMES_DL_CHUNK = 2 * 1024 * 1024  # raw bytes per exec; ~2.7 MB base64 stdout


async def _hermes_fetch_bytes(rel: str, max_bytes: int | None = None) -> bytes:
    """Pull a file out of the sandbox in base64 chunks over `sandbox
    exec` — the same channel ls/read/delete already trust. Live deploy
    found `sandbox download` (and `sandbox upload`) ENOENTing on every
    source, even image-baked files: the transfer resolver is not
    looking at the running sandbox's filesystem, so bytes must not
    depend on it. A short read means EOF; the size cap aborts runaway
    pulls (the whole file is buffered — same as before)."""
    buf = bytearray()
    off = 0
    while True:
        d = await _hermes_exec(
            hermesfs.script_read_range(rel, off, HERMES_DL_CHUNK))
        n = int(d.get("n") or 0)
        b64 = d.get("b64") or ""
        data = base64.b64decode(b64) if b64 else b""
        if len(data) != n:
            raise HTTPException(500, f"chunk 資料不一致 (offset {off}: "
                                     f"回報 {n},實際 {len(data)})")
        buf.extend(data)
        if n < HERMES_DL_CHUNK:  # short read == EOF
            break
        off += n
        cap = HERMES_DL_MAX_BYTES if max_bytes is None else max_bytes
        if len(buf) > cap:
            raise HTTPException(413, f"檔案過大(上限 {cap} bytes)")
    return bytes(buf)


def _attachment(content: bytes, name: str, media: str) -> Response:
    # RFC 5987 name: filenames are Unicode (the quote chars that would
    # break this header were rejected by normalize_rel).
    return Response(
        content=content, media_type=media,
        headers={"content-disposition":
                 "attachment; filename*=UTF-8''"
                 + urllib.parse.quote(name, safe="")})


@app.get("/admin/hermes/download")
async def admin_hermes_download(request: Request, path: str) -> Response:
    _admin_gate(request)
    rel = _hermes_rel(path)
    if not rel:
        raise HTTPException(400, "請指定檔案(不可為 home 本身)")
    data = await _hermes_fetch_bytes(rel)
    return _attachment(data, rel.rsplit("/", 1)[-1],
                       "application/octet-stream")


# --- folder download: zip inside the sandbox, stage, serve, sweep ----------

async def _delete_sandbox_zip(zip_rel: str) -> None:
    """Best-effort removal of the sandbox-side staging zip. A failed
    delete just leaves the file for the next zip's 7-day sweep — the
    whole point of the sweep is that cleanup never has to be reliable,
    only eventual."""
    try:
        await _hermes_exec(hermesfs.script_delete(zip_rel))
    except HTTPException as exc:
        log.warning("zip cleanup %s failed (stale sweep will catch it): %s",
                    zip_rel, exc)


@app.get("/admin/hermes/download_dir")
async def admin_hermes_download_dir(request: Request, path: str,
                                    background: BackgroundTasks) -> Response:
    """Zip a sandbox folder into .opn_downloads/, pull the bytes over
    the exec channel (see _hermes_fetch_bytes), and serve as attachment.

    Deletion contract: the zip is scheduled for removal once the
    response has been sent (BackgroundTasks run after the body is
    flushed). The browser saving the file is not observable from the
    server — a mid-transfer disconnect looks the same as success to
    nothing but the client — so "download finished" is taken as "we
    finished sending". Anything a crash orphans inside the sandbox
    (killed exec, failed pull) is unlinked by the 7-day sweep baked
    into the next zip."""
    _admin_gate(request)
    rel = _hermes_rel(path)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    try:
        script = hermesfs.script_zip_dir(rel, stamp, HERMES_DL_MAX_BYTES)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    # the sweep + make_archive run in this one exec; big folders get the
    # full CLI budget (same 120 s the reload steps already allow)
    data = await _hermes_exec(script, timeout=120)
    try:
        zip_rel = _hermes_rel(data.get("zip"))
    except HTTPException:
        raise HTTPException(400, f"sandbox 壓縮未回傳暫存路徑: {data!r:.300}")
    if not zip_rel.startswith(hermesfs.DOWNLOADS_DIR + "/"):
        raise HTTPException(400, f"sandbox 壓縮回傳了非暫存路徑: {zip_rel!r}")
    try:
        content = await _hermes_fetch_bytes(zip_rel)
    except HTTPException:
        # the zip exists sandbox-side; no response will carry it, so
        # remove it here rather than wait a week for the sweep
        await _delete_sandbox_zip(zip_rel)
        raise
    background.add_task(_delete_sandbox_zip, zip_rel)
    return _attachment(content, zip_rel.rsplit("/", 1)[-1],
                       "application/zip")


# Upload/save caps (edit cap lives in hermesfs.EDIT_MAX_BYTES). The whole
# file is buffered launcher-side, so the cap doubles as the per-upload
# memory bound; both caps are env-tunable for operators with bigger files
# (the 50 MB default was hit by a real log upload on day one).
HERMES_UPLOAD_MAX_BYTES = int(os.environ.get(
    "OPN_HERMES_UPLOAD_MAX_BYTES", str(200 * 1024 * 1024)))

# Live deploy: the exec channel drops intermittently — "The service is
# currently unavailable", "exec relay closed before the command reported
# an exit status", occasional timeouts. Crucially these are UNKNOWN
# outcomes (the script may have completed sandbox-side, only its response
# was lost), so retry is only safe for idempotent scripts: the start/
# delete/stat actions are (re-)run blind, append replays through its
# offset guard, and promote verifies by stat'ing the target instead of
# trusting the reply.
_TRANSIENT = ("relay closed", "currently unavailable", "connection reset",
              "connection closed", "timed out", "eof occurred")


def _transient(exc: HTTPException) -> bool:
    """Channel-level trouble (retryable somewhere up the stack) vs a
    real verdict from the sandbox. 502 = our own "retried internally,
    still no progress" marker, so callers can degrade strategy instead
    of retrying blindly."""
    text = str(exc.detail).lower()
    return exc.status_code in (502, 504) or any(
        m in text for m in _TRANSIENT)


async def _exec_retry(script: str, *, tries: int = 3,
                      timeout: int = 30) -> dict:
    """_hermes_exec for idempotent action scripts: transient channel
    blips get a few backoff-spaced attempts; real errors raise at once."""
    last = None
    for attempt in range(tries):
        try:
            return await _hermes_exec(script, timeout=timeout)
        except HTTPException as exc:
            if not _transient(exc):
                raise
            last = exc
            await asyncio.sleep(0.8 * (attempt + 1))
    raise last


async def _append_batch(rel_tmp: str, off: int, want: int,
                        blob: bytes) -> int:
    """Pipe one base64 batch to stdin through the offset+length-guarded
    append (hermesfs.script_upload_append); return the staging file's
    authoritative size after the attempt. The guards make every attempt
    all-or-nothing, so relay deaths are safely replayable:
    n==want (or at==off+want from an attempt whose reply was lost)
              -> landed; returns off+want
    short=<k> / at==off -> nothing landed (channel died before or mid
              stdin); retry the same batch, and count as an unstable-
              channel signal for the caller's shrink decision
    at>off            -> an earlier (possibly larger-chunk) attempt landed
              further than this batch would; returns at and the caller
              resumes from there — those bytes are ours, at the right
              offsets, so re-syncing beats rewriting them
    at<off            -> the file SHRANK: corruption; 500, abort."""
    script = hermesfs.script_upload_append(rel_tmp, off, want)
    last = None
    for attempt in range(3):
        try:
            d = await _hermes_exec(script, timeout=120, stdin=blob)
            n = int(d.get("n") or 0)
            if n:
                if n == want:
                    return off + n
                raise HTTPException(500, f"區塊寫入長度異常: {n}!={want}")
            at = d.get("at")
            if at is None:  # short stdin (or unparseable): never written
                last = HTTPException(502, f"append 未生效(offset {off}, "
                                          f"stdin short={d.get('short')}, "
                                          f"第 {attempt + 1} 次)")
            else:
                at = int(at)
                if at > off:
                    return at  # off+want: whole batch landed earlier;
                    # anything else in (off, ...) the caller re-syncs to
                if at < off:
                    raise HTTPException(500, f"暫存檔位移異常: 期望 {off},"
                                             f"實際 {at}(中止以免寫壞)")
                last = HTTPException(502, f"append 未生效(offset {off},"
                                          f"第 {attempt + 1} 次)")
        except HTTPException as exc:
            if not _transient(exc):
                raise
            last = exc
        await asyncio.sleep(0.8 * (attempt + 1))
    raise last


async def _promote_verified(rel_tmp: str, dst_rel: str, size: int) -> None:
    """os.replace the staging file onto its target, then CONFIRM the
    target is there at the expected size — the reply of the promote exec
    itself may be lost to a relay blip, and a blind retry would then
    report 暫存檔不存在 (os.replace already consumed the staging file).
    Only transient failures retry; the deterministic 大小不符/不是檔案
    errors surface immediately."""
    script = hermesfs.script_promote(rel_tmp, dst_rel, size)
    last = None
    for attempt in range(4):
        try:
            await _hermes_exec(script, timeout=60)
        except HTTPException as exc:
            if not _transient(exc):
                raise
            last = exc
        d = await _exec_retry(hermesfs.script_stat_size(dst_rel))
        if int(d.get("size", -1)) == size:
            return
        last = HTTPException(502, f"換名後目標大小不符: 實際 "
                                  f"{d.get('size')},期望 {size}")
        await asyncio.sleep(0.8 * (attempt + 1))
    raise last


# Persisted across uploads: halved whenever the channel repeatedly dies
# mid-append at the current batch size (live deploy: DETERMINISTIC
# "exec relay closed" once the exec command string hit ~450 KB of base64
# argv — small execs kept working, so this is a size wall, not luck).
# Batches ride stdin instead, which has no published cap; the shrink
# path stays as insurance for whatever wall stdin does hit.
_put_chunk = [hermesfs.UPLOAD_STDIN_CHUNK_RAW]


async def _sandbox_put_bytes(data: bytes, dst_rel: str) -> None:
    """Write bytes to a sandbox file over the exec channel — `sandbox
    upload` is as dead as `sandbox download` (live probe: ENOENT even
    with an explicit dest). Each batch is base64'd per exec (no
    whole-file copy) and PIPED TO STDIN (see _put_chunk for why not
    argv); the offset+length guards make every append all-or-nothing, so
    relay deaths replay without duplicating or skipping bytes; the
    staged file is size-verified sandbox-side, os.replace'd into place,
    then stat-checked at the destination. Repeated channel deaths at the
    current batch size halve it (down to UPLOAD_CHUNK_RAW) and the
    smaller size sticks for later uploads. Orphaned staging is swept by
    the next upload's start script after STALE_SECONDS."""
    rel_tmp = (f"{hermesfs.UPLOADS_DIR}/{int(time.time())}-"
               f"{os.getpid()}-{os.urandom(6).hex()}")
    await _exec_retry(hermesfs.script_upload_start(rel_tmp))
    total = len(data)
    chunk = _put_chunk[0]
    try:
        off = 0
        while off < total:
            want = min(chunk, total - off)
            try:
                off = await _append_batch(rel_tmp, off, want,
                                          base64.b64encode(
                                              data[off:off + want]))
            except HTTPException as exc:
                if (not _transient(exc)
                        or chunk <= hermesfs.UPLOAD_CHUNK_RAW):
                    raise
                chunk = max(hermesfs.UPLOAD_CHUNK_RAW, chunk // 2)
                _put_chunk[0] = chunk
                log.warning("upload append 在 %d bytes/批 連續失手,"
                            "縮至 %d 重試(並沿用到後續上傳)", want, chunk)
        await _promote_verified(rel_tmp, dst_rel, total)
    except HTTPException:
        try:  # best effort — the stale sweep catches what survives
            await _hermes_exec(hermesfs.script_delete(rel_tmp))
        except HTTPException:
            pass
        raise


@app.get("/admin/hermes/read")
async def admin_hermes_read(request: Request, path: str) -> dict:
    """File bytes (base64) for the web editor; capped at EDIT_MAX_BYTES."""
    _admin_gate(request)
    rel = _hermes_rel(path)
    if not rel:
        raise HTTPException(400, "請指定檔案(不可為 home 本身)")
    return await _hermes_exec(hermesfs.script_read(rel))


@app.post("/admin/hermes/upload")
async def admin_hermes_upload(request: Request, path: str = Form(""),
                              file: UploadFile = File(...)) -> dict:
    """Multipart upload: stream to a launcher temp file (cap enforced
    there), then write into the sandbox over the exec channel — see
    _sandbox_put_bytes for why not `sandbox upload`."""
    _admin_gate(request)
    rel_dir = _hermes_rel(path)
    try:
        name = hermesfs.validate_basename(file.filename or "")
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    tmp = tempfile.mkdtemp(prefix="opn-ul-")
    lp = os.path.join(tmp, name)
    try:
        size = 0
        with open(lp, "wb") as fh:
            while chunk := await file.read(1 << 20):
                size += len(chunk)
                if size > HERMES_UPLOAD_MAX_BYTES:
                    raise HTTPException(413, f"上傳過大(上限 "
                                             f"{HERMES_UPLOAD_MAX_BYTES} bytes)")
                fh.write(chunk)
        with open(lp, "rb") as fh:
            data = fh.read()
    finally:
        await file.close()
        shutil.rmtree(tmp, ignore_errors=True)
    dst = (rel_dir + "/" if rel_dir else "") + name
    await _sandbox_put_bytes(data, dst)
    return {"ok": True, "path": dst}


@app.post("/admin/hermes/save")
async def admin_hermes_save(request: Request) -> dict:
    """Editor save: write the new bytes over the sandbox-side file via
    the exec channel. os.replace inside script_promote clobbers in one
    step, so the CLI's overwrite-refusal and the old delete-then-retry
    dance are gone."""
    _admin_gate(request)
    body = await _json_body(request)
    rel = _hermes_rel(body.get("path"))
    if not rel:
        raise HTTPException(400, "請指定檔案(不可為 home 本身)")
    content = body.get("content")
    if not isinstance(content, str):
        raise HTTPException(400, "content 需為字串")
    data = content.encode("utf-8")
    if len(data) > hermesfs.EDIT_MAX_BYTES:
        raise HTTPException(413, f"內容過大(上限 "
                                 f"{hermesfs.EDIT_MAX_BYTES} bytes)")
    await _sandbox_put_bytes(data, rel)
    return {"ok": True, "path": rel}


# --------------------------------------------------------------------------
# Web entry point
# --------------------------------------------------------------------------

def _session_user(request: Request) -> str | None:
    tok = request.cookies.get(auth.COOKIE_NAME)
    return auth.verify_token(tok) if tok else None


def _auth_ok(request: Request) -> bool:
    cfg = state["cfg"]
    if cfg is not None and not cfg.users_enabled:
        return True
    return _session_user(request) is not None


def _admin_ok(request: Request) -> bool:
    # Console gate (/admin*). With the login gate disabled the whole
    # entry point is open anyway — the visitor is treated as admin, in
    # line with "loopback-only unless you exposed it deliberately".
    cfg = state["cfg"]
    if cfg is None or not cfg.users_enabled:
        return True
    user = _session_user(request)
    # role_for -> None fences out accounts deleted mid-session
    return user is not None and auth.role_for(cfg, user) == "admin"


@app.get("/status")
async def status() -> dict:
    cfg = state["cfg"]
    return {"ready": state["ready"],
            "error": state["error"],
            "auth_required": bool(cfg and cfg.users_enabled),
            # If you edited listen.json but this still shows 127.0.0.1, the
            # compose host bind is stale: rerun bootstrap.sh, then up -d.
            "listen_url": f"{cfg.listen_host}:{cfg.listen_port}" if cfg else None,
            "warnings": cfg.warnings if cfg else [],
            # last result of POST /admin/reload (None = never since boot)
            "last_reload": state["last_reload"],
            # last recreate's hermes backup/restore (None = no recreate
            # this boot or nothing to save)
            "hermes_restore": state["hermes_restore"]}


@app.get("/login", response_class=HTMLResponse)
async def login_get() -> str:
    return auth.login_page()


@app.post("/login", response_class=HTMLResponse)
async def login_post(username: str = Form(""), passkey: str = Form("")) -> Response:
    cfg = state["cfg"]
    if cfg is not None and auth.check_credentials(cfg, username, passkey):
        # admins land on the console, plain users straight on hermes
        role = auth.role_for(cfg, username)
        resp = RedirectResponse("/admin" if role == "admin" else "/",
                                status_code=302)
        resp.set_cookie(auth.COOKIE_NAME, auth.make_token(username),
                        httponly=True, samesite="lax", max_age=auth.SESSION_TTL)
        return resp
    return HTMLResponse(auth.login_page("帳號或 passkey 錯誤"), status_code=401)


@app.get("/logout")
async def logout() -> Response:
    resp = RedirectResponse("/login", status_code=302)
    resp.delete_cookie(auth.COOKIE_NAME)
    return resp


async def _proxy_http(request: Request) -> Response:
    if not state["ready"]:
        msg = "OpnAgent is not ready yet"
        detail = state["error"] or "sandbox is starting"
        return Response(f"{msg}: {detail}", status_code=503,
                        media_type="text/plain")
    if not _auth_ok(request):
        if request.method == "GET" and not request.url.path.startswith("/api/"):
            return RedirectResponse("/login", status_code=302)
        return Response("unauthorized", status_code=401)
    return await state["reverse"].handle_http(request)


@app.websocket("/ws")
async def ws_root(ws: WebSocket) -> None:
    if not (state["ready"] and _auth_ok(ws)):
        await ws.close(code=4401)
        return
    await state["reverse"].handle_ws(ws)


@app.websocket("/ws/{path:path}")
async def ws_path(ws: WebSocket, path: str) -> None:  # pragma: noqa
    if not (state["ready"] and _auth_ok(ws)):
        await ws.close(code=4401)
        return
    await state["reverse"].handle_ws(ws)


@app.websocket("/{path:path}")
async def ws_any(ws: WebSocket, path: str) -> None:  # pragma: noqa
    # hermes' webui does not put its socket under /ws (live deploy: page
    # loads, chat dies with "WebSocket connection failed"), and the real
    # path is whatever the bundled dist says today — bridge every upgrade
    # that HTTP routes above didn't claim, so the guess stops mattering.
    if not (state["ready"] and _auth_ok(ws)):
        await ws.close(code=4401)
        return
    await state["reverse"].handle_ws(ws)


# Catch-all: any method, any path not claimed above.
@app.api_route("/{path:path}",
               methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD",
                        "OPTIONS"])
async def catch_all(request: Request) -> Response:
    return await _proxy_http(request)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("OPN_PORT", "8000")))
