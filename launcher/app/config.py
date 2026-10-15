"""Parse the OpnAgent config directory (mounted rw at /config — rw so the
/admin console can write back the list files and users.json; everything
else still edits these files on the host).

File names use underscores only (no spaces, whitelist/blacklist are one
word): "LLM_Porting_Map.json", "url_whitelist.json", "url_blacklist.json",
"python_pkg_whitelist.json", "python_pkg_blacklist.json", "users.json",
"listen.json".
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

def _config_dir() -> str:
    # Read per call so tests (and --env overrides) can change it at runtime.
    return os.environ.get("OPN_CONFIG_DIR", "/config")

F_LLM_MAP = "LLM_Porting_Map.json"
F_URL_WL = "url_whitelist.json"
F_URL_BL = "url_blacklist.json"
F_PKG_WL = "python_pkg_whitelist.json"
F_PKG_BL = "python_pkg_blacklist.json"
F_USERS = "users.json"
F_LISTEN = "listen.json"

LISTEN_DEFAULT_HOST = "127.0.0.1"
LISTEN_DEFAULT_PORT = 8000


@dataclass
class LLMEntry:
    url: str
    key: str
    inner_port: int
    inner_key: str
    # Optional model id for this endpoint ("model" in the map entry). Purely
    # informational for OpenShell; the sandbox entrypoint writes it into
    # ~/.hermes/config.yaml as default_model so the chat UI starts ready.
    model: str = ""
    # Optional context window ("context-length" in the map entry). hermes
    # cannot infer the length of a model id it doesn't know from the endpoint
    # and warns "falling back to 256,000 tokens" once per process; the
    # entrypoint writes it into ~/.hermes/config.yaml at BOTH documented
    # points: model.context_length (default runtime) and the providers.<name>
    # entry (applies to every model that entry serves, survives /model).
    context_length: int = 0
    # Wire protocol of the endpoint ("protocol" in the map entry):
    # "openai" (default, chat_completions) or "anthropic" (/v1/messages).
    # Feeds the sandbox entrypoint's providers.<name>.transport so a
    # Messages-format relay gets hermes' anthropic_messages client instead
    # of the OpenAI one (which 404s on /chat/completions there).
    protocol: str = "openai"
    # Optional catalogued vendor the endpoint resells ("catalog-provider").
    # Forwarded to hermes' providers.<name>.catalog_provider: metadata lookups
    # only (models.dev), NEVER routing — the endpoint still answers. Set e.g.
    # "openai" on an OpenAI-compatible reseller so context/capability lookups
    # hit the catalog instead of probe-down.
    catalog_provider: str = ""

    @property
    def host(self) -> str:
        return urlsplit(self.url).hostname or ""

    @property
    def port(self) -> int:
        parts = urlsplit(self.url)
        return parts.port or (443 if parts.scheme == "https" else 80)

    @property
    def secure(self) -> bool:
        return urlsplit(self.url).scheme == "https"

    @property
    def path_prefix(self) -> str:
        return urlsplit(self.url).path.rstrip("/")

    @property
    def cred_env(self) -> str:
        return f"OPNL_{self.index}"

    index: int = 0


@dataclass
class NameList:
    enabled: bool = False
    items: list[str] = field(default_factory=list)


@dataclass
class UserEntry:
    username: str
    passkey: str
    # "admin" sees the launcher console (/admin: hot reload, list editing,
    # user management); "user" goes straight to hermes. Absent role in the
    # JSON = admin — accounts created before the role existed keep their
    # access (a silent demotion would lock the operator out of /admin).
    role: str = "user"


@dataclass
class OpnConfig:
    llm_map: list[LLMEntry]
    url_wl: NameList
    url_bl: NameList
    pkg_wl: NameList
    pkg_bl: NameList
    users_enabled: bool
    users: list[UserEntry]
    # Host bind of the launcher's web entry point, from listen.json. The
    # ACTUAL bind is a compose host-port mapping (bootstrap.sh mirrors this
    # value into deploy/.env -> OPN_LISTEN_HOST/PORT), so the container
    # itself always listens on 0.0.0.0:8000; we parse it to validate, to
    # gate exposure on users.json, and to surface staleness on /status.
    listen_host: str = LISTEN_DEFAULT_HOST
    listen_port: int = LISTEN_DEFAULT_PORT
    warnings: list[str] = field(default_factory=list)


class ConfigError(Exception):
    pass


def _read_json(name: str) -> object:
    path = os.path.join(_config_dir(), name)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return None
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{name}: invalid JSON: {exc}")


def _list_cfg(raw, name: str) -> NameList:
    if raw is None:
        return NameList()
    if not isinstance(raw, dict):
        raise ConfigError(f"{name}: expected an object")
    items = raw.get("list") or []
    if not isinstance(items, list) or not all(isinstance(i, str) for i in items):
        raise ConfigError(f"{name}: 'list' must be a list of strings")
    return NameList(enabled=bool(raw.get("enabled")), items=[i.strip() for i in items if i.strip()])


def _safe_host_or_pkg(item: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9.*_\-/]+", item))


def _parse_listen() -> tuple[str, int]:
    """listen.json: {"listen_url": "<host>[:<port>]"} (scheme optional).

    "0.0.0.0"/"0.0.0.0:8000" or an intranet IP lets other machines reach
    the entry point directly (no ssh -L). Default stays loopback-only.
    """
    raw = _read_json(F_LISTEN)
    if raw is None:
        return LISTEN_DEFAULT_HOST, LISTEN_DEFAULT_PORT
    if not isinstance(raw, dict) or "listen_url" not in raw:
        raise ConfigError(f"{F_LISTEN}: expected {{\"listen_url\": \"host[:port]\"}}")
    value = str(raw["listen_url"]).strip()
    for scheme in ("http://", "https://"):
        if value.lower().startswith(scheme):
            value = value[len(scheme):]
    # bracketed IPv6 ([::1]:8000) or plain host/IPv4 with optional :port
    m = re.fullmatch(r"(?:(\[[0-9A-Fa-f:.]+\])|([A-Za-z0-9.\-]+))(?::(\d{1,5}))?",
                     value)
    if not m:
        raise ConfigError(f"{F_LISTEN}: invalid listen_url {raw['listen_url']!r}")
    host = (m.group(1) or m.group(2)).strip()
    port = int(m.group(3)) if m.group(3) else LISTEN_DEFAULT_PORT
    if not (1 <= port <= 65535):
        raise ConfigError(f"{F_LISTEN}: port out of range in {raw['listen_url']!r}")
    return host, port


def _is_loopback(host: str) -> bool:
    h = host.strip("[]").lower()
    return h in ("localhost", "::1") or h.startswith("127.")


def load_config() -> OpnConfig:
    warnings: list[str] = []

    raw_map = _read_json(F_LLM_MAP)
    if raw_map is None:
        raise ConfigError(f"{F_LLM_MAP} is required")
    if not isinstance(raw_map, dict) or not raw_map:
        raise ConfigError(f"{F_LLM_MAP}: expected a non-empty object")
    llm_map: list[LLMEntry] = []
    seen_ports: set[int] = set()
    for i, (url, ent) in enumerate(raw_map.items()):
        if not isinstance(ent, dict):
            raise ConfigError(f"{F_LLM_MAP}: entry for {url} must be an object")
        try:
            port = int(ent["inner-port"])
        except (KeyError, TypeError, ValueError):
            raise ConfigError(f"{F_LLM_MAP}: entry for {url} needs integer 'inner-port'")
        key, inner_key = ent.get("key"), ent.get("inner-key")
        if not key or not inner_key:
            raise ConfigError(f"{F_LLM_MAP}: entry for {url} needs 'key' and 'inner-key'")
        # The sandbox entrypoint passes inner-key through tab-delimited
        # bash lines — tabs/newlines would corrupt it; reject early.
        if re.search(r"[\t\r\n]", str(key)) or re.search(r"[\t\r\n]", str(inner_key)):
            raise ConfigError(f"{F_LLM_MAP}: entry for {url}: key/inner-key "
                              f"must not contain tab or newline")
        parts = urlsplit(url)
        if parts.scheme not in ("https", "http") or not parts.hostname:
            raise ConfigError(f"{F_LLM_MAP}: entry {url!r} must be an http(s) URL")
        if parts.scheme == "http":
            warnings.append(
                f"LLM map entry {url} is plain http: the supervisor injects "
                "the REAL api key at egress, so that leg carries the key in "
                "cleartext. Use https whenever the endpoint offers it.")
        if port in seen_ports or not (1024 <= port <= 65535):
            raise ConfigError(f"{F_LLM_MAP}: inner-port {port} invalid or duplicated")
        seen_ports.add(port)
        model = str(ent.get("model") or "").strip()
        if re.search(r"[\t\r\n]", model):
            raise ConfigError(f"{F_LLM_MAP}: entry for {url}: 'model' "
                              f"must not contain tab or newline")
        context_length = 0
        ctx_raw = ent.get("context-length")
        if ctx_raw not in (None, ""):
            # int() on the stripped string: JSON numbers and "262144" both
            # parse; "128k", floats and bools all raise ValueError/TypeError.
            try:
                context_length = int(str(ctx_raw).strip())
            except (TypeError, ValueError):
                raise ConfigError(f"{F_LLM_MAP}: entry for {url}: "
                                  f"'context-length' must be an integer")
            if not (1024 <= context_length <= 2_000_000_000):
                raise ConfigError(f"{F_LLM_MAP}: entry for {url}: "
                                  f"'context-length' out of range "
                                  f"(1024..2000000000)")
        # "protocol": absent/"openai" = chat_completions, "anthropic" =
        # /v1/messages. Anything else is an operator typo — fail loudly
        # rather than silently serving the wrong client.
        protocol = str(ent.get("protocol") or "openai").strip().lower()
        if protocol not in ("openai", "anthropic"):
            raise ConfigError(f"{F_LLM_MAP}: entry for {url}: 'protocol' "
                              f"must be 'openai' or 'anthropic', got "
                              f"{ent.get('protocol')!r}")
        catalog = str(ent.get("catalog-provider") or "").strip()
        if catalog and not re.fullmatch(r"[A-Za-z0-9._\-]{1,64}", catalog):
            raise ConfigError(f"{F_LLM_MAP}: entry for {url}: "
                              f"'catalog-provider' must be a short vendor id")
        e = LLMEntry(url=url, key=str(key), inner_port=port,
                     inner_key=str(inner_key), index=i, model=model,
                     context_length=context_length, catalog_provider=catalog,
                     protocol=protocol)
        llm_map.append(e)

    url_wl = _list_cfg(_read_json(F_URL_WL), F_URL_WL)
    url_bl = _list_cfg(_read_json(F_URL_BL), F_URL_BL)
    pkg_wl = _list_cfg(_read_json(F_PKG_WL), F_PKG_WL)
    pkg_bl = _list_cfg(_read_json(F_PKG_BL), F_PKG_BL)

    for src, label in ((url_wl, "url white"), (url_bl, "url black")):
        bad = [i for i in src.items if not _safe_host_or_pkg(i)]
        if bad:
            raise ConfigError(f"invalid {label} entries: {bad}")
    for src, label in ((pkg_wl, "pkg white"), (pkg_bl, "pkg black")):
        bad = [i for i in src.items if not re.fullmatch(r"[A-Za-z0-9._\-]+", i)]
        if bad:
            raise ConfigError(f"invalid {label} entries: {bad}")

    # Wildcard-coverage trap: exact blacklist entries TRIM exact whitelist
    # entries (policy.py), but a whitelist wildcard like *.example.com is a
    # single connection-layer allow — OpenShell has no host-level deny over
    # a raw (uninspected) endpoint, so a blacklisted host it covers would
    # silently pass. Fail closed instead: refuse to start and name the pair
    # so the operator can narrow the whitelist to explicit entries.
    if url_bl.enabled and url_wl.enabled:
        covered = []
        for w in url_wl.items:
            if "*" not in w:
                continue
            pat = re.compile("^" + re.escape(w.lower()).replace(r"\*", ".+") + "$")
            for b in url_bl.items:
                if "*" not in b and pat.match(b.lower()):
                    covered.append(f"{b} (covered by whitelist {w})")
        if covered:
            raise ConfigError(
                "url_blacklist entries covered by a url_whitelist wildcard "
                "cannot be enforced (OpenShell has no host-level deny on raw "
                "endpoints) — narrow the whitelist to explicit hosts, "
                "removing: " + "; ".join(covered))

    if url_bl.enabled and not url_wl.enabled:
        warnings.append(
            "url_blacklist is enabled but url_whitelist is disabled: the "
            "connection layer is deny-by-default and OpenShell offers NO "
            "'allow everything' expression (wildcard hosts need >=3 labels; "
            "supervisor middleware only sees traffic policy already allowed). "
            "This therefore stays FULLY CLOSED (only pypi + mapped LLM "
            "endpoints), the blacklist changes nothing. For an allow list with "
            "exclusions: enable url_whitelist (blacklist trims exact hits).")

    raw_users = _read_json(F_USERS) or {"enabled": False, "user-list": []}
    if not isinstance(raw_users, dict):
        raise ConfigError(f"{F_USERS}: expected an object")
    users_enabled = bool(raw_users.get("enabled"))
    users: list[UserEntry] = []
    for u in raw_users.get("user-list") or []:
        if not isinstance(u, dict) or not u.get("username") or not u.get("passkey"):
            raise ConfigError(f"{F_USERS}: each user needs 'username' and 'passkey'")
        role = str(u.get("role") or "admin")
        if role not in ("admin", "user"):
            raise ConfigError(f"{F_USERS}: {u['username']}: role must be "
                              f"'admin' or 'user', got {role!r}")
        if any(x.username == str(u["username"]) for x in users):
            raise ConfigError(f"{F_USERS}: duplicate username {u['username']!r}")
        users.append(UserEntry(username=str(u["username"]),
                               passkey=str(u["passkey"]), role=role))
    if users_enabled and not users:
        raise ConfigError(f"{F_USERS}: enabled but user-list is empty")
    if users_enabled and not any(u.role == "admin" for u in users):
        warnings.append(
            f"{F_USERS}: enabled but no account has role 'admin' — the web "
            "console (/admin) is unreachable; edit the file on the host to "
            "grant one.")

    listen_host, listen_port = _parse_listen()
    if not _is_loopback(listen_host):
        if not users_enabled:
            raise ConfigError(
                f"{F_LISTEN}: listen_url {listen_host}:{listen_port} exposes the "
                f"entry point beyond loopback while {F_USERS} is disabled — the "
                "login gate is the ONLY defense there (gateway 8080 stays on "
                "127.0.0.1 and has no auth of its own). Enable users.json first.")
        if listen_host == "0.0.0.0":
            warnings.append(
                "listen_url binds 0.0.0.0: every interface (and any future "
                "VPN/tailnet one) serves the login page over plain http. "
                "Prefer pinning the intranet IP if you know it.")
        warnings.append(
            f"entry point exposed on http://{listen_host}:{listen_port} — LAN "
            "traffic carries the login password and session cookie in cleartext; "
            "behind a TLS reverse proxy is the supported long-term shape.")

    return OpnConfig(llm_map=llm_map, url_wl=url_wl, url_bl=url_bl,
                     pkg_wl=pkg_wl, pkg_bl=pkg_bl,
                     users_enabled=users_enabled, users=users,
                     listen_host=listen_host, listen_port=listen_port,
                     warnings=warnings)
