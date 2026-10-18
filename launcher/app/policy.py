"""Generate the OpenShell sandbox policy (version: 1 YAML).

OpenShell is allow-list-only at the connection layer: anything not allowed
is denied. Translation rules:

 - python_pkg_whitelist -> pypi.org GET allow-paths /simple/<pkg>/* (the
   only place the package NAME appears; files.pythonhosted.org URLs are
   content hashes and cannot be name-filtered, so /packages/** is open).
 - python_pkg_blacklist -> deny_rules on /simple/<pkg>/* (deny beats allow).
 - url_whitelist        -> one allow rule per host entry.
 - url_blacklist        -> trims the whitelist (effective). Host-level deny
   of an otherwise-wide allow is NOT expressible; config.load_config()
   records a warning when only the blacklist is enabled.

LLM hosts need no rules here: each attached provider contributes the
reserved `_provider_*` rules automatically.
"""

from __future__ import annotations

import json
import os

import yaml

from .config import OpnConfig

# The interpreter hermes, pip and the shim all resolve to (OpenShell
# identifies scripts by their interpreter binary). Must name the REAL
# resolved path in the sandbox image: an unmatched binary fails CLOSED
# in the sneakiest way — allow-list-only means the shim's connect()
# gets EACCES from the supervisor and every LLM call surfaces as
# `upstream error: [Errno 13] Permission denied` (502 from the shim).
# ubuntu:26.04 ships Python 3.14 (older bases: 3.12 — the refdocs
# network-rules snapshot still shows the 24.04 example). Overridable
# via env so a base-image python bump is a compose-env fix, not a
# launcher rebuild.
BIN_PY_PATH = os.environ.get("OPN_SANDBOX_PYTHON", "/usr/bin/python3.14")
# FUNCTIONS returning fresh dicts, on purpose: shared module-level
# objects make PyYAML emit YAML anchors/aliases for the repeats, and
# the deployed OpenShell parser rejects high alias ratios ("alias_
# anchor_ratio heuristic tripped: 11 aliases / 2 anchors > 5" — live
# with a ~11-host url_whitelist; the test box had too few hosts to
# trip it). policy_yaml() additionally json round-trips as a root-cause
# guard, so future sharing cannot reintroduce aliases either.
BIN_PY_PATH = "/usr/bin/python3.12"


def _pypi_binaries() -> list[dict]:
    return [{"path": BIN_PY_PATH}]


def _url_binaries() -> list[dict]:
    return [{"path": BIN_PY_PATH}, {"path": "/usr/bin/curl"},
            {"path": "/usr/bin/git"}]


def _simple_paths(pkg: str) -> list[str]:
    # pip requests both /simple/<pkg> and (after the 301) /simple/<pkg>/;
    # `**` is not guaranteed to match the empty remainder, so list it.
    return [f"/simple/{pkg}", f"/simple/{pkg}/", f"/simple/{pkg}/**"]


# Schema forbids combining `access` with `rules`, and a rest endpoint needs
# one of the two. An enabled-but-empty pkg whitelist therefore gets a rule
# for a path that matches nothing real on pypi.
_NO_PKG_RULE = {"allow": {"method": "GET", "path": "/__opn_no_packages__"}}


def build_policy(cfg: OpnConfig) -> dict:
    rules: dict = {}

    # --- PyPI -------------------------------------------------------------
    pypi_endpoints: list[dict] = []
    simple_ep: dict = {
        "host": "pypi.org",
        "port": 443,
        "protocol": "rest",
        "enforcement": "enforce",
    }
    if cfg.pkg_wl.enabled:
        allow = [{"allow": {"method": "GET", "path": p}}
                 for pkg in cfg.pkg_wl.items for p in _simple_paths(pkg)]
        simple_ep["rules"] = allow or [_NO_PKG_RULE]
    else:
        simple_ep["access"] = "read-only"   # preset; mutually exclusive w/ rules
    if cfg.pkg_bl.enabled:
        # deny beats allow, so this also applies on top of a whitelist.
        simple_ep["deny_rules"] = [
            {"method": "GET", "path": pat}
            for pkg in cfg.pkg_bl.items
            for pat in (f"/simple/{pkg}", f"/simple/{pkg}/", f"/simple/{pkg}/**",
                        f"/json/{pkg}", f"/pypi/{pkg}/**")
        ]
    pypi_endpoints.append(simple_ep)

    # Wheels live on content-hashed URLs — package name is invisible there,
    # so downloads are gated upstream (at /simple/) only. rules-only (no
    # access: the two cannot be combined).
    pypi_endpoints.append({
        "host": "files.pythonhosted.org",
        "port": 443,
        "protocol": "rest",
        "enforcement": "enforce",
        "rules": [{"allow": {"method": "GET", "path": "/packages/**"}}],
    })
    rules["pypi"] = {"endpoints": pypi_endpoints,
                     "binaries": _pypi_binaries()}

    # --- URL allow list -----------------------------------------------------
    blocked = set(h.lower() for h in cfg.url_bl.items) if cfg.url_bl.enabled else set()
    if cfg.url_wl.enabled:
        n = 0
        for host in cfg.url_wl.items:
            if host.lower() in blocked:
                continue  # black list trims the white list
            n += 1
            rules[f"url-allow-{n:03d}"] = {
                "endpoints": [{"host": host, "ports": [80, 443]}],
                "binaries": _url_binaries(),
            }

    # Unlisted paths are INACCESSIBLE; OpenShell only enriches the proxy-mode
    # baseline (/usr /lib /etc /app /var/log /proc ... — NOT /opt, NOT /home),
    # which is why spawning /opt/opnagent/entrypoint.sh dies with EACCES when
    # this section just says include_workdir. Docs: policies/default-policy
    # ("list the paths your workload needs"). Kept disjoint so no
    # nested-rule semantics are relied on:
    #   /opt/opnagent       ro  — entrypoint + shim stay tamper-proof from the
    #                              workload (venv/home below are writable)
    #   /opt/hermes         ro  — the hermes SOURCE CHECKOUT (0.21+ installs
    #                              editable from it; also holds the baked
    #                              web_dist/ui-tui dists + node_modules).
    #                              Runtime writes go to HOME/.hermes; ro on
    #                              purpose — hermes' update/npm cascades must
    #                              not touch the tree (same immutable-install
    #                              stance as their official image), and
    #                              PYTHONDONTWRITEBYTECODE keeps it .pyc-free
    #   /opt/hermes-webui   ro  — hermes-webui checkout (the web frontend
    #                              since the dashboard swap); its state is
    #                              written to HOME/.hermes/webui, never
    #                              into the checkout
    #   /opt/hermes-venv    rw  — hermes' venv, plus runtime `pip install`
    #                              of whitelisted packages lands here
    #   /home/opn           rw  — HOME: hermes state, pip/wheel caches,
    #                              workspace (include_workdir is a subset)
    #   /dev/ptmx, /dev/pts,
    #   /dev/tty            rw  — the dashboard's embedded chat runs the TUI
    #                              under a PTY (PtyBridge→openpty); the
    #                              baseline only grants /dev/null, so
    #                              open("/dev/ptmx") is EACCES and hermes
    #                              surfaces it as "Chat unavailable: out of
    #                              pty devices"
    #   /dev/shm            rw  — hermes-webui runs each cron job in a
    #                              multiprocessing "spawn" child with a Queue
    #                              result pipe; sem_open() writes /dev/shm/
    #                              sem.* and EACCES there kills manual "Run
    #                              now" ("subprocess exited … without
    #                              producing a result")
    return {
        "version": 1,
        "filesystem_policy": {
            "include_workdir": True,
            "read_only": ["/opt/opnagent", "/opt/hermes", "/opt/hermes-webui"],
            "read_write": ["/opt/hermes-venv", "/home/opn",
                           "/dev/ptmx", "/dev/pts", "/dev/tty", "/dev/shm"],
        },
        "network_policies": rules,
    }


def policy_yaml(cfg: OpnConfig) -> str:
    """The policy document for `sandbox create --policy` / `policy set`.

    The json round-trip is deliberate and load-bearing: yaml.safe_dump
    anchors ANY dict/list object that appears more than once and emits
    *aliases for the repeats, and the deployed OpenShell parser refuses
    such documents outright (alias_anchor_ratio heuristic). The round-
    trip hands safe_dump a tree of guaranteed-fresh objects, so the
    output contains no &anchors/*aliases regardless of how build_policy
    is written. Everything in the tree is JSON-native (dicts/lists/
    strs/ints/bools), so the round-trip is lossless."""
    return yaml.safe_dump(json.loads(json.dumps(build_policy(cfg))),
                          sort_keys=False)
