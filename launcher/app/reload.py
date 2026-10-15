"""Hot-list support: swap network_policies on the RUNNING sandbox.

Only the four list files (url/pkg white + black) are hot-reloadable:
they feed nothing but the `network_policies` section, which OpenShell
reloads in place (`policy set --wait`; long-lived connections opened
under the old rules are closed). Everything else — LLM map (providers +
shim), users (auth gate), listen (compose host bind) — is baked into
the sandbox/providers/container at bootstrap, so a reload touching them
is rejected outright and the caller must restart the launcher.

The submission is the CURRENT BASE policy with only its network section
replaced, never build_policy()'s output wholesale: OpenShell enriched
the filesystem section at sandbox start, and shipping back our smaller
fs section would count as a filesystem change — rejected once the
workload runs.
"""

from __future__ import annotations

from .config import OpnConfig
from .policy import build_policy


def guard_fingerprint(cfg: OpnConfig) -> tuple:
    """Fingerprint of everything that is NOT hot-reloadable.

    NameLists are deliberately excluded — they are what reload swaps.
    Carries secrets (LLM keys, passkeys); compared in-process only."""
    return (
        tuple((e.url, e.inner_port, e.key, e.inner_key, e.model,
               e.context_length, e.catalog_provider)
              for e in cfg.llm_map),
        cfg.users_enabled,
        tuple((u.username, u.passkey) for u in cfg.users),
        cfg.listen_host,
        cfg.listen_port,
    )


def merge_network(base_policy: dict, cfg: OpnConfig) -> dict:
    """`base_policy` (as printed by `policy get --base -o json`'s .policy)
    with only network_policies replaced by the freshly built one."""
    if not isinstance(base_policy, dict):
        raise RuntimeError(f"base policy is not an object: {type(base_policy)}")
    merged = dict(base_policy)
    merged["network_policies"] = build_policy(cfg)["network_policies"]
    return merged
