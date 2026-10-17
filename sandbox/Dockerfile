# OpnAgent sandbox image: Ubuntu Server 24.04 + hermes-agent + opn-shim.
#
# This image is NOT run by docker compose — it is handed to OpenShell:
#   openshell sandbox create --from opnagent-sandbox:latest ...
# deploy/bootstrap.sh builds it with the host Docker engine.
#
# OpenShell requirements honored here:
#  - non-root USER (workload identity; UID >= 1)
#  - WORKDIR becomes the sandbox workspace on the Docker driver
#  - the agent and every tool it needs must be preinstalled
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# build-essential/python3-dev: without their uv.lock we resolve
# hermes' [all] extra with plain pip, and a dep occasionally sdist-builds.
# (Their [matrix] extra — the one needing libolm — we do not carry.)
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-venv python3-pip python3-dev build-essential \
        ca-certificates curl git ripgrep jq \
    && rm -rf /var/lib/apt/lists/*

# SQLite, pinned: ubuntu:24.04 ships libsqlite3 3.45.1, which hermes
# blacklists at startup (WAL-reset corruption bug, sqlite.org/wal.html
# #walresetbug) — every state db then degrades to journal_mode=DELETE
# with a WARNING per process per db. Fix is >=3.51.3, so we build the
# release from source into /usr/local: python3.12's stdlib _sqlite3
# dlopen's libsqlite3.so.0 by soname (stable since 3.x, ABI backward
# compatible) and ldconfig's cache resolves /usr/local/lib (listed first
# via libc.conf) ahead of /usr/lib/x86_64-linux-gnu. The venv python is
# a symlink to the system one, so the hermes interpreter inherits it.
# Pinned to an EXACT version (not "latest"): rebuilds must be bit-stable
# against upstream drift. Bump SQLITE_VER + SQLITE_YEAR together (tarballs
# live under sqlite.org/<release-year>/). The final assert fails the build
# if the pin and the loaded library ever disagree.
ARG SQLITE_VER=3.53.4
ARG SQLITE_YEAR=2026
RUN set -e; \
    VNN=$(echo "$SQLITE_VER" | awk -F. '{printf "%d%02d%02d00", $1, $2, $3}'); \
    curl -fsSLo /tmp/sqlite.tar.gz \
      "https://sqlite.org/${SQLITE_YEAR}/sqlite-autoconf-${VNN}.tar.gz"; \
    tar -xzf /tmp/sqlite.tar.gz -C /tmp; \
    cd /tmp/sqlite-autoconf-${VNN}; \
    ./configure --prefix=/usr/local --disable-static >/dev/null; \
    make -j"$(nproc)" >/dev/null; \
    make install >/dev/null; \
    ldconfig; \
    rm -rf /tmp/sqlite.tar.gz /tmp/sqlite-autoconf-${VNN}; \
    python3 -c "import sqlite3, sys; v = sqlite3.sqlite_version; print('stdlib sqlite3 ->', v); sys.exit(0 if tuple(map(int, v.split('.'))) >= tuple(map(int, '${SQLITE_VER}'.split('.'))) else 1)"

# hermes-agent from a git CHECKOUT at a GitHub date tag. Since 0.20 PyPI
# is not a distribution channel at all (setup.py hard-fails wheel builds)
# and since 0.21 wheels would not carry the web/TUI assets either —
# setup.py's docstring: assets are "resolved at runtime via env-var
# overrides set by the nix wrapper or the source-checkout layout". So we
# ship the checkout itself (their sanctioned layout) and pip-EDITABLE
# install into a dedicated venv: the guard only blocks bdist_wheel/sdist,
# build_editable is explicitly allowed. venv python stays the resolved
# interpreter OpenShell network rules bind to (/usr/bin/python3.12 —
# venv's python symlinks there); PYTHONDONTWRITEBYTECODE keeps the
# policy-read-only checkout free of runtime .pyc writes.
#
# GitHub date tags are the primary releases; --build-arg HERMES_REF=
# rc.35-v0.21.5 selects the release-candidate series instead. The
# v2026.9.24 tag IS version 0.21.5 (PyPI's newest, 0.19.0, is the
# v2026.7.20-era build and carries a dashboard bug — sessions page never
# leaves "loading" — reproduced against hermes directly with our stack
# fully bypassed).
ARG HERMES_REF=v0.22.2
RUN set -e; \
    git clone --depth 1 --branch "${HERMES_REF}" \
      https://github.com/NousResearch/hermes-agent.git /opt/hermes; \
    python3 -m venv /opt/hermes-venv; \
    /opt/hermes-venv/bin/pip install --no-cache-dir -e "/opt/hermes[all]"; \
    ln -sf /opt/hermes-venv/bin/hermes /usr/local/bin/hermes; \
    ln -sf /opt/hermes-venv/bin/hermes-agent /usr/local/bin/hermes-agent; \
    ln -sf /opt/hermes-venv/bin/hermes-acp /usr/local/bin/hermes-acp || true

# hermes-webui (github.com/nesquena/hermes-webui): the replacement for
# hermes' built-in dashboard web UI. Pure Python + vanilla JS — no build
# step, no bundler — so the git checkout IS the deployment. It runs the
# agent IN-PROCESS against the same ~/.hermes config.yaml the entrypoint
# generates, so provider/key wiring is unchanged (fake keys -> shim).
# Deps are only pyyaml + cryptography; install into hermes' venv so the
# server imports the agent packages side by side.
# Pinned to a release tag (GHCR images exist too, but we run inside OUR
# sandbox image, not a sidecar — a sidecar would run tools outside the
# OpenShell policy boundary, their two-container limitation #681).
ARG HERMES_WEBUI_REF=v0.52.458
RUN set -e; \
    git clone --depth 1 --branch "${HERMES_WEBUI_REF}" \
      https://github.com/nesquena/hermes-webui.git /opt/hermes-webui; \
    /opt/hermes-venv/bin/pip install --no-cache-dir \
      -r /opt/hermes-webui/requirements.txt; \
    test -f /opt/hermes-webui/server.py; \
    echo "hermes-webui ${HERMES_WEBUI_REF} baked at /opt/hermes-webui"

# Node 26 LTS: hermes' own Dockerfile "pins its toolchain to Node 26
# everywhere" and copies node+npm out of the node:26 image — both the
# build-time vite runs below and the dashboard's embedded chat TUI
# (`node --expose-gc /opt/hermes/ui-tui/dist/entry.js`) use it. The
# hermes-webui swap does NOT need node — the vite dists below are only
# kept so `hermes dashboard`/TUI still work as the entrypoint fallback
# and for manual CLI use inside the sandbox.
# Pre-baked under /usr (already read+exec in the sandbox policy
# baseline) so hermes never downloads node from nodejs.org at runtime —
# keep it out of the URL whitelist. Version looked up from nodejs.org's
# index.json (newest-first) so the patch number never needs hand-
# bumping. (.tar.gz not .tar.xz: ubuntu:24.04 ships no xz binary.)
ARG NODE_MAJOR=26
RUN set -e; \
    NV=$(curl -fsSL https://nodejs.org/dist/index.json \
          | jq -r --arg maj "v${NODE_MAJOR}." \
              '[.[] | select(.version | startswith($maj))][0].version'); \
    test -n "$NV" && test "$NV" != "null"; \
    curl -fsSLo /tmp/node.tar.gz \
      "https://nodejs.org/dist/${NV}/node-${NV}-linux-x64.tar.gz"; \
    mkdir -p /usr/local/node; \
    tar -xzf /tmp/node.tar.gz -C /usr/local/node --strip-components=1; \
    rm /tmp/node.tar.gz; \
    ln -sf /usr/local/node/bin/node /usr/local/bin/node; \
    ln -sf /usr/local/node/bin/npm  /usr/local/bin/npm; \
    ln -sf /usr/local/node/bin/npx  /usr/local/bin/npx; \
    node --version; npm --version

# hermes' two frontends are NOT in git — web (dashboard SPA; vite's
# outDir is hermes_cli/web_dist/) and ui-tui (chat TUI → ui-tui/dist/
# entry.js). The official image builds them exactly like the two
# `npm run build` lines below. Explicit `-w` workspaces mirror the
# official image's curated install (root + web + ui-tui + the two `file:`
# deps): apps/desktop (electron) and tests-js are deliberately NOT
# installed. npm_config_install_links=false is their own image's env —
# file: workspace deps must symlink so node_modules/.package-lock.json
# agrees with the root lock; when it disagrees _tui_need_npm_install()
# trips forever and hermes npm-installs at launch (EACCES/EROFS for us).
#
# HERMES_TUI_DIR makes _make_tui_argv take the prebuilt-bundle fast path
# (node --expose-gc $HERMES_TUI_DIR/dist/entry.js) and skip the npm
# cascade entirely; HERMES_WEB_DIST points the dashboard at the built
# SPA (their ENVs, verbatim paths). entrypoint.sh re-exports both —
# OpenShell does override image ENVs (HOME is proof).
# Playwright/headless-shell (~900 MB) and the s6-overlay/sqlite-rebuild
# machinery of their image are intentionally omitted: chat + dashboard
# is the whole surface here.
ENV npm_config_install_links=false \
    HERMES_WEB_DIST=/opt/hermes/hermes_cli/web_dist \
    HERMES_TUI_DIR=/opt/hermes/ui-tui
RUN set -e; cd /opt/hermes; \
    npm install --no-audit --fetch-retries=5 \
      -w web -w apps/shared -w ui-tui -w ui-tui/packages/hermes-ink; \
    npm cache clean --force; \
    (cd web && npm run build); \
    (cd ui-tui && npm run build); \
    test -f hermes_cli/web_dist/index.html; \
    test -f ui-tui/dist/entry.js; \
    echo "hermes assets: web_dist + ui-tui dist OK"

# No explicit --uid: ubuntu:24.04 already ships an `ubuntu` user at uid 1000.
# OpenShell only requires non-root; our policies bind binaries by PATH, not uid.
RUN useradd --create-home --shell /bin/bash opn
COPY shim/shim.py /opt/opnagent/shim/shim.py
COPY entrypoint.sh /opt/opnagent/entrypoint.sh
RUN chmod 755 /opt/opnagent/entrypoint.sh

USER opn
WORKDIR /home/opn/workspace
ENV HOME=/home/opn

CMD ["/opt/opnagent/entrypoint.sh"]
