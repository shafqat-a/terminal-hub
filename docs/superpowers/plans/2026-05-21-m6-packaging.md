# M6 — Packaging & Release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Important:** Refresh this plan after M5 ships. Binary names, CLI subcommand names, and config-file locations may have shifted; reconcile against what landed before writing any file contents below verbatim.

**Goal:** Make terminal-hub shippable. CI on every push (build + test + lint + fmt) on Linux musl and macOS aarch64. Tagged releases produce signed-by-GitHub tarballs with binaries + static assets + service templates. An `install.sh` script downloads the right artifact, drops binaries into `/usr/local/bin`, installs systemd-user or launchd templates, and prints next steps. Install docs cover prerequisites, bootstrap, peer pairing, and WSL2.

**Architecture:** Two GitHub Actions workflows (`ci.yml`, `release.yml`) using a shared OS matrix. `dist/` holds platform-specific service templates with `__USER__` / `__INSTALL_PREFIX__` placeholders that `install.sh` substitutes at install time. `deny.toml` enforces license + advisory hygiene in CI. Release profile in the root `Cargo.toml` enables LTO + symbol strip for small, fast binaries. No new Rust code lands; this milestone is configuration, scripts, and docs.

**Tech Stack:** GitHub Actions, `actions/checkout@v4`, `dtolnay/rust-toolchain@stable`, `Swatinem/rust-cache@v2`, `EmbarkStudios/cargo-deny-action@v1`, `softprops/action-gh-release@v2`. Linux uses `musl-tools` + `x86_64-unknown-linux-musl`. macOS builds natively for `aarch64-apple-darwin`. POSIX `sh` for `install.sh`.

**Spec reference:** `docs/superpowers/specs/2026-05-21-terminal-hub-design.md` §3 (non-goals — Windows is WSL2-only), §4 (platform targets + service install per platform), §14 (stack picks).

---

## Task 1: Release profile tuning in root `Cargo.toml`

Smaller, faster binaries for tagged releases. Thin LTO + one codegen unit gives most of the size/speed win without ballooning compile time the way `fat` LTO does. `strip = "debuginfo"` keeps panic backtraces working but removes ~70% of the binary size.

**Files:**
- Modify: `Cargo.toml`

- [ ] **Step 1: Append the release profile block**

Add to the bottom of root `Cargo.toml` (workspace manifest):

```toml
[profile.release]
lto = "thin"
codegen-units = 1
strip = "debuginfo"
```

- [ ] **Step 2: Smoke build**

Run: `cargo build --workspace --release`
Expected: clean build. Check the resulting binary size:

```bash
ls -lh target/release/terminal-hub target/release/terminal-hub-cli
```

Both should be in the low single-digit megabytes (vs ~25 MB unstripped debug). Run once to ensure it actually starts:

```bash
./target/release/terminal-hub --help 2>&1 | head -5 || true
```

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml
git commit -m "build: tune release profile for size (thin LTO, strip debuginfo)"
```

---

## Task 2: `cargo-deny` configuration

Bans unmaintained crates, fails on advisory-db CVEs, and pins an explicit license allow-list. Catches supply-chain regressions before they ship.

**Files:**
- Create: `deny.toml`

- [ ] **Step 1: Create the config**

Create `deny.toml`:

```toml
# https://embarkstudios.github.io/cargo-deny/checks/cfg.html

[graph]
all-features = false
no-default-features = false

[advisories]
db-path = "~/.cargo/advisory-db"
db-urls = ["https://github.com/rustsec/advisory-db"]
yanked = "deny"
ignore = []

[licenses]
confidence-threshold = 0.92
allow = [
  "MIT",
  "Apache-2.0",
  "Apache-2.0 WITH LLVM-exception",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "ISC",
  "MPL-2.0",
  "Unicode-DFS-2016",
  "Unicode-3.0",
  "Zlib",
  "CC0-1.0",
]
exceptions = []

[[licenses.clarify]]
name = "ring"
expression = "MIT AND ISC AND OpenSSL"
license-files = [{ path = "LICENSE", hash = 0xbd0eed23 }]

[bans]
multiple-versions = "warn"
wildcards = "deny"
highlight = "all"

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
allow-git = []
```

- [ ] **Step 2: Local smoke**

Install `cargo-deny` if missing, then run all checks:

```bash
cargo install --locked cargo-deny || true
cargo deny check
```

Expected: `advisories ok`, `bans ok`, `licenses ok`, `sources ok`. If a transitive crate uses an unlisted license, either add it to `licenses.allow` (if it's compatible with the project's MIT-OR-Apache-2.0 stance) or add a `[[licenses.clarify]]` block. Do **not** add unknown copyleft licenses (GPL, AGPL).

- [ ] **Step 3: Commit**

```bash
git add deny.toml
git commit -m "build: cargo-deny config (license allow-list + advisory check)"
```

---

## Task 3: GitHub Actions CI workflow

Runs on every push to `main` and every PR. Matrix over Ubuntu (Linux musl) and macOS (aarch64). Each job: install toolchain from `rust-toolchain.toml`, install `tmux` (needed for integration tests), build, test, clippy, fmt-check. A separate `deny` job runs `cargo-deny` once on Linux (license/advisory checks are platform-independent).

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Create the workflow**

Create `.github/workflows/ci.yml`:

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: "-D warnings"

jobs:
  fmt:
    name: rustfmt
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt
      - run: cargo fmt --all -- --check

  deny:
    name: cargo-deny
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: EmbarkStudios/cargo-deny-action@v1
        with:
          command: check
          arguments: --all-features

  build-test:
    name: build & test (${{ matrix.name }})
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        include:
          - name: linux-musl-x86_64
            os: ubuntu-latest
            target: x86_64-unknown-linux-musl
          - name: macos-arm64
            os: macos-latest
            target: aarch64-apple-darwin
    steps:
      - uses: actions/checkout@v4

      - name: Install rust toolchain (from rust-toolchain.toml)
        uses: dtolnay/rust-toolchain@stable
        with:
          targets: ${{ matrix.target }}
          components: clippy

      - uses: Swatinem/rust-cache@v2
        with:
          key: ${{ matrix.target }}

      - name: Install Linux deps
        if: runner.os == 'Linux'
        run: |
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends \
            musl-tools \
            tmux \
            pkg-config

      - name: Install macOS deps
        if: runner.os == 'macOS'
        run: |
          brew update
          brew install tmux

      - name: Verify tmux version
        run: tmux -V

      - name: Build (release)
        run: cargo build --workspace --release --target ${{ matrix.target }}

      - name: Test
        run: cargo test --workspace --target ${{ matrix.target }}

      - name: Clippy
        run: cargo clippy --workspace --target ${{ matrix.target }} -- -D warnings
```

- [ ] **Step 2: Validate the YAML**

Locally:

```bash
python3 -c 'import yaml,sys; yaml.safe_load(open(".github/workflows/ci.yml"))' && echo OK
```

Or, if `actionlint` is available:

```bash
actionlint .github/workflows/ci.yml
```

Expected: no errors.

- [ ] **Step 3: Push a throwaway branch and confirm the run**

After committing this task, push a branch and open a PR (manually, separately). All four jobs should go green. If `cargo test` fails on macOS because tmux startup paths differ, file a follow-up but do not loosen the workflow.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: matrix workflow (linux-musl + macos-arm64): fmt, clippy, test, deny"
```

---

## Task 4: GitHub Actions release workflow

Triggered by `v*.*.*` tags. Same matrix as CI. Builds release binary, strips it, copies static assets + service templates + sample config into a versioned tarball, uploads as a GitHub release asset. macOS dynamically links (allowed by spec §4); Linux statically links via musl.

**Files:**
- Create: `.github/workflows/release.yml`

- [ ] **Step 1: Create the workflow**

Create `.github/workflows/release.yml`:

```yaml
name: Release

on:
  push:
    tags:
      - 'v*.*.*'

env:
  CARGO_TERM_COLOR: always

permissions:
  contents: write   # needed to create the release + upload assets

jobs:
  build:
    name: build (${{ matrix.name }})
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        include:
          - name: linux-musl-x86_64
            os: ubuntu-latest
            target: x86_64-unknown-linux-musl
            artifact: terminal-hub-${{ github.ref_name }}-x86_64-unknown-linux-musl.tar.gz
          - name: macos-arm64
            os: macos-latest
            target: aarch64-apple-darwin
            artifact: terminal-hub-${{ github.ref_name }}-aarch64-apple-darwin.tar.gz
    steps:
      - uses: actions/checkout@v4

      - name: Install rust toolchain
        uses: dtolnay/rust-toolchain@stable
        with:
          targets: ${{ matrix.target }}

      - uses: Swatinem/rust-cache@v2
        with:
          key: release-${{ matrix.target }}

      - name: Install Linux deps
        if: runner.os == 'Linux'
        run: |
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends musl-tools

      - name: Build release binaries
        run: |
          cargo build --workspace --release --target ${{ matrix.target }}

      - name: Stage artifact tree
        shell: bash
        run: |
          set -euo pipefail
          VERSION="${GITHUB_REF_NAME#v}"
          STAGE="staging/terminal-hub-${VERSION}"
          mkdir -p "$STAGE/bin" "$STAGE/static" "$STAGE/dist"

          cp "target/${{ matrix.target }}/release/terminal-hub"      "$STAGE/bin/"
          cp "target/${{ matrix.target }}/release/terminal-hub-cli"  "$STAGE/bin/"

          # Strip — `strip` exists on both platforms; -x is macOS, no-op for Linux is fine.
          if [ "${{ runner.os }}" = "macOS" ]; then
            strip -x "$STAGE/bin/terminal-hub" "$STAGE/bin/terminal-hub-cli"
          else
            strip "$STAGE/bin/terminal-hub" "$STAGE/bin/terminal-hub-cli"
          fi

          # Static frontend assets (xterm.js page, CSS, JS) — served by the binary at runtime.
          cp -R crates/server/static/. "$STAGE/static/"

          # Service templates + install script + sample config.
          cp -R dist/. "$STAGE/dist/"

          # Top-level metadata.
          cp README.md LICENSE-MIT LICENSE-APACHE "$STAGE/" 2>/dev/null || true

          tar -C staging -czf "${{ matrix.artifact }}" "terminal-hub-${VERSION}"
          shasum -a 256 "${{ matrix.artifact }}" > "${{ matrix.artifact }}.sha256"
          ls -lh "${{ matrix.artifact }}"*

      - name: Upload to GitHub release
        uses: softprops/action-gh-release@v2
        with:
          files: |
            ${{ matrix.artifact }}
            ${{ matrix.artifact }}.sha256
          fail_on_unmatched_files: true
          generate_release_notes: true
```

- [ ] **Step 2: Validate the YAML**

```bash
python3 -c 'import yaml,sys; yaml.safe_load(open(".github/workflows/release.yml"))' && echo OK
```

- [ ] **Step 3: Dry-run check (no actual tag)**

Confirm the workflow file is wired correctly:

```bash
grep -E '^name:|^on:|tags:|aarch64|musl' .github/workflows/release.yml
```

Expected lines all present. Do **not** push a tag from this task — the next maintainer cuts the first real `v0.1.0` after install.sh + docs land.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: release workflow — tag v*.*.* builds linux-musl + macos-arm64 tarballs"
```

---

## Task 5: systemd user units (Linux)

Two units. `tmux-server.service` keeps the tmux server (socket `terminal-hub`) alive so that PTYs survive terminal-hub restarts (spec §8.3). `terminal-hub.service` runs the web server and depends on tmux being up. Both are **user** units (live under `~/.config/systemd/user/`), enabled with `systemctl --user enable --now`.

`__USER__` and `__INSTALL_PREFIX__` are substituted by `install.sh` at install time.

**Files:**
- Create: `dist/systemd/tmux-server.service`
- Create: `dist/systemd/terminal-hub.service`

- [ ] **Step 1: tmux-server unit**

Create `dist/systemd/tmux-server.service`:

```ini
[Unit]
Description=tmux server for terminal-hub (socket: terminal-hub)
Documentation=https://github.com/__USER__/terminal-hub
After=network.target

[Service]
Type=forking
# Start a detached tmux server on the dedicated `terminal-hub` socket with a
# placeholder session so the server has something to keep alive. terminal-hub
# itself attaches via `-CC` and never owns the tmux lifecycle.
ExecStart=/usr/bin/tmux -L terminal-hub new-session -d -s _boot 'sleep infinity'
ExecStop=/usr/bin/tmux -L terminal-hub kill-server
Restart=on-failure
RestartSec=2
# tmux exits 0 when killed cleanly; treat anything non-zero as a crash.
SuccessExitStatus=0

[Install]
WantedBy=default.target
```

- [ ] **Step 2: terminal-hub unit**

Create `dist/systemd/terminal-hub.service`:

```ini
[Unit]
Description=terminal-hub web server
Documentation=https://github.com/__USER__/terminal-hub
Requires=tmux-server.service
After=tmux-server.service network.target

[Service]
Type=simple
ExecStart=__INSTALL_PREFIX__/bin/terminal-hub
Restart=on-failure
RestartSec=3

# Hardening. Conservative defaults; revisit if the binary needs more.
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=%h/.config/terminal-hub %h/.local/share/terminal-hub

Environment=RUST_LOG=info
# Optional overrides — uncomment and edit, or use `systemctl --user edit terminal-hub`.
# Environment=TERMINAL_HUB_BIND=127.0.0.1:5999
# Environment=TERMINAL_HUB_TMUX_SOCKET=terminal-hub

[Install]
WantedBy=default.target
```

- [ ] **Step 3: Smoke test the unit files locally (Linux only)**

If on a Linux box with `systemd-analyze` available:

```bash
mkdir -p /tmp/th-unit-check
sed -e "s|__USER__|example|g" -e "s|__INSTALL_PREFIX__|/usr/local|g" \
    dist/systemd/tmux-server.service > /tmp/th-unit-check/tmux-server.service
sed -e "s|__USER__|example|g" -e "s|__INSTALL_PREFIX__|/usr/local|g" \
    dist/systemd/terminal-hub.service > /tmp/th-unit-check/terminal-hub.service
systemd-analyze verify /tmp/th-unit-check/tmux-server.service /tmp/th-unit-check/terminal-hub.service
```

Expected: no errors. (On macOS this step is skipped.)

- [ ] **Step 4: Commit**

```bash
git add dist/systemd/
git commit -m "dist: systemd user units for terminal-hub + dedicated tmux server"
```

---

## Task 6: launchd plists (macOS)

LaunchAgent equivalents of the systemd units, installed into `~/Library/LaunchAgents/`. `KeepAlive` ensures both processes respawn after crashes. Logs go to `~/Library/Logs/terminal-hub/` so users can `tail -f` them without root. Placeholders: `__HOME__`, `__INSTALL_PREFIX__`, `__TMUX_BIN__` (the last one is needed because Homebrew installs tmux to `/opt/homebrew/bin` on Apple Silicon and `/usr/local/bin` on Intel).

**Files:**
- Create: `dist/launchd/dev.terminal-hub.tmux.plist`
- Create: `dist/launchd/dev.terminal-hub.plist`

- [ ] **Step 1: tmux LaunchAgent**

Create `dist/launchd/dev.terminal-hub.tmux.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>dev.terminal-hub.tmux</string>

  <key>ProgramArguments</key>
  <array>
    <string>__TMUX_BIN__</string>
    <string>-L</string>
    <string>terminal-hub</string>
    <string>new-session</string>
    <string>-d</string>
    <string>-s</string>
    <string>_boot</string>
    <string>sleep infinity</string>
  </array>

  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>

  <key>StandardOutPath</key>
  <string>__HOME__/Library/Logs/terminal-hub/tmux.out.log</string>
  <key>StandardErrorPath</key>
  <string>__HOME__/Library/Logs/terminal-hub/tmux.err.log</string>
</dict>
</plist>
```

- [ ] **Step 2: terminal-hub LaunchAgent**

Create `dist/launchd/dev.terminal-hub.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>dev.terminal-hub</string>

  <key>ProgramArguments</key>
  <array>
    <string>__INSTALL_PREFIX__/bin/terminal-hub</string>
  </array>

  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
  <key>ThrottleInterval</key>
  <integer>3</integer>

  <key>EnvironmentVariables</key>
  <dict>
    <key>RUST_LOG</key>
    <string>info</string>
  </dict>

  <key>StandardOutPath</key>
  <string>__HOME__/Library/Logs/terminal-hub/server.out.log</string>
  <key>StandardErrorPath</key>
  <string>__HOME__/Library/Logs/terminal-hub/server.err.log</string>
</dict>
</plist>
```

- [ ] **Step 3: Validate**

If on macOS:

```bash
mkdir -p /tmp/th-plist-check
sed -e "s|__HOME__|$HOME|g" -e "s|__INSTALL_PREFIX__|/usr/local|g" -e "s|__TMUX_BIN__|/opt/homebrew/bin/tmux|g" \
    dist/launchd/dev.terminal-hub.tmux.plist > /tmp/th-plist-check/dev.terminal-hub.tmux.plist
sed -e "s|__HOME__|$HOME|g" -e "s|__INSTALL_PREFIX__|/usr/local|g" \
    dist/launchd/dev.terminal-hub.plist > /tmp/th-plist-check/dev.terminal-hub.plist
plutil -lint /tmp/th-plist-check/dev.terminal-hub.tmux.plist
plutil -lint /tmp/th-plist-check/dev.terminal-hub.plist
```

Expected: both report `OK`.

On Linux: `xmllint --noout dist/launchd/*.plist` at minimum verifies well-formed XML (skip if `xmllint` is missing).

- [ ] **Step 4: Commit**

```bash
git add dist/launchd/
git commit -m "dist: launchd plists for terminal-hub + tmux on macOS"
```

---

## Task 7: Sample config in `dist/`

Ship a commented `config.toml` so users have a starting point. Mirrors the schema spec §11 names; values are inert defaults the binary will overwrite on first bootstrap.

**Files:**
- Create: `dist/config.sample.toml`

- [ ] **Step 1: Create the sample**

Create `dist/config.sample.toml`:

```toml
# terminal-hub configuration.
# Copy to your config dir on first install:
#   Linux:   ~/.config/terminal-hub/config.toml
#   macOS:   ~/Library/Application Support/terminal-hub/config.toml
# Then run `terminal-hub-cli bootstrap` to register the primary user.

# Where the HTTP server listens. Loopback by default — put a reverse proxy
# (or ssh -L) in front if you want to expose it on a LAN.
bind = "127.0.0.1:5999"

# tmux socket name. Matches the -L flag passed to tmux by the systemd/launchd
# service template. Do not change unless you also edit the service unit.
tmux_socket = "terminal-hub"

# Boot session — terminal-hub uses `tmux -CC attach -t <this>` for the control
# channel. Created by the tmux-server service. Leave as default.
tmux_boot_session = "_boot"

# Primary user email. Set by `terminal-hub-cli bootstrap`; leave commented out
# until you've run it.
# primary_email = "you@example.com"
```

- [ ] **Step 2: Commit**

```bash
git add dist/config.sample.toml
git commit -m "dist: sample config.toml with commented defaults"
```

---

## Task 8: `install.sh` — download, install, configure

POSIX `sh` (not bash). Detects OS + arch, downloads the right tarball + SHA-256 from the latest GitHub release (or a pinned `--version`), verifies the checksum, places binaries in `/usr/local/bin/` (or `--prefix`), substitutes placeholders in service templates, copies them into the user service dir, and prints next steps.

**Files:**
- Create: `dist/install.sh`

- [ ] **Step 1: Write the script**

Create `dist/install.sh`:

```sh
#!/bin/sh
# terminal-hub installer.
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/__USER__/terminal-hub/main/dist/install.sh | sh
#   ./install.sh --version v0.1.0 --prefix /usr/local
#
# Supported platforms: Linux x86_64 (musl), macOS aarch64 (Apple silicon).
# Windows users: install WSL2 + Ubuntu, then run this script inside WSL.

set -eu

REPO="${TERMINAL_HUB_REPO:-__USER__/terminal-hub}"
VERSION=""
PREFIX="/usr/local"

usage() {
  cat <<EOF
terminal-hub installer

Options:
  --version v0.1.0     Install a specific tag (default: latest release)
  --prefix /usr/local  Install prefix for binaries (default: /usr/local)
  --help               Show this help

Environment:
  TERMINAL_HUB_REPO    Override the GitHub repo (default: __USER__/terminal-hub)
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --prefix)  PREFIX="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage >&2; exit 2 ;;
  esac
done

# ---- detect OS + arch ----
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux)
    case "$ARCH" in
      x86_64|amd64) TARGET="x86_64-unknown-linux-musl" ;;
      *) echo "unsupported Linux arch: $ARCH (only x86_64 is published)" >&2; exit 1 ;;
    esac ;;
  Darwin)
    case "$ARCH" in
      arm64|aarch64) TARGET="aarch64-apple-darwin" ;;
      x86_64) echo "Intel Macs are not currently published; build from source." >&2; exit 1 ;;
      *) echo "unsupported macOS arch: $ARCH" >&2; exit 1 ;;
    esac ;;
  *) echo "unsupported OS: $OS (Linux/macOS only; Windows users see WSL2 docs)" >&2; exit 1 ;;
esac

# ---- check prerequisites ----
need() { command -v "$1" >/dev/null 2>&1 || { echo "missing required tool: $1" >&2; exit 1; }; }
need curl
need tar
command -v shasum >/dev/null 2>&1 || command -v sha256sum >/dev/null 2>&1 || {
  echo "missing required tool: shasum or sha256sum" >&2; exit 1;
}

if ! command -v tmux >/dev/null 2>&1; then
  echo "WARNING: tmux is not installed."
  echo "  Linux:  sudo apt-get install tmux   (or your distro equivalent)"
  echo "  macOS:  brew install tmux"
  echo "  terminal-hub will refuse to start without it."
fi

# ---- resolve version ----
if [ -z "$VERSION" ]; then
  VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)"
  if [ -z "$VERSION" ]; then
    echo "could not resolve latest release; pass --version v0.1.0 explicitly" >&2
    exit 1
  fi
fi
VERSION_NUM="${VERSION#v}"

ARTIFACT="terminal-hub-${VERSION}-${TARGET}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARTIFACT}"

echo "==> downloading ${ARTIFACT}"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT
cd "$TMPDIR"

curl -fL --proto '=https' --tlsv1.2 -o "$ARTIFACT" "$URL"
curl -fL --proto '=https' --tlsv1.2 -o "${ARTIFACT}.sha256" "${URL}.sha256"

echo "==> verifying checksum"
if command -v shasum >/dev/null 2>&1; then
  shasum -a 256 -c "${ARTIFACT}.sha256"
else
  sha256sum -c "${ARTIFACT}.sha256"
fi

echo "==> extracting"
tar -xzf "$ARTIFACT"
STAGE="terminal-hub-${VERSION_NUM}"

# ---- install binaries ----
echo "==> installing binaries to ${PREFIX}/bin (sudo may prompt)"
SUDO=""
if [ "$(id -u)" -ne 0 ] && [ ! -w "${PREFIX}/bin" ]; then SUDO="sudo"; fi
$SUDO install -m 0755 "${STAGE}/bin/terminal-hub"     "${PREFIX}/bin/terminal-hub"
$SUDO install -m 0755 "${STAGE}/bin/terminal-hub-cli" "${PREFIX}/bin/terminal-hub-cli"

# ---- install service templates ----
USER_NAME="$(id -un)"
HOME_DIR="${HOME:-$(cd ~ && pwd)}"
TMUX_BIN="$(command -v tmux 2>/dev/null || echo /usr/bin/tmux)"

substitute() {
  # $1 = src, $2 = dst
  sed \
    -e "s|__USER__|${USER_NAME}|g" \
    -e "s|__INSTALL_PREFIX__|${PREFIX}|g" \
    -e "s|__HOME__|${HOME_DIR}|g" \
    -e "s|__TMUX_BIN__|${TMUX_BIN}|g" \
    "$1" > "$2"
}

case "$OS" in
  Linux)
    UNIT_DIR="${HOME_DIR}/.config/systemd/user"
    mkdir -p "$UNIT_DIR"
    substitute "${STAGE}/dist/systemd/tmux-server.service"   "${UNIT_DIR}/tmux-server.service"
    substitute "${STAGE}/dist/systemd/terminal-hub.service"  "${UNIT_DIR}/terminal-hub.service"
    echo "==> installed systemd user units to ${UNIT_DIR}"
    NEXT_ENABLE="systemctl --user daemon-reload && systemctl --user enable --now tmux-server.service terminal-hub.service"
    NEXT_LOGS="journalctl --user -u terminal-hub.service -f"
    ;;
  Darwin)
    AGENT_DIR="${HOME_DIR}/Library/LaunchAgents"
    LOG_DIR="${HOME_DIR}/Library/Logs/terminal-hub"
    mkdir -p "$AGENT_DIR" "$LOG_DIR"
    substitute "${STAGE}/dist/launchd/dev.terminal-hub.tmux.plist" "${AGENT_DIR}/dev.terminal-hub.tmux.plist"
    substitute "${STAGE}/dist/launchd/dev.terminal-hub.plist"      "${AGENT_DIR}/dev.terminal-hub.plist"
    echo "==> installed LaunchAgents to ${AGENT_DIR}"
    NEXT_ENABLE="launchctl load -w ${AGENT_DIR}/dev.terminal-hub.tmux.plist && launchctl load -w ${AGENT_DIR}/dev.terminal-hub.plist"
    NEXT_LOGS="tail -f ${LOG_DIR}/server.err.log"
    ;;
esac

# ---- install sample config (don't overwrite an existing one) ----
case "$OS" in
  Linux)  CFG_DIR="${HOME_DIR}/.config/terminal-hub" ;;
  Darwin) CFG_DIR="${HOME_DIR}/Library/Application Support/terminal-hub" ;;
esac
mkdir -p "$CFG_DIR"
if [ ! -f "${CFG_DIR}/config.toml" ]; then
  cp "${STAGE}/dist/config.sample.toml" "${CFG_DIR}/config.toml"
  echo "==> wrote sample config to ${CFG_DIR}/config.toml"
else
  echo "==> existing config at ${CFG_DIR}/config.toml — left untouched"
fi

cat <<EOF

terminal-hub ${VERSION} installed.

Next steps:
  1. Bootstrap the primary user (one time):
       terminal-hub-cli bootstrap --email you@example.com --pubkey ~/.ssh/id_ed25519.pub

  2. Start the services:
       ${NEXT_ENABLE}

  3. Open https://127.0.0.1:5999/ in your browser.
     macOS: you will see a self-signed cert warning. Run
       terminal-hub-cli install-cert
     to trust it system-wide (see docs/INSTALL.md).

  4. Tail logs if anything looks wrong:
       ${NEXT_LOGS}

Docs: https://github.com/${REPO}/blob/main/docs/INSTALL.md
EOF
```

- [ ] **Step 2: Lint the script**

```bash
sh -n dist/install.sh && echo "syntax OK"
shellcheck dist/install.sh 2>/dev/null || echo "(shellcheck not installed; skipping)"
chmod +x dist/install.sh
```

Expected: `syntax OK`. Any shellcheck `SC2086` warnings around `$SUDO` are intentional (we want word-splitting there) — silence with `# shellcheck disable=SC2086` on the affected lines if shellcheck is enforced.

- [ ] **Step 3: Dry-run smoke (no network)**

Test the OS-detection branch without actually downloading:

```bash
sh -x dist/install.sh --help
```

Expected: prints usage and exits 0.

- [ ] **Step 4: Commit**

```bash
git add dist/install.sh
git commit -m "dist: install.sh — detects OS/arch, downloads release, wires services"
```

---

## Task 9: Install / operator documentation

The doc users hit before they hit anything else. Covers prerequisites, the three install paths (script / manual tarball / build-from-source), first-run bootstrap, peer pairing, and troubleshooting. Includes the WSL2 path for Windows users (spec §3 + §4).

**Files:**
- Create: `docs/INSTALL.md`

- [ ] **Step 1: Write the doc**

Create `docs/INSTALL.md`:

```markdown
# Installing terminal-hub

terminal-hub is a small Rust web server that fronts long-lived tmux sessions in your browser. This guide walks through installation, first-run setup, peer pairing, and the most common operational tasks.

## Supported platforms

| Platform | Status | Notes |
|---|---|---|
| Linux x86_64 (any glibc or musl distro) | first-class | statically linked musl binary |
| macOS Apple Silicon (M1+) | first-class | dynamically linked |
| macOS Intel | build from source | no published binary |
| Linux aarch64 | build from source | no published binary |
| Windows | use WSL2 | see "Windows via WSL2" below |

## Prerequisites

- **tmux ≥ 3.0** on `PATH`.
  - Linux: `sudo apt-get install tmux` or your distro's equivalent.
  - macOS: `brew install tmux`.
- A modern browser (Chrome, Firefox, Safari, Edge — all current versions).
- For SSH-key enrollment: an existing ed25519 or RSA SSH key pair, ideally already loaded into `ssh-agent`.

## Install via the script (recommended)

    curl -fsSL https://raw.githubusercontent.com/__USER__/terminal-hub/main/dist/install.sh | sh

What it does:
1. Detects your OS + arch and downloads the matching release tarball from GitHub.
2. Verifies the SHA-256 checksum.
3. Installs `terminal-hub` and `terminal-hub-cli` to `/usr/local/bin/` (sudo will prompt if needed).
4. Installs systemd user units (Linux) or LaunchAgents (macOS) into your home directory.
5. Drops a sample config at `~/.config/terminal-hub/config.toml` (Linux) or `~/Library/Application Support/terminal-hub/config.toml` (macOS) if you don't already have one.

To pin a specific version: `./install.sh --version v0.1.0`. To install to a different prefix: `--prefix $HOME/.local`.

## Install manually from a release tarball

1. Grab the tarball + `.sha256` from the releases page for your target.
2. Verify and extract:

       shasum -a 256 -c terminal-hub-v0.1.0-aarch64-apple-darwin.tar.gz.sha256
       tar -xzf terminal-hub-v0.1.0-aarch64-apple-darwin.tar.gz
       cd terminal-hub-0.1.0

3. Copy `bin/terminal-hub` and `bin/terminal-hub-cli` somewhere on your `PATH`.
4. Copy `dist/systemd/*.service` to `~/.config/systemd/user/` (Linux) or `dist/launchd/*.plist` to `~/Library/LaunchAgents/` (macOS), substituting `__USER__`, `__INSTALL_PREFIX__`, `__HOME__`, `__TMUX_BIN__` placeholders with your values.

## Install by building from source

    git clone https://github.com/__USER__/terminal-hub
    cd terminal-hub
    cargo build --workspace --release
    sudo cp target/release/terminal-hub /usr/local/bin/
    sudo cp target/release/terminal-hub-cli /usr/local/bin/

Requires Rust ≥ the version pinned in `rust-toolchain.toml` and `tmux` on `PATH`. Same service-template substitution as the manual path above.

## First-run bootstrap

terminal-hub starts with no users. Until you bootstrap a primary, the HTTP layer refuses requests.

    terminal-hub-cli bootstrap \
        --email you@example.com \
        --pubkey ~/.ssh/id_ed25519.pub

This writes your SSH pubkey into the local state DB as the primary user's recovery factor.

Then start the services:

**Linux:**

    systemctl --user daemon-reload
    systemctl --user enable --now tmux-server.service terminal-hub.service

**macOS:**

    launchctl load -w ~/Library/LaunchAgents/dev.terminal-hub.tmux.plist
    launchctl load -w ~/Library/LaunchAgents/dev.terminal-hub.plist

## First-login (passkey enrollment)

From your laptop (which is allowed to talk to the server):

    terminal-hub-cli enroll --server https://your-host:5999 --email you@example.com

The CLI signs a server-issued challenge with your SSH key (via ssh-agent), receives a short-lived bootstrap token, and prints a URL. Open the URL, complete the WebAuthn passkey registration, and you're in. Every subsequent login uses the passkey.

## Peer pairing

To make instance **A** show sessions from instance **B** in its sidebar:

1. On **B**: `terminal-hub-cli peer-info` — prints B's peer pubkey fingerprint and TLS cert fingerprint (both verified out-of-band).
2. On **B**, authorize A's pubkey: `terminal-hub-cli peer-allow --pubkey <A-pubkey> --name "instance-a"`.
3. On **A**, in the browser sidebar: **+ Add server**, fill in URL, friendly name, peer fingerprint, TLS cert fingerprint. A will refuse to connect if either fingerprint doesn't match — no TOFU.

## TLS / cert trust

terminal-hub generates a self-signed certificate on first boot.

**macOS:** to silence the browser warning, run `terminal-hub-cli install-cert` to import the cert into the system keychain marked trusted for SSL. You can also do it by hand: open `~/Library/Application Support/terminal-hub/tls.crt`, drag into Keychain Access, double-click, expand "Trust", set "Secure Sockets Layer (SSL)" to "Always Trust".

**Linux:** browser trust is per-browser. Import the cert into Chrome/Firefox individually, or run terminal-hub behind a reverse proxy that has a real cert (Caddy, Tailscale Funnel, etc.).

## Windows via WSL2

terminal-hub does not ship a Windows binary. Use WSL2:

1. Install WSL2 with an Ubuntu distro:

       wsl --install -d Ubuntu

   Reboot if prompted. Open the Ubuntu shell from the Start menu.

2. Inside the WSL2 Ubuntu shell, install prerequisites and run the installer:

       sudo apt-get update && sudo apt-get install -y tmux curl
       curl -fsSL https://raw.githubusercontent.com/__USER__/terminal-hub/main/dist/install.sh | sh

3. WSL2 forwards `127.0.0.1` to Windows, so you can hit `https://127.0.0.1:5999/` from a Windows browser. If that doesn't work in your WSL2 networking mode, find the WSL2 IP with `ip addr show eth0 | grep inet` and use that instead.

4. To make terminal-hub auto-start when WSL boots, the systemd user units installed by the script work as-is — provided systemd is enabled in WSL2 (Ubuntu 22.04+ enables it by default; older versions need `/etc/wsl.conf` with `[boot]` then `systemd=true`).

## Troubleshooting

**`tmux: command not found` at startup.** Install tmux (see Prerequisites). terminal-hub refuses to start without it.

**`failed to connect to tmux socket "terminal-hub"`.** The tmux-server unit isn't running. Check it:

- Linux: `systemctl --user status tmux-server.service`
- macOS: `launchctl list | grep terminal-hub`

Start it manually to debug:

    tmux -L terminal-hub new-session -d -s _boot 'sleep infinity'

**Browser shows "your connection is not private."** The self-signed cert isn't trusted. See "TLS / cert trust" above.

**Logs:**

- Linux: `journalctl --user -u terminal-hub.service -f`
- macOS: `tail -f ~/Library/Logs/terminal-hub/server.err.log`

**Passkey login fails on a different device.** Passkeys are bound to the browser/device they were registered on. Re-run `terminal-hub-cli enroll` to issue a new bootstrap token and register a fresh passkey on the new device.

**Peer marked unreachable.** Sidebar dot is hollow. Expand the peer to trigger a reconnect; check that the peer's URL is reachable from this machine, and that the TLS cert + peer pubkey fingerprints still match (they change when the peer rotates either).

## Uninstall

**Linux:**

    systemctl --user disable --now terminal-hub.service tmux-server.service
    rm ~/.config/systemd/user/terminal-hub.service ~/.config/systemd/user/tmux-server.service
    sudo rm /usr/local/bin/terminal-hub /usr/local/bin/terminal-hub-cli
    # Optionally also: rm -rf ~/.config/terminal-hub

**macOS:**

    launchctl unload ~/Library/LaunchAgents/dev.terminal-hub.plist
    launchctl unload ~/Library/LaunchAgents/dev.terminal-hub.tmux.plist
    rm ~/Library/LaunchAgents/dev.terminal-hub.plist ~/Library/LaunchAgents/dev.terminal-hub.tmux.plist
    sudo rm /usr/local/bin/terminal-hub /usr/local/bin/terminal-hub-cli
    # Optionally also: rm -rf "~/Library/Application Support/terminal-hub" ~/Library/Logs/terminal-hub
```

- [ ] **Step 2: Lint the markdown**

```bash
wc -l docs/INSTALL.md
grep -E '^##' docs/INSTALL.md
```

Expected: a reasonable number of `##` section headers (around 10–12), no broken fences. If `mdformat` or `markdownlint` is installed locally, run it.

- [ ] **Step 3: Commit**

```bash
git add docs/INSTALL.md
git commit -m "docs: INSTALL.md — install, bootstrap, peer pairing, WSL2, troubleshooting"
```

---

## Task 10: README + CLAUDE.md status update

**Files:**
- Modify: `README.md`
- Modify: `CLAUDE.md`

- [ ] **Step 1: README — point at the install doc**

Add a section near the top of `README.md` (after the existing "Status" / "Dev setup" sections):

```markdown
## Install

See [docs/INSTALL.md](docs/INSTALL.md). Short version:

    curl -fsSL https://raw.githubusercontent.com/__USER__/terminal-hub/main/dist/install.sh | sh

Linux x86_64 (musl) and macOS Apple Silicon are published as release tarballs. Windows users: WSL2 + Ubuntu, then the same installer.
```

- [ ] **Step 2: CLAUDE.md status — mark M6 done**

Replace the `## Repository status` block in `CLAUDE.md` with:

```markdown
## Repository status

M6 (packaging & release) complete. CI matrix on Linux musl + macOS arm64 runs fmt/clippy/test/deny on every push. Tagged `v*.*.*` releases publish signed-by-GitHub tarballs containing static binaries + frontend assets + service templates. `dist/install.sh` installs from a release; `docs/INSTALL.md` walks through bootstrap, peer pairing, and WSL2.

Build: `cargo build --workspace --release`
Test: `cargo test --workspace` (requires `tmux` on PATH)
Run: `cargo run -p terminal-hub-server` (after `tmux -L terminal-hub new-session -d -s _boot 'sleep infinity'`)
Release: tag `vX.Y.Z` on `main` and push — GitHub Actions builds + publishes both platform tarballs.
```

- [ ] **Step 3: Commit**

```bash
git add README.md CLAUDE.md
git commit -m "docs: README + CLAUDE.md status reflecting M6 completion"
```

---

## Done criteria for M6

- `cargo build --workspace --release` produces stripped binaries < 10 MB each on both platforms.
- `cargo deny check` passes locally and in CI.
- `.github/workflows/ci.yml` runs green on push to `main`.
- Tagging `v0.0.1-rc1` (or any `v*.*.*`) triggers `release.yml`, which uploads:
  - `terminal-hub-<version>-x86_64-unknown-linux-musl.tar.gz` + `.sha256`
  - `terminal-hub-<version>-aarch64-apple-darwin.tar.gz` + `.sha256`
- A **clean Linux VM** (no Rust, no prior install): `apt-get install tmux`, then `curl … | sh` from `install.sh`, then `terminal-hub-cli bootstrap` + service enable → server reachable at `https://127.0.0.1:5999/`, passkey enrollment completes, sessions work.
- A **clean macOS box** (no Xcode, no Rust): `brew install tmux`, then the same install path → server reachable, cert-trust step works, passkey enrollment completes.
- `docs/INSTALL.md` accurately documents both paths end-to-end with no missing prerequisites.

## After M6 — follow-ups (not in scope)

- **macOS code signing + notarization.** A signed `.pkg` (or at minimum signed/notarized standalone binaries) so users don't have to dismiss Gatekeeper warnings. Requires an Apple Developer account and the signing identity wired into the release workflow as a GitHub secret.
- **Windows EV cert.** If a native Windows build ever lands (currently out of scope per spec §3), it'll want an EV code-signing cert to avoid SmartScreen warnings.
- **Homebrew tap.** `homebrew-terminal-hub` formula auto-bumped by the release workflow.
- **`.deb` / `.rpm` packages.** Native Linux packages with proper dependency declarations on tmux, post-install hooks for the systemd units, and uninstall cleanup. `cargo-deb` and `cargo-generate-rpm` are the obvious tools.
- **Auto-update.** terminal-hub-cli could check for newer releases and self-update; today users re-run `install.sh`.
- **Linux aarch64 + macOS Intel.** Both are mechanical additions to the matrix once we have CI runners (Linux arm64 via `runs-on: ubuntu-24.04-arm`, macOS Intel via `macos-13`).
- **SBOM generation.** `cargo cyclonedx` or `syft` in the release workflow, attached as a release asset.
- **Reproducible builds.** Pinning `--locked` everywhere is half the story; full reproducibility needs deterministic timestamps and a frozen toolchain image.
