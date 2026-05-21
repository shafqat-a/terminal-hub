#!/bin/sh
# terminal-hub install script (POSIX).
# Installs binaries into PREFIX/bin and the appropriate service template
# (systemd-user on Linux, launchd on macOS). Run from the unpacked release
# tarball directory.
#
# Env vars:
#   PREFIX        install prefix (default /usr/local)
#   SKIP_SERVICE  set to 1 to skip installing the service unit

set -eu

PREFIX="${PREFIX:-/usr/local}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
BIN_SRC="$HERE/bin"
DIST_SRC="$HERE/dist"

if [ ! -x "$BIN_SRC/terminal-hub" ] || [ ! -x "$BIN_SRC/terminal-hub-cli" ]; then
  echo "ERROR: expected $BIN_SRC/terminal-hub and terminal-hub-cli; run from the unpacked release tarball." >&2
  exit 1
fi

uname_s="$(uname -s)"
case "$uname_s" in
  Linux) OS=linux ;;
  Darwin) OS=macos ;;
  *) echo "ERROR: unsupported OS: $uname_s (Linux + macOS only; Windows: use WSL2)" >&2; exit 1 ;;
esac

TMUX_BIN="$(command -v tmux 2>/dev/null || true)"
if [ -z "$TMUX_BIN" ]; then
  echo "ERROR: tmux not on PATH. Install: brew install tmux  /  apt-get install tmux" >&2
  exit 1
fi

echo "Installing binaries to $PREFIX/bin/"
sudo install -m 0755 "$BIN_SRC/terminal-hub" "$PREFIX/bin/terminal-hub"
sudo install -m 0755 "$BIN_SRC/terminal-hub-cli" "$PREFIX/bin/terminal-hub-cli"

if [ "${SKIP_SERVICE:-0}" = "1" ]; then
  echo "SKIP_SERVICE=1; not installing service templates."
else
  case "$OS" in
    linux)
      DEST="$HOME/.config/systemd/user"
      mkdir -p "$DEST"
      for unit in tmux-server.service terminal-hub.service; do
        sed -e "s|__TMUX_BIN__|$TMUX_BIN|g" \
            -e "s|__INSTALL_PREFIX__|$PREFIX|g" \
            -e "s|__HOME__|$HOME|g" \
            "$DIST_SRC/systemd/$unit" > "$DEST/$unit"
      done
      echo "Installed systemd-user units to $DEST/"
      echo "Enable + start: systemctl --user enable --now tmux-server.service terminal-hub.service"
      ;;
    macos)
      DEST="$HOME/Library/LaunchAgents"
      mkdir -p "$DEST"
      for plist in dev.terminal-hub.tmux.plist dev.terminal-hub.plist; do
        sed -e "s|__TMUX_BIN__|$TMUX_BIN|g" \
            -e "s|__INSTALL_PREFIX__|$PREFIX|g" \
            -e "s|__HOME__|$HOME|g" \
            "$DIST_SRC/launchd/$plist" > "$DEST/$plist"
      done
      mkdir -p "$HOME/Library/Logs"
      echo "Installed launchd plists to $DEST/"
      echo "Load: launchctl load $DEST/dev.terminal-hub.tmux.plist $DEST/dev.terminal-hub.plist"
      ;;
  esac
fi

cat <<EOF

Next steps:
  1. Bootstrap the primary user (only the first time):
       $PREFIX/bin/terminal-hub-cli bootstrap --email you@example.com --pubkey ~/.ssh/id_ed25519.pub
  2. Open https://localhost:5999/login.html in your browser.
  3. Enroll a passkey from your laptop:
       $PREFIX/bin/terminal-hub-cli enroll --server https://localhost:5999 --email you@example.com --insecure
  4. For federation, see \`terminal-hub-cli peer-info\` and dist/config.sample.toml.

Install complete.
EOF
