#!/bin/sh
# Build a Debian package of terminal-hub (Linux x86_64 musl by default).
#
# Prerequisites:
#   cargo install cargo-deb
#   For musl: rustup target add x86_64-unknown-linux-musl + musl-tools
#
# Output: target/debian/ (or target/<triple>/debian/) — final .deb path is
# printed at the end.
#
# Env vars:
#   TARGET   build target triple (default x86_64-unknown-linux-musl)
#            set to empty string to use the host glibc target instead.

set -eu

TARGET="${TARGET-x86_64-unknown-linux-musl}"

if ! command -v cargo-deb >/dev/null 2>&1; then
  echo "ERROR: cargo-deb not installed. Run: cargo install cargo-deb" >&2
  exit 1
fi

echo "Building release binaries…"
if [ -n "$TARGET" ]; then
    cargo build --release --target "$TARGET" -p terminal-hub-server -p terminal-hub-cli
    # cargo-deb's asset paths use target/release/. Symlink so they resolve
    # when we cross-build for musl.
    mkdir -p target/release
    ln -sf "$PWD/target/$TARGET/release/terminal-hub" target/release/terminal-hub
    ln -sf "$PWD/target/$TARGET/release/terminal-hub-cli" target/release/terminal-hub-cli
    DEB_TARGET_FLAG="--target=$TARGET"
else
    cargo build --release -p terminal-hub-server -p terminal-hub-cli
    DEB_TARGET_FLAG=""
fi

echo "Packaging .deb…"
# --no-strip: our release profile already does `strip = "debuginfo"` (root
# Cargo.toml). Letting cargo-deb call `strip` again breaks on macOS hosts
# whose Apple `strip` doesn't accept GNU's --strip-unneeded.
cargo deb -p terminal-hub-server --no-build --no-strip $DEB_TARGET_FLAG

echo
echo "Built:"
find target -maxdepth 4 -name '*.deb' -newer Cargo.toml -print
