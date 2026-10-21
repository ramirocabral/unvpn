#!/usr/bin/env bash
# unvpn installer — builds the engine (static OpenSSL) and the GUI, then installs
# both, the icons, the .desktop entry, and (optionally) a polkit rule.
#
#   ./install.sh              build + install under /usr/local
#   PREFIX=~/.local ./install.sh   user-local install (no root)
#   ./install.sh --uninstall  remove everything this script installed
set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
REPO="$(cd "$(dirname "$0")" && pwd)"

sudo_if_needed() {
    if [ "$(id -u)" -ne 0 ] && [ ! -w "$1" ]; then echo sudo; fi
}

uninstall() {
    local S; S="$(sudo_if_needed "$PREFIX/bin")"
    echo "Removing unvpn from $PREFIX …"
    $S rm -f "$PREFIX/bin/unvpn" "$PREFIX/bin/unvpn-gui"
    $S rm -f "$PREFIX/share/applications/unvpn.desktop"
    for sz in 32 48 64 128 256; do
        $S rm -f "$PREFIX/share/icons/hicolor/${sz}x${sz}/apps/unvpn.png"
    done
    [ -f /etc/polkit-1/rules.d/49-unvpn.rules ] && sudo rm -f /etc/polkit-1/rules.d/49-unvpn.rules || true
    echo "Done."
}

[ "${1:-}" = "--uninstall" ] && { uninstall; exit 0; }

command -v cargo >/dev/null || { echo "Need Rust/cargo — see https://rustup.rs"; exit 1; }

echo "==> Building engine (static OpenSSL, portable)…"
cargo build --release --features vendored --manifest-path "$REPO/unvpn/Cargo.toml"
echo "==> Building GUI…"
cargo build --release --manifest-path "$REPO/unvpn-gui/Cargo.toml"

S="$(sudo_if_needed "$PREFIX/bin")"
[ -n "$S" ] && echo "==> Installing to $PREFIX (sudo)…" || echo "==> Installing to $PREFIX …"
$S install -Dm755 "$REPO/unvpn/target/release/unvpn"    "$PREFIX/bin/unvpn"
$S install -Dm755 "$REPO/unvpn-gui/target/release/unvpn-gui"        "$PREFIX/bin/unvpn-gui"
for sz in 32 48 64 128 256; do
    $S install -Dm644 "$REPO/packaging/icons/unvpn-$sz.png" \
        "$PREFIX/share/icons/hicolor/${sz}x${sz}/apps/unvpn.png"
done
$S install -Dm644 "$REPO/packaging/unvpn.desktop" "$PREFIX/share/applications/unvpn.desktop"

printf "Install polkit rule (connect prompts for admin once, then caches)? [y/N] "
read -r ans
if [ "$ans" = y ] || [ "$ans" = Y ]; then
    tmp="$(mktemp)"
    sed "s#/usr/local/bin/unvpn#$PREFIX/bin/unvpn#" "$REPO/packaging/49-unvpn.rules" > "$tmp"
    sudo install -Dm644 "$tmp" /etc/polkit-1/rules.d/49-unvpn.rules
    rm -f "$tmp"
fi

command -v gtk-update-icon-cache >/dev/null && $S gtk-update-icon-cache -qtf "$PREFIX/share/icons/hicolor" 2>/dev/null || true
command -v update-desktop-database >/dev/null && $S update-desktop-database -q "$PREFIX/share/applications" 2>/dev/null || true

echo
echo "Installed. Launch 'unvpn-gui', or find 'unvpn' in your application menu."
echo "  CLI engine: 'unvpn' (see 'unvpn --help')."
