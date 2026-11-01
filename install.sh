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
SWAY_CONF="${XDG_CONFIG_HOME:-$HOME/.config}/sway/config"
SWAY_MARK="# unvpn: start in the tray at login (added by install.sh)"

sudo_if_needed() {
    if [ "$(id -u)" -ne 0 ] && [ ! -w "$1" ]; then echo sudo; fi
}

uninstall() {
    local S; S="$(sudo_if_needed "$PREFIX/bin")"
    echo "Removing unvpn from $PREFIX …"
    $S rm -f "$PREFIX/bin/unvpn" "$PREFIX/bin/unvpn-gui" "$PREFIX/bin/unvpn-f5-launch"
    $S rm -f "$PREFIX/share/applications/unvpn.desktop" "$PREFIX/share/applications/unvpn-f5-handler.desktop"
    for sz in 32 48 64 128 256; do
        $S rm -f "$PREFIX/share/icons/hicolor/${sz}x${sz}/apps/unvpn.png"
    done
    [ -f /etc/polkit-1/rules.d/49-unvpn.rules ] && sudo rm -f /etc/polkit-1/rules.d/49-unvpn.rules || true
    rm -f "${XDG_CONFIG_HOME:-$HOME/.config}/autostart/unvpn.desktop"
    [ -f /etc/xdg/autostart/unvpn.desktop ] && sudo rm -f /etc/xdg/autostart/unvpn.desktop || true
    [ -f "$SWAY_CONF" ] && sed -i --follow-symlinks "/^$SWAY_MARK\$/,+1d" "$SWAY_CONF" || true
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

# f5-vpn:// scheme handler (webtop "Start" → native tunnel). Bake the installed
# engine path as the wrapper's default so it works even off PATH.
wtmp="$(mktemp)"
sed "s#/usr/local/bin/unvpn#$PREFIX/bin/unvpn#" "$REPO/packaging/unvpn-f5-launch" > "$wtmp"
$S install -Dm755 "$wtmp" "$PREFIX/bin/unvpn-f5-launch"
rm -f "$wtmp"
$S install -Dm644 "$REPO/packaging/unvpn-f5-handler.desktop" "$PREFIX/share/applications/unvpn-f5-handler.desktop"

printf "Install polkit rule (connect prompts for admin once, then caches)? [y/N] "
read -r ans
if [ "$ans" = y ] || [ "$ans" = Y ]; then
    tmp="$(mktemp)"
    sed "s#/usr/local/bin/unvpn#$PREFIX/bin/unvpn#" "$REPO/packaging/49-unvpn.rules" > "$tmp"
    sudo install -Dm644 "$tmp" /etc/polkit-1/rules.d/49-unvpn.rules
    rm -f "$tmp"
fi

printf "Start unvpn in the tray automatically at login? [y/N] "
read -r ans
if [ "$ans" = y ] || [ "$ans" = Y ]; then
    case "$PREFIX" in
        /usr|/usr/*|/opt|/opt/*) AUTOSTART_DIR=/etc/xdg/autostart; AS=sudo ;;
        *) AUTOSTART_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/autostart"; AS= ;;
    esac
    $AS install -Dm644 "$REPO/packaging/unvpn-autostart.desktop" "$AUTOSTART_DIR/unvpn.desktop"
    echo "==> Autostart entry: $AUTOSTART_DIR/unvpn.desktop (GNOME, KDE, …)"
    # Sway ignores XDG autostart: it needs an exec line in its own config.
    if [ -f "$SWAY_CONF" ]; then
        if grep -qE '^\s*exec.*unvpn-gui.*--tray' "$SWAY_CONF"; then
            echo "==> $SWAY_CONF already starts unvpn-gui --tray"
        else
            [ -n "$(tail -c1 "$SWAY_CONF")" ] && echo >> "$SWAY_CONF"
            printf '%s\nexec %s --tray\n' "$SWAY_MARK" "$PREFIX/bin/unvpn-gui" >> "$SWAY_CONF"
            echo "==> Added 'exec $PREFIX/bin/unvpn-gui --tray' to $SWAY_CONF (from next login)"
        fi
    else
        echo "    On a bare WM that ignores XDG autostart (Sway, i3), add"
        echo "    'exec unvpn-gui --tray' to its config."
    fi
fi

command -v gtk-update-icon-cache >/dev/null && $S gtk-update-icon-cache -qtf "$PREFIX/share/icons/hicolor" 2>/dev/null || true
command -v update-desktop-database >/dev/null && $S update-desktop-database -q "$PREFIX/share/applications" 2>/dev/null || true
# Make unvpn the default handler for f5-vpn:// links (writes the invoking user's
# mimeapps.list — best effort; run manually if installed as root for another user).
command -v xdg-mime >/dev/null && xdg-mime default unvpn-f5-handler.desktop x-scheme-handler/f5-vpn 2>/dev/null || true

echo
echo "Installed. Launch 'unvpn-gui', or find 'unvpn' in your application menu."
echo "  CLI engine: 'unvpn' (see 'unvpn --help')."
echo "  F5 webtop 'Start' → 'unvpn' is now the handler for f5-vpn:// links."
