#!/usr/bin/env bash
# Install this pre-release as a standalone graphical user application.
# No root privileges, terminal emulator, daemon, or compositor edits required.
set -euo pipefail

if [[ "$(id -u)" -eq 0 ]]; then
  echo "Run the user installer as your regular account, not root." >&2
  exit 1
fi

package_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
binary="$package_dir/passflick"
desktop="$package_dir/passflick.desktop"
if [[ ! -f "$binary" || ! -f "$desktop" ]]; then
  echo "The package must contain passflick and passflick.desktop." >&2
  exit 1
fi

bin_dir="${XDG_BIN_HOME:-$HOME/.local/bin}"
apps_dir="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
install -Dm755 -- "$binary" "$bin_dir/passflick"
mkdir -p -- "$apps_dir"

# Graphical launchers do not necessarily inherit an interactive shell's PATH.
# Point to the binary itself, not a terminal or shell command.
exec_path="$(cd -- "$bin_dir" && pwd -P)/passflick"
# Desktop-entry quoting, including literal percent signs (field codes).
exec_path="$(printf '%s' "$exec_path" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\$/\\$/g' -e 's/\x60/\\\x60/g' -e 's/%/%%/g')"

target="$apps_dir/passflick.desktop"
tmp="$(mktemp "$apps_dir/.passflick.desktop.XXXXXXXX")"
trap 'rm -f -- "$tmp"' EXIT
sed -e '/^Exec=/d' -e '/^TryExec=/d' -- "$desktop" > "$tmp"
printf 'Exec="%s"\n' "$exec_path" >> "$tmp"
chmod 644 "$tmp"
mv -f -- "$tmp" "$target"
trap - EXIT

printf 'Installed Passflick to %s\n' "$bin_dir/passflick"
printf 'Installed graphical launcher to %s\n' "$target"
printf 'Launch from your application menu or bind the binary in Hyprland.\n'
