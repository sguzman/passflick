#!/usr/bin/env bash
# Offline desktop integration test with a dummy executable, never credentials.
set -euo pipefail
root="$(mktemp -d)"
trap 'rm -rf -- "$root"' EXIT
bundle="$root/package"
mkdir -p -- "$bundle"
cp -- scripts/install-user.sh "$bundle/install-user.sh"
cp -- desktop/passflick.desktop "$bundle/passflick.desktop"
printf '#!/bin/sh\nexit 0\n' > "$bundle/passflick"
chmod 755 "$bundle/passflick"

export HOME="$root/example home"
export XDG_BIN_HOME="$HOME/my local bin"
export XDG_DATA_HOME="$HOME/my app data"
mkdir -p -- "$HOME"
bash "$bundle/install-user.sh"

installed="$XDG_DATA_HOME/applications/passflick.desktop"
test -x "$XDG_BIN_HOME/passflick"
cmp -- "$bundle/passflick" "$XDG_BIN_HOME/passflick"
desktop-file-validate "$installed"
grep -Fx 'Terminal=false' "$installed"
grep -Fx "Exec=\"$XDG_BIN_HOME/passflick\"" "$installed"
if grep -E '^Exec=.*(kitty|sh -c|bash -c)' "$installed"; then
  echo "Graphical launcher unexpectedly depends on a terminal or shell." >&2
  exit 1
fi
echo "Standalone desktop installer passed."
