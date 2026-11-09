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
cp -- "$installed" "$root/original-legacy.desktop"

# The feature-gated Vaultwarden picker gets its own desktop entry. Test with
# a fake CLI so no user data or encrypted projection can be accessed.
mkdir -p -- "$HOME/.cargo/bin"
cat > "$HOME/.cargo/bin/passflick" <<'EOF'
#!/bin/sh
if [ "${1:-}" = "--help" ]; then
  echo '  passflick projection <unlock|lock|status|picker>   EXPERIMENTAL offline projection'
else
  exit 0
fi
EOF
chmod 755 "$HOME/.cargo/bin/passflick"
fish --no-execute scripts/install-vaultwarden-launcher.fish
fish scripts/install-vaultwarden-launcher.fish
preview="$XDG_DATA_HOME/applications/passflick-vaultwarden.desktop"
desktop-file-validate "$preview"
grep -Fx "Exec=\"$HOME/.cargo/bin/passflick\" projection picker" "$preview"
grep -Fx 'Terminal=false' "$preview"
cmp -- "$root/original-legacy.desktop" "$installed" # existing launcher untouched
grep -Fx "Exec=\"$XDG_BIN_HOME/passflick\"" "$installed" # old installed entry untouched
sha_before="$(sha256sum "$preview" | cut -d ' ' -f1)"
if fish scripts/install-vaultwarden-launcher.fish; then
  echo "Preview launcher must refuse to overwrite an existing entry." >&2
  exit 1
fi
test "$sha_before" = "$(sha256sum "$preview" | cut -d ' ' -f1)"
echo "Opt-in Vaultwarden desktop launcher passed."
