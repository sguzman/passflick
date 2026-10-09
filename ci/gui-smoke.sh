#!/usr/bin/env bash
# Synthetic X11 smoke test for the real egui picker. No vault or real password data.
set -euo pipefail

root="$(mktemp -d)"
picker_pid=""
cleanup() {
  if [[ -n "$picker_pid" ]]; then
    kill "$picker_pid" 2>/dev/null || true
    wait "$picker_pid" 2>/dev/null || true
  fi
  rm -rf "$root"
}
trap cleanup EXIT

mkdir -p "$root/bin"
cat > "$root/bin/wl-copy" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
case " $* " in *" --sensitive "*) ;; *) exit 23 ;; esac
case " $* " in *" --trim-newline "*) exit 24 ;; esac
cat > "$PASSFLICK_TEST_CLIPBOARD"
STUB
chmod 700 "$root/bin/wl-copy"
export PATH="$root/bin:$PATH"
export PASSFLICK_TEST_CLIPBOARD="$root/clipboard"
export PASSFLICK_VAULT="$root/nonexistent.passvault"
export LIBGL_ALWAYS_SOFTWARE=1
export WINIT_UNIX_BACKEND=x11
unset WAYLAND_DISPLAY

launch_picker() {
  if [[ "${1:-demo}" == "normal" ]]; then
    ./target/debug/passflick > "$root/stdout" 2> "$root/stderr" &
  else
    ./target/debug/passflick demo > "$root/stdout" 2> "$root/stderr" &
  fi
  picker_pid="$!"
  local window=""
  for _ in $(seq 1 150); do
    window="$(xdotool search --onlyvisible --name Passflick 2>/dev/null | head -n 1 || true)"
    if [[ -n "$window" ]]; then
      sleep 0.4
      xdotool windowfocus --sync "$window"
      echo "$window"
      return 0
    fi
    if ! kill -0 "$picker_pid" 2>/dev/null; then
      cat "$root/stderr" >&2
      echo "Picker terminated before a visible window appeared" >&2
      return 1
    fi
    sleep 0.1
  done
  cat "$root/stderr" >&2
  echo "Picker did not open a visible window within the smoke-test budget" >&2
  return 1
}

await_exit() {
  for _ in $(seq 1 100); do
    if ! kill -0 "$picker_pid" 2>/dev/null; then
      wait "$picker_pid"
      picker_pid=""
      return 0
    fi
    sleep 0.1
  done
  cat "$root/stderr" >&2
  echo "Picker did not close after the expected key" >&2
  return 1
}

echo "Synthetic GUI test: fuzzy search, Enter -> password, exit"
launch_picker >/dev/null
xdotool type --clearmodifiers --delay 35 'Another'
xdotool key --clearmodifiers Return
await_exit
printf 'synthetic-demo-password-gamma' > "$root/expected"
cmp "$root/expected" "$PASSFLICK_TEST_CLIPBOARD"

echo "Synthetic GUI test: Shift+Enter -> username, exit"
launch_picker >/dev/null
xdotool type --clearmodifiers --delay 35 'Example'
xdotool key --clearmodifiers shift+Return
await_exit
printf 'alice@example.test' > "$root/expected"
cmp "$root/expected" "$PASSFLICK_TEST_CLIPBOARD"

echo "Synthetic GUI test: Escape leaves clipboard unchanged"
launch_picker >/dev/null
xdotool key --clearmodifiers Escape
await_exit
cmp "$root/expected" "$PASSFLICK_TEST_CLIPBOARD"

echo "Synthetic GUI test: first-run setup rejects mismatched passphrases"
export PASSFLICK_VAULT="$root/new-vault.passvault"
launch_picker normal >/dev/null
xdotool type --clearmodifiers --delay 25 'fictional-test-passphrase-42'
xdotool key --clearmodifiers Tab
xdotool type --clearmodifiers --delay 25 'mismatch-test-passphrase'
xdotool key --clearmodifiers Return
sleep 0.4
test ! -e "$PASSFLICK_VAULT"
xdotool key --clearmodifiers Escape
await_exit

echo "Synthetic GUI test: first-run setup creates private encrypted vault"
launch_picker normal >/dev/null
xdotool type --clearmodifiers --delay 25 'fictional-test-passphrase-42'
xdotool key --clearmodifiers Tab
xdotool type --clearmodifiers --delay 25 'fictional-test-passphrase-42'
xdotool key --clearmodifiers Return
for _ in $(seq 1 100); do
  if [[ -f "$PASSFLICK_VAULT" ]]; then break; fi
  sleep 0.1
done
test -f "$PASSFLICK_VAULT"
test "$(stat -c '%a' "$PASSFLICK_VAULT")" = "600"
if grep -aq 'fictional-test-passphrase-42' "$PASSFLICK_VAULT"; then
  echo "Vault file unexpectedly includes the plaintext test passphrase." >&2
  exit 1
fi
xdotool key --clearmodifiers Escape
await_exit

echo "Passflick synthetic GUI checks passed."
