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
  ./target/debug/passflick demo > "$root/stdout" 2> "$root/stderr" &
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

echo "Passflick synthetic GUI checks passed."
