#!/usr/bin/env bash
# Disposable Vaultwarden CI only. Uses an Xvfb-hosted Weston *Wayland* seat
# and actual pinned wl-copy 2.3.0 --sensitive; X11 transports test input only.
# Never invoke with real credentials or the user's real clipboard/session.
set -euo pipefail
umask 077

: "${PASSFLICK_PREVIEW_BINARY:?missing synthetic preview binary}"
: "${PASSFLICK_DISPOSABLE_TEST_DATA:?missing synthetic projection directory}"
: "${PASSFLICK_DISPOSABLE_TEST_LEGACY:?missing fictional legacy vault path}"
: "${PASSFLICK_NATIVE_FIRST_PASSWORD:?missing synthetic ordering hint}"
[[ "${PASSFLICK_NATIVE_FIRST_PASSWORD}" == first || "${PASSFLICK_NATIVE_FIRST_PASSWORD}" == second ]]
[[ "${PASSFLICK_PREVIEW_BINARY}" == /* ]]
[[ -n "${DISPLAY:-}" ]] || { echo 'Nested Weston requires virtual X11 host.' >&2; exit 1; }
command -v weston >/dev/null
command -v xdotool >/dev/null
command -v wl-copy >/dev/null
command -v wl-paste >/dev/null
wl-copy --help 2>&1 | grep -q -- '^[[:space:]]*--sensitive[[:space:]]'

root="$(mktemp -d)"
weston_pid=""
picker_pid=""
cleanup() {
  if [[ -n "$picker_pid" ]]; then
    kill "$picker_pid" 2>/dev/null || true
    wait "$picker_pid" 2>/dev/null || true
  fi
  if [[ -n "$weston_pid" ]]; then
    kill "$weston_pid" 2>/dev/null || true
    wait "$weston_pid" 2>/dev/null || true
  fi
  rm -rf "$root"
}
trap cleanup EXIT

export XDG_RUNTIME_DIR="$root/runtime"
mkdir -m 700 "$XDG_RUNTIME_DIR"
export WAYLAND_DISPLAY="passflick-ci-native"
export LIBGL_ALWAYS_SOFTWARE=1
# Keep Xvfb available ONLY to the nested compositor and input injector.
# The picker and clipboard tools explicitly have DISPLAY removed.
weston --backend=x11 --renderer=gl --no-config --idle-time=0 \
    --socket="$WAYLAND_DISPLAY" --width=960 --height=700 \
    --log="$root/weston.log" >"$root/weston.stdout" 2>"$root/weston.stderr" &
weston_pid="$!"

for _ in $(seq 1 120); do
  [[ -S "$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY" ]] && break
  if ! kill -0 "$weston_pid" 2>/dev/null; then
    echo 'Nested Weston exited before exposing native Wayland seat.' >&2
    exit 1
  fi
  sleep 0.1
done
[[ -S "$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY" ]] || { echo 'Weston socket unavailable.' >&2; exit 1; }

weston_window=""
for _ in $(seq 1 120); do
  weston_window="$(xdotool search --onlyvisible --name 'Weston' 2>/dev/null | head -n 1 || true)"
  [[ -n "$weston_window" ]] && break
  sleep 0.1
done
[[ -n "$weston_window" ]] || { echo 'Weston X11 output was not visible.' >&2; exit 1; }

launch() {
  env -u DISPLAY -u WINIT_UNIX_BACKEND \
    XDG_DATA_HOME="$PASSFLICK_DISPOSABLE_TEST_DATA" \
    PASSFLICK_VAULT="$PASSFLICK_DISPOSABLE_TEST_LEGACY" \
    "$PASSFLICK_PREVIEW_BINARY" projection picker >"$root/picker.stdout" 2>"$root/picker.stderr" &
  picker_pid="$!"
  # The compositor window is the X11 test-input target, not the application.
  # Input is forwarded by Weston to the actual native Wayland egui surface.
  for _ in $(seq 1 50); do
    if ! kill -0 "$picker_pid" 2>/dev/null; then
      echo 'Native Wayland projection picker exited before input.' >&2
      exit 1
    fi
    sleep 0.1
  done
  xdotool windowfocus --sync "$weston_window"
  # A real input serial and surface focus are required before wl-copy can
  # become the Wayland clipboard selection owner.
  xdotool mousemove --window "$weston_window" 430 125 click 1
  sleep 0.3
}
await_close() {
  for _ in $(seq 1 100); do
    if ! kill -0 "$picker_pid" 2>/dev/null; then
      wait "$picker_pid"
      picker_pid=""
      return 0
    fi
    sleep 0.1
  done
  echo 'Native Wayland picker did not exit after copy action.' >&2
  exit 1
}
read_clipboard() {
  for _ in $(seq 1 60); do
    if env -u DISPLAY timeout 3s wl-paste --no-newline \
        --type 'text/plain;charset=utf-8' > "$root/actual" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  echo 'Native Wayland clipboard was not available.' >&2
  exit 1
}

# Copy the actual fictional Unicode username from the populated projection.
launch
xdotool key --clearmodifiers shift+Return
await_close
read_clipboard
printf 'mañana用户' > "$root/expected"
cmp "$root/expected" "$root/actual"
env -u DISPLAY wl-copy --clear >/dev/null 2>&1 || true

# Copy the selected password from the authenticated projection, including
# Unicode and intentional whitespace. No test data is written to public logs.
launch
xdotool key --clearmodifiers Return
await_close
read_clipboard
if [[ "$PASSFLICK_NATIVE_FIRST_PASSWORD" == first ]]; then
  printf '  🗝️ contraseña  ' > "$root/expected"
else
  printf 'second secret' > "$root/expected"
fi
cmp "$root/expected" "$root/actual"

# Escape must close the populated native Wayland picker WITHOUT copying or
# clearing the existing clipboard. Reuse the fictional password already copied
# above so the test does not create another clipboard owner or rely on a mock.
launch
xdotool key --clearmodifiers Escape
await_close
read_clipboard
cmp "$root/expected" "$root/actual"
env -u DISPLAY wl-copy --clear >/dev/null 2>&1 || true

echo 'Native Wayland populated picker copied exact fictional credentials and preserved clipboard on Escape.'
