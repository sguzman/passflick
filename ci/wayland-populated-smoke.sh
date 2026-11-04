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
: "${PASSFLICK_NATIVE_LOCAL_PASSPHRASE:?missing fictional local unlock passphrase}"
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

# Weston sets an X11 UTF-8 output title using its configurable output
# name. It is NOT guaranteed to contain "Weston" (the old search failed).
# In this isolated Xvfb server, find the *mapped 960x700 output window*
# instead of relying on the compositor title/class or a locale.
weston_window=""
for _ in $(seq 1 120); do
  while IFS= read -r candidate; do
    [[ -n "$candidate" ]] || continue
    geometry="$(xdotool getwindowgeometry --shell "$candidate" 2>/dev/null || true)"
    if [[ "$geometry" == *"WIDTH=960"* && "$geometry" == *"HEIGHT=700"* ]]; then
      weston_window="$candidate"
      break
    fi
  done < <(xdotool search --onlyvisible --name '.*' 2>/dev/null || true)
  [[ -n "$weston_window" ]] && break
  if ! kill -0 "$weston_pid" 2>/dev/null; then
    echo 'Nested Weston compositor exited before creating X11 output.' >&2
    exit 1
  fi
  sleep 0.1
done
[[ -n "$weston_window" ]] || { echo 'Nested Weston X11 output geometry was not discoverable.' >&2; exit 1; }

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
  timeout 10s xdotool windowfocus --sync "$weston_window"
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
# The clipboard owner can become visible after the picker has exited.
# Poll for an exact match instead of accepting any available (possibly stale)
# selection. Do not print clipboard content, even on failure.
assert_clipboard() {
  local stage="$1"
  for _ in $(seq 1 60); do
    if env -u DISPLAY timeout 3s wl-paste --no-newline \
        --type 'text/plain;charset=utf-8' > "$root/actual" 2>/dev/null &&
        cmp -s "$root/expected" "$root/actual"; then
      return 0
    fi
    sleep 0.1
  done

  if [[ "$stage" == username ]]; then
    if [[ "$PASSFLICK_NATIVE_FIRST_PASSWORD" == first ]]; then
      printf '  🗝️ contraseña  ' > "$root/wrong-field"
    else
      printf 'second secret' > "$root/wrong-field"
    fi
    if cmp -s "$root/wrong-field" "$root/actual"; then
      echo 'Native Wayland Shift+Enter copied a password instead of a username.' >&2
      exit 1
    fi
  fi
  echo "Native Wayland $stage clipboard did not match the fictional fixture." >&2
  exit 1
}

# Copy the actual fictional Unicode username from the populated projection.
launch
xdotool key --clearmodifiers shift+Return
await_close
printf 'mañana用户' > "$root/expected"
assert_clipboard username
env -u DISPLAY wl-copy --clear >/dev/null 2>&1 || true

# Copy the selected password from the authenticated projection, including
# Unicode and intentional whitespace. No test data is written to public logs.
launch
xdotool key --clearmodifiers Return
await_close
if [[ "$PASSFLICK_NATIVE_FIRST_PASSWORD" == first ]]; then
  printf '  🗝️ contraseña  ' > "$root/expected"
else
  printf 'second secret' > "$root/expected"
fi
assert_clipboard password

# Escape must close the populated native Wayland picker WITHOUT copying or
# clearing the existing clipboard. Reuse the fictional password already copied
# above so the test does not create another clipboard owner or rely on a mock.
launch
xdotool key --clearmodifiers Escape
await_close
assert_clipboard Escape
env -u DISPLAY wl-copy --clear >/dev/null 2>&1 || true

# Additional native Wayland locked-GUI test, following the separate populated
# copy actions above. The local passphrase is fictional and never printed.
# This runs with the SAME independent projection directory and Linux keyring
# as the executable. No Vaultwarden server or historical vault is accessed.
projection_cli() {
  env -u DISPLAY -u WINIT_UNIX_BACKEND \
    XDG_DATA_HOME="$PASSFLICK_DISPOSABLE_TEST_DATA" \
    PASSFLICK_VAULT="$PASSFLICK_DISPOSABLE_TEST_LEGACY" \
    "$PASSFLICK_PREVIEW_BINARY" projection "$1" </dev/null 2>/dev/null
}
projection_cli lock >"$root/lock.status"
grep -Fxq 'Offline projection manually locked.' "$root/lock.status"
projection_cli status >"$root/lock.status"
grep -Fxq 'Offline projection manually locked.' "$root/lock.status"

# A known fictional sensitive selection must be preserved by *both* unlock
# attempts. This proves that a focused masked field's Enter is not a copy.
printf 'fictional pre-unlock clipboard marker' >"$root/expected"
env -u DISPLAY wl-copy --sensitive <"$root/expected"
assert_clipboard before-unlock

launch
# launch() clicks the generic header for clipboard serials, which can steal
# focus from the locked screen's auto-focused password editor. The native
# 740x495 preview is centered within Weston's 960x700 test output: target its
# masked input, not the title region used by the already-open picker tests.
xdotool mousemove --window "$weston_window" 430 307 click 1
sleep 0.2
xdotool type --clearmodifiers --delay 15 -- 'fictional wrong native passphrase'
xdotool key --clearmodifiers Return
# The bogus KDF must finish before we type into the now-cleared masked input.
sleep 3
[[ -n "$picker_pid" ]] && kill -0 "$picker_pid"
projection_cli status >"$root/lock.status"
grep -Fxq 'Offline projection manually locked.' "$root/lock.status"
assert_clipboard wrong-unlock

# Re-focus after a rejected KDF, and explicitly replace any still-visible
# fictional input so no timing-dependent text append can change the attempt.
xdotool mousemove --window "$weston_window" 430 307 click 1
xdotool key --clearmodifiers ctrl+a
xdotool type --clearmodifiers --delay 15 -- "$PASSFLICK_NATIVE_LOCAL_PASSPHRASE"
xdotool key --clearmodifiers Return
# Wait for an independent authenticated keyring status, not a blind sleep.
unlocked=0
for _ in $(seq 1 120); do
  if projection_cli status >"$root/lock.status" &&
      grep -Fq 'Offline projection unlocked:' "$root/lock.status"; then
    unlocked=1
    break
  fi
  [[ -n "$picker_pid" ]] && kill -0 "$picker_pid" || {
    echo 'Native Wayland locked picker exited unexpectedly during unlock.' >&2
    exit 1
  }
  sleep 0.1
done
[[ "$unlocked" == 1 ]] || {
  echo 'Native Wayland masked GUI unlock failed to authenticate local projection.' >&2
  exit 1
}
assert_clipboard correct-unlock

# A second deliberate Enter, after successful local unlock, may copy a secret.
xdotool key --clearmodifiers Return
await_close
if [[ "$PASSFLICK_NATIVE_FIRST_PASSWORD" == first ]]; then
  printf '  🗝️ contraseña  ' >"$root/expected"
else
  printf 'second secret' >"$root/expected"
fi
assert_clipboard after-unlock-copy
env -u DISPLAY wl-copy --clear >/dev/null 2>&1 || true

echo 'Native Wayland populated and masked-unlock picker passed exact fictional clipboard and lock checks.'
