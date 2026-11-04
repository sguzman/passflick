#!/usr/bin/env bash
# Only a fictional first-run state; never touches an existing user vault.
set -euo pipefail
dir="$(mktemp -d)"
pid=""
cleanup() {
  if [[ -n "$pid" ]]; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
  rm -rf "$dir"
}
trap cleanup EXIT
export XDG_DATA_HOME="$dir/xdg"
export PASSFLICK_VAULT="$dir/sentinel-legacy.passvault"
export WINIT_UNIX_BACKEND=x11
export LIBGL_ALWAYS_SOFTWARE=1
unset WAYLAND_DISPLAY
printf 'historical fictional vault sentinel' > "$PASSFLICK_VAULT"
./target/debug/passflick projection picker >"$dir/stdout" 2>"$dir/stderr" &
pid="$!"
window=""
for _ in $(seq 1 120); do
  window="$(xdotool search --onlyvisible --name 'Passflick.*Offline Projection' 2>/dev/null | head -n 1 || true)"
  if [[ -n "$window" ]]; then break; fi
  if ! kill -0 "$pid" 2>/dev/null; then
    echo 'Offline preview picker terminated early' >&2
    exit 1
  fi
  sleep 0.1
done
test -n "$window"
xdotool windowfocus --sync "$window"
xdotool key --clearmodifiers Return
sleep 0.25
kill -0 "$pid"
test ! -e "$XDG_DATA_HOME/passflick/vault.passvault"
test ! -e "$XDG_DATA_HOME/passflick/projection.pfsnapshot"
test "$(cat "$PASSFLICK_VAULT")" = 'historical fictional vault sentinel'
xdotool key --clearmodifiers Escape
for _ in $(seq 1 80); do
  if ! kill -0 "$pid" 2>/dev/null; then
    wait "$pid"
    pid=""
    echo 'Locked offline preview picker smoke passed.'
    exit 0
  fi
  sleep 0.1
done
echo 'Offline picker did not exit on Escape' >&2
exit 1
