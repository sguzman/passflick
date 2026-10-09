#!/usr/bin/env bash
# Headless Wayland compositor startup test with fictional demo credentials.
# This verifies a native Wayland window reaches its first egui frame; it does
# not claim to test Hyprland's floating rules or real clipboard behavior.
set -euo pipefail

tmp="$(mktemp -d)"
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
  rm -rf "$tmp"
}
trap cleanup EXIT

export XDG_RUNTIME_DIR="$tmp/runtime"
mkdir -m 700 "$XDG_RUNTIME_DIR"
export WAYLAND_DISPLAY="passflick-ci-wayland"
export PASSFLICK_TRACE_STARTUP=1
export PASSFLICK_VAULT="$tmp/nonexistent.passvault"
export LIBGL_ALWAYS_SOFTWARE=1
unset DISPLAY WINIT_UNIX_BACKEND

weston --backend=headless --renderer=gl --no-config --idle-time=0 \
  --socket="$WAYLAND_DISPLAY" --width=800 --height=600 \
  --log="$tmp/weston.log" >"$tmp/weston.stdout" 2>"$tmp/weston.stderr" &
weston_pid="$!"

for _ in $(seq 1 100); do
  if [[ -S "$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY" ]]; then
    break
  fi
  if ! kill -0 "$weston_pid" 2>/dev/null; then
    cat "$tmp/weston.log" "$tmp/weston.stderr" >&2
    echo "Headless Weston compositor exited before opening its socket" >&2
    exit 1
  fi
  sleep 0.1
done
if [[ ! -S "$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY" ]]; then
  cat "$tmp/weston.log" "$tmp/weston.stderr" >&2
  echo "No Wayland display socket appeared" >&2
  exit 1
fi

./target/debug/passflick demo >"$tmp/picker.stdout" 2>"$tmp/picker.stderr" &
picker_pid="$!"

for _ in $(seq 1 150); do
  if grep -q '^passflick-startup first-frame ' "$tmp/picker.stderr"; then
    echo "Passflick reached its first native Wayland frame with synthetic credentials."
    exit 0
  fi
  if ! kill -0 "$picker_pid" 2>/dev/null; then
    cat "$tmp/picker.stderr" "$tmp/weston.log" >&2
    echo "Wayland picker exited before its first frame" >&2
    exit 1
  fi
  sleep 0.1
done
cat "$tmp/picker.stderr" "$tmp/weston.log" >&2
echo "Wayland picker never rendered its first frame" >&2
exit 1
