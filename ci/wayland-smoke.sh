#!/usr/bin/env bash
# Headless Wayland compositor startup test with fictional demo credentials.
# Verify native Wayland first-frame rendering and a fictional clipboard
# round-trip. This does not prove Hyprland-specific floating or focus behavior.
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
# Nested Weston on Xvfb provides a Wayland seat; the pure headless backend
# has no seat and cannot exercise clipboard protocols.
unset WINIT_UNIX_BACKEND

weston --backend=x11 --renderer=gl --no-config --idle-time=0 \
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

# Weston already inherited DISPLAY; prevent winit from silently using X11.
unset DISPLAY
./target/debug/passflick demo >"$tmp/picker.stdout" 2>"$tmp/picker.stderr" &
picker_pid="$!"

first_frame=0
for _ in $(seq 1 150); do
  if grep -q '^passflick-startup first-frame ' "$tmp/picker.stderr"; then
    first_frame=1
    break
  fi
  if ! kill -0 "$picker_pid" 2>/dev/null; then
    cat "$tmp/picker.stderr" "$tmp/weston.log" >&2
    echo "Wayland picker exited before its first frame" >&2
    exit 1
  fi
  sleep 0.1
done
if [[ "$first_frame" -ne 1 ]]; then
  cat "$tmp/picker.stderr" "$tmp/weston.log" >&2
  echo "Wayland picker never rendered its first frame" >&2
  exit 1
fi
echo "Passflick reached its first native Wayland frame with synthetic credentials."

# Exercise the same MIME type, sensitive hint, and byte-preserving clipboard
# transport as Passflick. Do not run this with a real vault or user clipboard.
printf 'fictional-wayland-password  \n\n' > "$tmp/clipboard.expected"
# Ubuntu 24.04 ships wl-clipboard 2.2.1, which lacks --sensitive.
# Test raw Wayland byte transport on that runner, while the application
# deliberately fails closed rather than silently copying without the hint.
flags=()
if wl-copy --help 2>&1 | grep -q -- '--sensitive'; then
  flags+=(--sensitive)
else
  echo "Runner lacks wl-copy --sensitive; testing clipboard transport only."
fi
wl-copy "${flags[@]}" --type 'text/plain;charset=utf-8' < "$tmp/clipboard.expected"
timeout 10s wl-paste --no-newline --type 'text/plain;charset=utf-8' > "$tmp/clipboard.actual"
cmp "$tmp/clipboard.expected" "$tmp/clipboard.actual"
echo "Native Wayland clipboard preserved synthetic trailing spaces and newlines."
