# Vaultwarden projection — native Wayland host acceptance

**Target-host acceptance: not yet passed.** This is an acceptance specification, not an instruction to migrate live credentials. The opt-in `vaultwarden-preview` picker has **passed** [disposable Vaultwarden/native Weston clipboard acceptance](https://github.com/sguzman/passflick/actions/runs/41893572619), and a real fictional masked GUI unlock has passed under Xvfb. This is **not** acceptance on the actual EndeavourOS/Hyprland login session. The historical default picker must remain usable until the target-host and migration gates pass.

## Fixture isolation before every test

- Use **fictional** `example.test` logins on a **disposable** Vaultwarden server; never authenticate the preview against a personal account or expose real credentials in screenshots, logs, or public artifacts.
- Use a private temporary `XDG_DATA_HOME` and an independently named `PASSFLICK_VAULT` path **that is not the historical vault**, and build the feature-enabled executable through the approved `mbx` workflow. Avoid alternate Cargo targets and scratch build directories.
- Test under the actual login session with `WAYLAND_DISPLAY` set and X11 fallback disabled. The feature-enabled command is `passflick projection picker`; plain `passflick` is still the legacy picker. Verify the Wayland app ID with `hyprctl clients`.
- Verify `wl-copy --help` advertises its long `--sensitive` option before copying; old helpers must fail without copying. Do not use clipboard managers that send fictional test values to a network service.
- Before testing with a disposable server, prove that the preview opens in its locked state with **no snapshot**, and that Escape closes without creating a legacy vault or changing the existing clipboard.

## Native Wayland input and clipboard

- A populated feature-enabled preview launches as a floating, centered `passflick-projection-preview` window, without moving tiled windows or focusing another workspace. Record measured first-frame focus/startup latency, not an assumed target.
- Website search is initially focused; typing filters title and every URI. Ctrl+Space switches to the account filter, retains both query strings, and does not leak URL paths or tokens through row labels.
- Arrow Up/Down selects among separately preserved upstream item IDs; identical site/username pairs remain separately selectable and show a safe variant suffix.
- Enter copies **exact fictional password bytes**, including Unicode, leading/trailing whitespace and any trailing newline, and closes. Shift+Enter copies **exact fictional username bytes**, including Unicode, and closes. Fast Shift release in the same frame must not choose the wrong field. Escape closes without modifying clipboard selection.
- Use the real sensitive-capable `wl-copy` and `wl-paste` in the Wayland session; no X11-mode fallback for this test. Check the **actual clipboard history policy** independently because `--sensitive` is an advisory hint, not guaranteed suppression.

## Offline, locking and refresh

- With the disposable Vaultwarden server offline, the most recently verified encrypted snapshot remains readable **only** after the appropriate local unlock; the UI labels its sync age and that offline access may be stale. A corrupt or absent snapshot fails closed.
- In the **locked GUI**, type the independent local passphrase into the masked field and press Enter. A wrong passphrase must not copy, close, or clear a manual-lock denial. A correct local passphrase must restore the authenticated snapshot **without a network request or a copy on that Enter event**; only a new, deliberate Enter should copy the fictional credential. This sequence passed in disposable Xvfb CI; repeat it on the actual Wayland target.
- From a separate CLI process, run `passflick projection lock` while the populated GUI is open; the GUI must stop copying and clear displayed credentials. A failed unlock must not remove manual-lock denial; an explicit correct local unlock restores access.
- Edit a fictional password remotely, then explicitly refresh with `passflick update`. A previously open picker must refuse to copy the unseen changed value even if the upstream ID matches. Server/account identity swaps must not authorize a colliding item ID.
- Test archive/deletion, failed network/TLS/MFA, malformed sync, concurrent update/lock and interrupted write. Failures must preserve the last good encrypted snapshot, with no stale data represented as live server state.
- On **the target host**, record session-keyring behavior after logout/login. This requires an explicitly agreed login-session change; **never log out or reboot automatically** during acceptance. No clipboard contents should be written to disk.

## Migration gate

Do not cut over the default command, remove old browser source code or delete `vault.passvault` until all the above pass and there is a documented reversible rollback. Record results in `ROADMAP.md` with the commit SHA, CI run IDs, host environment and which checks are still unverified. These checks are product prerequisites, not an automatic release authorization.
