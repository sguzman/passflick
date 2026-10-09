# Development queue

## Initial product

- [x] Identity, architecture, and interaction contract
- [x] Multi-source credential schema and CSV parsing
- [x] Encrypted vault, masked in-window unlock, and session-key caching adapted from OTPick
- [x] Per-vault session-key/explicit-lock isolation for safe independent testing
- [x] One-shot keyboard picker with Enter/Shift+Enter
- [x] Synthetic demo picker that never opens a real vault
- [x] Commit Cargo.lock and enforce locked builds in CI
- [x] Locked Linux CI: build, 42 tests, CLI smoke checks, formatting, and strict Clippy
- [x] Automated X11 keyboard/copy/close smoke tests under Xvfb
- [x] Automated native Wayland first-frame smoke test under headless Weston
- [ ] Complete [synthetic target-host acceptance](acceptance.md) on EndeavourOS/Hyprland
- [ ] Test actual Edge, Chrome, Firefox, and Apple export variants
- [ ] Confirm clipboard exit behavior and source import refresh

## Follow-on

- [x] Show source counts and snapshot age in the CLI (`passflick sources`)
- [ ] Show optional source refresh details in the picker without clutter
- [x] Group identical credentials with combined source labels; keep conflicts separate
- [x] Highlight competing password values for the same credential identity
- [ ] Highlight potentially stale source snapshots in the picker
- [x] Add non-secret local browser profile discovery (`passflick discover`)
- [ ] Evaluate authorized read-only browser credential adapters
- [x] Add bounds to import and vault parsing, private filesystem permissions, write locking, and encrypted backups
- [x] Authenticated encrypted restore with pre-restore safety backup
- [x] Automatic encrypted pre-refresh backups for existing credential sources
- [x] Atomically published backups with no overwrite and safe temporary-file cleanup
- [x] Provider-signature and duplicate-header checks for CSV import snapshots
- [ ] More security review: symlink races, keyring lifecycle, clipboard history, import edge cases
- [x] Checksummed Linux x86_64 pre-release binary build workflow
- [ ] Keyboard latency profiling, target-host packaging validation, and MVP acceptance

Initial code is **experimental** until the security and target-host validation gates pass.
