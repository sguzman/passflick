# Development queue

## Initial product

- [x] Identity, architecture, and interaction contract
- [x] Multi-source credential schema and CSV parsing
- [x] Encrypted vault and session-unlock design adapted from OTPick
- [x] One-shot keyboard picker with Enter/Shift+Enter
- [x] Synthetic demo picker that never opens a real vault
- [x] Commit Cargo.lock and enforce locked builds in CI
- [ ] Confirm the newest changes pass Rust formatting, build, tests, and CI on Linux
- [ ] Perform target-host verification with synthetic credentials on EndeavourOS/Hyprland
- [ ] Test actual Edge, Chrome, Firefox, and Apple export variants
- [ ] Confirm clipboard exit behavior and source import refresh

## Follow-on

- [x] Show source counts and snapshot age in the CLI (`passflick sources`)
- [ ] Show optional source refresh details in the picker without clutter
- [x] Group identical credentials with combined source labels; keep conflicts separate
- [ ] Highlight conflicts and potentially stale source snapshots
- [x] Add non-secret local browser profile discovery (`passflick discover`)
- [ ] Evaluate authorized read-only browser credential adapters
- [x] Add bounds to import and vault parsing, private filesystem permissions, write locking, and encrypted backups
- [ ] More security review: symlink races, keyring lifecycle, clipboard history, import edge cases, backup restoration
- [ ] Keyboard latency profiling, release packaging, and MVP acceptance

Initial code is **experimental** until the security and target-host validation gates pass.
