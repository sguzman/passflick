# Development queue

## Initial product

- [x] Identity, architecture, and interaction contract
- [x] Multi-source credential schema and CSV parsing
- [x] Encrypted vault and session-unlock design adapted from OTPick
- [x] One-shot keyboard picker with Enter/Shift+Enter
- [ ] Confirm Rust formatting, build, tests, and CI on Linux
- [ ] Perform target-host verification with synthetic credentials on EndeavourOS/Hyprland
- [ ] Test actual Edge, Chrome, Firefox, and Apple export variants
- [ ] Confirm clipboard exit behavior and source import refresh

## Follow-on

- [ ] Expose provenance and last refresh date in the UI
- [ ] Make cross-source duplicate grouping explainable without losing any source
- [ ] Highlight conflicts and potentially stale source snapshots
- [ ] Evaluate optional read-only browser adapters using authorized interfaces
- [ ] Harden vault parser, clipboard lifecycle, disk permissions, and backups
- [ ] Keyboard latency profiling, release packaging, and MVP acceptance

Initial code is **experimental** until the security and target-host validation gates pass.
