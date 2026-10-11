# Development queue

## Initial product

- [x] Identity, architecture, and interaction contract
- [x] Multi-source credential schema and CSV parsing
- [x] Encrypted vault, masked in-window unlock, and session-key caching adapted from OTPick
- [x] Standalone first-run vault setup in the graphical picker
- [x] Per-vault session-key/explicit-lock isolation for safe independent testing; report cleanup failures accurately after cached-key decryption errors
- [x] Graceful one-shot GUI and interactive CLI fallback when session caching is unavailable
- [x] Reject empty/mixed-provider import batches and NUL-containing clipboard values before committing; enforce the same empty-password, NUL, and missing-site checks at the transaction boundary for future source adapters
- [x] Neutralize terminal escape and bidirectional text-control characters in visible metadata without changing copied usernames
- [x] One-shot keyboard picker with Enter/Shift+Enter
- [x] Synthetic demo picker that never opens a real vault
- [x] Commit Cargo.lock and enforce locked builds in CI
- [x] Rust CI verified at [`df972c2`](https://github.com/sguzman/passflick/actions/runs/38102388987): 80 passed tests, locked CLI checks, formatting, desktop installation smoke, four-source encrypted recovery/restore/import smoke, and strict Clippy
- [x] Synthetic CLI encrypted-recovery smoke passed: passphrase prompts, backup verification, wrong-passphrase rejection, tamper recovery, and displaced ciphertext safety snapshot
- [x] Synthetic ordinary restore smoke passed: explicit confirmation, corrupted and hard-linked snapshot rejection, four-source restoration, and encrypted pre-restore safety backup
- [x] Synthetic CLI source refresh passed: Firefox survives Edge replacement; a large accidental Edge shrink is rejected without vault mutation, and `--allow-shrink` preserves Firefox
- [x] Four-provider synthetic CLI ingestion passed: Edge, Chrome, Firefox, and Apple coexist; Apple exports mislabeled as Edge are rejected without mutation
- [x] Synthetic concurrent source imports passed: two writers race, serialize using the persistent write lock, and preserve both providers after reopening
- [x] Simultaneous initial vault creations never overwrite one another; Argon2 derives its key directly into zeroizing storage
- [x] Synthetic filesystem regression tests passed in Rust CI
- [ ] Confirm filesystem edge cases on target EndeavourOS/Hyprland
- [x] Automated X11 keyboard/copy/close smoke tests under Xvfb
- [x] Automated native Wayland first-frame and exact synthetic clipboard transport under nested Weston (Xvfb)
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
- [x] Authenticated encrypted restore with pre-restore safety backup; reject hard-link aliases to the active vault using device/inode identity
- [x] Read-only encrypted backup authentication command (`passflick verify FILE`)
- [x] Passphrase-authenticated disaster recovery from a missing or corrupted primary vault, preserving original raw bytes before replacement
- [ ] Validate disaster recovery and session-key invalidation on target EndeavourOS/Hyprland
- [x] Failed source refresh restores original in-memory projection without cloning secrets
- [x] Automatic encrypted pre-refresh backups for existing credential sources
- [x] Atomically published backups with no overwrite and safe temporary-file cleanup
- [x] Provider-signature and duplicate-header checks for CSV import snapshots
- [x] Reject ambiguous semantic CSV header aliases and missing username headers before importing a source snapshot
- [x] Synthetic complete-format Firefox and Apple exports; Apple OTPAuth and Notes are not persisted
- [x] Detect Apple Title + OTPAuth exports without Notes, rejecting wrong-source imports
- [x] Require sensitive clipboard support instead of silently copying password values into unmarked history
- [x] CI passed synthetic regression tests for early-exiting legacy `wl-copy` and exact bytes with a supported helper
- [x] Reject named-pipe vault and lock paths without blocking; require private effective-user-owned active vault, lock, and managed backup paths while keeping external encrypted snapshots verifiable
- [x] Reject named pipes and non-regular CSV import paths without blocking; preserve regular-file symlink imports and explicit stdin streaming
- [x] Verify backup creation rejects a symlink-substituted backup directory without changing the vault or redirected target
- [ ] More security review: symlink races, keyring lifecycle, clipboard history, import edge cases
- [x] Checksummed Linux x86_64 pre-release binary build workflow
- [ ] Keyboard latency profiling, target-host packaging validation, and MVP acceptance

Initial code is **experimental** until the security and target-host validation gates pass.
