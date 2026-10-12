# Development queue

## Initial product

- [x] Identity, architecture, and interaction contract
- [x] Multi-source credential schema and CSV parsing; future direct source adapters use site titles rather than whitespace-only URLs as identities, preserving distinct accounts after encrypted import and reopen
- [x] Encrypted vault, masked in-window unlock, and session-key caching adapted from OTPick
- [x] Standalone first-run vault setup in the graphical picker
- [x] Per-vault session-key/explicit-lock isolation for safe independent testing; report cleanup failures accurately after cached-key decryption errors; desktop-keyring enrollment respects manual locks, retries stale keys with a passphrase, preserves session state if Secret Service storage fails, and never imports an unverified desktop key into the kernel session cache during CLI maintenance
- [x] Graceful one-shot GUI and interactive CLI fallback when session caching is unavailable
- [x] Reject empty/mixed-provider import batches and NUL-containing clipboard values before committing; enforce the same empty-password, NUL, and missing-site checks at the transaction boundary for future source adapters
- [x] Neutralize terminal escape, bidirectional controls, and additional invisible Unicode format marks in visible metadata, CLI filesystem path output, top-level error text, and graphical error/notice display without modifying stored values or actual paths
- [x] Hide URL userinfo, paths, query strings, and fragments in URL-only or HTTP(S)-title picker and CLI labels without modifying stored URLs or search identities; trim surrounding title whitespace for URL detection and number otherwise-indistinguishable credential variants; suppress scheme-only URL payloads (`data:`, `javascript:`, etc.) in URL-only and URL-shaped-title displays, retain ordinary host:port labels and colon-separated titles; reject non-web authority-shaped payloads (`data://`, `javascript://`, `file://`, etc.) as local-site labels
- [x] One-shot keyboard picker with Enter/Shift+Enter; cache visible row labels between egui redraws and clear cached labels after a vault projection change; zeroize owned search text on close or reload, cached picker row labels on drop, and case-folded search query, indexed field, and sort-key temporaries; normalize one zeroizing title sort key per matched search result instead of per comparator call
- [x] Synthetic demo picker that never opens a real vault
- [x] Commit Cargo.lock and enforce locked builds in CI
- [x] [Rust CI](https://github.com/sguzman/passflick/actions/runs/38187312021) passed 117 tests, locked CLI checks, formatting, desktop installation smoke, four-source encrypted recovery/restore/import smoke, and strict Clippy; [synthetic GUI and real pinned wl-clipboard 2.3.0 transport](https://github.com/sguzman/passflick/actions/runs/38187312087) also passed
- [x] Synthetic CLI encrypted-recovery smoke passed: passphrase prompts, backup verification, wrong-passphrase rejection, tamper recovery, and displaced ciphertext safety snapshot
- [x] Synthetic ordinary restore smoke passed: explicit confirmation, corrupted and hard-linked snapshot rejection, four-source restoration, and encrypted pre-restore safety backup
- [x] Synthetic CLI source refresh passed: Firefox survives Edge replacement; a large accidental Edge shrink is rejected without vault mutation, and `--allow-shrink` preserves Firefox
- [x] Rust regression rejects a zero-overlap, same-size replacement of an established source before backup or mutation; intentional override retains a byte-exact encrypted rollback backup
- [x] Four-provider synthetic CLI ingestion passed: Edge, Chrome, Firefox, and Apple coexist; Apple exports mislabeled as Edge are rejected without mutation
- [x] Synthetic concurrent source imports passed: two writers race, serialize using the persistent write lock, and preserve both providers after reopening
- [x] Simultaneous initial vault creations never overwrite one another; Argon2 derives its key directly into zeroizing storage
- [x] Session, desktop keyring, and encrypted backup key loading avoid temporary raw-key arrays; malformed key lengths are rejected
- [x] Vault AEAD decrypts inside zeroizing memory, and tampered ciphertext is rejected before record decoding; credential-owned labels, URLs and usernames are zeroized on record drop
- [x] Stale cached keys trigger a CLI passphrase retry instead of blocking maintenance; non-decryption failures still fail closed
- [x] `passflick status` authenticates cached session keys against the current encrypted vault before claiming it is unlocked, and rejects unsafe vault-file kinds instead of treating dangling symlinks as absent
- [x] Picker startup clears a cached session key only on authentication failure; filesystem, header and schema errors preserve the key
- [x] Synthetic filesystem regression tests passed in Rust CI
- [ ] Confirm filesystem edge cases on target EndeavourOS/Hyprland
- [x] Automated X11 keyboard/copy/close smoke tests under Xvfb
- [x] Automated native Wayland first-frame and exact synthetic clipboard transport under nested Weston (Xvfb)
- [ ] Complete [synthetic target-host acceptance](acceptance.md) on EndeavourOS/Hyprland
- [ ] Test actual Edge, Chrome, Firefox, and Apple export variants
- [ ] Confirm clipboard exit behavior and source import refresh

## Follow-on

- [x] Show source counts and snapshot age in the CLI (`passflick sources`)
- [x] Show compact per-source snapshot counts and refresh ages in the picker via a minimal hover detail, computed once on load (never synced browser state)
- [x] Group identical credentials with combined source labels; keep conflicts separate
- [x] Highlight competing password values for the same credential identity
- [x] Highlight source snapshots whose latest import is 30 or more full days old without treating unknown/future import times as stale; status metadata never contains usernames, URLs or secrets
- [x] Add non-secret local browser profile discovery (`passflick discover`), with terminal-safe rendering of untrusted Firefox profile names
- [ ] Evaluate authorized read-only browser credential adapters
- [x] Add bounds to import and vault parsing, private filesystem permissions, write locking, and encrypted backups; reject oversized regular vault files from metadata before the bounded read, including sparse files
- [x] Authenticated encrypted restore with pre-restore safety backup; reject hard-link aliases to the active vault using device/inode identity
- [x] Read-only encrypted backup authentication command (`passflick verify FILE`)
- [x] Passphrase-authenticated disaster recovery from a missing or corrupted primary vault, preserving original raw bytes before replacement
- [ ] Validate disaster recovery and session-key invalidation on target EndeavourOS/Hyprland
- [x] Failed source refresh restores original in-memory projection without cloning secrets
- [x] Automatic encrypted pre-refresh backups for existing credential sources
- [x] Atomically published backups with no overwrite and safe temporary-file cleanup
- [x] Provider-signature and duplicate-header checks for CSV import snapshots; deduplication index zeroizes its site-title, URL, and username copies on release or parsing failure while preserving Unicode and password-variant distinctions
- [x] Bound both raw CSV record count and direct-adapter transaction count at 100,000, independent of the 32 MiB raw input limit; deduplicate password variants with keyed, process-local fingerprints and exact collision checks rather than quadratic linear scans
- [x] Reject ambiguous semantic CSV header aliases and missing username headers before importing a source snapshot
- [x] Synthetic complete-format Firefox and Apple exports; Apple OTPAuth and Notes are not persisted
- [x] Lossless encrypted import round trip preserves Unicode usernames, quoted site titles, and multiline passwords with leading/trailing whitespace
- [x] Detect Apple Title + OTPAuth exports without Notes, rejecting wrong-source imports
- [x] Require sensitive clipboard support instead of silently copying password values into unmarked history; probe helper capabilities *before* sending credential bytes, with synthetic CLI/GUI regression coverage for preflight refusal
- [x] Clipboard transport itself rejects NUL-containing legacy values before launching `wl-copy`
- [x] Bound stalled clipboard helper capability probes and post-write process waits, killing and reaping timed-out direct children; synthetic regression tests verify preflight non-disclosure and bounded failure (blocked large stdin writes and forked helpers need separate review)
- [x] CI passed synthetic regression tests for early-exiting legacy `wl-copy`, misleading help text, and exact bytes with a supported helper; GUI smoke also verifies legacy helpers leave the picker open and existing clipboard untouched
- [x] CI builds pinned upstream `wl-clipboard` 2.3.0 and verifies a real `--sensitive` Wayland clipboard round-trip with fictional data under nested Weston; host clipboard-manager behavior remains unverified
- [x] Reject named-pipe vault and lock paths without blocking; require private effective-user-owned active vault, lock, and managed backup paths while keeping external encrypted snapshots verifiable
- [x] Reject named pipes and non-regular CSV import paths without blocking; preserve regular-file symlink imports and explicit stdin streaming
- [x] Bound never-ending stdin streams at the 32 MiB import limit plus one byte before parsing; reject oversized regular CSV files from metadata before buffer allocation, including sparse files
- [x] Verify backup creation rejects a symlink-substituted backup directory without changing the vault or redirected target
- [ ] More security review: symlink races, keyring lifecycle, clipboard history, import edge cases
- [x] Checksummed Linux x86_64 pre-release binary build workflow
- [ ] Keyboard latency profiling, target-host packaging validation, and MVP acceptance

Initial code is **experimental** until the security and target-host validation gates pass.
