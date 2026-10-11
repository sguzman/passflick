# Acceptance plan

Passflick is pre-release until the following checks are run against its real Linux/Wayland target. Automated tests use fictional `example.test` credentials exclusively. CI has validated the X11 search/Enter/Shift+Enter/Escape lifecycle under Xvfb and a native Wayland first frame under nested Weston. The synthetic GUI workflow additionally builds upstream `wl-clipboard` 2.3.0 pinned to commit `67a7b937895bceec1ae5ccebb10216f63f70ca1b`, and [verified `wl-copy --sensitive` with byte-exact synthetic Wayland clipboard transport](https://github.com/sguzman/passflick/actions/runs/38185127615). Its X11 tests also confirm that unsupported helpers leave the picker open without modifying the existing clipboard. The [Rust CI workflow](https://github.com/sguzman/passflick/actions/runs/38185127614) passed 112 tests, locked CLI checks, formatting, encrypted recovery and multi-source import smoke tests, and strict Clippy. Testing a real helper under nested Weston is not a substitute for checking clipboard-history behavior, focus, latency, and keyring integration on the actual EndeavourOS/Hyprland target. The checklist below contains those remaining target-host gates.

## 1. Synthetic graphical picker

Use the project's existing `passflick demo` command. It does not access the real vault.

- The picker opens as a floating overlay without rearranging tiled windows. Large-vault row labels must remain stable while searching and scrolling; cached labels must be invalidated after unlocking a different projection. Synthetic Rust CI tests cache invalidation; real keyboard latency is still an acceptance gate.
- A dangling symlink at the active vault filename must not trigger first-run vault creation. `passflick status` must reject symlink and directory vault filenames instead of reporting them as absent or usable.
- The search field has keyboard focus on first frame and accepts typing immediately. Owned search text must be zeroized on drop and scrubbed when loading a new vault projection; normalized search and field/sort-key temporaries must also use zeroizing storage. Credential-owned labels, URLs, and usernames, plus cached picker row labels, must be zeroized on drop. This is not proof of total process-memory erasure.
- Matching and Arrow Up/Down selection behave correctly for multiple entries.
- Exact duplicates from Edge and Chrome appear as one item with combined provenance.
- A conflicting Firefox value remains a distinct selectable item.
- Enter copies the selected synthetic password exactly and exits.
- Shift+Enter copies the selected synthetic username exactly and exits.
- Escape exits without modifying the current clipboard.
- A second invocation can retrieve the other field without session unlock.
- First launch with no vault offers masked passphrase creation inside the picker, without a terminal. Short or mismatched entries must not create a vault; valid entries create a private encrypted file.
- If the session key is absent, the picker presents a masked vault unlock field; a correct passphrase opens the picker, an incorrect one never exposes records, and Escape closes without copying.
- If the Linux session keyring is unavailable, a correctly entered passphrase still permits one-shot picker use; the next launch must require another unlock and provide a clear explanation. Rust CI also verifies that stale cached CLI keys allow a passphrase retry while unsafe vault-file errors do not.
- Test focus, resize behavior, and keyboard repeat using the real compositor and application class.

Record startup latency from process entry to first visible, focused frame. No numerical performance guarantee is asserted until it has been measured.

## 2. Encrypted projection

Use isolated temporary XDG data directories and synthetic CSV exports for all four providers.

- Initialize and unlock a fresh vault, import a source, then reopen successfully. CI also verifies that two simultaneous first-run initializations cannot overwrite each other.
- Show source counts and snapshot age without printing any secret. The picker displays a compact, cached source-status row with optional hover details and warns at 30 days since the most recent import for a provider. A missing source, unknown timestamp (0), or future timestamp is not labelled stale. This reflects imports, not live browser state.
- Import the same source twice; confirm its snapshot updates rather than accumulating duplicates, and the original encrypted snapshot is automatically saved under `backups/` before replacement.
- Import two sources and refresh one; verify the other is preserved. Synthetic CLI checks verified Firefox/Edge isolation, then loaded all four sources in one vault. Target-host acceptance remains a separate gate.
- Reject malformed rows, missing required columns, and oversized exports without changing a valid snapshot. Future source adapters supplying distinct titled credentials with whitespace-only URL fields must preserve both identities through encrypted save/reopen and search; synthetic Rust CI verifies this without real data. Direct snapshot commits, including future non-CSV adapters, must independently reject empty passwords, NUL-containing usernames/passwords, and entries without a usable website or title before creating a backup.
- Reject two different CSV header aliases for one field (such as `password` and `pass`, or `url` and `website`) before source replacement. Also reject a missing username header without rejecting rows whose username value is blank. Recognize Apple Title + OTPAuth headers even when Notes is absent.
- Test unusually small snapshots and the explicit `--allow-shrink` override. CI verified both non-destructive refusal and a deliberate reduction from 12 Edge records to 3 without affecting Firefox. A Rust regression also verifies zero-overlap same-size source replacement refusal (with no backup or mutation) and an intentional override preserving the old ciphertext.
- Verify private file and directory permissions, effective-user ownership of active vault/lock/managed-backup paths, encrypted contents, and authenticated decryption failure after tampering.
- Confirm an active vault refuses unlock from a shared or symlinked immediate directory even if its file is mode 0600; confirm encrypted snapshots remain verifiable from an external directory when the snapshot file itself is private. A symlink substituted for the managed `backups/` directory must be rejected without following the redirect.
- Substitute named pipes for the vault file, write-lock file, and an explicit CSV import path in isolated synthetic directories. All must reject without blocking for a counterpart process. Use `import SOURCE -` for intentional streaming. Rust CI additionally verifies that a never-ending stream is bounded and rejected as oversized.
- Exercise two simultaneous imports and verify that the exclusive write lock preserves both updates. Rust CI verified this with two racing source transactions followed by a vault reopen; cross-process behavior on the actual host remains an acceptance check.
- Create and reopen a byte-exact encrypted backup.
- Verify session unlock, explicit lock, failed unlock, and the optional Secret Service integration. Desktop-keyring enrollment must ask for a passphrase if the cached kernel key is stale or an explicit manual lock exists, and failure to store in Secret Service must preserve the manual lock/session cache. A stale desktop-keyring key discovered during CLI maintenance must not be installed into the kernel cache before vault authentication. Rust CI verifies that `status` reports an unlocked session only if its cached key authenticates the current vault, and that non-authentication picker errors do not discard that key.
- Switch between two isolated `PASSFLICK_VAULT` paths in one login session; cached keys and manual-lock markers must not cross between them.
- With an isolated synthetic vault and a symlinked ancestor (not an immediate symlinked vault directory), compare session and desktop-key cache identities before creation, while the file exists, and after deletion/recovery. They must remain stable.
- Simulate failure to clear one or more cached keys after recovery; the CLI must disclose incomplete invalidation instead of promising that a fresh passphrase will be required. The GUI must likewise avoid claiming stale session keys were removed when invalidation fails.
- Verify an encrypted backup with `passflick verify FILE` before any restore; corrupt or incompatible backups must fail without changing live data. A second pathname that is a hard link to the active vault is not a valid restore or recovery source.
- Restore a compatible encrypted snapshot with `--confirm`; verify automatic pre-restore backup and that a corrupted snapshot leaves the live vault unchanged. Synthetic CLI CI now covers an unconfirmed restore, corrupted snapshot, hard-link alias, four-source restoration, and a byte-exact displaced-vault safety backup.
- Corrupt or delete the primary vault in a synthetic environment, then run `passflick recover FILE --confirm`: require the backup passphrase, preserve existing raw ciphertext, reconstruct a private encrypted file, and require a fresh session unlock. An incorrect passphrase must leave existing primary bytes unchanged.
- In CLI smoke automation, verify `recover` without `--confirm` is refused without changing the primary, and restoring a missing primary does not create a spurious displaced-primary safety snapshot.
- Confirm no plaintext CSV remains in Passflick-controlled storage. A regular CSV file exceeding 32 MiB, including a sparse file, must be rejected from metadata before a large read; deliberately streamed stdin remains capped at 32 MiB plus one detection byte.

## 3. Clipboard and input boundary

- Verify literal spaces, Unicode, quoted CSV values, embedded newlines, and trailing newlines survive import and copy. Rust CI verifies exact Unicode and whitespace after parse, encrypted save, and vault reopen; an actual Wayland clipboard handoff is still a target-host check.
- Confirm `wl-clipboard` 2.3+ and the `wl-copy --sensitive` hint; old versions must give an explicit diagnostic before any credential bytes are sent to the helper, without writing unmarked secrets. Synthetic GUI CI verifies an old helper leaves the picker open and clipboard unchanged. Test exact whitespace and trailing newline preservation using synthetic supported helpers and the pinned real 2.3.0 helper under nested Weston; separately evaluate the target host clipboard manager's actual history handling.
- Check the tool never prints passwords or vault keys in ordinary output, startup traces, crash diagnostics, or screenshots.
- Imported site names and usernames containing terminal escape sequences, Unicode direction-control characters, or invisible formatting marks must be displayed harmlessly; Shift+Enter must still copy the original username exactly. Filesystem-derived Firefox profile names printed by `passflick discover` must also render without control sequences; preserve the real filesystem path.
- URL-only credentials and URL-shaped HTTP(S) titles must display only the site authority, omitting userinfo, paths, query strings, and fragments, including mixed-case URL schemes and titles padded with whitespace. URL-only and URL-shaped-title `data:`, `javascript:`, `file:`, and other non-authority scheme payloads, including `data://`, `javascript://`, and `file://` forms, must not be displayed; numeric host:port addresses and ordinary titles such as `Data: Science` should remain recognizable. The exact URL must remain stored and searchable; validate a path-specific search when two logins share the same host and username. Distinct credentials with the same visible site and username must receive non-secret variant labels; exact duplicates across sources must not create extra variants.
- Do not record or upload clipboard contents from production sessions.

## 4. Provider export compatibility

Against current browser versions, separately validate actual export headers for Edge, Chrome/Chromium, Firefox, and Apple Passwords using source-owner authorization. Provider export samples must be sanitized before they become regression fixtures.

An import is not validated merely because a synthetic CSV with similar column names passed. At least one export representative of each provider must be checked before production-source support is advertised.

## 5. Release gate

- CI formatting, locked tests, locked CLI smoke checks, and strict Clippy are green.
- Synthetic target-host picker and vault workflows pass.
- User-facing docs and source compatibility statements match reality.
- No actual credentials, exports, local profile paths, or key material enter the public repository or CI artifacts. Picker notices and graphical error messages containing path-derived control characters must render safely. Verify that filenames containing terminal escape or bidirectional controls are rendered harmlessly in CLI status, backup notices, and error output; Rust CI exercises the display projection without changing file paths.
- No release is described as production-ready without security review and explicit target-host acceptance.

A full independent security audit remains a separate goal even after the first usability acceptance.
