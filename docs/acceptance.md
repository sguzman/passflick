# Acceptance plan

Passflick is pre-release until the following checks are run against its real Linux/Wayland target. Automated tests use fictional `example.test` credentials exclusively. CI has already validated the X11 search/Enter/Shift+Enter/Escape lifecycle under Xvfb and the first native Wayland frame plus a synthetic byte-exact clipboard round-trip under nested Weston. The Rust workflow's synthetic CLI recovery and multi-source import smoke test passed on [October 9, 2026](https://github.com/sguzman/passflick/actions/runs/37970160238), alongside 75 Rust tests, locked CLI checks, formatting, and strict Clippy. The CI runner uses an older `wl-copy`, so its transport test does not validate the sensitive-data hint; that remains a target-host acceptance item. The checklist below contains the remaining target-host acceptance work. This document is an acceptance gate, not a feature changelog.

## 1. Synthetic graphical picker

Use the project's existing `passflick demo` command. It does not access the real vault.

- The picker opens as a floating overlay without rearranging tiled windows.
- A dangling symlink at the active vault filename must not trigger first-run vault creation.
- The search field has keyboard focus on first frame and accepts typing immediately.
- Matching and Arrow Up/Down selection behave correctly for multiple entries.
- Exact duplicates from Edge and Chrome appear as one item with combined provenance.
- A conflicting Firefox value remains a distinct selectable item.
- Enter copies the selected synthetic password exactly and exits.
- Shift+Enter copies the selected synthetic username exactly and exits.
- Escape exits without modifying the current clipboard.
- A second invocation can retrieve the other field without session unlock.
- First launch with no vault offers masked passphrase creation inside the picker, without a terminal. Short or mismatched entries must not create a vault; valid entries create a private encrypted file.
- If the session key is absent, the picker presents a masked vault unlock field; a correct passphrase opens the picker, an incorrect one never exposes records, and Escape closes without copying.
- If the Linux session keyring is unavailable, a correctly entered passphrase still permits one-shot picker use; the next launch must require another unlock and provide a clear explanation.
- Test focus, resize behavior, and keyboard repeat using the real compositor and application class.

Record startup latency from process entry to first visible, focused frame. No numerical performance guarantee is asserted until it has been measured.

## 2. Encrypted projection

Use isolated temporary XDG data directories and synthetic CSV exports for all four providers.

- Initialize and unlock a fresh vault, import a source, then reopen successfully.
- Show source counts and snapshot age without printing any secret.
- Import the same source twice; confirm its snapshot updates rather than accumulating duplicates, and the original encrypted snapshot is automatically saved under `backups/` before replacement.
- Import two sources and refresh one; verify the other is preserved. The synthetic CLI smoke test verified this for Firefox and Edge. Target-host acceptance remains a separate gate.
- Reject malformed rows, missing required columns, and oversized exports without changing a valid snapshot. Direct snapshot commits, including future non-CSV adapters, must independently reject empty passwords, NUL-containing usernames/passwords, and entries without a usable website or title before creating a backup.
- Reject two different CSV header aliases for one field (such as `password` and `pass`, or `url` and `website`) before source replacement. Also reject a missing username header without rejecting rows whose username value is blank.
- Test unusually small snapshots and the explicit `--allow-shrink` override.
- Verify private file and directory permissions, effective-user ownership of active vault/lock/managed-backup paths, encrypted contents, and authenticated decryption failure after tampering.
- Confirm an active vault refuses unlock from a shared or symlinked immediate directory even if its file is mode 0600; confirm encrypted snapshots remain verifiable from an external directory when the snapshot file itself is private.
- Substitute named pipes for the vault file and the write-lock file in isolated synthetic directories. Both operations must reject them without blocking for a counterpart process.
- Exercise two simultaneous imports and verify that the exclusive write lock preserves both updates.
- Create and reopen a byte-exact encrypted backup.
- Verify session unlock, explicit lock, failed unlock, and the optional Secret Service integration.
- Switch between two isolated `PASSFLICK_VAULT` paths in one login session; cached keys and manual-lock markers must not cross between them.
- With an isolated synthetic vault and a symlinked ancestor (not an immediate symlinked vault directory), compare session and desktop-key cache identities before creation, while the file exists, and after deletion/recovery. They must remain stable.
- Simulate failure to clear one or more cached keys after recovery; the CLI must disclose incomplete invalidation instead of promising that a fresh passphrase will be required. The GUI must likewise avoid claiming stale session keys were removed when invalidation fails.
- Verify an encrypted backup with `passflick verify FILE` before any restore; corrupt or incompatible backups must fail without changing live data. A second pathname that is a hard link to the active vault is not a valid restore or recovery source.
- Restore a compatible encrypted snapshot with `--confirm`; verify automatic pre-restore backup and that a corrupted snapshot leaves the live vault unchanged.
- Corrupt or delete the primary vault in a synthetic environment, then run `passflick recover FILE --confirm`: require the backup passphrase, preserve existing raw ciphertext, reconstruct a private encrypted file, and require a fresh session unlock. An incorrect passphrase must leave existing primary bytes unchanged.
- In CLI smoke automation, verify `recover` without `--confirm` is refused without changing the primary, and restoring a missing primary does not create a spurious displaced-primary safety snapshot.
- Confirm no plaintext CSV remains in Passflick-controlled storage.

## 3. Clipboard and input boundary

- Verify literal spaces, Unicode, quoted CSV values, embedded newlines, and trailing newlines survive import and copy.
- Confirm `wl-clipboard` 2.3+ and the `wl-copy --sensitive` hint; old versions must give an explicit diagnostic even when the helper exits before stdin can be fully written, without writing unmarked secrets. Test exact whitespace and trailing newline preservation using a synthetic supported helper, and evaluate the host clipboard manager's actual history handling.
- Check the tool never prints passwords or vault keys in ordinary output, startup traces, crash diagnostics, or screenshots.
- Imported site names and usernames containing terminal escape sequences or Unicode direction-control characters must be displayed harmlessly; Shift+Enter must still copy the original username exactly.
- Do not record or upload clipboard contents from production sessions.

## 4. Provider export compatibility

Against current browser versions, separately validate actual export headers for Edge, Chrome/Chromium, Firefox, and Apple Passwords using source-owner authorization. Provider export samples must be sanitized before they become regression fixtures.

An import is not validated merely because a synthetic CSV with similar column names passed. At least one export representative of each provider must be checked before production-source support is advertised.

## 5. Release gate

- CI formatting, locked tests, locked CLI smoke checks, and strict Clippy are green.
- Synthetic target-host picker and vault workflows pass.
- User-facing docs and source compatibility statements match reality.
- No actual credentials, exports, local profile paths, or key material enter the public repository or CI artifacts.
- No release is described as production-ready without security review and explicit target-host acceptance.

A full independent security audit remains a separate goal even after the first usability acceptance.
