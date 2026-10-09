# Acceptance plan

Passflick is pre-release until the following checks are run against its real Linux/Wayland target. Automated tests use fictional `example.test` credentials exclusively. CI has already validated the X11 search/Enter/Shift+Enter/Escape lifecycle under Xvfb and the first native Wayland frame under headless Weston. The checklist below contains the remaining target-host acceptance work. This document is an acceptance gate, not a feature changelog.

## 1. Synthetic graphical picker

Use the project's existing `passflick demo` command. It does not access the real vault.

- The picker opens as a floating overlay without rearranging tiled windows.
- The search field has keyboard focus on first frame and accepts typing immediately.
- Matching and Arrow Up/Down selection behave correctly for multiple entries.
- Exact duplicates from Edge and Chrome appear as one item with combined provenance.
- A conflicting Firefox value remains a distinct selectable item.
- Enter copies the selected synthetic password exactly and exits.
- Shift+Enter copies the selected synthetic username exactly and exits.
- Escape exits without modifying the current clipboard.
- A second invocation can retrieve the other field without session unlock.
- If the session key is absent, the picker presents a masked vault unlock field; a correct passphrase unlocks for the session, an incorrect one never exposes records, and Escape closes without copying.
- Test focus, resize behavior, and keyboard repeat using the real compositor and application class.

Record startup latency from process entry to first visible, focused frame. No numerical performance guarantee is asserted until it has been measured.

## 2. Encrypted projection

Use isolated temporary XDG data directories and synthetic CSV exports for all four providers.

- Initialize and unlock a fresh vault, import a source, then reopen successfully.
- Show source counts and snapshot age without printing any secret.
- Import the same source twice; confirm its snapshot updates rather than accumulating duplicates, and the original encrypted snapshot is automatically saved under `backups/` before replacement.
- Import two sources and refresh one; verify the other is preserved.
- Reject malformed rows, missing required columns, and oversized exports without changing a valid snapshot.
- Test unusually small snapshots and the explicit `--allow-shrink` override.
- Verify private file and directory permissions, encrypted contents, and authenticated decryption failure after tampering.
- Exercise two simultaneous imports and verify that the exclusive write lock preserves both updates.
- Create and reopen a byte-exact encrypted backup.
- Verify session unlock, explicit lock, failed unlock, and the optional Secret Service integration.
- Switch between two isolated `PASSFLICK_VAULT` paths in one login session; cached keys and manual-lock markers must not cross between them.
- Restore a compatible encrypted snapshot with `--confirm`; verify automatic pre-restore backup and that a corrupted snapshot leaves the live vault unchanged.
- Confirm no plaintext CSV remains in Passflick-controlled storage.

## 3. Clipboard and input boundary

- Verify literal spaces, Unicode, quoted CSV values, embedded newlines, and trailing newlines survive import and copy.
- Confirm the `wl-copy` sensitive hint and evaluate the host clipboard manager's actual history handling.
- Check the tool never prints passwords or vault keys in ordinary output, startup traces, crash diagnostics, or screenshots.
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
