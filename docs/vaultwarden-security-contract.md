# 🔒 Vaultwarden projection security and lifecycle contract

**State:** proposed implementation gate, not a security audit or evidence that the new backend works. Applies to the Vaultwarden-only migration in [ROADMAP.md](../ROADMAP.md). Do not use real credentials to test these semantics before the synthetic acceptance matrix passes.

## Trust boundaries

1. **Remote source of truth:** Bitwarden-compatible server owns items, changes, folder membership, archive and Trash state. All upstream access by Passflick must be read-only, except the authentication exchanges needed to obtain/refresh authorized sessions.
2. **Native Rust adapter:** authenticates and reads encrypted upstream data, verifies the entire response, decrypts with reviewed Bitwarden-compatible primitives, and yields a complete snapshot. HTTPS hostname and CA verification may never be disabled.
3. **Encrypted local projection:** owned by Passflick, contains only necessary local-picker data and authoritative upstream IDs. It is a derivative snapshot, not a place to edit passwords. Never publish a partial or unauthenticated snapshot.
4. **Picker and clipboard:** ordinary launches read only the local encrypted snapshot after local unlock. Do not make network requests or write upstream data when summoning, searching, copying or exiting.
5. **Repository/CI/logs:** exclusively fictional fixtures and sanitized diagnostics; no home IPs, real account names, private certificates, passwords, session tokens, secret-bearing exports or runtime profiles.

## Local unlock is distinct from remote authentication

- **Local lock** prevents Passflick from opening its cached projection until the local unlock policy succeeds. Existing session-keyring and optional Secret Service behavior must be reviewed against the new projection identity and tested under real Hyprland.
- **Remote login/session** is necessary to *update*, not to *read a previously unlocked local snapshot*. Avoid putting secrets in arguments, environment variables, logs, crash dumps or plaintext persistence. Support authenticated token refresh and expiration explicitly; never silently downgrade authentication.
- **Remote logout** must revoke/forget update credentials and close any session retained by Passflick. An optional explicit local purge is distinct from logout; neither implicitly deletes the old user-managed encrypted vault.
- **Remote account password change, revocation or extension lock** cannot instantly revoke an offline copy on another machine. Document this as a deliberate offline-cache trade-off; disclose the last successful update age and preserve an immediately effective local lock.
- **Stolen workstation:** encrypted at-rest snapshot with private ownership and permissions is required but not sufficient against an already unlocked same-user session or compromised host. Treat local keyring and clipboard histories as risk boundaries.

## Snapshot admission and update rules

- Require a valid complete, bounded remote sync response. Preserve upstream cipher IDs; abort the entire refresh for duplicate/malformed IDs or missing/malformed status fields.
- **Archive is a hard gate.** Vaultwarden/Bitwarden represent it as `archivedDate` (or `ArchivedDate` in PascalCase responses); a non-null date means hidden from the active picker. Missing archive metadata must fail closed rather than promoting archived historical credentials.
- **Trash is separate:** non-null `deletedDate` excludes items. Ignore unsupported non-login item types, and accept multiple independent login IDs with the same site and username.
- Admission checks operate on *raw encrypted envelopes* before a library can drop optional metadata. Native decrypt/validation is a separate stage. If an upstream version changes its archive representation, fail safely and update the adapter with test evidence.
- On an explicit update: authenticate → retrieve → verify metadata → decrypt supported ciphers → validate projected items → encrypt candidate snapshot → atomically replace prior encrypted projection. Publish the successful timestamp only with the verified snapshot. Failed, cancelled, timed-out or concurrent updates leave the previous authenticated snapshot intact.
- **Zero logins is possible**, e.g. after the user archives everything. Never treat it as a reason to automatically preserve old logins; do distinguish a *valid empty server result* from a parse/auth/network failure before replacing the old snapshot.
- **No auto-refresh** on picker invocation, no hourly polling daemon, and no account edits. Manual `passflick update` or an explicit GUI action are the sole accepted update triggers.

## Minimum retained data

Projection should contain: upstream account/server identity, cipher UUID, user-facing title, URI identity for search, username, password and optionally a folder label, together with nonsecret sync timestamp/version metadata. Do not persist password history, TOTP seeds, attachments, notes, card details or other sensitive fields unless a separately justified user workflow requires them. Keep provider provenance *upstream* instead of reimplementing Edge/Chrome/Firefox/Apple source priority.

Full URLs can contain tokens. Encrypt them at rest, sanitize search labels and errors, and avoid leaking them through process titles or CLI output. Site and username strings may also be private. Keep sensitive material in zeroizing memory where feasible without claiming complete memory erasure.

## Critical security acceptance checks

| Scenario | Required result |
| --- | --- |
| Empty or malformed server response | Reject without replacing last good encrypted snapshot |
| Archived item or newly archived item | Excluded from active projection after successful update |
| Missing `archivedDate` | Fail sync, never silently treat item as active |
| Deleted item | Excluded after successful update |
| Password edited at same cipher ID | Replaces cached value, no duplicate accumulation |
| Same site+username, different IDs | Both remain selectable without leaking secrets |
| TLS untrusted CA / wrong hostname | Hard failure, no bypass |
| Offline and previous successful snapshot exists | Local search/copy allowed after local unlock, visibly marked stale |
| Offline before first sync | Clear error and no invented credentials |
| Expired login / MFA required | Bounded authentication failure, existing projection retained |
| Remote logout or revoked session | Cannot update without reauthentication; offline cache revocation limitations disclosed |
| Local explicit lock | No password retrieval until successful local unlock |
| Interrupted concurrent update | Valid old or valid new encrypted snapshot, never a partial one |
| Clipboard helper failure | Fail closed without exposing plaintext through unsupported clipboard |
| First-run migration | Old `vault.passvault` and backups untouched until replacement accepted and rollback verified |

## Native backend decision evidence

- **`rbw` v1.15.0** ([source](https://github.com/doy/rbw)): MIT Rust crate with public `api`, `actions`, `cipherstring`, `identity`, `locked` modules. Login/auth, sync and cryptography may be reusable without spawning a Node CLI. Its README says maintenance is primarily regression fixes and some 2FA methods are unsupported. A deep dependency/compatibility spike is still needed.
- **Concrete archive incompatibility:** at inspected upstream `src/api.rs`, `SyncResCipher` models `deleted_date` but not `archived_date`, and `to_entry` drops deleted items while returning all other entries. The high-level `Client::sync` loses access to raw cipher metadata. **Do not consume those entries directly.** A narrow, reviewed library adapter or pinned fork must explicitly preserve archive status before item conversion; verify through a disposable test server.
- **Bitwarden internal Rust SDK** ([upstream](https://github.com/bitwarden/sdk-internal)) is GPL-based and explicitly unsupported for public password-manager clients; its interfaces can change without warning. Not selected as a production dependency merely for being official.
- **Disposable sync-ingress test module:** `src/bitwarden/sync_filter.rs` is compiled only in test builds during the first spike. It exercises raw-envelope archive/trash/ID admission and **does not** authenticate, contact a server or decrypt a password. It must be wired into a genuine backend before counting any native integration milestone complete.

**Selection remains pending.** Favor Rust and review upstream crypto rather than implementing it from scratch. No unsafe server access, no TLS bypass, no secrets committed to Git.

## Explicitly out of scope

Autofill, background source scraping, password edits, an automatic sync daemon, Vaultwarden administration, browser export ingestion in the final UX, and iOS app development. Other credential types and passkey retrieval are not silently added to this contract.
