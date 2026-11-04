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


## Local projection lock and revocation policy (design decision; not implemented)

The new projection **must have a separate file identity, encryption key, session keyring namespace and optional desktop keyring identity** from the historical `vault.passvault`. A new cache must never repurpose the old file or silently unlock it using old key labels. The current `src/session.rs` caches a session key; `src/desktop_keyring.rs` can persist and automatically retrieve an existing vault key. Those mechanisms are not approved for reuse unchanged: a persisted Secret Service auto-unlock must **not** defeat an explicit local lock.

- **Local session:** after an explicit local unlock, a projection key may be retained in the Linux login-session keyring for fast repeated picker invocation. `passflick lock` must invalidate it and impose a lock marker that all subsequent key lookup paths obey. The key is not promised to expire merely because a window closes or a remote extension locks. The login-session end must invalidate the key. Real suspend/lockscreen interaction needs target-host acceptance.
- **Durable offline ciphertext:** the last authenticated projection remains encrypted on disk, including after local lock, remote logout, remote credential changes, and transient network loss. Reopening it after local lock requires **explicit local unlock**; storing a persistent desktop-keyring secret must never silently bypass that decision. A local cache passphrase is not transported to the server and must not appear in command arguments.
- **Remote update session:** any remote tokens or Bitwarden-derived decryption keys needed for `update` have a separately bounded lifetime and storage policy; they are not the local projection key. Remote `logout` revokes/forgets update credentials and **also locks Passflick locally**. Neither operation deletes the encrypted cache. A future explicit `purge --confirm` may delete only the new projection, never historical vault/backup files.
- **Remote revocation and freshness:** locking a browser, expiring a token, changing the upstream master password, or removing user access cannot erase an offline cache. Until a subsequent successful update, the local snapshot may remain readable after local unlock. Always show the timestamp as *last successful sync*, never as proof of current authority; an update failure preserves the old ciphertext and marks it stale.
- **Account separation:** endpoint/account identity must be bound to the authenticated encrypted snapshot. Updating another account/server cannot silently overwrite, reinterpret or unlock the prior account's projection. Account-switch behavior requires explicit action and its own acceptance test.
- **Threat boundaries:** stolen disk with no usable unlock key should expose only authenticated ciphertext; a compromised already-unlocked user session, compromised Secret Service, malicious clipboard manager, and process-memory capture are **not** solved by disk encryption alone. Do not claim otherwise. Disallow remote-derived secrets in environment variables, command arguments, log lines, panic output and public CI artifacts.

These are implementation requirements, **not claims that current Passflick behaves this way**. A03/A04 and C03/G04 remain open until the native backend, cache key lifecycle and real Wayland tests substantiate them.

## Real disposable Vaultwarden acceptance (2026-11-04)

The isolated adapter was successfully tested against a real, disposable **Vaultwarden 1.37.5** instance using synthetic credentials, PBKDF2 100,000 iterations and a temporary CA-signed HTTPS hostname. Its identity login and `GET /api/sync` are separated from the fixture-only account/cipher provisioning client. Two independently identified login ciphers decrypted and round-tripped through a distinct encrypted offline projection without requiring HTTP to reopen the snapshot. The launcher explicitly opts into disposable storage **only** for this synthetic CI container, never for a user's server.

[Live server CI](https://github.com/sguzman/passflick/actions/runs/41752298727) passed the ignored integration test in its dedicated job. [Regular Rust](https://github.com/sguzman/passflick/actions/runs/41752173484) passed 188 tests with the live test excluded from standard unit runs, and [synthetic GUI](https://github.com/sguzman/passflick/actions/runs/41752173545) passed. No personal credentials, production hosts, user profiles or historical encrypted vault files were used.

The acceptance shows native protocol **feasibility only**. It does not establish the security of real session persistence, remote MFA or refresh-token expiry, local lock/logout enforcement, private key storage, organization policies, ongoing credential changes, or end-to-end real desktop behavior. The incomplete production path must not be enabled yet.

## Native Bitwarden crypto and token lifecycle boundaries (test-only)

The adapter currently uses the pinned MIT `rbw` Rust library for master-password KDF, wrapped user key, type-2 ciphertext decoding and HMAC verification. Since the library's verifier assumes a fixed 32-byte decoded MAC, Passflick rejects malformed decoded lengths, missing MAC, incorrect IV length and non-block-aligned ciphertext **before** dispatching to it. Error types must remain non-secret and failed candidate updates must never mutate the prior encrypted cache.

Authentication uses the existing strict HTTPS/no-redirect transport for prelogin, password grant and refresh; it bounds server-provided KDF cost, authenticates only against the explicitly configured endpoint, supports TOTP/email-code challenge values, and holds access/refresh tokens in zeroizing in-memory structures with an expiry boundary. This is not yet a complete session manager, and transient HTTP encoding/serialization buffers should not be represented as cryptographically guaranteed zeroized.

Unsupported organization ciphers and master-password re-prompt flags are currently rejected at the candidate snapshot level. This is deliberately fail-closed but does not mean Passflick can yet synchronize arbitrary users' vaults. Server/device compatibility, TLS CA tests, endpoint auth errors, logout and explicit local-lock policy remain acceptance requirements.

## Native read-only HTTPS admission (test-only baseline)

The isolated `src/bitwarden/transport.rs` sends an HTTPS GET only to the selected server's derived `/api/sync` endpoint. The adapter rejects insecure endpoint schemes, credentials embedded in URLs, queries/fragments, invalid bearer header characters, redirects and non-success HTTP statuses. Connection and total timeouts bound stalls; a 64 MiB limit applies to both declared and actually read body bytes. All network and parsing errors have sanitized messages. The bearer token is supplied by a future authentication layer and is not persisted by this transport.

TLS chain and hostname verification remain enabled using rustls with native trust roots. **Actual private-CA acceptance, invalid certificate, mismatch and disposable Vaultwarden runs remain unverified** and are required for B05. No real credentials may be used to bridge this gap. The full response must match an expected account identity before moving to decryption.

`strict_json.rs` now rejects duplicate JSON keys *before* the normal `Value` parser could discard an earlier key, including conflicting profile identities, archive/deletion timestamps and password visibility fields. The JSON decoder still has no authority to update the old encrypted cache.

## New encrypted projection and CA regression results (2026-11-04)

A separate test-only `projection.pfsnapshot` is encrypted with XChaCha20-Poly1305 and an independent local key provided by the caller; neither the key nor ciphertext is borrowed from legacy `vault.passvault`. A versioned authenticated header, private owner-owned directory, 0600 regular file, bounded reads, symlink/hardlink defenses, advisory exclusive lock and synced atomic publish protect the candidate. The old snapshot is authenticated before replacement, with cross-account/server and timestamp rollback rejection. Synthetic tests also verify offline decoding, exact Unicode secrets, and failure-preservation when any admitted record cannot decrypt or the sync is incomplete.

A temporary OpenSSL CA signs a localhost-only leaf. The native trusted-root path correctly rejects the untrusted CA, accepts it after **explicit root provision**, and rejects a hostname mismatch despite a valid chain. Custom CA PEM parsing rejects empty/malformed bundles; disabling TLS verification is not an option.

**CI evidence:** [Rust 188/188 tests and full gates](https://github.com/sguzman/passflick/actions/runs/41748051101) and [synthetic GUI success](https://github.com/sguzman/passflick/actions/runs/41748051062), for tested commit `58ae8b3`. **Not proven:** actual Vaultwarden login/sync, a permanent secure local unlock key lifecycle, remote revocation, true power-cut recovery or target-host security acceptance. The above Rust implementation remains excluded from production.

## Snapshot admission and update rules

- Require a valid complete, bounded remote sync response. Preserve upstream cipher IDs; abort the entire refresh for duplicate/malformed IDs or missing/malformed status fields.
- **Archive is a hard gate.** Vaultwarden/Bitwarden represent it as `archivedDate` (or `ArchivedDate` in PascalCase responses); a non-null date means hidden from the active picker. Missing archive metadata must fail closed rather than promoting archived historical credentials.
- **Trash is separate:** non-null `deletedDate` excludes items. Missing `deletedDate` fails closed instead of assuming an item remains active.
- **Respect upstream password permissions:** a user sync contains boolean `viewPassword`. An item with `viewPassword: false` is not eligible for a password picker. Missing/malformed visibility state fails the whole update; do not infer it from `edit` (a read-only but viewable item is different from a hidden password). This is grounded in the [Vaultwarden user-sync cipher serializer](https://github.com/dani-garcia/vaultwarden/blob/main/src/db/models/cipher.rs).
- **Reject ambiguous key casing:** an envelope with both `ciphers` and `Ciphers`, or a cipher with both lower/Pascal-case identity/type/login/permission keys, cannot be admitted by arbitrarily choosing one. Ignore unsupported non-login item types, and accept multiple independent login IDs with the same site and username.
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
| Missing `deletedDate` | Reject update without replacing prior projection |
| `viewPassword: false` (restricted organization item) | Omit credential |
| Missing/invalid `viewPassword` | Reject update; do not guess access rights |
| Ambiguous lower/Pascal-case fields | Reject update; do not prefer one field silently |
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
- **Disposable sync-ingress test module:** `src/bitwarden/sync_filter.rs` is compiled only in test builds during the first spike. It exercises raw-envelope archive/trash/visibility/ID admission and **does not** authenticate, contact a server or decrypt a password. It must be wired into a genuine backend before counting any native integration milestone complete.

**Selection remains pending.** Favor Rust and review upstream crypto rather than implementing it from scratch. No unsafe server access, no TLS bypass, no secrets committed to Git.

## Explicitly out of scope

Autofill, background source scraping, password edits, an automatic sync daemon, Vaultwarden administration, browser export ingestion in the final UX, and iOS app development. Other credential types and passkey retrieval are not silently added to this contract.
