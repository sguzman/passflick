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

## Test-only independent local keywrap and manual-lock boundary (2026-11-04)

A separate `projection.pfkey` file now wraps a random XChaCha20-Poly1305 snapshot content key under Argon2id from an **independent local passphrase**, bound by authenticated associated data to the full normalized Vaultwarden server identity and upstream account. The wrapped key is never a legacy vault key or Vaultwarden token. Private 0600 create-only file storage, metadata/KDF caps, corruption and identity rejection have synthetic tests, and actual disposable server acceptance has reopened the complete encrypted snapshot offline after dropping its remote session.

The session-cache prototype has **separate** key/lock namespaces and a fail-closed manual-lock marker that outranks cached keys. Its fake-keyring tests check non-destructive wrong unlock, authenticated cached reads, failed removal ordering and explicit re-unlock. The **real kernel adapter is compiled but not exercised**, so this does not establish real login-session key lifetime or automatic lock/revocation guarantees. All new code remains behind test-only module inclusion.

[CI evidence: 198 Rust tests and security gates](https://github.com/sguzman/passflick/actions/runs/41758871921), [synthetic GUI](https://github.com/sguzman/passflick/actions/runs/41758871891) and [disposable Vaultwarden 1.37.5](https://github.com/sguzman/passflick/actions/runs/41758871854) passed on `e2ffb82`. Remains unverified: real local keyring, Secret Service enrollment, terminal/GUI secret entry and cleanup, logout/purge and target-host Wayland acceptance.

## Projection session-scope identity binding (2026-11-04)

In the test-only session cache, each attempted cached read or explicit passphrase unlock first recomputes its scope from the actual encrypted projection filename, canonical parent path, HTTPS server identity, and upstream account. A scope supplied for a different path/server/account is rejected **before touching the kernel-keyring or keywrap adapter**. The session label is only a lookup hint: every successful read still authenticates the full encrypted snapshot and verifies the account/source binding. No production picker or legacy-keyring path is changed.

[All 199 Rust tests, smoke and Clippy](https://github.com/sguzman/passflick/actions/runs/41759929489), [disposable real server acceptance](https://github.com/sguzman/passflick/actions/runs/41759929533), and [synthetic GUI](https://github.com/sguzman/passflick/actions/runs/41759929565) passed for code commit `af45a51`. Real kernel keyring operations were **not** exercised; scope and lock backend tests use a synthetic store.

## Keywrap sibling pairing and remote token endpoint binding (2026-11-04)

The isolated local passphrase unlock requires its `projection.pfkey` file to be the **exact sibling** of the requested `projection.pfsnapshot`. A foreign-directory or renamed envelope is rejected before keywrap or kernel-keyring access, alongside the existing authenticated server/account/snapshot checks.

Native `RemoteSession` now records the canonical HTTPS server endpoint that issued the token pair. Refreshing against a different host or reverse-proxy root fails **before** a refresh-token HTTP request. The explicit updater also checks the session/endpoint match before sending an unexpired bearer token. This does not imply that arbitrary account/org policy support or production secret entry is complete.

[Verified Rust CI: 201 passed, 0 failed](https://github.com/sguzman/passflick/actions/runs/41761539145), [synthetic GUI CI](https://github.com/sguzman/passflick/actions/runs/41761539259), [real disposable Vaultwarden 1.37.5](https://github.com/sguzman/passflick/actions/runs/41761539159), on code commit [`675523b`](https://github.com/sguzman/passflick/commit/675523bf356d391044bc2a6214043f82e659d2ff). Both boundaries remain test-only; target-host kernel-keyring and final local lock/unlock are not yet verified.

## Authenticated first-time account discovery and encrypted create-only installation (2026-11-04)

The test-only native initializer verifies a complete trusted HTTPS `GET /api/sync` response under the authenticated session endpoint, extracts its **server-issued** account ID, decrypts all supported active logins and creates a versioned in-memory projection. It never asks a fixture client or user to invent an account identity. A malformed/ambiguous response fails admission before storage. Only a subsequent explicit local setup creates the independent Argon2id keywrap and encrypted snapshot.

Initial publication is **create-only under a writer lock**, including a second existence check at publication. It cannot replace a prior authenticated or corrupt snapshot. A stranded encrypted keywrap from an interrupted first install can be reopened by the same local passphrase and setup retried safely; incorrect passphrases cannot authenticate it, and legacy `vault.passvault` remains unchanged. This is not yet an interactive production setup/CLI path, nor evidence of full power-cut/target-host acceptance.

[Green Rust CI: 206 passing tests](https://github.com/sguzman/passflick/actions/runs/41763434948), [synthetic GUI](https://github.com/sguzman/passflick/actions/runs/41763434980), and [real disposable Vaultwarden 1.37.5](https://github.com/sguzman/passflick/actions/runs/41763434898) on code commit `50e2a18`. Separately, B05 HTTPS/CA trust and C01 versioned projection schema now meet their objective acceptance criteria; all production migration and keyring gates stay open.

## Opt-in experimental masked terminal update (2026-11-04)

The new `vaultwarden-preview` Cargo feature exposes a **preview-only** `passflick update` command while keeping it absent from the default executable. Server URL, email, master password, optional MFA code, optional trusted custom CA PEM path and local passphrase are entered through masked prompts; credentials and tokens are never accepted as command arguments. Access and refresh tokens are in-memory only, with no automatic or picker-triggered network requests. Errors are sanitized and non-secret.

The preview uses a server-issued account ID from a complete authenticated sync and encrypts the new local projection under the independent Argon2id-wrapped local content key. A first install is create-only, and any subsequent refresh must successfully decrypt the prior snapshot bound to the same account/server before atomic replacement. Wrong local passphrases and identity/AEAD failures preserve existing ciphertext. The historical `vault.passvault` remains untouched, including when `PASSFLICK_VAULT` is set.

**Limits:** the preview still generates a fresh device ID on each explicit invocation, cannot enforce instant remote revocation of an offline copy, has no verified real Linux kernel-keyring lock lifecycle or stable device enrollment, and is not integrated into the normal picker or a validated terminal/Wayland installation. Only synthetic and disposable-server secrets were used for verification; this is not owner authorization to migrate personal vaults.

[Rust CI on `89e93fa`: 206 baseline + 2 preview tests, strict Clippy and smoke](https://github.com/sguzman/passflick/actions/runs/41767285591), [synthetic GUI](https://github.com/sguzman/passflick/actions/runs/41767285478) and [disposable HTTPS Vaultwarden](https://github.com/sguzman/passflick/actions/runs/41767285570) are green. D01 remains active and uncredited pending default-build, terminal and lifecycle acceptance.

## Stable private preview device identity (2026-11-04)

The opt-in `passflick update` preview now reuses one random device identifier across explicit login attempts rather than creating a new remote device on every invocation. It stores **only** a 32-character lowercase-hex identifier (not a token, password or key) in owner-only `projection.pfdevice` beside the independently encrypted snapshot and keywrap. The 0600 file is created without replacing existing data and synchronized; opening rejects symlinks, extra hard links, wrong ownership/permissions, invalid lengths and malformed content. An unsafe file causes failure rather than silent ID rotation.

Synthetic tests cover stable reuse and preservation of the legacy encrypted file, plus malformed, symlink, hardlink and permission rejection. [Rust: 206 baseline + 4 preview tests, both strict Clippy configurations](https://github.com/sguzman/passflick/actions/runs/41768931554), [synthetic GUI](https://github.com/sguzman/passflick/actions/runs/41768931435), and [disposable Vaultwarden](https://github.com/sguzman/passflick/actions/runs/41768931335) are green on [`0a46e07`](https://github.com/sguzman/passflick/commit/0a46e075eaa71a0cf19b160d2a7c19eeb3717228).

This demonstrates local ID persistence **only**; target-host enrollment, remote device revocation, logout, actual session-keyring policy and production migration still require their own acceptance. No user accounts were used in CI.

## Real preview CLI terminal echo security and end-to-end validation (2026-11-04)

The Linux pseudo-terminal acceptance test discovered that the previous preview's library prompt was written to the terminal **before** it disabled echo. A rapidly supplied secret could appear in captured terminal output. The preview-only implementation now disables `ECHO` and `ECHONL` via termios *before displaying any prompt*, retains a restoration guard for success or failure, and invokes the existing password reader while echo remains disabled. Each prompt in the new PTY driver is checked against actual terminal flags **before** test input is supplied, and any echoed fictional credential causes the test to fail without printing its content.

The same PTY driver runs the real opt-in CLI (not a helper-only simulation) over disposable trusted HTTPS Vaultwarden. The acceptance covers first setup, wrong local-passphrase preservation, successful encrypted repeat update, stable local device ID, synthetic TOTP authentication, and encrypted offline reopening. Only a fixture-only HTTP client may edit the disposable vault; Passflick's native sync remains read-only. No personal credentials or old encrypted data were involved. The original legacy input prompts were not changed in this step.

[Code `056d267`](https://github.com/sguzman/passflick/commit/056d2670d3b7140a4cb43eb564f2962c8ccbc0d6) passes [Rust: 206 baseline and four preview tests, both strict Clippy configurations](https://github.com/sguzman/passflick/actions/runs/41844078843), [synthetic GUI](https://github.com/sguzman/passflick/actions/runs/41844078897), and [real disposable Vaultwarden CLI acceptance](https://github.com/sguzman/passflick/actions/runs/41844078786). This does **not** attest that target-host terminal state, kernel keyring, revocation, default-build integration or normal picker migration are safe yet.

## Preview-only offline source locator and projection session commands (2026-11-04)

An opt-in `projection unlock|lock|status` CLI now exercises the independent offline-cache keywrap and projection-specific Linux session keyring, without any HTTP or Vaultwarden tokens. The old `unlock|lock|status` and legacy `vault.passvault` remain unchanged. Each successful new projection publication can create an immutable, owner-only 0600 `projection.pfidentity` sidecar. It contains the canonical server identity and opaque upstream account ID **in cleartext** (not credentials or bearer/refresh tokens). This is intentionally a **non-secret lookup hint**; it may expose a private hostname/account identifier to processes with access as the same OS user. The secure keywrap and encrypted snapshot remain the sole authority for authenticated local access.

The hint uses a fixed binary format with bounded server/account lengths, private-directory ownership enforcement and symlink/hardlink/permission checks. An absent hint on an older preview snapshot requires a successful remote update to recreate it; malformed or conflicting data fails closed. Local manual lock establishes its denial marker before cached-key invalidation; explicit unlock checks the keywrap and snapshot first, and only then caches the key and clears the marker. A failed cache or kernel operation is reported, not represented as unlocked.

**Evidence:** [Rust on `1d33832`](https://github.com/sguzman/passflick/actions/runs/41854391053) passed 206 baseline and 9 focused preview tests (4 update, 3 locator and 2 offline lifecycle), smoke tests, formatting and strict Clippy; [disposable Vaultwarden](https://github.com/sguzman/passflick/actions/runs/41853774795) and [synthetic GUI](https://github.com/sguzman/passflick/actions/runs/41853774807) passed on the identical source code. **The kernel backend has only been compiled in this round**—its behavior across separate processes, manual lock after desktop logout, and Wayland picker integration remain unverified. This is not production cache/session acceptance.

## Linux cross-process manual lock and concurrent unlock boundary (2026-11-04)

The opt-in projection CLI has now been tested across **independent executable processes on a real Ubuntu CI kernel session keyring**. Synthetic encrypted data was created through a disposable HTTPS Vaultwarden account; subsequent offline status/unlock/lock commands made no network requests. A new process can reuse the authenticated session key, manual lock persists to other processes, a wrong local passphrase cannot remove the denial marker, and correct explicit unlock restores access. [Disposable live-server PTY acceptance](https://github.com/sguzman/passflick/actions/runs/41858482713) passes.

Code review also found a manual-lock race: an in-flight unlock might cache a new key *after* the completed lock had removed the old one, then clear the denial marker. Both `session_cache::lock` and `unlock` now acquire the existing cross-process encrypted-snapshot writer guard before accessing either keyring entry. This serializes lock and unlock with each other and with snapshot publication, including keywrap authentication. A synthetic two-thread regression pauses key insertion and verifies a concurrent lock cannot finish until unlock releases the guard; the resulting state is locked. [Rust CI `7ab85d1`](https://github.com/sguzman/passflick/actions/runs/41858482910) passes 207 baseline tests, nine focused opt-in preview tests, recovery smoke and both strict Clippy configurations; [synthetic GUI CI](https://github.com/sguzman/passflick/actions/runs/41858482805) is green.

**Limits:** this proves one CI-host Linux session keyring lineage, **not** actual EndeavourOS/Hyprland desktop login/logout, all PAM/systemd keyring policy variants, or atomic revocation of already-copied credentials. The production picker is still on the legacy vault; no real user account or historical encrypted data was touched.

## Offline picker sensitive copy gate (2026-11-04)

The feature-gated `passflick projection picker` never reads browser CSVs, the legacy encrypted vault or remote network data. A missing/locked/unusable independent projection opens only a locked notice. Display labels omit URL path, userinfo, query and password content; memory of authenticated records and labels is zeroized on drop and when an explicit lock is detected.

**Copy requires renewed authentication:** the picker holds the same cross-process file guard as explicit local lock/unlock and encrypted snapshot publication, opens the currently authenticated snapshot, resolves the selected upstream item ID and writes only the requested password/username bytes to the reviewed `wl-copy --sensitive` adapter. An already completed manual lock prevents an open picker from copying. Clipboard bytes copied before a lock cannot be retracted, and other same-user processes are outside the isolation boundary.

On [`d78e7f7`](https://github.com/sguzman/passflick/commit/d78e7f7db02159ad55f3352bd1cda4ba67879ec8), the [populated disposable Xvfb GUI](https://github.com/sguzman/passflick/actions/runs/41869547409), [separate GUI/Weston clipboard transport](https://github.com/sguzman/passflick/actions/runs/41869547535) and [Rust](https://github.com/sguzman/passflick/actions/runs/41869547745) checks all pass. Actual populated native Wayland, target-host keyring logout and selected-secret consistency across simultaneous remote refresh are still acceptance gates.

## Fail-closed selected-item refresh boundary (2026-11-04)

A refresh can replace the secret under the **same upstream Vaultwarden item ID**, without the already-open egui preview re-rendering its row. Copying by ID alone would silently transmit a credential different from the one the user selected. The preview picker now compares the displayed and newly authenticated record's title, full URI set, username and password while holding the shared writer guard used by lock/unlock and encrypted publication. Missing or changed selected records prevent the sensitive clipboard call and require reopening the window. The error remains constant text; no secret values are logged or displayed.

[Verified `7651a4d`](https://github.com/sguzman/passflick/commit/7651a4ded94b105854a453f3c6e409f821c12a34): the [disposable live Vaultwarden GUI regression](https://github.com/sguzman/passflick/actions/runs/41873368338) proves that the server-side fictional edit was published to the authenticated encrypted projection, the Linux keyring stayed unlocked, and a stale window copied nothing; [strict Rust](https://github.com/sguzman/passflick/actions/runs/41873368337) and [GUI/Wayland transport](https://github.com/sguzman/passflick/actions/runs/41873368464) pass. This does not make offline cached secrets immediately revocable by the remote server or prove target-host Hyprland focus/session behavior.

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
