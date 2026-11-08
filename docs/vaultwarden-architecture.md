# 🏗️ Vaultwarden-only projection architecture (design baseline)

**Status:** ADR-001 integration path accepted; the native Vaultwarden adapter and opt-in `vaultwarden-preview` updater pass disposable Vaultwarden 1.37.5 integration, including a real CLI pseudo-terminal security run. The regular build/picker still uses the legacy encrypted vault. See [ROADMAP.md](../ROADMAP.md) for scope, weights, dependencies and acceptance gates.

## Current implementation checkpoint (2026-11-03)

The repository now contains **test-only** modules `src/bitwarden/envelope.rs`, `src/bitwarden/pipeline.rs`, and `src/projection.rs`. Together with `sync_filter.rs`, they demonstrate the **admission → fictional decode → validate complete replacement** shape using exclusively synthetic data. These are not network clients or password cryptography. They are intentionally excluded from the production binary.

A full `/sync` response must include the `object: "sync"` marker, a profile ID, folders and cipher list. A bare `{"ciphers":[]}` is not evidence of an intentionally empty vault. Both the upstream account and selected server identity must be bound to every future encrypted projection. A malformed or cross-account response is never sufficient to overwrite an existing snapshot.

The new projection model has no browser-provider identity and never deduplicates separate Vaultwarden item IDs. Its JSON representation is plaintext **only inside a zeroizing in-memory buffer**; it is not a file format until a distinct authenticated-encryption store, rollback checks, key lifecycle and atomic publish are implemented and tested.

## Isolated native HTTPS read-only transport (2026-11-03)

The test-only `src/bitwarden/transport.rs` contains a native Rust `reqwest` client for a single read-only `GET /api/sync`. It uses the Linux system trust store through rustls, rejects non-HTTPS root URLs, does not follow redirects, validates the expected account ID, and bounds streamed responses to 64 MiB. It has no login or session manager: a future authenticated caller must supply the bearer token and expected account ID. The module remains excluded from the production binary, and `reqwest` is only a dev dependency.

`src/bitwarden/strict_json.rs` rejects duplicate keys before any regular `serde_json::Value` admission, including nested conflicting lifecycle/visibility metadata. The existing complete sync envelope check and projection pipeline remain downstream. No plaintext cache is written and no real credentials are used.

**This is not a working Vaultwarden client.** It still requires native authentication and reviewed decryption, an HTTPS test server with trusted and bad-chain/hostname cases, encrypted transactional snapshot storage and real host acceptance. The single GET transport does not satisfy those requirements by itself.

## Rust crypto/auth integration in progress (2026-11-03)

The test-only `src/bitwarden/decryptor.rs` now uses `rbw` 1.15.0's MIT-licensed **library** key-derivation and authenticated AES-CBC cipherstring implementations. Personal login title/username/password and encrypted URIs are decrypted without synthetic prefix shortcuts, including per-item wrapped keys. Org-scoped items and nonzero master re-prompt are **hard failures for the entire update**, not silently projected under wrong credentials. Cipherstrings must carry a valid 32-byte HMAC, 16-byte IV and block-aligned ciphertext: upstream `rbw` otherwise panics for certain malformed MAC lengths.

The separate `src/bitwarden/auth.rs` performs native HTTPS prelogin and password-grant exchange, accepts TOTP/email-code MFA and models refresh/expiry with zeroizing in-memory session tokens. The same strict HTTPS CA/no-redirect client is reused. This layer is **not connected to the actual picker**, has not been exercised against a disposable Vaultwarden server, and has no token persistence. `rbw` is currently a **dev-only** dependency: adopting it for production still needs audited licensing/compatibility and stable API selection.

## Encrypted offline projection and trusted private CA (2026-11-04)

The isolated synthetic full-sync pipeline now decrypts **real authenticated type-2 personal-login cipherstrings** with reviewed `rbw` primitives, validates a complete upstream-ID-indexed projection, encrypts it with XChaCha20-Poly1305 under a distinct caller-supplied local key, and writes `projection.pfsnapshot` through a private owner-owned atomic file-publish path. Reopening the authenticated snapshot requires no network request. Failed or mismatched update candidates do not replace prior valid ciphertext; the legacy `vault.passvault` is never repurposed.

The disposable OpenSSL HTTPS test proves CA trust and hostname validation with no insecure fallback. It is not a working Vaultwarden integration. `reqwest` and `rbw` remain dev dependencies of test-only modules; production keyring, manual update and picker migration are **not** enabled. Synthetic CI passed all 188 Rust tests, fmt, CLI/desktop/encrypted-recovery smoke, Clippy and GUI on code commit `58ae8b3`.

**Next:** Validate full authentication, MFA and sync against a disposable real Vaultwarden; then review local key provisioning and explicit update/logout/lock UX before any production cutover.

## Disposable Vaultwarden 1.37.5 protocol evidence (2026-11-04)

A standalone GitHub Actions job launches a real Vaultwarden `1.37.5` server behind a local TLS Caddy proxy, generates a synthetic CA and permits volatile storage only in the throwaway container. A fixture-only provisioning client registers a fictional account, then creates two distinct encrypted login ciphers. The **Passflick** side authenticates with native Rust prelogin/password grant, consumes `GET /api/sync` without upstream writes, decrypts both records through MIT `rbw 1.15.0` primitives, persists an authenticated encrypted projection and reloads it offline. PBKDF2 is set to the server's enforced minimum of 100,000 iterations. All real login names, credentials, URLs and domain values are fictional.

**Verified:** [live server test: 1 passed](https://github.com/sguzman/passflick/actions/runs/41752298727), [Rust: 188 passed, 1 ignored](https://github.com/sguzman/passflick/actions/runs/41752173484), and [synthetic GUI green](https://github.com/sguzman/passflick/actions/runs/41752173545). The live test intentionally remains ignored during regular Rust tests to avoid a Docker requirement; its dedicated job runs it explicitly.

**Decision impact:** B01 native feasibility is established on this specific tested server/library pair. `rbw` is a CLI/agent with public but unstable embeddable modules; its high-level sync is not lossless for archive/permission metadata. The raw-sync adapter is the viable candidate; **A03 production selection remains open** pending authentication/MFA variants, upgrade maintenance plan, dependency/license review for the final build, and secure cache-key lifecycle. All new adapter modules remain under `#[cfg(test)]`.

## Independent local keywrap and projection session-cache checkpoint (2026-11-04)

The test-only `keywrap` module encrypts a **new random content key** with bounded Argon2id parameters and XChaCha20-Poly1305 under a separate local passphrase. The fixed-size `projection.pfkey` file is owner-only, create-only and authenticated against the exact projection server and account; it never borrows `vault.passvault` keys. Disposable Vaultwarden acceptance now uses it for the encrypted snapshot and proves locally reopening ciphertext after dropping remote token/decryptor state.

The separate test-only `session_cache` module introduces projection-only Linux session-keyring labels and manual lock markers, with an injected fake backend to prove lock ordering, stale-key authentication, and fail-closed behavior when key removal or unlock-marker removal fails. The Linux keyctl backend **compiles** but has not run on the user's machine or a privileged keyring-enabled CI fixture.

These pass [Rust CI](https://github.com/sguzman/passflick/actions/runs/41758871921), [live disposable server](https://github.com/sguzman/passflick/actions/runs/41758871854) and [synthetic GUI](https://github.com/sguzman/passflick/actions/runs/41758871891), all for code commit `e2ffb82`. This is implementation work toward C03, **not** production unlock, actual kernel-keyring QA, or a completed login/logout lifecycle.

**Additional accepted test-only boundary (2026-11-04):** Before a local session key is considered, its projection scope is recomputed from the full cache path, server and account. A mismatch never reaches the keyring or passphrase keywrap. [Rust CI: 199 passing tests](https://github.com/sguzman/passflick/actions/runs/41759929489) and the disposable-server/GUI workflows are green on `af45a51`; runtime Linux keyctl and target-host desktop semantics remain unverified.

## Native initial setup and first-cache transaction (2026-11-04)

The **test-only** `prepare_initial_sync` path derives the account ID from the server's complete authenticated sync response after binding the in-memory login session to its HTTPS endpoint; neither a fixture-specific account lookup nor user-supplied account ID is needed. The `ProjectionSnapshot` schema is versioned and strictly validated with upstream item IDs and no browser-source precedence.

The create-only `install_initial_projection` path stores a separately wrapped local content key then publishes a first encrypted snapshot under an exclusive writer lock. It refuses to replace existing ciphertext and supports passphrase-authenticated recovery when an interruption leaves only `projection.pfkey`. The real disposable Vaultwarden CI exercises this exact initial installation and offline reopening; [206 Rust tests](https://github.com/sguzman/passflick/actions/runs/41763434948), [GUI](https://github.com/sguzman/passflick/actions/runs/41763434980) and [Vaultwarden](https://github.com/sguzman/passflick/actions/runs/41763434898) are green on `50e2a18`.

**Acceptance update:** C01 (schema) and B05 (native trusted HTTPS/CA failures) are verified; the full session/lock/setup UI, production updater, real kernel keyring and target-host migration remain incomplete. Earlier dated sections below describe prior historical checkpoints.

## Explicit CLI update preview (2026-11-04)

An **optional, non-default** `vaultwarden-preview` Cargo feature now exposes a masked-terminal `passflick update` proof of integration. It reuses native login, trusted no-redirect TLS, complete account-bound read-only sync, independent Argon2id keywrap, authenticated offline schema and atomic publication. The default picker and legacy encrypted vault are unchanged. The command deliberately avoids persistent tokens, command-line secrets or automatic polling, while the first-run setup and refresh paths remain explicit.

Future session-keyring and picker-only APIs remain test-only so the preview binary contains only its necessary components. A trusted custom PEM CA may be selected without bypassing hostname verification. New local ciphertext is written to dedicated fixed XDG paths, never to a legacy vault override. Preview-specific tests and real disposable Vaultwarden acceptance are green at [code commit `89e93fa`](https://github.com/sguzman/passflick/commit/89e93fa78f18dc8bc63ca82bd516b83e78b6110b).

**Still pending:** persistent device ID, end-to-end terminal/Wayland acceptance, real kernel lock and logout, offline picker integration and migration safety. See the new D01 checkpoint in ROADMAP.md; it has **no additional weighted completion credit yet**.

## Stable preview device enrollment identifier (2026-11-04)

The opt-in native updater now owns a stable per-install 32-character hexadecimal device identifier stored in owner-only `projection.pfdevice` alongside the distinct local projection files, **never** in the legacy encrypted vault. All existing-device reads enforce private regular-file ownership, 0600 permissions, one hard link and exact byte-level format; an invalid identity fails closed rather than rotating. Initial directory validation and file persistence occur before the remote login handshake.

[CI-verified on `0a46e07`](https://github.com/sguzman/passflick/commit/0a46e075eaa71a0cf19b160d2a7c19eeb3717228): [Rust and preview tests](https://github.com/sguzman/passflick/actions/runs/41768931554), [GUI](https://github.com/sguzman/passflick/actions/runs/41768931435), [disposable Vaultwarden](https://github.com/sguzman/passflick/actions/runs/41768931335). Device enrollment/revocation under a real host and production local lock/offline picker integration remain outside this milestone.

## Real CLI pseudo-terminal acceptance (2026-11-04)

The disposable-server workflow now builds the opt-in preview executable and drives its **real interactive terminal prompts** under a Linux controlling PTY. This verifies one-time encrypted installation, failed passphrase preservation, repeat update, stable local device identity, TOTP sign-in, offline ciphertext authentication, non-echoed secrets and isolation from the legacy encrypted file. Echo is disabled **before** prompt display; the prior library helper could print first and create a fast-input echo race. The test also verifies actual termios flags before sending each fictional input.

[CI on `056d267`](https://github.com/sguzman/passflick/commit/056d2670d3b7140a4cb43eb564f2962c8ccbc0d6): [Rust](https://github.com/sguzman/passflick/actions/runs/41844078843), [GUI](https://github.com/sguzman/passflick/actions/runs/41844078897), [real disposable Vaultwarden and CLI](https://github.com/sguzman/passflick/actions/runs/41844078786) all passed. This is not production or actual EndeavourOS/Hyprland keyring/clipboard acceptance; the feature flag remains non-default.

## Opt-in local offline projection lifecycle (2026-11-04)

After a successful authenticated encrypted preview refresh, a create-only owner-only `projection.pfidentity` file can record the server URL identity and upstream account ID as a **non-secret, unencrypted routing hint**. It is not trusted to grant decryption: `projection unlock` must authenticate the dedicated Argon2id keywrap and AEAD snapshot against that same scope before adding the content key to the separately named Linux session-keyring entry. `projection lock` sets a deny marker before key invalidation; `projection status` checks the marker and authenticates any cached key before returning only count/timestamp metadata. All three commands run strictly offline. The historical vault and default picker are never read by this path.

[Code `4e55e9f`](https://github.com/sguzman/passflick/commit/4e55e9f3a83011b2c600874e9f22cd0c2665ce82) and [expanded Rust tests on `1d33832`](https://github.com/sguzman/passflick/actions/runs/41854391053) verify fake-backend manual-lock precedence, passphrase/identity failure boundaries and strict locator storage. The real kernel session lifetime, cross-process behavior, offline picker rendering and actual EndeavourOS/Hyprland QA remain unverified and are required before release.

## Additional verified native KDF compatibility (2026-11-08)

The second independent fictional account in disposable Vaultwarden 1.37.5 uses **Argon2id** (3 iterations, 64 MiB, parallelism 2). The real native adapter rejects an incorrect master password, accepts the correct password grant, unwraps that account's encrypted personal vault key and synchronizes/decrypts an upstream-ID-bound Unicode login with two URIs. This runs after (and independently of) the existing PBKDF2/TOTP fixture, on [code `0791634`](https://github.com/sguzman/passflick/commit/07916346f2cde42560ea3ae7aa49016881fbc8fc) with [Rust](https://github.com/sguzman/passflick/actions/runs/42496779350), [GUI](https://github.com/sguzman/passflick/actions/runs/42496779478) and [real disposable Vaultwarden](https://github.com/sguzman/passflick/actions/runs/42496779372) all green. Compatibility is not asserted for other server versions, organizational vaults, SSO or email-code MFA, and no default-picker migration is authorized.

## Responsibilities

| Component | Owns | Does not own |
| --- | --- | --- |
| Bitwarden-compatible server | Credentials, password updates, item IDs, archive/deletion state, authoritative synchronization data | Passflick's local picker UX |
| Native Rust read-only adapter (planned) | Explicit server configuration, authentication, transport, vault crypto via reviewed implementations, decrypted read-only items | Creating/updating/deleting server items; per-launch network dependency |
| Encrypted local projection (existing machinery, new schema needed) | Atomic copy of most recent successfully synchronized item set, private persistence, local lock and freshness metadata | Editing authoritative credentials |
| egui picker (existing) | Fast local search, selection, sensitive Wayland copy, on-demand update affordance | Background scraping, acting as a password editor |

**Explicit refresh is the default:** user calls `passflick update` or explicitly clicks the update affordance; no network use during ordinary launch/search/copy. The user retains an encrypted local projection between sessions and across temporary server/network outages. No autonomous polling is needed for the accepted product.

## Proposed data flow

1. **Initial connect:** user configures server URL, trusts CA through OS-supported TLS, authenticates using supported provider flows. No browser vault export or CSV is needed.
2. **Update:** adapter authenticates, retrieves a consistent upstream snapshot, decrypts supported login items, maps them into an intermediate schema keyed by **upstream item ID**, rejects malformed/unsupported data under a documented policy.
3. **Commit:** validate counts and data shape, encrypt a private temporary projection, fsync and atomically replace the prior projection only after successful verification; persist a non-secret timestamp/version and preserve recoverability.
4. **Use:** launch egui, unlock the local projection under an explicit policy, search in memory; copy selected password or username with sensitive clipboard mode; exit.
5. **Repeat update:** changed passwords and newly created items replace their previous IDs; removed/archived items disappear from the *new active projection*; transient failures leave the older encrypted snapshot intact and its last-sync age visible.

## Item identity and display policy

- Primary identity is the stable upstream cipher/item ID; do **not** treat site+username as unique or automatically select one of several password variants.
- Searchable content: title, sanitized display host and URL search identity, username. Full metadata is encrypted on disk. URL-bearing tokens must not leak into row labels.
- Project only supported logins into the picker at first. Ignore unsupported item classes deliberately with non-secret aggregate diagnostics rather than silently treating them as valid login credentials.
- Archive and Trash are upstream states; the active picker omits them once refreshed. Folder status may be displayed for curation but is not a filtering/security boundary.
- Prefer exact round trips for password, username, and nontrivial Unicode; preserve password byte semantics. Unsupported crypto or cipher states fail safely and visibly.
- No source-priority preference for Edge/Chrome/Firefox/Apple. Historic import provenance can remain upstream custom fields but is not a Passflick source type.

## Locking and offline trade-off

**Accepted security policy:** [ADR-002](adr-002-local-cache-security.md) defines the independent local content key, versioned Argon2id passphrase wrapping, explicit manual-lock priority, session-scoped key caching, opt-in desktop keyring, remote revocation limits, offline freshness and cleanup semantics. These are implementation requirements; existing legacy unlock behavior does **not** implement them for the new projection.


An encrypted cached projection and a remote password-manager account **do not share an automatic global lock state**. Logging out or locking a browser extension cannot instantly destroy a separately cached offline decrypted copy.

Before release, document and test:

- Local Passflick unlock and explicit lock; when keys can remain in the Linux session keyring, and when cached keys expire or are removed.
- Clear distinction between session credentials/tokens used for update and at-rest cache keys used for offline picker operation; no permanent plaintext access tokens.
- Expected behavior if the remote account password changes, a session is revoked, the server is unreachable, or an item is archived between updates. Last known data can remain locally available until next successful update or local cache removal.
- Privacy of auth errors, process arguments, environment variables, terminal logs, panic output, application surfaces, backup files and temporary snapshots.
- Safe restore/migration without silently trusting an arbitrary old encrypted vault as current server state.

This is a **security decision gate**, not a claim that the existing session design already meets these semantics.

## Rust integration selection (ADR-001 accepted)

**Selection (2026-11-04):** Candidate C is **chosen for development and production implementation**, using `reqwest` Rustls raw HTTPS sync plus narrow MIT `rbw 1.15.0` primitives and a separate encrypted offline projection. Read [ADR-001](adr-001-native-vaultwarden-adapter.md) for the rationale, tested TOTP/token-refresh and lifecycle behavior, explicitly scoped organization/email-MFA/SSO limitations, plus the separately verified Argon2id personal-account KDF path, dependency stability and upgrade gates. This is a settled **architecture choice**, not authorization to move the test-only adapter into the production picker before the key/unlock/CLI acceptance gates.


**Candidate A — `rbw` implementation:** an MIT-licensed Rust Bitwarden CLI/agent, with public Rust modules and self-hosted support. Its crate surface is designed around the tool/daemon rather than a stable embeddable SDK. Audit auth, crypto, archive fields, current encryption formats, maintenance and dependency footprint; try a disposable prototype before deciding whether code/library reuse is sensible.

**Candidate B — Bitwarden internal SDK:** password-manager features exist in Rust but upstream explicitly labels external use **unsupported and unstable**. Explore compatibility only with an explicit maintenance and licensing review; do not install it merely because it is official Rust code.

**Candidate C — reviewed native adapter built on reusable crypto/API modules:** justified only if A/B do not provide an appropriate stable read-only client; minimize custom cryptography, isolate protocol code, and test with synthetic fixture servers. Do not confuse a self-hosted server REST API with decrypted password access.

**Official `bw` client:** useful as a synthetic test oracle. Do not assume Node/CLI will be a runtime dependency or that `bw serve` is safe to expose; a fallback production bridge needs an explicit engineering decision.

**A03/B01 decision:** ADR-001 documents the selected raw-sync architecture with native TLS, MIT `rbw` KDF/cipherstring primitives, live TOTP and token-renewal tests, lifecycle behavior and compatibility risks. Do not promote the adapter to production before the remaining security gates. Never log actual credential values in tests.

## Modules and migration sketch

The following are *responsibility boundaries*, **not** a mandate to create one file per bullet or arbitrary line-count limits:

- `src/bitwarden/...` (planned): endpoint, auth, read-only protocol, decryption/adapter
- `src/projection/...` (planned): model, validation, encrypted publish, freshness, lock policy
- Existing `src/app.rs`, `src/search.rs`, `src/clipboard.rs`: retain picker behavior but replace legacy source attributes with upstream-ID metadata.
- Existing `src/vault.rs`, `src/backup.rs`, `src/session.rs`, `src/desktop_keyring.rs`: reuse or refactor only after checking new lifecycle and identity requirements.
- `src/import.rs`, `src/discovery.rs`, `src/source_status.rs`: retire only after new sync and migration gates pass; keep history, don't keep an invisible second ingestion feature.

Prefer cohesive modules; never centralize unrelated auth/crypto/sync/GUI functionality in a god file. There is no source-file size quota.

## Explicit initial command surface (proposal)

- `passflick configure` / setup screen: self-hosted server URL, credentials via safe input mechanisms; no secrets in shell argument history.
- `passflick update`: intentionally initiated refresh, no plaintext stdout, distinct success/failure codes.
- `passflick status`: local unlock state, last successful sync age and non-secret item count; no password listing in unattended logs.
- `passflick lock`: clear local usable key/session under documented behavior.
- `passflick`: local picker, no mandatory HTTP request.

CLI naming and login flow require implementation review and are not yet shipped.

## Verified preview offline picker and GUI fixture (2026-11-04)

The opt-in `passflick projection picker` opens a **read-only, offline, authenticated** snapshot independently of `vault.passvault` and all browser imports. It preserves distinct upstream login IDs, filters titles/all URIs and usernames, displays safe token-stripped labels and a last-sync-age warning, and supports System/Light/Dark. Manual locking clears in-memory rows on the next check and blocks all subsequent copying. Every copy obtains the shared cross-process file guard, authenticates the current snapshot and resolves the selected upstream item ID before invoking the sensitive Wayland clipboard helper. Previously copied data is not revoked retroactively.

[Verified code `d78e7f7`](https://github.com/sguzman/passflick/commit/d78e7f7db02159ad55f3352bd1cda4ba67879ec8): [disposable populated Xvfb/real Vaultwarden GUI](https://github.com/sguzman/passflick/actions/runs/41869547409) checks actual fictional Unicode/whitespace copying and manual-lock denial; [separate GUI/Wayland smoke](https://github.com/sguzman/passflick/actions/runs/41869547535) checks locked-state GUI and native sensitive transport; [Rust strict lint and recovery](https://github.com/sguzman/passflick/actions/runs/41869547745) are green. Populated native Wayland/Hyprland rendering, session logout and concurrent selected-credential changes are not yet accepted.

## Selected-credential consistency across remote refresh (2026-11-04)

In the non-default offline GUI, the selected upstream ID alone does not authorize copying a possibly updated password. A copy holds the private cross-process writer guard, authenticates the latest encrypted projection, then compares the original displayed title/URIs/username/password for that ID against the latest authenticated record. A changed or removed selected record yields a non-secret request to reopen the picker, without calling the clipboard adapter. A normal distinct upstream ID and unaffected entry remain independently selectable. This does not imply real-time server revocation while offline.

[Runtime and fixture `7651a4d`](https://github.com/sguzman/passflick/commit/7651a4ded94b105854a453f3c6e409f821c12a34) passed [disposable Vaultwarden with populated Xvfb egui GUI](https://github.com/sguzman/passflick/actions/runs/41873368338), [Rust](https://github.com/sguzman/passflick/actions/runs/41873368337), and [synthetic GUI including Weston transport](https://github.com/sguzman/passflick/actions/runs/41873368464). The real fixture verifies remote edit, explicit refresh, authenticated local replacement and *continued unlocked keyring*, then refusal by the already-open UI. **Target Hyprland/Wayland GUI and logout acceptance remain unverified.**

## Deterministic acceptance fixtures

Use only fictional `example.test` data on a disposable Vaultwarden-compatible server. Test login creation and update; changed password; archive/restore; delete; same domain and username with different upstream item IDs; Unicode/whitespace password fidelity; unsupported item kind and encryption type; invalid CA, expired token, network outage; interrupted and concurrent updates; rollback and local lock; repeat update with no duplicate accumulation; actual Wayland sensitive clipboard and performance.

Existing `docs/acceptance.md` includes valuable GUI/security gates. Rewrite or adapt those gates after new implementation rather than treating browser CSV acceptance as new product requirements.

## Source references for the decision gate

- Bitwarden [internal SDK statement](https://github.com/bitwarden/sdk-internal): password manager interface unsupported for third parties and unstable.
- Bitwarden [SDK architecture](https://contributing.bitwarden.com/architecture/sdk/): crypto, auth and state are part of the SDK responsibilities.
- [rbw crate](https://docs.rs/rbw/latest/rbw/), [rbw repository](https://github.com/doy/rbw): Rust CLI + agent, not guaranteed stable embedded API.
- [Passflick security model](security.md), [current acceptance plan](acceptance.md), and [original development queue](queue.md): existing verified behavior and legacy work to reconcile.

**Public/privacy boundary:** this document deliberately includes no private server hostname, machine paths, real vault counts, usernames, credentials or personal narrative.