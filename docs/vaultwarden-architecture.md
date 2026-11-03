# 🏗️ Vaultwarden-only projection architecture (design baseline)

**Status:** target architecture only; no native Vaultwarden integration implemented or tested yet. See [ROADMAP.md](../ROADMAP.md) for scope, weights, dependencies and acceptance gates.

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

An encrypted cached projection and a remote password-manager account **do not share an automatic global lock state**. Logging out or locking a browser extension cannot instantly destroy a separately cached offline decrypted copy.

Before release, document and test:

- Local Passflick unlock and explicit lock; when keys can remain in the Linux session keyring, and when cached keys expire or are removed.
- Clear distinction between session credentials/tokens used for update and at-rest cache keys used for offline picker operation; no permanent plaintext access tokens.
- Expected behavior if the remote account password changes, a session is revoked, the server is unreachable, or an item is archived between updates. Last known data can remain locally available until next successful update or local cache removal.
- Privacy of auth errors, process arguments, environment variables, terminal logs, panic output, application surfaces, backup files and temporary snapshots.
- Safe restore/migration without silently trusting an arbitrary old encrypted vault as current server state.

This is a **security decision gate**, not a claim that the existing session design already meets these semantics.

## Rust integration selection (not yet finalized)

**Candidate A — `rbw` implementation:** an MIT-licensed Rust Bitwarden CLI/agent, with public Rust modules and self-hosted support. Its crate surface is designed around the tool/daemon rather than a stable embeddable SDK. Audit auth, crypto, archive fields, current encryption formats, maintenance and dependency footprint; try a disposable prototype before deciding whether code/library reuse is sensible.

**Candidate B — Bitwarden internal SDK:** password-manager features exist in Rust but upstream explicitly labels external use **unsupported and unstable**. Explore compatibility only with an explicit maintenance and licensing review; do not install it merely because it is official Rust code.

**Candidate C — reviewed native adapter built on reusable crypto/API modules:** justified only if A/B do not provide an appropriate stable read-only client; minimize custom cryptography, isolate protocol code, and test with synthetic fixture servers. Do not confuse a self-hosted server REST API with decrypted password access.

**Official `bw` client:** useful as a synthetic test oracle. Do not assume Node/CLI will be a runtime dependency or that `bw serve` is safe to expose; a fallback production bridge needs an explicit engineering decision.

**Go/no-go decision record (A03/B01):** choose exactly one production integration path after documenting supported login/2FA, KDF and encrypted item formats, archive handling, dependency license, maintenance, TLS trust and failures for the intended Vaultwarden version. Never log actual credential values in tests.

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

## Deterministic acceptance fixtures

Use only fictional `example.test` data on a disposable Vaultwarden-compatible server. Test login creation and update; changed password; archive/restore; delete; same domain and username with different upstream item IDs; Unicode/whitespace password fidelity; unsupported item kind and encryption type; invalid CA, expired token, network outage; interrupted and concurrent updates; rollback and local lock; repeat update with no duplicate accumulation; actual Wayland sensitive clipboard and performance.

Existing `docs/acceptance.md` includes valuable GUI/security gates. Rewrite or adapt those gates after new implementation rather than treating browser CSV acceptance as new product requirements.

## Source references for the decision gate

- Bitwarden [internal SDK statement](https://github.com/bitwarden/sdk-internal): password manager interface unsupported for third parties and unstable.
- Bitwarden [SDK architecture](https://contributing.bitwarden.com/architecture/sdk/): crypto, auth and state are part of the SDK responsibilities.
- [rbw crate](https://docs.rs/rbw/latest/rbw/), [rbw repository](https://github.com/doy/rbw): Rust CLI + agent, not guaranteed stable embedded API.
- [Passflick security model](security.md), [current acceptance plan](acceptance.md), and [original development queue](queue.md): existing verified behavior and legacy work to reconcile.

**Public/privacy boundary:** this document deliberately includes no private server hostname, machine paths, real vault counts, usernames, credentials or personal narrative.