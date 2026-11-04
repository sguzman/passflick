# 🗺️ Passflick — Vaultwarden projection roadmap

**Status:** native adapter verified in disposable Vaultwarden CI; an opt-in, non-default native update preview is available behind `vaultwarden-preview`. The installed production picker remains on the encrypted legacy vault. Do not use personal credentials for acceptance until target-host security gates pass.  
**Target:** Rust + egui on Linux/Wayland (EndeavourOS/Hyprland first).  
**Mission:** Passflick is a small, fast, keyboard-first, **read-only downstream projection of a Bitwarden-compatible personal vault**, not an independent password manager or a browser CSV aggregator.

## 🎯 Authorized product contract

- **One source of truth:** a user-selected Bitwarden-compatible server, including self-hosted Vaultwarden. Passflick must never edit, create, delete, archive, or reorganize upstream items.
- **Explicit refresh:** the user can call `passflick update`; a compact in-app update affordance may do the same. No mandatory periodic polling, invisible background syncing, or network access per picker invocation. Never overwrite a healthy projection because a refresh failed.
- **Always-available projection:** after successful synchronization, retain an authenticated, encrypted local snapshot and search it quickly when offline. First-time use requires an authenticated initial sync; locked caches require a local unlock policy. Show the age of the snapshot.
- **Picker remains intentionally tiny:** summon → filter site and username → select → copy password with Enter or username with Shift+Enter → exit. Escape does not copy. Preserve keyboard navigation, sensitive clipboard behavior, metadata sanitization, and fast startup.
- **Upstream item identity:** maintain distinct item IDs even if titles, usernames, or passwords collide. Preserve useful URLs, names, folder/status metadata, and opaque IDs required for reconciliation; omit archived/deleted items from the *active* projection after a successful refresh. Do not infer that stale offline data reflects current upstream archival decisions.
- **No new password manager:** no password editing, no browser-profile scraping, no CSV import workflow in the final supported UX, no second independent authority. Historical implementation may remain in Git history; remove legacy mode only after replacement acceptance.
- **Security:** trust the configured CA without disabling HTTPS verification; do not log passwords, session tokens, recovery keys, vault exports, decrypted snapshots, or private machine configuration. Use synthetic fixtures in CI. Review key lifetime, auth state, revocation behavior, rollback and offline threats.
- **Technology:** Rust/Cargo, egui, existing repository license unless a reviewed dependency forces a deliberate decision. No npm. Prefer a native Rust client; do not claim that a binary-only project is a stable library. The official CLI is an integration test oracle or explicitly approved contingency, not an assumed production dependency.

The **user-controlled update** model is deliberate: search/copy may work offline from the latest successfully synchronized encrypted snapshot. Offline access and instant remote revocation cannot both be guaranteed; a clear cache lock/revocation policy and visible freshness indicator are required before release.

## ⚖️ Progress accounting and evidence

New scope replaces the previous multi-browser-source objective, so old and new percentages are **not comparable**. Preserve existing verified picker, clipboard and encrypted-vault capabilities while re-estimating all *new* integration, migration and acceptance work.

**Rebaseline: 13/100 weighted points verified (13%) as of adoption.** Current verified completion: **29/100 weighted points (29%)**, including accepted native architecture/local-cache policy, the versioned projection schema (C01), and native HTTPS/CA acceptance (B05). Both newly credited components have passing synthetic/security acceptance; their surrounding native integration remains test-only. **This is not a production-ready Vaultwarden picker.** The disposable live-server evidence is documented below.

`█████▊░░░░░░░░░░░░░░` **29%** (previous verified 29% → 29%, **+0 percentage points** this development round; adoption baseline 13%).

**Status key:** ✅ verified complete | 🟡 active | ⬜ pending | ⛔ blocked. Every item's bracketed **w** is its share of the 100-point overall estimate. An item earns all its weight only after its acceptance check passes; partial activity is documented but not counted. Adjust weights transparently if discoveries materially change the project.

## M0 🧭 Reconnaissance and product architecture — 12 points

| ID | Task | w | Status | Acceptance / dependency |
| --- | --- | ---: | --- | --- |
| A01 🔍 | Audit existing code, CI, dependencies, historical roadmap and reusable components | 3 | ✅ | Identify real source importer, independent encrypted vault, picker, keyring and security gates from repository evidence; initial audit recorded below |
| A02 🎯 | Establish new user contract and non-goals | 3 | ✅ | Single upstream authority, explicit refresh, encrypted cache, offline semantics, picker and read-only scope documented in this roadmap and PROJECT.md |
| A03 ⚖️ | Decide and document supported native Rust integration approach | 3 | ✅ | Prototype/auth feasibility and dependency stability/license findings; select an implementation only after evidence; requires A02 |
| A04 🛡️ | Threat model and lock/freshness/revocation policy | 3 | ✅ | Define access after Vaultwarden logout or account revocation, local unlock, stolen-disk/session threat, cache destruction, and update failure behavior; requires A03 |

**Existing state:** `src/app.rs`, `src/search.rs`, `src/clipboard.rs`, `src/vault.rs`, `src/session.rs` and `src/desktop_keyring.rs` contain candidate reusable behavior. `src/import.rs`, `src/discovery.rs`, `src/source_status.rs` and browser-specific source ranking are legacy. Current `PROJECT.md`, `docs/queue.md`, `docs/sources.md` and existing CI are for the original product and require careful reconciliation. Preserve privacy and historical evidence.

## M1 🦀 Native Rust Bitwarden-compatible client — 20 points

| ID | Task | w | Status | Acceptance / dependency |
| --- | --- | ---: | --- | --- |
| B01 🧪 | Protocol/library evaluation and isolated spike | 4 | ✅ | Test currently relevant `rbw`-derived APIs, Bitwarden SDK boundaries, and feasibility of a native adapter against a disposable server; document license, stability, maintenance and version risks; A03 candidate |
| B02 🔑 | Authenticate self-hosted account safely | 5 | 🟡 | Support an explicitly configured endpoint, supported primary auth, session expiration, token refresh and MFA/error handling appropriate to selected backend; no token leaks; B01 |
| B03 🔐 | Retrieve/decrypt compatible vault items | 6 | 🟡 | Correctly handle supported login cipher types, key derivation, server sync and distinct IDs in fictional fixture; reject unknown encryption formats safely; B02 |
| B04 🧱 | Enforce read-only adapter boundary | 3 | ⬜ | Adapter exposes fetch/list only, no upstream mutations; tests demonstrate absence of write operations under normal/error paths; B03 |
| B05 🧷 | Self-hosted HTTPS and CA trust | 2 | ✅ | System/private CA support and hostname validation pass; bad-chain, MITM-like mismatch and inaccessible server fail closed; B02 |

**Backend decision gate:** ADR-001 accepts the narrow native raw-sync adapter using pinned MIT `rbw` cryptographic components and trusted Rustls transport after disposable-server proof. The unsupported Bitwarden internal SDK and lossy high-level `rbw` sync are not adopted. Production deployment, version-upgrade compatibility, session UX and target-host security remain independently gated.

## M2 💾 Encrypted local projection and key lifecycle — 19 points

| ID | Task | w | Status | Acceptance / dependency |
| --- | --- | ---: | --- | --- |
| C01 🗃️ | Define versioned upstream-ID indexed projection schema | 4 | ✅ | Preserve exact secrets and nonsecret searchable metadata without legacy provider precedence; reject malformed/oversized records; B03 |
| C02 💽 | Atomic encrypted snapshot replacement and recovery | 4 | 🟡 | Snapshot remains authenticated, private and recoverable; power-loss/interruption simulation never replaces last good snapshot with partial records; C01 |
| C03 🔒 | Local unlock, key caching, lock/logout and key zeroization | 4 | 🟡 | Reuse reviewed existing keyring/AEAD where appropriate; user can lock local projection; no silent unlock of stale/revoked credentials contrary to documented policy; A04, C01 |
| C04 ♻️ | All-or-nothing refresh lifecycle | 4 | 🟡 | Authenticate/fetch/decrypt/validate/publish stages; failed or concurrent updates leave valid snapshot intact and report outcome; B04, C02 |
| C05 📴 | Offline and stale-cache behavior | 3 | ⬜ | Last successful snapshot is readable offline under chosen lock policy, freshness visible, first-run/offline/no-cache fails informatively; C03, C04 |

**Source-of-truth warning:** The snapshot is not a second independently curated authority; it is a synchronized encrypted *view*. Local snapshots cannot prove an upstream deletion/archive happened while offline.

## M3 🔄 User-initiated sync and observability — 12 points

| ID | Task | w | Status | Acceptance / dependency |
| --- | --- | ---: | --- | --- |
| D01 ⬆️ | Implement `passflick update` | 4 | 🟡 | Explicit on-demand refresh with private error output, exit codes, unchanged cache on failure, and no console secrets; C04 |
| D02 🎚️ | Provide compact in-picker update control | 3 | ⬜ | Keyboard-accessible action that does not block everyday search/copy or require refresh for each launch; D01 |
| D03 ⏳ | Show last success, stale/failed update and offline status | 2 | ⬜ | Clear distinction between snapshot age and password validity; user can distinguish server failure from bad login; C05 |
| D04 🧾 | Handle upstream archive, deletion, folders and updates | 3 | ⬜ | After refresh active view excludes archived/deleted records; preserves duplicates with different IDs; folder labels do not trigger upstream writes; B03, C04 |

## M4 🔎 Picker experience preservation and adaptation — 12 points

| ID | Task | w | Status | Acceptance / dependency |
| --- | --- | ---: | --- | --- |
| E01 ⌨️ | Preserve existing keyboard-first picker and sensitive copy | 5 | ✅ | Existing synthetic UI/clipboard tests demonstrate search focus, selection, Enter/Shift+Enter/Escape, and sensitive Wayland copy; **retest after backend replacement** under G03/G04 |
| E02 🪪 | Replace browser provider identity with vault item identity | 3 | ⬜ | Search by title/site/username, show safe distinct variants, avoid misleading Edge/Chrome priority and display, retain source-provenance fields only as optional metadata; C01 |
| E03 🧹 | Keep genuine duplicate passwords separately selectable | 2 | ⬜ | Same-site/username entries with different IDs remain identifiable without revealing secret contents; E02 |
| E04 🎨 | Support System/Light/Dark selector | 2 | ⬜ | Theme changes apply immediately, System is default, keyboard/contrast QA; preserve existing visual design; E02 |

## M5 🧽 Retire old import mode safely — 8 points

| ID | Task | w | Status | Acceptance / dependency |
| --- | --- | ---: | --- | --- |
| F01 🧳 | Preserve encrypted legacy data and rollback path | 3 | ⬜ | Original `vault.passvault` and any backups remain untouched until new projection end-to-end acceptance; migration and recovery instructions use fictional examples; C02 |
| F02 🧨 | Remove unsupported CSV/discovery UX after parity | 3 | ⬜ | Remove obsolete import commands/docs/modules only after Vaultwarden update/search/copy works; no accidental deletion of user's legacy vault; D01, E02, G05 |
| F03 🧬 | Clean persisted schema/CLI compatibility transition | 2 | ⬜ | Existing installations fail safely or migrate explicitly; fresh installs don't require CSV; no silent re-key, provider reconciliation or empty projection overwrite; F01, F02 |

**Scope:** do not keep a second permanent CSV ingestion mode just for historical compatibility. Retain the old implementation through Git history and a reversible migration path, not as an active feature.

## M6 🧪 Security, regression and real-world acceptance — 13 points

| ID | Task | w | Status | Acceptance / dependency |
| --- | --- | ---: | --- | --- |
| G01 ✅ | Preserve existing synthetic regression baseline | 2 | ✅ | Prior documented CI demonstrated Rust unit, GUI, clipboard and encrypted-vault checks; new behavior remains unverified and must pass fresh CI in G03 |
| G02 🧪 | Synthetic server integration matrix | 3 | ⬜ | Disposable Vaultwarden; fictional logins, Unicode, multiple URIs, name collisions, TOTP-present records, archives, deletes, edits, MFA/session failures, expired auth and repeat update; B03, D01 |
| G03 🛡️ | Failure-path/security/regression review | 3 | ⬜ | No accidental upstream writes, plaintext leak, insecure TLS fallback, incomplete cache replacement, unlocked secret exposure or clipboard-history regression; all relevant Cargo gates green; C04, E02 |
| G04 🖥️ | Real EndeavourOS/Hyprland acceptance and latency | 3 | ⬜ | Test on actual host with synthetic secrets; floating focus, UI theme, keyring, Wayland clipboard, update performance, offline launch and search responsiveness; E04, D01 |
| G05 🧯 | End-to-end reversible migration validation | 2 | ⬜ | Demonstrate old encrypted vault kept intact, new snapshot sourced from a disposable test server, repeatable verification/recovery and zero upstream mutations; F01, G02 |

**Performance gate:** measure first-frame focus, typical search, and copy/exit on representative 2,000+ synthetic records; set realistic limits after baseline profiling. Do not assert invented millisecond targets. Refresh latency is independent of ordinary picker latency.

## M7 📦 Documentation, packaging and acceptance — 4 points

| ID | Task | w | Status | Acceptance / dependency |
| --- | --- | ---: | --- | --- |
| H01 📚 | Reconcile README, project contract, CLI help, security docs and changelog | 2 | ⬜ | All user-facing docs correctly describe supported native Vaultwarden behavior, read-only limits, manual refresh, cache security and legacy retirement; D01, F02 |
| H02 🚦 | Locked build, CI, install smoke and release readiness | 2 | ⬜ | Cargo fmt/check/test/Clippy and GUI checks pass, reproducible package installed and verified, no secret-bearing artifacts, owner accepts any release; G03, G04, H01 |

## 🧱 Dependency chain and release gates

**Critical path:** A03/A04 → B01/B02/B03 → B04/C01/C02/C03/C04 → D01/D04/E02 → G02/G03/G04/G05 → F02/F03/H01/H02.

1. **Architecture gate:** select an implementable Rust client after an isolated proof, and explicitly resolve licensing and authentication. No unsupported SDK assumed production-ready.
2. **Data safety gate:** prove authenticated cache replacement, explicit update semantics, lock lifetime and failure preservation before using personal credentials.
3. **Behavior gate:** synthetic local Vaultwarden update → disconnect network → summon/search/copy locally → restart → update again; test archive and password change after sync without duplicate accumulation.
4. **Retirement gate:** do not remove working legacy code or user's existing encrypted data until the replacement passes all critical tests.
5. **Target/release gate:** real Wayland/Hyprland, offline/security tests, documentation, packaging and owner-approved release. No new release tags without explicit authorization.

## 🧪 2026-11-03 implementation checkpoint

**Scope touched:** A03 ⚖️, A04 🛡️ and B01 🧪 (all **active, not verified complete**). In addition to the previously completed roadmap, a **test-only native Rust sync admission prototype** was added at `src/bitwarden/sync_filter.rs` and wired only under `#[cfg(test)]`. It applies fail-closed archive/trash filtering to raw sync envelopes and preserves item IDs. Seven synthetic unit tests exercise normal, malformed, archived, deleted, duplicate-ID and case-variant cases. It does **not** authenticate, decrypt, fetch, refresh the persistent vault, or affect production runtime behavior.

The API audit found a concrete compatibility gap in `rbw` v1.15.0: its current `SyncResCipher` has `deleted_date` but no `archived_date`; `Client::sync` converts ciphers into entries before exposing them, losing the archive state. Thus consuming `rbw`'s existing entries directly is **not acceptable** for this project's legacy-archive requirements. The backend choice remains under investigation; a reviewed, archive-aware native Rust adapter and disposable-server proof are required before B01/A03 can be verified.

See [security and lifecycle contract](docs/vaultwarden-security-contract.md) for offline/local lock and refresh invariants. This contract is a design gate, not a completed security audit.

**CI evidence:** [Rust workflow](https://github.com/sguzman/passflick/actions/runs/41731198692) passed committed formatting, the Rust test stage (including the new synthetic sync-ingress tests), CLI and encrypted-recovery smoke tests, and Clippy; [synthetic GUI workflow](https://github.com/sguzman/passflick/actions/runs/41731198812) passed against the same code commit `0eff95e16837a155ffa97688f76e77d43d43f7a9`. These tests do **not** demonstrate real Vaultwarden authentication or decrypted credential synchronization.

**Progress accounting:** 13/100 weighted points remain verified. The prototype is tracked as partial work within unfinished B01; no points are awarded until its acceptance criteria (including a disposable-server integration) pass. Prior and current percentages: **13% → 13% (+0 pp)**.

### 2026-11-03 additional sync-admission hardening

The test-only sync filter was extended to honor the upstream `viewPassword` restriction, require deletion status and reject ambiguous case variants. Four new synthetic test cases cover these invariants (11 sync-filter tests total). The local lock/logout/revocation design has also been made explicit in [the security contract](docs/vaultwarden-security-contract.md).

**Fresh CI evidence:** [Rust workflow](https://github.com/sguzman/passflick/actions/runs/41734515325) and [synthetic GUI workflow](https://github.com/sguzman/passflick/actions/runs/41734515123) both passed for code commit `b4f91d408dbff9f9194a827118d81b5ae496e1be`, including committed formatting, Cargo tests, CLI/desktop/encrypted-recovery smoke and Clippy. Earlier corrective runs failed during formatting or a synthetic-test borrow lifetime and were repaired before these green runs. The checks are **not** evidence of live authentication, decryption, or refresh.

**Progress:** still 13/100 weighted points verified (13% → 13%, +0 pp). B01 remains active because the end-to-end disposable-server and native adapter acceptance gates remain unverified.

### 2026-11-03 native sync-envelope / projection slice (CI being checked)

**Touched:** B01 🧪, B03 🔐 (interface only), C01 🗃️ (schema prototype). No weighted item is complete yet.

- `src/bitwarden/envelope.rs` validates the **complete** Vaultwarden user sync object, bounded JSON input, profile/account ID, folder set, and prevents accidental acceptance of a bare or mismatched cipher list. It then calls the existing archive/trash/`viewPassword` ingress filter.
- `src/projection.rs` defines a **versioned, account-bound, upstream-item-ID-indexed plaintext-in-memory schema** with limits, duplicate-ID validation, zeroizing password storage, private error variants, exact UTF-8/whitespace password fidelity and explicit all-items replacement semantics. The serialization result is **plaintext** and must only be encrypted before any disk write.
- `src/bitwarden/pipeline.rs` provides a test-only, read-only decryptor interface and rejects all partial decodes, identity changes, and invalid projected records. It does **not** implement Bitwarden cipher cryptography: its fictional decoder is strictly a test double.
- No real HTTP transport, login, MFA, token refresh, cipher decryption, encrypted projection storage or `passflick update` exists. Existing legacy encrypted data is unchanged; all modules remain behind `#[cfg(test)]` while the production adapter is unsafe to enable.
- **Verification:** [Rust CI](https://github.com/sguzman/passflick/actions/runs/41737618475) passed committed formatting, tests, desktop/CLI/encrypted-recovery smoke and Clippy. [Synthetic GUI CI](https://github.com/sguzman/passflick/actions/runs/41737618727) also passed. Both validate code commit `8224699174ac424449a2566699e86782615b1dcb`. Earlier runs found formatting and an unused test-only accessor; both were corrected and fresh CI passed. **B01/B03/C01 remain incomplete** until the native server adapter, actual decryption and integration/storage gates pass. Verified overall progress remains **13/100 weighted points (13% → 13%, +0 pp)**.

**Next for this checkpoint:** validate the isolated HTTPS/auth/decrypt/cache pipeline against a disposable actual Vaultwarden and complete the separate local unlock/key lifecycle. The unchanged `rbw` high-level `Client::sync` still discards archive and permission metadata and must not replace the raw admissible sync adapter.

### 2026-11-03 native Rust read-only HTTPS transport (synthetic CI verified)

**Touched:** B01 🧪, B05 🧷, and the admission/security boundary. No new weighted acceptance criteria are complete.

- `src/bitwarden/transport.rs` is an isolated, **test-only** `reqwest` HTTPS adapter. The dependency is `dev-dependencies` only so the production picker does not acquire network access or this dependency. It issues exactly one GET to the derived `/api/sync` endpoint, using a token supplied by a future auth layer. It never edits upstream records, accepts HTTP endpoints, follows redirects, or bypasses certificate verification.
- Its request policy enforces HTTPS, rejects URL credentials/query/fragment and malformed bearer tokens, applies connection/request timeouts, bounds `Content-Length` and actual streamed payload bytes, classifies auth failures without printing response bodies, and requires the complete response to match an **expected upstream account ID** before returning the JSON.
- `src/bitwarden/strict_json.rs` rejects **duplicate JSON keys at any nesting depth**, preventing serde's ordinary last-value-wins behavior from hiding conflicting `profile.id`, `archivedDate`, `viewPassword` or encrypted login fields. Admission failures return sanitized error variants.
- `Cargo.lock` was resolved by a temporary GitHub Actions workflow. The one-time workflow was then removed from the repository. Tests use exclusively fictional data and make no authenticated requests.
- **CI evidence:** [Rust](https://github.com/sguzman/passflick/actions/runs/41739512610) and [synthetic GUI](https://github.com/sguzman/passflick/actions/runs/41739513485) completed **successfully** against code commit `3e07dc56d98c32350fa93995ce3b9be6495d0777`. Rust passed formatting, unit tests including new HTTP/strict-JSON fixtures, desktop/CLI/encrypted-recovery smoke and Clippy. No actual server authentication, HTTPS CA fixture or vault migration was tested.
- **Still missing:** actual native Bitwarden authentication/MFA/token renewal/decryption, an HTTPS fixture verifying private CA trust and bad certificates/hostnames, and encrypted cache publishing. This is **not** a complete or usable Vaultwarden adapter. No additional weighted points are earned beyond the existing **13/100 (13% → 13%, +0 pp)**.

### 2026-11-03 native Bitwarden crypto + authentication slice (CI pending)

**Touched:** A03/B01 protocol review, B02 🔑 password-grant authentication, B03 🔐 real personal-login decryption, B05 🧷 shared trusted transport. All remain **incomplete** under the original weighted acceptance gate.

- The MIT-licensed `rbw = 1.15.0` **Rust library** is now a **pinned dev-only dependency** (no extra runtime dependency for the production picker). `src/bitwarden/decryptor.rs` uses its KDF/HMAC/AES routines to unlock encrypted personal-account keys, decrypt type-2 personal-login titles/usernames/passwords and multiple URI values, support per-item encrypted keys and retain upstream IDs. Real cipherstrings are round-tripped from synthetic encryption keys, not merely stripped of fake prefixes. Tests also confirm archive exclusion in the existing admission/pipeline layer.
- `src/bitwarden/auth.rs` is an **isolated test-only** HTTPS prelogin/password-grant/token-refresh implementation that shares the existing system-CA, no-redirect `reqwest` client. It derives password hashes using `rbw` KDFs, limits server-provided KDF cost, handles TOTP/email-code MFA inputs and MFA-required response classification, and holds bearer/refresh tokens in zeroizing in-memory objects with an expiry check. The token exchange has no real-server acceptance yet, and does not persist tokens.
- **Important security defect found and guarded:** `rbw` can panic during HMAC verification if a malicious type-2 MAC decodes to the wrong length. Passflick validates type, authenticated MAC presence, 16-byte IV, 32-byte decoded MAC and block-aligned nonempty ciphertext **before** calling the library. It rejects macless/unknown/encryption formats, malformed UTF-8, nonzero upstream re-prompt and currently unsupported organization items by failing the **entire candidate** update. This policy prevents partial credential projections, but still needs deliberate UX/design for organization vaults.
- `Cargo.lock` has been resolved. The one-shot lock-generation workflow was removed. All test cases use synthetic strings and domains; no real login credentials, actual Vaultwarden server or live account state is touched.
- **Missing before acceptance:** confirm prelogin/password-grant/MFA/refresh against disposable Vaultwarden; verify certificate-chain/hostname failures; support or clearly scope organization and special cipher cases; connect native session + decrypted projection to the distinct encrypted local store, explicit `passflick update` and real offline picker. Existing production legacy encrypted vault remains unchanged.
- **Progress:** 13/100 weighted points verified (13% → 13%, **+0 pp**) until the dependent real-server and encrypted-cache gates pass. Do not claim the new upstream adapter is operational in production.

### 2026-11-04 encrypted offline projection and private-CA trust (green synthetic CI)

**Touched:** B01/B02/B03/B05 integration, C01 schema, C02 💽 encrypted storage, C04 ♻️ transaction pipeline, and G03 failure-path tests. All remain **active or pending**, not verified complete against their original live-server and production acceptance gates.

- `src/bitwarden/cache_store.rs` is a **test-only** XChaCha20-Poly1305 store for `projection.pfsnapshot`, completely separate from historical `vault.passvault`. It authenticates an encrypted versioned header, schema/account/server identity, enforces private directory and file permissions, rejects symlinks/hardlinks, bounds reads, and publishes synced ciphertext atomically under an exclusive write lock. A separate local 32-byte key must be supplied by the caller; no production key-unlock lifecycle exists yet.
- `src/bitwarden/update.rs` joins complete raw sync admission → real personal-login decryption using `rbw` → versioned projection validation → encrypted commit. Synthetic tests cover multiple upstream IDs for the same site/user, multiple encrypted URIs, Unicode/whitespace secrets, changed passwords, archive/trash/`viewPassword:false` exclusion, and old-ciphertext preservation on failed, incomplete, malformed, cross-account and timestamp-rollback candidates. The new snapshot reloads offline without a network request.
- `src/bitwarden/tls_acceptance.rs` uses an ephemeral local OpenSSL HTTPS server and synthetic CA to verify unknown chain rejection, success with an explicitly trusted test CA, and rejection of the same trusted chain on a mismatched hostname. Empty or malformed CA PEM bundles are rejected by the explicit-root constructor; no insecure TLS mode exists. OpenSSL deliberately responds with HTML to prove only TLS acceptance, **not** Vaultwarden protocol support.
- **Verification:** commit `58ae8b322fa95b6f2ae586951ab85db02365f56d` passed [Rust CI](https://github.com/sguzman/passflick/actions/runs/41748051101): **188 tests passed, 0 failed**, formatting, desktop/CLI/encrypted-recovery smoke and Clippy. [Synthetic GUI CI](https://github.com/sguzman/passflick/actions/runs/41748051062) also passed. The test runner contains **no real user accounts, secrets, hostnames or production data**.
- **Remaining blockers:** disposable real Vaultwarden sign-in/MFA/token-refresh and end-to-end sync, target-host CA verification, explicit local passphrase/session-keyring and lock/logout lifecycle, manual production `passflick update`, picker migration, actual offline freshness UI and power-loss/real Wayland acceptance. Existing encrypted legacy vault, recovery and production picker were not changed.
- **Overall verified progress:** **13/100 (13% → 13%, +0 pp)**. No unfinished roadmap item earns weighted points.

### 2026-11-04 disposable Vaultwarden 1.37.5 native integration (CI verified)

**Milestone completed:** **B01 🧪 protocol/library evaluation and isolated spike**, earning its full **4 weighted points**. The previous checkpoint was 13/100; current verified completion is **17/100 (13% → 17%, +4 pp)**. B02/B03/B04/B05, C02/C04 and production migration remain unfinished.

- An opt-in ignored Rust test at `src/bitwarden/live_acceptance.rs` now runs against **actual Vaultwarden 1.37.5** on an ephemeral Docker network behind Caddy HTTPS with an OpenSSL-generated private CA. `ci/vaultwarden-disposable.sh` creates the server, explicitly allows volatile storage **for this disposable instance only**, waits for `/api/config` health and cleans up the containers/certificates on exit.
- A **separate test-only provisioning client** registers a fictional account and writes two encrypted personal-login ciphers with different Vaultwarden-assigned IDs, the same title/username, two encrypted URIs each, and exact Unicode/whitespace credentials. These writes are not part of the Passflick adapter: its own functions make authenticated identity requests and read-only `GET /api/sync`.
- The **native Passflick adapter** successfully performed a real Vaultwarden prelogin/password-grant login (100,000 PBKDF2 iterations), obtained the encrypted account key and authenticated session, fetched a complete live `/api/sync`, decrypted both actual server records with pinned MIT `rbw = 1.15.0` primitives, atomically published the distinct XChaCha20-Poly1305 offline projection, and reopened it without HTTP. The live test verifies upstream IDs remain distinct and both URL lists and exact secret values survive.
- **Live acceptance CI:** [Disposable Vaultwarden acceptance](https://github.com/sguzman/passflick/actions/runs/41752298727), commit `9ccd71af11195180f99d7a0f0bebc405f5591a9a`: **1 passed, 0 failed**. **Standard regression CI:** [Rust](https://github.com/sguzman/passflick/actions/runs/41752173484), code commit `035a2f92b3c92273b8756aa69c14345ae1d8557b`: **188 passed, 0 failed, 1 intentionally ignored** (the live test is run separately), with formatting, CLI/desktop/encrypted-recovery smoke and Clippy green; [synthetic GUI](https://github.com/sguzman/passflick/actions/runs/41752173545) also green. The later commit changes only the disposable CI launcher.
- **Architecture evidence:** Bitwarden's internal password-manager SDK does not promise a supported external integration; `rbw` is MIT-licensed and provides compatible native cryptographic primitives, but does **not** promise a stable embeddable API. High-level `rbw::api::Client::sync` omits archival/permission information required by the local projection. The version-pinned, raw-sync, native-Rust adapter works on the tested **Vaultwarden 1.37.5 / rbw 1.15.0** combination. This demonstrates feasibility, **not** long-term compatibility or a production backend selection; explicit version upgrade/maintenance audits remain necessary for A03.
- **Not yet accepted:** live TOTP/email-code MFA and refresh-token rotation/expiry, Argon2id account interoperability, organization/re-prompt policies, live archive/delete/update repetition, private-key provisioning/local lock/logout, secure production update CLI, picker migration, and actual EndeavourOS/Hyprland acceptance. Synthetic security and cache tests remain separate from those real-server cases. No release tags or user-data migrations were performed.

### 2026-11-04 A03 native backend decision and live MFA/refresh lifecycle validation

- **A03 ⚖️ accepted, +3 points:** Choose the narrow **native read-only raw-sync Rust adapter** powered by Rustls `reqwest` transport and pinned MIT `rbw 1.15.0` cryptographic/KDF components, not lossy high-level `rbw` sync, unstable Bitwarden internal SDK or a Node/`bw` runtime. Full rationale, dependencies, maintenance and fail-closed limits in [ADR-001](docs/adr-001-native-vaultwarden-adapter.md). This closes the architecture choice **only**, not production rollout.
- **Expanded real Vaultwarden 1.37.5 acceptance:** same fictional disposable account now exercises an **expired access token → actual refresh-token grant**, multiple consecutive full updates, changed upstream password, archive/unarchive, soft-delete, same-site duplicate upstream IDs, and a wrong-account update that preserves previous ciphertext. TOTP enrollment by the fixture-only client is followed by a native MFA challenge, invalid-code rejection, valid authenticator login, and another read-only authenticated sync.
- **Green on `7a69b6d`:** [real disposable HTTPS CI](https://github.com/sguzman/passflick/actions/runs/41754548371) 1/1 pass, [Rust CI](https://github.com/sguzman/passflick/actions/runs/41754548505) 188/188 passing with one intentionally ignored live test (run separately), rustfmt, smoke and Clippy green; [synthetic GUI CI](https://github.com/sguzman/passflick/actions/runs/41754548316) green. TOTP test uses only synthetic credentials and test-only HMAC/SHA1/Base32 dependencies already present in the lock graph.
- **B02, B03, B04, B05, C02, C03, C04 and D04 are not being credited here:** email-code MFA and server policy variants, authenticated production secrets/keyring, local lock/logout, read-only boundary audit, full interrupted/concurrent behavior, actual manual update command and target-host UX remain incomplete.
- **Verified overall:** **17/100 → 20/100, +3 percentage points**. No production vault, user secret, source importer, or real remote account was modified.

### 2026-11-04 A04 local unlock/lock and offline threat-model decision

- **A04 🛡️ complete, +3 weighted points:** The target behavior for offline access after remote logout/revocation, stolen disks, a compromised user session, local passphrase setup/Argon2id keywrap, independent `projection.pfsnapshot` content key, explicit lock/logout and session-keyring separation, freshness and cache purge is now specified in [ADR-002](docs/adr-002-local-cache-security.md).
- **Compatibility/reuse review:** Existing `src/session.rs` has session-scoped key caching and manual-lock markers; `src/desktop_keyring.rs` uses optional Secret Service; `src/vault.rs` contains Argon2id key derivation and XChaCha20-Poly1305 helpers. The new projection must use **separate keyring namespaces/identity and a separate keywrap format**; it may reuse patterns, never reinterpret historical `vault.passvault` keys/data.
- **Threat-model limits:** remote revocation cannot erase an offline snapshot; session memory/keyrings do not defend against malware running as the same user; deletion on SSD/backups is not guaranteed erasure. These must be visible in future UX and cannot be silently claimed away.
- **Production implementation not credited:** C03 local unlock and lock, C05 offline/picker freshness, D01 manual update, and target-host verification remain pending. This is a **documented security policy**, not a deployed key-management flow.
- **Progress:** **20/100 → 23/100, +3 percentage points**.

### 2026-11-04 independent local keywrap and session-keyring boundary (CI verified)

- **C03 🔒 is active (not complete):** `src/bitwarden/keywrap.rs` now provides a **distinct, create-only** `projection.pfkey` envelope wrapping a fresh random 256-bit content key with bounded Argon2id KDF settings and XChaCha20-Poly1305, authenticated over canonical server/account identity and the keywrap header. The key is neither derived from a Vaultwarden password nor reused from historical `vault.passvault`. This remains test-only. Tests cover correct offline unlock, bad passphrase, mismatched identity, tampering, owner-only 0600 file, symlink refusal, and non-overwrite of the legacy vault.
- **Live server acceptance now exercises local keywrap:** the actual disposable Vaultwarden 1.37.5 login/sync publishes an encrypted projection under the newly wrapped key, then reopens that key using a separate local passphrase. After dropping remote session and account-decryptor objects, the encrypted last-known snapshot remains readable offline; bad local passwords and wrong-account attempts do not replace files. [Disposable server CI](https://github.com/sguzman/passflick/actions/runs/41758871854) green.
- `src/bitwarden/session_cache.rs` adds a test-only projection-specific Linux kernel-keyring adapter and a deterministic fake backend for security ordering. New key/lock labels are distinct from the legacy `passflick:vault-key:v2` and `passflick:manual-lock:v2` namespaces. An explicit lock writes its deny marker **before** invalidating the session key. A failed invalidation leaves the deny marker active; wrong cached keys must authenticate the ciphertext or fail closed. Explicit passphrase unlock verifies both keywrap and complete snapshot **before** caching a key and removing a manual-lock marker. CI only type-checks the real kernel backend; actual kernel-keyring, login-session, Secret Service and lock semantics require target-host QA.
- **Verified code commit:** `e2ffb822d7519dce8a6f331d7f6eede780bbd4d4` passed [Rust CI](https://github.com/sguzman/passflick/actions/runs/41758871921): **198 tests passed, 0 failed, 1 intentionally ignored** live test, formatting, desktop/CLI/encrypted-recovery smoke and Clippy; [synthetic GUI](https://github.com/sguzman/passflick/actions/runs/41758871891) and [disposable Vaultwarden](https://github.com/sguzman/passflick/actions/runs/41758871854) also passed.
- **Not yet accepted:** production `passflick update`, local keywrap/passphrase setup UX, persistent Secret Service enrollment, end-to-end lock/logout/purge, explicit key lifecycle across a real kernel session, offline/stale UI and real Hyprland focus/copy acceptance. No real credentials or old vaults were migrated.
- **Weighted progress:** **23/100 → 23/100 (23%, +0 percentage points)**; C03 is active but earns no partial points.

### 2026-11-04 projection session scope binding verified

The isolated local key-cache adapter now checks that its lookup scope matches the **actual snapshot path, Vaultwarden HTTPS server identity, and upstream account ID before any keyring/keywrap access**. It rejects a mismatched scope without reading or writing local keyring state. The regression tests cover mismatched account, server, and path. This is an extra defense alongside mandatory authenticated decryption; it does not weaken or replace AEAD checks.

**Green CI on code commit `af45a51a4729b0a72342504bc9813969f8f1fbf0`:** [Rust](https://github.com/sguzman/passflick/actions/runs/41759929489) **199 passed, 0 failed, 1 intentionally ignored live test**, formatting, desktop/CLI/encrypted-recovery smoke and Clippy; [synthetic GUI](https://github.com/sguzman/passflick/actions/runs/41759929565); and [real disposable Vaultwarden 1.37.5](https://github.com/sguzman/passflick/actions/runs/41759929533). The real kernel session backend remains compile-checked only, not functionally exercised on the target desktop.

**C03 remains 🟡 active, not complete. Verified progress stays 23/100 = 23% → 23%, +0 percentage points.** Target-host kernel session and desktop keyring behavior, local lock/logout/purge, passphrase UX, production command/picker integration, and offline freshness acceptance still remain.

### 2026-11-04 keywrap path pairing and remote token endpoint binding (CI verified)

- **C03 🔒 local keywrap boundary:** explicit offline unlock now rejects any `projection.pfkey` path that is not the exact sibling of the selected `projection.pfsnapshot` path, before opening the keywrap or changing keyring state. Synthetic regression covers foreign directories and filenames; commit [`6327b84`](https://github.com/sguzman/passflick/commit/6327b84c159115eb2dc4f022c2ed0198d1e92a9a).
- **B02 🔑 remote session boundary:** the token pair is now bound in memory to the authenticated server endpoint (including its reverse-proxy root). A different host or proxy root is rejected before a refresh-token request; the explicit update orchestrator also checks before using an unexpired bearer token. Synthetic regression covers both mismatches; commit [`675523b`](https://github.com/sguzman/passflick/commit/675523bf356d391044bc2a6214043f82e659d2ff).
- **Full green code CI on `675523b`:** [Rust](https://github.com/sguzman/passflick/actions/runs/41761539145) 201 passed / 0 failed / 1 intentionally ignored (run in dedicated live-server job), formatting, installation and recovery smoke, CLI smoke, and Clippy; [synthetic GUI](https://github.com/sguzman/passflick/actions/runs/41761539259) passed; [disposable Vaultwarden 1.37.5](https://github.com/sguzman/passflick/actions/runs/41761539159) passed.
- These are **test-only safeguards**. Neither B02 nor C03 meets full production acceptance, so **verified progress remains 23/100 (23% → 23%, +0 percentage points)**. Real kernel-keyring session semantics and CLI/GUI integration remain unverified.

### 2026-11-04 authenticated first-install and HTTPS/schema acceptance (CI verified)

- **Native first-run path (test-only):** `prepare_initial_sync` obtains the server-issued account ID from a **complete authenticated read-only `/api/sync`**, after verifying the remote session belongs to the selected HTTPS endpoint. This removes the fixture-client account-discovery shortcut. It returns only a validated in-memory projection and does not write any cache until explicit local setup.
- **Create-only initial install (test-only):** `install_initial_projection` validates designated sibling `projection.pfkey` / `projection.pfsnapshot` paths, checks for an existing snapshot before creating a keywrap, then publishes under a writer lock with **no replacement permitted**, including race rechecks. If interrupted after only the passphrase-wrapped key file is written, the same local passphrase can resume without overwriting it. Synthetic tests prove wrong-passphrase recovery failures and legacy `vault.passvault` byte preservation. The real disposable Vaultwarden acceptance now exercises the initial populated sync, encrypted initial installation, second-install refusal, and offline passphrase reopening.
- **C01 🗃️ verified, +4 weighted points:** the versioned, bounded, upstream-ID-indexed `ProjectionSnapshot` schema passes exact Unicode/whitespace secret, duplicate identity, oversized/malformed/unsupported schema, metadata and empty-full-sync checks. It has no browser-provider precedence and is only serialized into the authenticated encrypted cache. Production picker consumption remains separately gated.
- **B05 🧷 verified, +2 weighted points:** native HTTPS with system/private CA roots passes disposable localhost CA trust, untrusted certificate rejection, hostname mismatch, malformed PEM, inaccessible endpoint and no-insecure-fallback checks. A real Vaultwarden 1.37.5 fixture has also authenticated and synced over verified trusted HTTPS.
- **CI on [`50e2a18`](https://github.com/sguzman/passflick/commit/50e2a182dc84b7d9e1da51f52536376e6bf8135c):** [Rust](https://github.com/sguzman/passflick/actions/runs/41763434948) **206 passed / 0 failed / 1 intentionally ignored live test**, formatting, install/CLI/encrypted-recovery smoke and Clippy; [synthetic GUI](https://github.com/sguzman/passflick/actions/runs/41763434980) passed; [disposable real Vaultwarden](https://github.com/sguzman/passflick/actions/runs/41763434898) passed.
- **Progress:** **23/100 → 29/100 (+6 percentage points)**. B02/B03/C02/C03/C04 remain active and uncredited. No `passflick update` CLI, live kernel-keyring verification, production picker cutover or release was performed.

### 2026-11-04 opt-in native updater CLI preview (CI verified)

- **D01 ⬆️ active, not complete:** the non-default Cargo feature `vaultwarden-preview` builds an experimental `passflick update` command. Default builds, normal picker launches and legacy `vault.passvault` behavior remain unchanged. The command accepts **no secret-bearing command arguments**; it obtains server URL, email, master password, optional TOTP/email MFA code, optional additional trusted CA PEM path, and an independent local passphrase through masked terminal prompts. Remote session/access/refresh tokens remain in memory and are not persisted.
- **Read-only sync and local publication:** the preview authenticates to the explicitly provided HTTPS server, derives the server-issued account identity from an admitted complete sync, and decrypts the full candidate. First use installs only the new create-only `projection.pfkey` and `projection.pfsnapshot` files; subsequent updates require the local passphrase and authenticate the existing ciphertext before atomic replacement. Failed local authentication preserves the exact prior bytes. Legacy path overrides are not reused for the new projection.
- **Tests:** a real disposable Vaultwarden 1.37.5 acceptance exercises preview publication after authenticated sync, wrong local-passphrase failure, and offline reopen. Synthetic tests verify initial install, replacement refusal, successful update, private directory rejection and preservation of fictional legacy data. Unused future keyring/picker APIs remain test-only, rather than entering the preview build.
- **Green code CI on [`89e93fa`](https://github.com/sguzman/passflick/commit/89e93fa78f18dc8bc63ca82bd516b83e78b6110b):** [Rust](https://github.com/sguzman/passflick/actions/runs/41767285591) **206 baseline tests passed, 0 failed, 1 deliberately ignored live test; 2 dedicated preview tests passed**, plus formatting, installation/CLI/encrypted-recovery smoke and strict default/preview Clippy; [synthetic GUI](https://github.com/sguzman/passflick/actions/runs/41767285478) passed; [disposable HTTPS Vaultwarden](https://github.com/sguzman/passflick/actions/runs/41767285570) passed with the preview feature.
- **Historical limitation at this checkpoint:** interactive terminal/PTY security QA, real local kernel-keyring behavior, stable per-install device identity, remote logout/revocation, persistent endpoint setup, support for all vault policy variants, default-build activation, offline picker consumption and target-host Wayland acceptance were outstanding. The preview used a fresh device identifier per invocation at `89e93fa`; that specific gap is now addressed in the following checkpoint. No release tag or user-data migration was performed.
- **Weighted progress:** **29/100 → 29/100 (29%, +0 percentage points)**. D01 is 🟡 active but earns no milestone points until its complete acceptance and dependencies pass.

### 2026-11-04 stable native-preview device identity (CI verified)

- **B02 🔑 / D01 ⬆️ implementation:** the opt-in updater now generates a cryptographically random, 32-character lowercase-hex Vaultwarden device identifier **once per local installation**, and reuses it across explicit password/MFA logins. A 0600 `projection.pfdevice` file is created with `O_EXCL` in the private, owner-owned Passflick data directory and synchronized to disk, separate from the legacy `vault.passvault`, passphrase keywrap and encrypted snapshot. Device ID is non-secret and contains no account password, bearer or refresh token.
- **Fail-closed reads:** existing ID files must be an owner-owned regular 0600 file, contain exactly 32 lowercase hexadecimal characters and have only one hard link. Symlinks, multi-linked files, damaged lengths/contents and weakened permissions are rejected without silently generating a new identity or overwriting the file. The local directory is validated before sending a network login request. Two synthetic tests cover persistence, legacy-vault preservation and tampering cases.
- **Green code CI [`0a46e07`](https://github.com/sguzman/passflick/commit/0a46e075eaa71a0cf19b160d2a7c19eeb3717228):** [Rust](https://github.com/sguzman/passflick/actions/runs/41768931554) **206 baseline passed / 0 failed / 1 intentionally ignored disposable test; 4 preview-specific passed**, formatting, installation/CLI/encrypted recovery smoke and both strict Clippy configurations; [synthetic GUI](https://github.com/sguzman/passflick/actions/runs/41768931435) passed; [disposable Vaultwarden](https://github.com/sguzman/passflick/actions/runs/41768931335) passed.
- **Remaining:** device-ID persistence has synthetic file-security verification, **not** target-host device enrollment/revocation or terminal/Wayland acceptance. Real Linux kernel-keyring lock/unlock, default CLI integration, offline picker consumption, stored endpoint setup, broader MFA and release remain unaccepted. **Weighted progress: 29% → 29% (+0 percentage points)**; B02 and D01 remain 🟡 active.

## 📍 Durable checkpoint — 2026-11-04

- **Repository:** `sguzman/passflick`, branch `main`. Latest verified code commit: [`0a46e07`](https://github.com/sguzman/passflick/commit/0a46e075eaa71a0cf19b160d2a7c19eeb3717228), with green Rust, synthetic GUI and disposable Vaultwarden CI linked above.
- **Verified weighted milestones:** A01–A04, B01, B05, C01, E01, G01 = **29/100 points**. B02 and D01 are active but uncredited.
- **Native opt-in preview now present:** masked terminal update, native trusted HTTPS password/TOTP/email-code authentication, stable owner-only device identity, server/account-bound full sync, independent encrypted projection, create-only first install, authenticated all-or-nothing replacement, synthetic regression and disposable Vaultwarden integration.
- **Still unfinished:** real host enrollment and device-revocation semantics, production local lock/unlock/session-keyring lifecycle, terminal/PTY and EndeavourOS/Hyprland QA, offline picker consumption, freshness display, default native updater cutover, legacy CSV retirement and release.
- **Next action:** verify the opt-in update terminal UX and remote device enrollment using a disposable server, then integrate explicit projection lock/offline picker behavior with target-host QA. Never touch `vault.passvault` or accept actual password-manager credentials during unreviewed development.

See [Vaultwarden architecture](docs/vaultwarden-architecture.md), [local security policy](docs/adr-002-local-cache-security.md), and [security contract](docs/vaultwarden-security-contract.md).
