# 🗺️ Passflick — Vaultwarden projection roadmap

**Status:** adoption/rebaseline, not yet a working Vaultwarden adapter.  
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

**Rebaseline: 13/100 weighted points verified (13%) as of adoption.** Verified points represent only the existing implementation audit, written replacement contract, and independently evidenced pre-existing picker/synthetic test capabilities. They do **not** represent a working Vaultwarden integration. No fresh target-host or new-backend tests were performed during roadmap authoring.

`███░░░░░░░░░░░░░░░░░` **13%** (rounded visual; +0 comparable percentage-point delta because this is a rebaseline).

**Status key:** ✅ verified complete | 🟡 active | ⬜ pending | ⛔ blocked. Every item's bracketed **w** is its share of the 100-point overall estimate. An item earns all its weight only after its acceptance check passes; partial activity is documented but not counted. Adjust weights transparently if discoveries materially change the project.

## M0 🧭 Reconnaissance and product architecture — 12 points

| ID | Task | w | Status | Acceptance / dependency |
| --- | --- | ---: | --- | --- |
| A01 🔍 | Audit existing code, CI, dependencies, historical roadmap and reusable components | 3 | ✅ | Identify real source importer, independent encrypted vault, picker, keyring and security gates from repository evidence; initial audit recorded below |
| A02 🎯 | Establish new user contract and non-goals | 3 | ✅ | Single upstream authority, explicit refresh, encrypted cache, offline semantics, picker and read-only scope documented in this roadmap and PROJECT.md |
| A03 ⚖️ | Decide and document supported native Rust integration approach | 3 | 🟡 | Prototype/auth feasibility and dependency stability/license findings; select an implementation only after evidence; requires A02 |
| A04 🛡️ | Threat model and lock/freshness/revocation policy | 3 | 🟡 | Define access after Vaultwarden logout or account revocation, local unlock, stolen-disk/session threat, cache destruction, and update failure behavior; requires A03 |

**Existing state:** `src/app.rs`, `src/search.rs`, `src/clipboard.rs`, `src/vault.rs`, `src/session.rs` and `src/desktop_keyring.rs` contain candidate reusable behavior. `src/import.rs`, `src/discovery.rs`, `src/source_status.rs` and browser-specific source ranking are legacy. Current `PROJECT.md`, `docs/queue.md`, `docs/sources.md` and existing CI are for the original product and require careful reconciliation. Preserve privacy and historical evidence.

## M1 🦀 Native Rust Bitwarden-compatible client — 20 points

| ID | Task | w | Status | Acceptance / dependency |
| --- | --- | ---: | --- | --- |
| B01 🧪 | Protocol/library evaluation and isolated spike | 4 | 🟡 | Test currently relevant `rbw`-derived APIs, Bitwarden SDK boundaries, and feasibility of a native adapter against a disposable server; document license, stability, maintenance and version risks; A03 candidate |
| B02 🔑 | Authenticate self-hosted account safely | 5 | 🟡 | Support an explicitly configured endpoint, supported primary auth, session expiration, token refresh and MFA/error handling appropriate to selected backend; no token leaks; B01 |
| B03 🔐 | Retrieve/decrypt compatible vault items | 6 | 🟡 | Correctly handle supported login cipher types, key derivation, server sync and distinct IDs in fictional fixture; reject unknown encryption formats safely; B02 |
| B04 🧱 | Enforce read-only adapter boundary | 3 | ⬜ | Adapter exposes fetch/list only, no upstream mutations; tests demonstrate absence of write operations under normal/error paths; B03 |
| B05 🧷 | Self-hosted HTTPS and CA trust | 2 | 🟡 | System/private CA support and hostname validation pass; bad-chain, MITM-like mismatch and inaccessible server fail closed; B02 |

**Backend decision gate:** Bitwarden's *internal* Rust password-manager SDK is explicitly unsupported for external consumers; the public SDK is primarily for Secrets Manager. `rbw` is an MIT Rust CLI/agent with modules but not a promised stable embedded client API. Neither option is adopted yet. Measure working functionality before importing large dependency trees. An official `bw` CLI integration may serve as a synthetic comparison oracle; production fallback requires an explicit architectural decision.

## M2 💾 Encrypted local projection and key lifecycle — 19 points

| ID | Task | w | Status | Acceptance / dependency |
| --- | --- | ---: | --- | --- |
| C01 🗃️ | Define versioned upstream-ID indexed projection schema | 4 | 🟡 | Preserve exact secrets and nonsecret searchable metadata without legacy provider precedence; reject malformed/oversized records; B03 |
| C02 💽 | Atomic encrypted snapshot replacement and recovery | 4 | ⬜ | Snapshot remains authenticated, private and recoverable; power-loss/interruption simulation never replaces last good snapshot with partial records; C01 |
| C03 🔒 | Local unlock, key caching, lock/logout and key zeroization | 4 | ⬜ | Reuse reviewed existing keyring/AEAD where appropriate; user can lock local projection; no silent unlock of stale/revoked credentials contrary to documented policy; A04, C01 |
| C04 ♻️ | All-or-nothing refresh lifecycle | 4 | ⬜ | Authenticate/fetch/decrypt/validate/publish stages; failed or concurrent updates leave valid snapshot intact and report outcome; B04, C02 |
| C05 📴 | Offline and stale-cache behavior | 3 | ⬜ | Last successful snapshot is readable offline under chosen lock policy, freshness visible, first-run/offline/no-cache fails informatively; C03, C04 |

**Source-of-truth warning:** The snapshot is not a second independently curated authority; it is a synchronized encrypted *view*. Local snapshots cannot prove an upstream deletion/archive happened while offline.

## M3 🔄 User-initiated sync and observability — 12 points

| ID | Task | w | Status | Acceptance / dependency |
| --- | --- | ---: | --- | --- |
| D01 ⬆️ | Implement `passflick update` | 4 | ⬜ | Explicit on-demand refresh with private error output, exit codes, unchanged cache on failure, and no console secrets; C04 |
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

**Next:** implement an isolated HTTPS, read-only `/sync` transport and a reviewed native Rust authentication/decryption implementation, then connect admitted data to the schema and a distinct encrypted snapshot. The `rbw` high-level `Client::sync` remains unsuitable unchanged because it discards archive and permission metadata. Validate against a disposable server before handling any real credentials.

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

## 📍 Durable checkpoint

- **Repository:** `sguzman/passflick`, branch `main`; audited head at adoption `7fd71fde7c4d`. Latest synthetic CI-verified code commit: `3e07dc5` (Rust and GUI both green). Later documentation-only updates do not alter the tested code.
- **Verified reuse:** existing Rust+egui picker, keyboard selection, sensitive clipboard, local encrypted vault, session/keyring architecture and prior synthetic CI evidence. These are not proof of a working Vaultwarden integration.
- **Unimplemented in production:** end-to-end authenticated live update, persistent encrypted projection, lock/revocation lifecycle, picker adaptation, legacy retirement and server/host acceptance. Native authentication and real personal-login decryption now exist only in isolated `#[cfg(test)]` modules; no real-server integration has been verified.
- **Next actionable work:** A03/B01/B02/B03/B05 — integrate native authentication/Bitwarden-compatible crypto with the validated read-only HTTPS path using a disposable test server, verify CA and hostname failures, and preserve the old encrypted vault until new cache acceptance.
- **No private data:** no user server hostnames, personal vault contents, tokens, passwords, exported records or private repository paths are required in public code or issue logs.

See [`docs/vaultwarden-architecture.md`](docs/vaultwarden-architecture.md) for the planned component boundaries and decision risks.