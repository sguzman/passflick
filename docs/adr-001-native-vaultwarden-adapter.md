# ⚖️ ADR-001 — native Rust read-only Vaultwarden adapter

**Decision:** accepted for project architecture on 2026-11-04. **Production implementation:** not yet released. This is a choice of integration approach, **not** a declaration that the adapter, local key lifecycle or replacement picker is ready for real user credentials.

## Choice

Use a small **native Rust, raw-sync, read-only adapter** built around `reqwest` over Rustls, with audited-in-use, version-pinned `rbw` cryptographic/KDF primitives (`=1.15.0`). Admit and filter the **unmodified complete** Vaultwarden `GET /api/sync` envelope before projecting data. Require authenticated personal-login decryption to succeed for the entire active set, preserve every upstream ID, and atomically publish the result under a **separate** locally unlocked XChaCha20-Poly1305 snapshot key. The ordinary picker must never call HTTP; only an explicit `passflick update` will, after its production CLI and key lifecycle are implemented.

Only the adapter's identity prelogin/password-grant and refresh-token requests send POST calls, to identity endpoints. It exposes no cipher modification calls. CI uses a **different, test-only provisioning client** to create, edit, archive, restore and delete fictional test data.

## Alternatives and rationale

- **Not the full `rbw` high-level sync:** its exported item view omits archive/`viewPassword` permissions needed to exclude restricted/archived records, so using it without a raw-envelope gate would lose authoritative security metadata. Reuse only scoped MIT `rbw` KDF/cipherstring primitives, not its lossy high-level sync.
- **Not Bitwarden's internal Rust password-manager SDK:** upstream does not promise supported, stable third-party integration. It would replace one private maintenance boundary with another.
- **Not the official JavaScript/Node `bw` binary:** no npm or background CLI daemon is needed for this Rust/Linux picker; any future comparison with `bw` must be confined to disposable test fixtures, not production process delegation.
- **Not custom cryptographic implementations:** use reviewed Rust libraries for HMAC/AES, KDF and AEAD, with strict ciphertext lengths/format bounds and fail-closed paths. Test-only HOTP/TOTP generation is confined to generating synthetic MFA fixture codes.

## Proven target and constraints

The selected combination is **Vaultwarden `1.37.5` over HTTPS**, `rbw ` version **1.15.0**, and `reqwest` Rustls with native/system trust and an explicitly provisioned private CA. In a disposable CI server, the test executed real password login with 100,000 PBKDF2 iterations, live refresh-token exchange after simulated expiry, TOTP challenge and valid-code authentication, invalid-code rejection, read-only `GET /api/sync`, exact Unicode/whitespace credentials, two encrypted URIs and distinct upstream IDs, real edit/archive/unarchive/soft-delete transitions, and account-mismatch refusal without replacing good local ciphertext. Synthetic TLS fixtures reject an untrusted chain, hostname mismatch and malformed private root. **A03 architectural selection and B01 feasibility are satisfied.**

**Evidence:** [disposable Vaultwarden run](https://github.com/sguzman/passflick/actions/runs/41754548371) (1 passed), [Rust CI](https://github.com/sguzman/passflick/actions/runs/41754548505) (188 passed, one separately run ignored live test, formatting/smokes/Clippy green), and [synthetic GUI](https://github.com/sguzman/passflick/actions/runs/41754548316). Tested code: `7a69b6de1b11820c2b287ebe8922648be7f31bb7`.

## Stability, licensing and upgrade policy

- The Passflick project remains **MIT**. `rbw` is MIT, `reqwest` is MIT/Apache-2.0; use only compatible reviewed dependencies. A full transitive-license and security-advisory audit is still required before promoting them from dev dependencies to production.
- Pin `rbw =1.15.0` and the full locked Rust dependency graph during the prototype. `rbw`'s exposed modules are **not** guaranteed a stable library SDK; avoid spreading its types across the picker/CLI.
- Maintain a narrow adapter boundary (`auth`, `transport`, `decryptor`, `envelope`, `update`) so upstream changes can be reviewed at one point. For every supported Vaultwarden or `rbw` upgrade, review release/protocol differences, compare the server's complete sync shape (archive, trash, permission, item keys and KDF), and require fresh **real disposable HTTPS**, adversarial synthetic, Rust and GUI CI before updating compatibility claims.
- Only a specific server/library combination that passed the integration gates may be advertised as tested. Unsupported org-scoped ciphers, re-prompt flows, unknown cipherstring types or unreasonable KDF parameters must **fail closed**, preserving the old encrypted snapshot rather than silently decrypting or merging partial data.
- The real disposable TOTP path and an independent **Argon2id** account are proven for this pinned server/library combination. The Argon2id fixture tested KDF parameters (3 iterations, 64 MiB, parallelism 2), incorrect-master-password rejection, correct password-grant/key unwrapping, account-ID separation, and exact fictional Unicode password plus two encrypted URIs after full authenticated sync. **Email-code MFA, SSO, organizational vault decryption, re-prompt flows and broader server/version combinations remain unverified or deliberately unsupported.**

**Expanded live compatibility evidence (November 8, 2026):** [implementation `0791634`](https://github.com/sguzman/passflick/commit/07916346f2cde42560ea3ae7aa49016881fbc8fc), [Rust `42496779350`](https://github.com/sguzman/passflick/actions/runs/42496779350), [Synthetic GUI `42496779478`](https://github.com/sguzman/passflick/actions/runs/42496779478), and [disposable Vaultwarden `42496779372`](https://github.com/sguzman/passflick/actions/runs/42496779372), all green. The second fixture account exists solely inside the disposable server. This evidence narrows the prior lack of Argon2id coverage; it does not extend support claims to other versions or authorize a production cutover.

**Authentication reply memory safety (November 8, 2026):** Malformed login/refresh JSON can fail after some token fields have already been allocated, before the complete reply's `Drop` method would run. Those sensitive Serde fields now use `Zeroizing<String>` at the moment of decoding, with zeroizing ownership preserved across session creation and token rotation. Focused partial-parse regression tests and the full [Rust](https://github.com/sguzman/passflick/actions/runs/42497403874), [GUI](https://github.com/sguzman/passflick/actions/runs/42497403858) and [disposable-server](https://github.com/sguzman/passflick/actions/runs/42497403851) workflows passed on `19f7e62`. This is not a substitute for a broader security audit or default-build integration.

## Outstanding production gates

**Do not turn on the new adapter for real credentials yet.** Required: a secure independent local snapshot-key provisioning, unlock, lock/logout and revocation policy; noninteractive/no-secret-output manual `passflick update`; target-host CA and UI tests; timeout/network failure and token renewal error UX; preservation of old `vault.passvault` and rollback until migration acceptance; read-only boundary audit and broader server-policy/organization compatibility decisions. No background sync, browser import fallback, remote credential mutation or hidden authority is authorized.
