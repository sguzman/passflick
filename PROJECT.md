# Project contract

Passflick is a low-latency, keyboard-first **read-only password projection for Linux**, with a Bitwarden-compatible server (including self-hosted Vaultwarden) as the **sole source of truth**. Passflick is not an independent password manager, password editor or browser-export aggregator.

**Transition status:** the native Rust Vaultwarden adapter passes disposable real-server CI (including password login, TOTP, token refresh and encrypted read-only sync). A **non-default, opt-in `vaultwarden-preview` feature** now compiles an experimental masked-terminal `passflick update` command, but neither the normal release binary nor production picker uses the new projection. The default picker still uses its historical encrypted vault/CSV flow. ADR-001 fixes the integration architecture without authorizing production migration. See [ROADMAP.md](ROADMAP.md), [the architecture design](docs/vaultwarden-architecture.md) and [ADR-001](docs/adr-001-native-vaultwarden-adapter.md) for the migration and verification gates.

## Accepted user experience

- Configure and authenticate with a user-selected Bitwarden-compatible server through a secure native Rust integration.
- Explicitly run `passflick update` or invoke a compact update control to refresh a securely encrypted local projection. **Ordinary picker launches never require a server request.**
- Search immediately by site and username using the most recently *successfully* synchronized and locally unlocked snapshot, even when the server is temporarily unavailable.
- Up/Down selects a result. Enter copies its password and exits; Shift+Enter copies its username and exits; Escape closes without copying. Search results never display passwords.
- Present distinct upstream items, including conflicting credentials at the same site/username; no guessing which password is correct. The last update time is visible; a stale offline projection is not represented as current server state.
- Following a successful update, the active local view reflects current server archive/deletion state. Local access when offline is governed by an explicit, separately tested cache lock policy.

Local offline-unlock and revocation behavior is governed by [ADR-002](docs/adr-002-local-cache-security.md), which is an accepted **policy** rather than a completed implementation.

## Architectural boundaries

- **Authoritative data:** the remote Bitwarden/Vaultwarden vault. Credential creation, edits, archival, deletion and organization happen there, not in Passflick.
- **Local data:** an authenticated encrypted *projection*, not a second curated authority. It is retained between launches and replaced transactionally only after a fully successful sync.
- **Integration:** prefer reviewed reusable Rust client/cryptography components; do not casually reimplement password-manager cryptography or assume the unsupported internal Bitwarden SDK is stable. The official CLI may be a disposable integration-test oracle; it is not an assumed runtime dependency.
- **Local security:** retain existing private permissions, sensitive clipboard transport, zeroizing buffers, core-dump restrictions and keyring patterns where appropriate, after review for the new auth/cache lifecycle. No secrets in logs, process arguments, CI fixtures or public artifacts.
- **Legacy retirement:** remove Edge/Chrome/Firefox/Apple import paths from the supported app only after the new adapter and rollback path pass acceptance. Do not delete the user's old encrypted data.

## Supported environment and status

Rust + egui on Linux/Wayland/Hyprland; theme selector for System (default), Light and Dark must be verified as part of the new accepted UI. No npm. Preserve the existing MIT repository license unless a reviewed dependency and the owner authorize a change.

This is an **existing-project architectural replacement**, not a new application. Progress is tracked with a weighted roadmap and evidence-based acceptance; the finished implementation is **not** claimed until real server integration, security QA and target-host validation pass.