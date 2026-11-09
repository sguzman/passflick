# Passflick

**A password picker, not another password manager.**

Passflick is becoming a small, keyboard-first, **read-only projection of one Vaultwarden/Bitwarden-compatible vault**. Vaultwarden remains the only authority for passwords; Passflick holds an authenticated, encrypted offline copy. The current default build still contains the historical browser-CSV picker until a safe migration is accepted.

`summon → search → copy → gone`

## Vaultwarden preview — implemented, not yet the default

The experimental `vaultwarden-preview` feature contains a **native HTTPS sync client**, a separate encrypted offline projection, local lock/unlock and an egui picker. Disposable-server and synthetic UI checks run in CI. **Real-account use and replacing the default picker remain gated on target-host security and migration QA.** Passflick does not edit, create, or delete upstream credentials.

Build the preview in release mode:

```sh
cargo build --release --locked --features vaultwarden-preview
```

Open the separate preview with a fresh, isolated `XDG_DATA_HOME`, not your existing Passflick data. In the first-run window, **Copy exact QA command** copies the absolute release executable and the matching temporary data directory into a command suitable for the fish shell. Paste it into a terminal only when you have a **disposable Vaultwarden account with fictional credentials** ready for testing. The native `update` operation privately prompts for a trusted HTTPS URL, login email, master password, optional certificate path, and a **separate local projection passphrase**. The picker itself never connects to the server.

```text
passflick update                      # feature-enabled build; explicit network sync
passflick projection picker           # offline picker
passflick projection unlock           # offline CLI unlock
passflick projection lock             # local manual lock
passflick projection status           # local state/freshness
```

Always run `update` and `projection picker` with the **same `XDG_DATA_HOME`**, otherwise the picker will report no projection. The first-run GUI distinguishes never-configured state from incomplete/unsafe projection files and does **not** request an impossible local passphrase on a pristine installation. Appearance supports System/Light/Dark; on Darkman-based Wayland desktops, System reads the session's current light/dark mode. No automatic periodic sync or upstream writes are performed.

### Launch the working Vaultwarden preview from your application menu

For a **feature-enabled** binary already installed by `cargo install --path . --locked --features vaultwarden-preview`, a separate, opt-in desktop entry is available. From the repository:

```fish
fish scripts/install-vaultwarden-launcher.fish
```

This installer **does not copy or rebuild executables**, change the existing `passflick` launcher, update Hyprland bindings, touch any encrypted data, or configure automatic syncing. It checks the installed `$CARGO_HOME/bin/passflick` (or `~/.cargo/bin/passflick`), verifies the `projection picker` command is available, and creates `$XDG_DATA_HOME/applications/passflick-vaultwarden.desktop` (normally `~/.local/share/applications/passflick-vaultwarden.desktop`). The desktop file uses the **absolute executable path**, not a shell or terminal, and is deliberately not installed again if that entry already exists.

In the app menu, launch **Passflick (Vaultwarden)**. Its first offline launch may request the *independent local projection passphrase*. Once unlocked, subsequent opens in a shared Linux keyring session can reuse the cached key; this does **not** automatically unlock after a new login or reboot. For CLI use, `passflick projection picker` remains the explicit entry point and `passflick projection lock` manually locks it.

In the **opt-in Vaultwarden picker**, **Lock now** clears decrypted entries and search text from that window, then uses the same session-keyring manual-lock mechanism as `passflick projection lock`. The encrypted projection remains on disk, and an explicit local passphrase unlock is required to resume. A keyring failure is reported as **unconfirmed**, not as a successful global lock; the window stays cleared. **Copy refresh command** provides an exact, explicitly invoked `update` command for your terminal. The picker itself stays offline and does not automatically refresh or prompt for remote credentials. On explicit `update`, a matching existing local server identity is now checked **before** the updater asks for account credentials. A different configured server is rejected without contacting it; the encrypted snapshot is not replaced. Older sidecar-less previews still require their normal full authenticated cache checks before publication.

**Rollback:** remove only the `passflick-vaultwarden.desktop` entry if you no longer want the new launcher. The historical `passflick.desktop` and `vault.passvault` remain untouched. Do not delete `projection.pfsnapshot`, `projection.pfkey`, `projection.pfidentity`, or `projection.pfdevice`: they hold the encrypted offline projection and its identity. Default-command cutover and release acceptance remain separate unfinished work.

For further constraints, see the [weighted roadmap](ROADMAP.md), [host QA plan](docs/vaultwarden-host-acceptance.md), and [architecture design](docs/vaultwarden-architecture.md).

## Historical default picker (browser CSV imports)
## Daily use

Launch `passflick` from your compositor shortcut. Typing immediately searches **sites and URLs**. Press **Ctrl+Space** (or Tab) to switch to **User**, then type a username to search only within the matching sites. Both filters stay active when you switch back; the top match is selected.

| Key | Action |
| --- | --- |
| Enter | Copy selected password and exit |
| Shift+Enter | Copy selected username and exit |
| Up / Down | Select a credential |
| Ctrl+Space | Switch between site and username filters |
| Tab / Shift+Tab | Move between search fields |
| Escape | Exit without copying |

There is no persistent tray app, no browser dependency for ordinary lookups, and no need to reveal a password on screen. Opening Passflick twice for a password and username is expected to be fast enough that a multi-action window is unnecessary.

## Getting started

Passflick is currently a **pre-release Rust application** targeting Linux/Wayland, with Hyprland as the primary desktop. Its functional workflow is being validated; real credentials should not be imported before target-host acceptance and further security testing.

Build locally if needed:

```sh
cargo build --release --locked
```

CI can produce a checksummed, **pre-release Linux x86_64 archive** under the [Linux Snapshot workflow](https://github.com/sguzman/passflick/actions/workflows/linux-snapshot.yml). Optimized snapshots are built on explicit workflow requests or version tags, not on every code commit; an existing artifact may therefore lag `main`. Its binary is not yet certified for production passwords or verified on Hyprland.

The archive also includes `passflick.desktop` and `install-user.sh`. After extracting the archive, `bash install-user.sh` installs the executable into your user binary directory and registers a graphical application launcher. This requires no root access, opens no terminal emulator, and does not modify Hyprland's configuration or any password manager. The launcher uses an absolute executable path so it works even if your desktop session has a different `PATH`.

### Safe picker demo

Before creating a vault or importing passwords, launch the same picker against fictional `example.test` records:

```sh
cargo run --release --locked -- demo
```

This runs without unlocking, reading, or writing the real vault. It exercises search, provider grouping, conflicts, **Enter** to copy a synthetic password, and **Shift+Enter** to copy a synthetic username. Both actions close the window.

On first launch, Passflick offers to create its own encrypted vault using a masked passphrase and confirmation field. New vaults require at least 12 characters (up to 1024); older vault passphrases remain valid for unlocking. Initial setup does **not** require a terminal. The original password managers are never changed.

For optional command-line setup and desktop Secret Service integration, the equivalent maintenance commands remain:

```sh
passflick init
passflick keyring enable
```

When the vault is locked, opening the picker displays a masked passphrase field. If Linux session-key caching is unavailable, the picker still works for that invocation and shows a notice; the next launch requires the passphrase again. CLI maintenance commands can also prompt directly for the passphrase if session caching is unavailable. The optional desktop-keyring command stores Passflick's derived vault key in your desktop Secret Service, allowing subsequent launches to unlock without re-entering it. The CLI fallback remains `passflick unlock`, and `passflick lock` explicitly locks the application for the current session. Passflick does not share OTPick's vault key.

### Importing existing credentials

Export passwords from your existing password manager, then import the resulting CSV snapshot:

```sh
passflick import edge /path/to/edge-export.csv
passflick import chrome /path/to/chrome-export.csv
passflick import firefox /path/to/firefox-export.csv
passflick import apple /path/to/apple-export.csv
```

The source name identifies which snapshot is updated. A successful Edge import replaces only the previous Edge projection, not the Firefox, Chrome, or Apple records. **Refreshing an existing source automatically preserves the previous encrypted vault in `backups/` before writing anything.** Empty-password rows in browser exports are skipped and their count is reported after successful import; an export containing no usable passwords is rejected without modifying the previous snapshot. Other malformed rows still stop the import. Imports are limited to 32 MiB of CSV and 100,000 input records (even if many records are duplicates), guarding against excessive memory growth. If a refreshed source suddenly contains fewer than half its former credentials (with at least ten previously stored), the import refuses the reduction by default. An intentional large cleanup can be imported using the final flag `--allow-shrink`.

For import pipelines that produce CSV on stdout without writing a file:

```sh
some-trusted-export-command | passflick import edge -
```

The `-` argument means stdin. Do not send credentials from unknown commands or untrusted exporters. **All password-manager CSV exports are plaintext**; move them out of shared/synced directories and remove them after verified import. Ordinary deletion cannot guarantee forensic erasure from every disk or backup.

Check local projection freshness without revealing passwords. The picker also shows a compact count of imported sources and marks snapshots whose most recent import is 30 or more days old. Hover the status line to see each source's import age; these are **local CSV snapshot ages, not live browser synchronization**.

```sh
passflick sources
passflick discover
passflick status
passflick backup
```

Passflick disables Linux process core dumps and ptrace attachment before loading vault secrets. Clipboard history behavior remains environment-dependent. Imported secrets are stored only in the local encrypted vault. The ordinary picker never contacts a network service. `passflick backup` creates a private, encrypted, no-overwrite snapshot beside the vault, under `backups/`. To restore a previous snapshot from the same vault encryption lineage, use `passflick restore /path/to/backup.passvault --confirm`. Passflick authenticates the snapshot before modifying anything, preserves the current encrypted vault as a separate safety backup, and never writes a plaintext restore file. Before a restore, `passflick verify /path/to/backup.passvault` performs read-only authenticated verification under the current vault key. Corrupted or foreign-vault backups fail without modifying the active vault. These normal verification and restore commands require a decryptable live vault. For an explicitly authorized disaster recovery when the primary file is missing or corrupt, use `passflick recover /path/to/backup.passvault --confirm` and enter the **backup's** passphrase. Recovery authenticates the exact encrypted backup bytes, atomically installs them, and preserves any previous primary ciphertext as an **unverified** raw snapshot before replacement. Session and desktop key caches are invalidated or removal is attempted; unlock using the backup passphrase afterward.

## How the projection works

Passflick keeps source provenance and import timestamps. Source priority is Edge, then Chrome, Firefox, and Apple. Exact matching credentials from multiple sources can appear as one result. Different passwords for the same site and username remain separately selectable and are marked **Conflict** without displaying the underlying secret. No operation modifies the original password managers.

The default encrypted vault lives under `$XDG_DATA_HOME/passflick/vault.passvault` (normally `~/.local/share/passflick/vault.passvault`). `PASSFLICK_VAULT` overrides the file path. Relative filenames are resolved against the process working directory, but absolute paths are recommended for graphical launchers. Empty and directory-only values are rejected. The vault uses Argon2id, XChaCha20-Poly1305, and a Linux session-keyring hot path. Clipboard copies require `wl-clipboard` 2.3 or newer so `wl-copy --sensitive` is supported. The picker also fails closed with a timeout if the helper hangs during its capability check, blocked stdin write, or post-write exit. Older releases fail with an explicit upgrade message rather than silently exposing passwords to ordinary clipboard history. Even with the hint, clipboard history isolation cannot be guaranteed across all environments.

## Browser integration

`passflick discover` already detects local Edge/Chrome/Chromium/Firefox profile candidates by filename only; it does not read credentials or unlock a browser store. CSV exports are the reliable baseline. Opt-in, read-only native source adapters are a future goal, especially for Edge and Chromium on Linux. Direct browser credential retrieval is not implemented and must respect browser and operating-system access controls. Apple Passwords remains an export-based source on Linux. See [Source integration](docs/sources.md) for details.

## Project documentation

- [Project contract](PROJECT.md)
- [Source integration](docs/sources.md)
- [Security model](docs/security.md)
- [Development queue](docs/queue.md)
- [Target-host acceptance plan](docs/acceptance.md)

## License

MIT.
