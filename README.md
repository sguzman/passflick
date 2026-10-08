# Passflick

**A password picker, not another password manager.**

Passflick gives Linux users a single, encrypted, searchable view of credentials saved elsewhere: Microsoft Edge, Chrome/Chromium, Firefox, and Apple Passwords. Your original password managers stay in charge. Passflick is an intentionally small, keyboard-driven companion to [OTPick](https://github.com/sguzman/otpick) and Glyphflick.

`summon → search → copy → gone`

## Daily use

Launch `passflick` from your compositor shortcut. Typing immediately searches account names, websites, URLs, and usernames. The top match is selected.

| Key | Action |
| --- | --- |
| Enter | Copy selected password and exit |
| Shift+Enter | Copy selected username and exit |
| Up / Down | Select a credential |
| Escape | Exit without copying |

There is no persistent tray app, no browser dependency for ordinary lookups, and no need to reveal a password on screen. Opening Passflick twice for a password and username is expected to be fast enough that a multi-action window is unnecessary.

## Getting started

Passflick is currently a **pre-release Rust application** targeting Linux/Wayland, with Hyprland as the primary desktop. Its functional workflow is being validated; real credentials should not be imported before target-host acceptance and further security testing.

Build:

```sh
cargo build --release --locked
```

### Safe picker demo

Before creating a vault or importing passwords, launch the same picker against fictional `example.test` records:

```sh
cargo run --release --locked -- demo
```

This runs without unlocking, reading, or writing the real vault. It exercises search, provider grouping, conflicts, **Enter** to copy a synthetic password, and **Shift+Enter** to copy a synthetic username. Both actions close the window.

Set up your own encrypted vault:

```sh
passflick init
passflick keyring enable
```

When the vault is locked, opening the picker displays a masked passphrase field and unlocks it for the login session. The optional desktop-keyring command stores Passflick's derived vault key in your desktop Secret Service, allowing subsequent launches to unlock without re-entering it. The CLI fallback remains `passflick unlock`, and `passflick lock` explicitly locks the application for the current session. Passflick does not share OTPick's vault key.

### Importing existing credentials

Export passwords from your existing password manager, then import the resulting CSV snapshot:

```sh
passflick import edge /path/to/edge-export.csv
passflick import chrome /path/to/chrome-export.csv
passflick import firefox /path/to/firefox-export.csv
passflick import apple /path/to/apple-export.csv
```

The source name identifies which snapshot is updated. A successful Edge import replaces only the previous Edge projection, not the Firefox, Chrome, or Apple records. The parser rejects malformed or empty snapshots rather than quietly wiping existing records. If a refreshed source suddenly contains fewer than half its former credentials (with at least ten previously stored), the import refuses the reduction by default. An intentional large cleanup can be imported using the final flag `--allow-shrink`.

For import pipelines that produce CSV on stdout without writing a file:

```sh
some-trusted-export-command | passflick import edge -
```

The `-` argument means stdin. Do not send credentials from unknown commands or untrusted exporters. **All password-manager CSV exports are plaintext**; move them out of shared/synced directories and remove them after verified import. Ordinary deletion cannot guarantee forensic erasure from every disk or backup.

Check local projection freshness without revealing passwords:

```sh
passflick sources
passflick discover
passflick status
passflick backup
```

Imported secrets are stored only in the local encrypted vault. The ordinary picker never contacts a network service. `passflick backup` creates a private, encrypted, no-overwrite snapshot beside the vault, under `backups/`.

## How the projection works

Passflick keeps source provenance and import timestamps. Source priority is Edge, then Chrome, Firefox, and Apple. Exact matching credentials from multiple sources can appear as one result. Different passwords for the same site or username remain separately selectable. No operation modifies the original password managers.

The default encrypted vault lives under `$XDG_DATA_HOME/passflick/vault.passvault` (normally `~/.local/share/passflick/vault.passvault`). `PASSFLICK_VAULT` overrides the file path. The vault uses Argon2id, XChaCha20-Poly1305, and a Linux session-keyring hot path. Clipboard copies use `wl-copy` with a sensitive hint, although clipboard history isolation cannot be guaranteed across all environments.

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
