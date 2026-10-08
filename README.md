# Passflick

**Fast password retrieval, without moving your password manager.**

Passflick is a local, keyboard-first password picker for Linux. It presents a unified, searchable projection of credentials originally managed by Microsoft Edge, Chromium/Chrome, Firefox, and Apple Passwords. The original password stores remain authoritative; Passflick does not create or modify credentials in them.

The ordinary interaction is intentionally tiny:

`summon → search → Enter to copy password or Shift+Enter to copy username → exit`

Passflick is a companion to [OTPick](https://github.com/sguzman/otpick) and [Glyphflick](https://github.com/sguzman/glyphflick), not a replacement for either.

## Interaction

- Type immediately to search sites, domains, usernames, and labels.
- Up/Down changes the selection; the top result is selected automatically.
- **Enter** copies the selected password and closes the picker.
- **Shift+Enter** copies the selected username and closes the picker.
- Escape exits without copying anything.
- Passwords are not displayed while browsing matches.

One launch performs at most one clipboard operation. Invoking it twice to retrieve a username and password is a feature, not a problem.

## Data and unlock model

Passflick maintains a local, encrypted **projection** assembled from external credential sources. A record keeps its source, original site/username identity, and snapshot provenance. Identical records may be grouped in the picker; conflicting credentials stay distinct rather than overwriting each other. A newer import from a source supersedes that source's older snapshot after successful validation, without deleting records from other sources.

The vault uses passphrase-based encryption at rest. Repeated launches in the same login session should use a cached key, as OTPick does, so the normal picker path never needs to repeat password-based key derivation. Optional desktop-keyring integration can make login-session unlock seamless. Passflick's key and vault are **separate from OTPick's**.

## Sources

The first ingestion path is an explicit **CSV export/import** for Edge, Chrome/Chromium, Firefox, and Apple Passwords. Export files are plaintext and must be handled accordingly. Passflick must not upload, retain, or log imported plaintext files.

The later direction is opt-in, read-only local source adapters where browser-supported mechanisms and operating-system permissions make them safe and dependable. No browser decryption bypasses, stealth collection, or silent uploads.

## Platform and status

Passflick targets Rust, Linux, Wayland, and keyboard-driven compositors such as Hyprland. The picker should be an overlay rather than a tiled work window.

**Status: initial development.** This repository is being bootstrapped; do not treat its initial code as an audited password manager or import real credentials until the import and vault paths have been exercised on the target host.

For the architectural contract see [PROJECT.md](PROJECT.md); for planned work see [docs/queue.md](docs/queue.md); for the threat model see [docs/security.md](docs/security.md).

## License

MIT OR Apache-2.0.
