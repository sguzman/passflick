# Project contract

Passflick is a low-latency, keyboard-first, read-only password projection for Linux. Existing password managers remain the systems of record. Passflick does not create, modify, autofill, or transmit credentials.

## User contract

The picker behaves like OTPick:

- Search as soon as the window appears.
- Up/Down selects a result.
- Enter copies its password and exits.
- Shift+Enter copies its username and exits.
- Escape closes without copying.
- One launch copies at most one value. No secret is shown in search results.

## Source model

The source set is Edge (primary), Chrome/Chromium, Firefox, and Apple Passwords. Imports preserve original source identity and the time of the snapshot. A successful source refresh replaces that source's projection, not another source's records. Failed imports leave existing data intact. Different passwords associated with the same site and username remain distinct.

CSV export and explicit local import are the baseline. Later adapters may support read-only, opt-in local retrieval when the browser exposes an authorized interface. No hidden background scraping or browser protection bypasses.

## Platform and security

Rust + egui, Linux/Wayland/Hyprland, Wayland clipboard via stdin. A separately encrypted local vault uses Argon2id and authenticated encryption, with a Linux session keyring hot path and optional desktop Secret Service unlock. Passflick's key material must never be shared with OTPick. Plaintext imports and vault contents must never be committed to GitHub or logged.

## Status

Initial development. Not security-audited. See docs/queue.md for engineering progress rather than using the README as an activity log.
