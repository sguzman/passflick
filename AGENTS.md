# Engineering guidance

Treat every credential and decrypted vault as sensitive. No real passwords, real usernames, customer data, private venting language, secrets, profile dumps, or plaintext exports may enter a commit, CI artifact, or issue.

Passflick is a projection and picker, not a password editor. Keep the README product-oriented; track the active goal in ROADMAP.md. docs/queue.md is the historical browser-CSV implementation queue. Do not silently claim native browser sync or target-host validation.

Use synthetic example.test fixtures in tests. Keep exact credential contents intact. The new Vaultwarden projection must preserve upstream item identities and exclude archived/deleted items; malformed or incomplete updates must not replace a healthy encrypted snapshot. The baseline UI behavior is Enter=password, Shift+Enter=username, Escape=exit.

Reuse design knowledge from OTPick, but maintain independent executable, vault, and session key. Changes belong in this repository, not in sibling projects.

## Current adopted objective

The active scope is the [Vaultwarden-only roadmap](ROADMAP.md): one Bitwarden-compatible source of truth, explicit `passflick update`, encrypted offline projection, native Rust integration if viable, and the same fast read-only picker. The old CSV-source guidance below is historical for code that still exists; do not keep browser imports as a permanent second mode. Do not delete existing encrypted local data, change upstream passwords or copy private hostnames/credentials into public files. Do not claim the adapter or refreshed cache works until verified.
