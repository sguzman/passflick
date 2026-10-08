# Engineering guidance

Treat every credential and decrypted vault as sensitive. No real passwords, real usernames, customer data, private venting language, secrets, profile dumps, or plaintext exports may enter a commit, CI artifact, or issue.

Passflick is a projection and picker, not a password editor. Keep the README product-oriented; track progress in docs/queue.md. Do not silently claim native browser sync or target-host validation.

Use synthetic example.test fixtures in tests. Preserve source attribution and exact password contents. Malformed imports must not replace a healthy snapshot. The baseline UI behavior is Enter=password, Shift+Enter=username, Escape=exit.

Reuse design knowledge from OTPick, but maintain independent executable, vault, and session key. Changes belong in this repository, not in sibling projects.
