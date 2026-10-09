# Security model

Passflick holds high-value credentials. It is **pre-release** and has not undergone an independent security audit. Real credentials should not be imported until target-host acceptance and security review are complete.

## Encrypted vault

Passflick stores a local, versioned encrypted projection using Argon2id and XChaCha20-Poly1305 authenticated encryption. It enforces private vault-file permissions (0600) and private vault directories (0700). The derived key can be cached in the Linux session keyring, separately for each vault. Desktop Secret Service integration is optional. A successful passphrase unlock can also proceed for one picker invocation when kernel session caching fails, without persisting any new unencrypted secret.

New vaults require a passphrase between 12 and 1024 characters. Passphrases do not require arbitrary combinations of character classes. Existing vaults remain unlockable with their original passphrases, including shorter values created by earlier versions.

On first launch, the graphical application can create an encrypted vault using masked passphrase and confirmation fields. Passphrase entry buffers are cleared after setup and unlock attempts. The normal picker shows labels and usernames, not passwords; copying requires an explicit key action.

## Process and clipboard

Before handling vault data, Passflick disables Linux core dumps and ptrace attachment with `RLIMIT_CORE=0` and `PR_SET_DUMPABLE=0`. Startup fails if these safeguards cannot be installed.

Password copying uses `wl-copy --sensitive`, preserving literal whitespace and newlines. **The sensitive hint is advisory**: clipboard managers or other software in the same desktop session may still capture clipboard contents. The application does not claim protection from a compromised user session.

## Data preservation

Source imports parse and validate the full CSV before changing a source snapshot. Suspicious bulk reductions require `--allow-shrink`. Updates take an exclusive file lock; refreshing an existing source first creates an encrypted rollback snapshot.

`passflick backup` creates a private encrypted snapshot without overwriting previous backups. `passflick restore FILE --confirm` authenticates the selected backup against the current vault key, acquires the write lock, and preserves another encrypted safety backup before replacing the live records. Vault initialization never silently overwrites an existing path.

## Source boundaries

CSV exports from browsers and password managers are **plaintext**. Passflick does not securely erase these source files, so they should not be left in shared or synchronized locations. Native browser profile discovery examines filenames only; it does not decrypt or import stored credentials.

Future native adapters must use authorized local interfaces. CI fixtures contain synthetic credentials rather than production account data.

These safeguards reduce identifiable risks. They do not replace real-world compositor, clipboard, browser-export, and security acceptance.
