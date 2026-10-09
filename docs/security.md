# Security model

Passflick holds high-value credentials. It is **pre-release** and has not undergone an independent security audit. Real credentials should not be imported until target-host acceptance and security review are complete.

## Encrypted vault

Passflick stores a local, versioned encrypted projection using Argon2id and XChaCha20-Poly1305 authenticated encryption. It enforces private vault-file permissions (0600) and private vault directories (0700). Both creation/writes and active-vault unlocks reject shared or symlinked immediate vault directories. File opens are nonblocking and reject symlinks and non-regular files before reading, so an unexpected FIFO cannot hold the process waiting for a writer. The derived key can be cached in the Linux session keyring, separately for each vault. Session and desktop key-cache identities use the canonical vault parent plus filename, so deleting the primary file for disaster recovery does not change the identity when the parent still exists. Desktop Secret Service integration is optional. A successful passphrase unlock can also proceed for one picker invocation when kernel session caching fails, without persisting any new unencrypted secret.

New vaults require a passphrase between 12 and 1024 characters. Passphrases do not require arbitrary combinations of character classes. Existing vaults remain unlockable with their original passphrases, including shorter values created by earlier versions.

On first launch, the graphical application can create an encrypted vault using masked passphrase and confirmation fields. Passphrase entry buffers are cleared after setup and unlock attempts. The normal picker shows labels and usernames, not passwords; copying requires an explicit key action. Metadata is rendered with terminal escape and bidirectional text-control characters replaced visibly; the original username is preserved for exact copying.

## Process and clipboard

Before handling vault data, Passflick disables Linux core dumps and ptrace attachment with `RLIMIT_CORE=0` and `PR_SET_DUMPABLE=0`. Startup fails if these safeguards cannot be installed.

Password copying requires `wl-clipboard` 2.3+ and uses `wl-copy --sensitive`, preserving literal whitespace and newlines. Older versions fail closed with an upgrade diagnostic rather than falling back to unmarked clipboard writes. **The sensitive hint is advisory**: clipboard managers or other software in the same desktop session may still capture clipboard contents. The application does not claim protection from a compromised user session.

## Data preservation

Source imports parse and validate the full CSV before changing a source snapshot. Conflicting aliases for the same semantic field (such as both `password` and `pass`) are rejected instead of silently choosing one. A missing username column is also rejected, although individual credentials may legitimately have an empty username value. Suspicious bulk reductions require `--allow-shrink`. Updates take an exclusive file lock; refreshing an existing source first creates an encrypted rollback snapshot.

`passflick backup` creates a private encrypted snapshot without overwriting previous backups. `passflick verify FILE` authenticates a selected backup with the active vault key without changing either file. These commands require the active vault to be unlocked. Explicit `passflick recover FILE --confirm` instead authenticates the backup using its own passphrase and can atomically reconstruct a missing or corrupted active file. The previous primary bytes are preserved as a raw, **not necessarily valid** safety snapshot; the application attempts to establish an explicit session lock, invalidate session credentials, and remove stale desktop credentials. If any of these steps fails, recovery still reports success for the authenticated file replacement but warns that automatic unlocking might remain possible. A fresh-passphrase prompt is promised only after all cache cleanup steps succeed. The backup directory must itself be private, and unsafe vault directories are rejected. `passflick restore FILE --confirm` authenticates the selected backup against the current vault key, acquires the write lock, and preserves another encrypted safety backup before replacing the live records. Vault initialization never silently overwrites an existing path.

Encrypted backup files remain portable: read-only verification and authenticated recovery may accept a private regular snapshot file outside the active vault directory, including one held in an otherwise shared directory. Such a snapshot is authenticated before its contents can affect the active vault; the active vault's private-directory requirement is never waived. Keeping backups in private directories is still recommended for integrity and availability. These checks do not eliminate every possible filesystem race or protect against a compromised session.

## Source boundaries

CSV exports from browsers and password managers are **plaintext**. Passflick does not securely erase these source files, so they should not be left in shared or synchronized locations. Native browser profile discovery examines filenames only; it does not decrypt or import stored credentials.

Future native adapters must use authorized local interfaces. CI fixtures contain synthetic credentials rather than production account data.

The Rust workflow also includes a synthetic end-to-end encrypted-recovery CLI smoke test using only fictional credentials, an isolated temporary directory, and a pseudo-terminal for passphrases. The test checks bad-passphrase non-destructiveness, exact ciphertext restoration, a displaced-raw safety snapshot, and subsequent read-only verification. This is an added test, not a claim of a passing CI run or an independent audit.

These safeguards reduce identifiable risks. They do not replace real-world compositor, clipboard, browser-export, and security acceptance.
