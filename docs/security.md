# Security model

Passflick holds high-value credentials and is not yet independently audited.

The local vault uses Argon2id passphrase-based key derivation and XChaCha20-Poly1305 authenticated encryption, with a versioned file format distinct from OTPick's. Persistent vault files are 0600 and created directories 0700. A Linux session-keyring entry stores the derived Passflick-only vault key. Optional Secret Service integration can make key recovery across picker launches convenient.

The normal picker must not reveal passwords in a list, copy them without an explicit key action, write them to logs, put them in process arguments, or send them over the network. The sensitive clipboard hint is advisory; clipboard managers and processes under the same desktop login may capture values. Unlocking the desktop exposes more risk than leaving a vault locked.

Unexpectedly small but syntactically valid snapshots are rejected by default to avoid accidental bulk deletion; an explicit `--allow-shrink` permits intentional cleanup.\n\nCSV files exported by password managers are **plaintext**. Passflick reads an explicit file, then writes encrypted records to its vault. It does not own the exported file or guarantee secure erasure. The user should delete plaintext exports and avoid syncing or committing them. A future import UX should minimize plaintext file persistence.

Direct source integrations must use authorized local interfaces. Do not attempt browser authentication bypass, cloud account access, or unattended decryption of profiles.

Never commit user credentials, exported files, browser profiles, screenshots with sensitive values, keys, or private language.
