# Credential source integration

The initial Passflick ingestion contract is a **user-authorized, local CSV snapshot**. `passflick discover` checks for potential local browser credential profiles using filenames only; discovery never reads credential contents or decrypts a browser store. The application never modifies browser stores, uses browser-login automation, or accesses a cloud password account.

| Source | Primary role | Current ingestion |
| --- | --- | --- |
| Microsoft Edge | Authoritative daily browser | Explicit exported CSV |
| Chrome / Chromium | Legacy browser | Explicit exported CSV |
| Firefox | Secondary browser | Explicit exported CSV |
| Apple Passwords / iPhone | Mobile passwords | Explicit exported CSV |

All four are exposed through `passflick import SOURCE FILE`, with the aliases `edge`, `chrome`, `firefox`, and `apple`.

## Snapshot rules

1. Validate every row before replacing anything in the encrypted vault. Incomplete rows, missing username headers (while allowing blank username values), empty exports, duplicate normalized or semantically ambiguous column names, and recognizable provider mismatches fail closed. Unrecognized **extra** columns are ignored rather than stored. A suspiciously large source shrink also requires explicit `--allow-shrink` confirmation.
2. Replacing one source's snapshot cannot remove records from any other source.
3. Credentials with different secret values remain separate entries even when they have the same website and username.
4. Entries with the same website, username, and password may be grouped for display. Original records remain intact.
5. Keep source and import timestamp. A missing or old snapshot is not represented as live browser state.

Source import updates are serialized through a private lock file, preventing concurrent source refreshes from accidentally overwriting each other. Plaintext CSV files are a transient exchange format and should be deleted after their import is verified. The stdin interface (`passflick import edge -`) permits trusted exporters to stream a snapshot directly. Explicit CSV file paths must resolve to regular files; named pipes and other special files are rejected without blocking. A symlink pointing to an ordinary export file remains supported.

## Documented CSV layouts

The parser includes fictional regression cases for the documented provider layouts. An [end-to-end CI run](https://github.com/sguzman/passflick/actions/runs/37974510558) also verified four concurrent provider projections, a rejected mislabeled Apple export, and source-specific shrink protection. These synthetic tests are not substitutes for checking a recent, authorized export from each real browser.

- Edge and Chrome/Chromium commonly use `name,url,username,password` or another header set containing `url,username,password`. The two cannot always be distinguished from header text alone.
- Firefox exports `url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged`. Its realm, GUID, and timestamps are not copied into the Passflick record.
- Apple/Safari exports commonly contain `Title,URL,Username,Password,Notes,OTPAuth`. Passflick also recognizes `Title` + `OTPAuth` as Apple-specific when `Notes` is absent, preventing a mislabeled import from replacing another source. It takes the password identity only: **Notes and OTPAuth are intentionally ignored**, so TOTP seeds are not silently imported into the password projection.

References: [Google Password Manager CSV format](https://support.google.com/chrome/answer/13068232?hl=en-GB), [Firefox LoginExport implementation](https://searchfox.org/mozilla-central/source/toolkit/components/passwordmgr/LoginExport.sys.mjs), [Apple Safari password-export columns](https://developer.apple.com/documentation/SafariServices/importing-data-exported-from-safari).

## Native integration research

### Edge / Chrome / Chromium

Chromium documents its password storage design on Linux: the profile's `Login Data` database may hold encrypted credentials, with the protection key stored in GNOME Secret Service / KWallet. There is no general public extension API allowing a third-party picker to enumerate arbitrary saved browser passwords. Any native importer must explicitly authenticate through the source's supported Linux secret-store mechanism and follow profile database version changes. No such adapter is currently implemented.

References:

- [Chromium Linux Password Storage](https://chromium.googlesource.com/chromium/src/+/main/docs/linux/password_storage.md)
- [Chromium security FAQ: browser credential storage](https://github.com/chromium/chromium/blob/main/docs/security/faq.md)

### Firefox

Mozilla documents `logins.json` and `key4.db` as protected login storage, using NSS and potentially a Firefox Primary Password. A local importer must use an explicitly authorized read-only path and honor Primary Password requirements. Extracting JSON alone is insufficient.

Reference: [Firefox Primary Password and saved login protection](https://support.mozilla.org/en-US/kb/use-primary-password-protect-stored-logins)

### Apple Passwords on iPhone

Apple documents exporting website/account passwords as CSV through iPhone settings. It excludes some password categories (including Wi-Fi and Sign in with Apple). Passflick has no direct access to the iPhone keychain on Linux and should not present exports as synchronized live state.

Reference: [Apple: export passwords on iPhone](https://support.apple.com/guide/iphone/export-passwords-iphf28f2e93e/ios)

## Future acceptance criteria for an adapter

- Opt-in and explicit per-source authorization.
- Read-only; never modify a source store or weaken browser protections.
- Fail safely if the source's format, key service, or permissions differ.
- Snapshot validation and provenance identical to CSV ingestion.
- Robust behavior while the source browser is running.
- Separate integration tests with synthetic vaults, never actual user credentials committed to the repository.

A browser integration must be *proven* before the README or release metadata calls it supported.
