# Sources

Passflick imports user-exported CSV snapshots. Edge is the primary source, followed by Chrome/Chromium, Firefox, and Apple Passwords.

`passflick import edge /path/to/export.csv`

Replace `edge` with `chrome`, `firefox`, or `apple` as appropriate. Imports replace only the specified source snapshot after parsing succeeds, and preserve the other sources. Actual export schemas require host verification; the current parser supports common fields such as name/title, url, username, and password.

The program does **not** automatically read password databases. Chromium profile storage depends on OS keyrings and version. Firefox uses its own protected login storage. An ordinary browser extension is not automatically privileged to enumerate passwords. Linux cannot directly read the iPhone's Apple Passwords database. Future local integration must be opt-in, respect source protections, and retain CSV import as a baseline.

Exported files contain plaintext. Never put them inside the repository or upload them.
