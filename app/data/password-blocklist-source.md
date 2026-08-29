# Production password blocklist

The 10,000 SHA-256 digests in `production-password-blocklist.sha256` are derived
from the first 10,000 unique nonempty UTF-8 entries in the SecLists common-password
list. Raw passwords are not bundled. Hashing preserves the complete password bytes;
only line delimiters are removed. This is a baseline common-password corpus, not
a complete or continuously updated breach database. Operators can supply a larger
maintained corpus through `PASSWORD_BLOCKLIST_PATH`.

Source: https://github.com/danielmiessler/SecLists/blob/830924cd2b522d82b870b37fd761a06c0f6b2bc8/Passwords/Common-Credentials/xato-net-10-million-passwords-100000.txt

Downloaded: 2026-08-28

Source SHA-256: `1472aafa2561df5e3293aee252aee3ca660c12b399a283cf808bb01b39be388b`

License: MIT; see `SecLists-LICENSE.txt` for attribution and terms.
