# Secure Share

Secure Share is a REST API for private, owner-controlled file transfer. A
registered user uploads a file, explicitly grants another registered user
access, and can revoke that access at any time. Knowing a filename or file ID
never grants access: every download is authenticated and authorized against the
file's owner and permission records.

The project targets Python 3.12+, Flask, SQLAlchemy, SQLite for local
development, and PostgreSQL for production.

## Architecture

The application factory in `app/__init__.py` wires together small modules with
distinct responsibilities:

```text
app/
├── models/       SQLAlchemy users, sessions, tokens, email jobs, files, grants
├── routes/       REST endpoints and server-rendered web entry points
├── services/     Authentication, file, and permission business rules
├── templates/    Accessible Flask page templates
├── static/       Bundled CSS and modular vanilla JavaScript
├── utils/        Bearer-token and authorization helpers
├── config.py     Environment-backed configuration
└── extensions.py Shared SQLAlchemy instance
```

Uploaded bytes live in the configured private storage directory. Only metadata
is stored in the database. Routes call the service layer, and the service layer
is the single authority for access checks and safe storage operations.

The main relationships are:

```text
User ──< FileRecord (owner_id)
User ──< AuthSession
User ──< AccountActionToken
User ──< SecurityEmailJob
User ──< FilePermission >── FileRecord
```

`FilePermission` has a unique constraint on `(file_id, user_id)`, preventing
duplicate grants. Foreign keys cascade permission deletion when a file or user
is removed. The schema uses database-neutral SQLAlchemy types and constraints
that work with both SQLite and PostgreSQL.

## Technologies

- Python 3.12+
- Flask, Flask-SQLAlchemy, and Flask-Migrate/Alembic
- SQLAlchemy 2.x ORM
- SQLite locally; PostgreSQL via psycopg in production
- Werkzeug scrypt password hashing
- 15-character new-password policy with an offline compromised-value blocklist
- Database-backed bearer API sessions and HttpOnly browser sessions
- Durable, secret-free database outbox for security email
- Flask-Limiter 4.x with Redis-backed production counters
- python-dotenv for local environment loading
- pytest for automated tests

## Installation

Clone the repository and create an isolated environment:

```bash
git clone https://github.com/VidulaWickramasinghe/Secure_Share.git
cd Secure_Share
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Contributors should install the test and security tooling as well:

```bash
python -m pip install -r requirements-dev.txt
```

Create local configuration from the safe example and replace its development
secret:

```bash
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Generate independent values for `SECRET_KEY`, `ACCOUNT_TOKEN_PEPPER`, and
`RATE_LIMIT_KEY_SECRET`; never reuse one value for another purpose. The `.env`
file and local database files are ignored by Git; never commit them.

Initialize the database and start the development server:

```bash
flask --app run.py init-db
flask --app run.py run
```

The API is then available at `http://127.0.0.1:5000`. After initialization,
`python run.py` also starts the development server. Flask's built-in server is
for development only; production should use a hardened WSGI deployment behind
HTTPS.

## Database migrations

`flask --app run.py init-db` is the supported initialization and upgrade
command. It uses the checked-in Alembic revisions and is safe in three cases:

- an empty database is initialized at the latest revision;
- a migration-tracked database is upgraded to the latest revision; and
- the exact four-table schema from releases predating Alembic is validated,
  stamped at the baseline, and then upgraded without replacing its data.

An unversioned database with missing, additional, or changed schema objects is
rejected without being stamped. Back up every production database before an
upgrade, investigate the mismatch, and never use `flask db stamp` merely to
bypass validation. Operators can inspect state with:

```bash
flask --app run.py db current
flask --app run.py db history
```

When changing a model, generate and review a child revision, then verify both
fresh installation and upgrade behavior:

```bash
flask --app run.py db migrate -m "describe the schema change"
flask --app run.py init-db
pytest tests/test_migrations.py
```

## Web Interface

Secure Share includes a responsive browser interface built with Flask
templates, HTML, CSS, and small vanilla JavaScript modules. Start it with the
same commands used for the API:

```bash
flask --app run.py init-db
flask --app run.py run
```

Open `http://127.0.0.1:5000/`. A signed-out visitor sees the Secure Share
landing and login screen; an authenticated visitor is taken to
`/dashboard`. The API remains available under `/api/*`.

To use the interface:

1. Select **Create account**, register a username, email address, and strong
   password, then open the single-use verification link sent to that address.
   Development messages are processed inline and written as private `.eml`
   files in `instance/mail-outbox`.
2. Sign in. If verification is still pending, the dashboard explains that the
   account may upload but cannot receive shares and offers a resend action.
3. In the dashboard upload area, choose a file, review its name and size, and
   select **Upload securely**. Uploaded bytes remain in the private configured
   storage directory, never under `/static`.
4. Under **My Files**, select **Manage access** for a file. Enter another
   verified registered user's numeric **Sharing ID** from their dashboard and
   select **Grant access**.
5. When that user signs in, the file appears under **Shared With Me**. Their
   **Download** action calls the protected API download endpoint, which checks
   the current database permission before returning any bytes.
6. To withdraw access, the owner opens **Manage access** again and selects
   **Revoke** next to the authorized user. A later download attempt is rejected
   by the backend with `403 Forbidden`.
7. **Logout** revokes the current server-side session, removes the browser's
   authentication state, and returns to the login page.

The browser never treats a visible file card, filename, or file ID as proof of
access. It renders only the safe records returned by `GET /api/files`, and all
uploads, downloads, grants, revocations, and deletions go through the existing
authenticated API. The service and database layers remain the single source
of truth for authentication, ownership, and authorization.

The web client authenticates with an `HttpOnly`, `SameSite=Lax` cookie. Its
session credential is never returned in JSON or made available to JavaScript.
Unsafe cookie-authenticated requests also send a separate CSRF token in the
`X-CSRF-Token` header; only that non-credential token is JavaScript-readable,
and the database stores only its SHA-256 digest. Logout deletes the current
server-side session and expires both cookies. Expired or revoked cookies are
rejected and cleared by the server on the next request.

The bearer-token login remains available for non-browser API clients. Explicit
`Authorization` credentials take precedence and never fall back to a browser
cookie, and bearer sessions cannot be replayed as cookie sessions (or vice
versa). A web user upgrading from an older `sessionStorage` release must sign in
once to establish the new cookie session.

## Environment configuration

| Variable | Purpose | Local default/example |
| --- | --- | --- |
| `SECRET_KEY` | Stable, high-entropy application secret | Random value required in production |
| `ACCOUNT_TOKEN_PEPPER` | Dedicated HMAC key for verification/reset token digests | Independent random value; distinct from `SECRET_KEY` in production |
| `APP_ENV` | Deployment safety mode: `development`, `test`, or `production` | `development` |
| `BROWSER_COOKIE_SECURE` | Send browser auth/CSRF cookies only over HTTPS | `0` locally; mandatory in production |
| `RATELIMIT_STORAGE_URI` | Shared rate-limit counter backend | `memory://` for development/tests; Redis required in production |
| `RATE_LIMIT_KEY_SECRET` | Dedicated HMAC secret protecting rate-limit bucket identifiers | Independent random value; required with shared storage |
| `RATELIMIT_KEY_PREFIX` | Namespace for this deployment's shared counters | `secure-share` |
| `DATABASE_URL` | SQLAlchemy database URL | `sqlite:///secure_share.db` in `.env.example` |
| `UPLOAD_FOLDER` | Private directory for uploaded bytes | `storage` |
| `MAX_CONTENT_LENGTH` | Maximum HTTP request size in bytes | `16777216` (16 MiB) |
| `SESSION_LIFETIME_SECONDS` | Browser and bearer session lifetime | `86400` (24 hours) |
| `EMAIL_VERIFICATION_TOKEN_LIFETIME_SECONDS` | Lifetime of a single-use verification link | `86400` (24 hours) |
| `PASSWORD_RESET_TOKEN_LIFETIME_SECONDS` | Lifetime of a single-use recovery link | `3600` (1 hour) |
| `PASSWORD_RESET_MINIMUM_RESPONSE_SECONDS` | Minimum recovery-request response time to reduce enumeration timing | `0.5`; at least `0.25` in production |
| `PUBLIC_BASE_URL` | External origin used in security-email links | `http://127.0.0.1:5000` locally; HTTPS required in production |
| `MAIL_BACKEND` | Security-email transport: `file`, `memory`, `smtp`, or `disabled` | `file` locally; `smtp` required in production |
| `MAIL_FROM_ADDRESS` | Sender for verification, recovery, and password alerts | `no-reply@secure-share.local` |
| `MAIL_FILE_OUTBOX` | Private development `.eml` directory | `instance/mail-outbox` |
| `SMTP_*` | SMTP host, port, credentials, TLS mode, and timeout | Required as appropriate for the production provider |
| `SECURITY_EMAIL_INLINE_DELIVERY` | Process security-email jobs inside local requests | `1` locally; must be `0` in production |
| `SECURITY_EMAIL_LEASE_SECONDS` | Exclusive worker lease for one delivery attempt | `300`; production requires at least 10× the SMTP timeout |
| `SECURITY_EMAIL_MAX_ATTEMPTS` | Maximum provider delivery attempts | `5` |
| `SECURITY_EMAIL_RETRY_BASE_SECONDS` | Initial retry backoff | `30` |
| `SECURITY_EMAIL_RETRY_MAX_SECONDS` | Maximum retry backoff | `3600` |
| `SECURITY_EMAIL_WORKER_BATCH_SIZE` | Maximum jobs processed in one batch | `100` |
| `SECURITY_EMAIL_WORKER_POLL_SECONDS` | Idle worker polling interval | `2` |
| `PASSWORD_BLOCKLIST_PATH` | Whole-password SHA-256 compromised corpus | Optional extension locally; at least 10,000 unique digests required in production |
| `FLASK_DEBUG` | Flask development debugging | `0` |

A production PostgreSQL URL looks like:

```dotenv
APP_ENV=production
BROWSER_COOKIE_SECURE=1
SECRET_KEY=<random-value-one>
ACCOUNT_TOKEN_PEPPER=<random-value-two>
PUBLIC_BASE_URL=https://share.example.com
DATABASE_URL=postgresql+psycopg://secure_share:password@db.example/secure_share
RATELIMIT_STORAGE_URI=rediss://redis.example:6379/0
RATE_LIMIT_KEY_SECRET=<random-value-three>
MAIL_BACKEND=smtp
MAIL_FROM_ADDRESS=no-reply@share.example.com
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SECURITY_EMAIL_INLINE_DELIVERY=0
SMTP_USE_STARTTLS=1
PASSWORD_BLOCKLIST_PATH=/etc/secure-share/compromised-passwords.sha256
```

Use a dedicated database role, a persistent private upload volume, and an
absolute `UPLOAD_FOLDER` path not served by the reverse proxy. Do not enable
debug mode in production. Run the WSGI application and this durable mail worker
as separate supervised processes against the same database:

```bash
flask --app run.py email-worker
```

The worker atomically leases queued jobs, retries provider failures with capped
backoff, and never stores message bodies or usable verification/reset tokens.
Raw action tokens exist only in worker memory while a message is constructed.
`--once`, `--batch-size`, and `--poll-seconds` are available for operations and
testing. Do not run `--once` as the only production delivery process.

Production startup rejects an insecure browser cookie, a reused account-token
key, a non-HTTPS public URL, synchronous security-email delivery, plaintext
SMTP, an unsafe worker lease, a missing or undersized password blocklist, a
non-SMTP mail transport, or process-local rate-limit storage.
Redis failures reject requests rather than falling back to memory or silently
disabling enforcement.

## Authentication

Registration stores only a Werkzeug-generated password hash.

Newly registered and replacement passwords must contain at least 15
characters. Spaces and Unicode are supported, and the server checks the whole
candidate value against a bundled offline list of common or compromised
passwords. Existing passwords remain valid after policy upgrades; the stronger
policy applies when a password is newly established, not while an existing
hash is being verified.

Operators can extend the bundled development safeguards by setting
`PASSWORD_BLOCKLIST_PATH` to an ASCII file containing one SHA-256 hex digest per
line. Relative paths are resolved from the project root. The file extends
rather than replaces the bundled protection, and raw passwords must never be
placed in it. Production startup requires a substantive external corpus of at
least 10,000 unique digests; the small checked-in set is not represented as a
complete breach corpus.

`POST /api/auth/login` is the non-browser API login and returns a random opaque
bearer token:

```json
{
  "token": "<opaque-session-token>",
  "token_type": "Bearer",
  "expires_at": "2026-08-26T00:00:00+00:00",
  "user": {
    "id": 1,
    "username": "alice",
    "email": "alice@example.com",
    "email_verified": true,
    "created_at": "2026-08-25T00:00:00+00:00"
  }
}
```

Send the token on every protected request:

```http
Authorization: Bearer <opaque-session-token>
```

Only the token's SHA-256 digest is stored in the database. Tokens expire after
`SESSION_LIFETIME_SECONDS`; logout deletes the active session. Changing a
password verifies the current password and revokes the user's other sessions.
Treat the returned token as a credential and transmit it only over HTTPS.

The web interface instead calls `POST /api/auth/browser-login`. A successful
response contains safe account data and expiry only; it establishes the
HttpOnly cookie plus a separate readable CSRF cookie. The browser sends cookies
only to the same origin and includes `X-CSRF-Token` on every POST, PUT, PATCH,
DELETE, or other unsafe authenticated request. `GET /api/auth/csrf` safely
rotates a browser session's CSRF token if the readable cookie must be restored;
it requires a non-simple same-origin script header and rejects cross-site Fetch
Metadata. This token proves request intent only: it is not an access code, a
file-integrity hash, or a document signature.

Browser login validates the browser-controlled `Origin` header against
`PUBLIC_BASE_URL`, which also controls the origin in email links. Configure it
to the exact external HTTPS origin in production. Flask additionally restricts
production `Host` headers to that origin's hostname; the application should be
reachable only through a trusted edge that preserves the external origin.

New accounts start with an unverified email address. Registration atomically
creates the account and a secret-free delivery job. The worker later creates a
256-bit verification token, stores only its purpose-separated HMAC digest, and
delivers the usable token in a URL fragment. Verification and recovery tokens
expire, work once, and are invalidated when a replacement is issued. A user may
upload before verification, but an owner cannot grant that account a new share
and the account cannot change sensitive password settings until its current
email is verified. Existing accounts adopted by migration remain unverified
until they prove their address; existing permission rows continue to work so
the migration does not retroactively revoke already-granted access.

Password-reset requests always return the same status and JSON whether or not
an account exists. Production requests only enqueue work, so provider latency
is kept out of the response path, and startup enforces a nonzero response-time
floor. A successful reset applies the current password policy, confirms control
of the token-bound email, invalidates every session and sibling action token,
cancels queued reset delivery, and transactionally queues a mandatory
password-change alert. The browser removes action tokens from the address-bar
fragment before submitting them and never stores them in browser storage.

## API

All endpoints return JSON except a successful download, which returns the file
as an attachment. Expected failures have a consistent `{"error": "..."}`
shape and use `400`, `401`, `403`, `404`, `409`, `413`, or `429` as appropriate.
Unexpected production failures return a generic `500` response without a stack
trace.

### Account endpoints

| Method | Endpoint | Authentication | Description |
| --- | --- | --- | --- |
| `POST` | `/api/auth/register` | No | Register with `username`, `email`, and `password` |
| `POST` | `/api/auth/login` | No | Create and return a bearer API session |
| `POST` | `/api/auth/browser-login` | Same-origin browser | Establish an HttpOnly browser session |
| `POST` | `/api/auth/logout` | Bearer or browser + CSRF | Revoke the current session |
| `GET` | `/api/auth/me` | Bearer or browser | Return the current account |
| `GET` | `/api/auth/csrf` | Browser | Rotate the browser session's CSRF token |
| `POST` | `/api/auth/email-verification/request` | Bearer or browser + CSRF | Send a replacement verification link if needed |
| `POST` | `/api/auth/email-verification/confirm` | Single-use token | Verify the token's bound email address |
| `POST` | `/api/auth/password-reset/request` | No | Request recovery with a non-enumerating response |
| `POST` | `/api/auth/password-reset/confirm` | Single-use token | Establish `new_password` and revoke all sessions |
| `PATCH` or `PUT` | `/api/auth/password` | Bearer or browser + CSRF | Change with `current_password` and `new_password` |

### File endpoints

| Method | Endpoint | Required access | Description |
| --- | --- | --- | --- |
| `POST` | `/api/files` | Authenticated | Upload multipart field `file` |
| `GET` | `/api/files` | Authenticated | List only owned and explicitly shared files |
| `GET` | `/api/files/<file_id>` | Owner or authorized | Read safe metadata |
| `GET` | `/api/files/<file_id>/download` | Owner or authorized | Download after a fresh authorization check |
| `DELETE` | `/api/files/<file_id>` | Owner only | Delete bytes, grants, and metadata |

The upload response wraps public metadata in a `file` object. The internal
server-side filename is never returned.

### Permission endpoints

| Method | Endpoint | Required access | Description |
| --- | --- | --- | --- |
| `GET` | `/api/files/<file_id>/permissions` | Owner only | List the file's authorized users |
| `POST` | `/api/files/<file_id>/permissions` | Owner only | Grant access using `{"user_id": 2}` |
| `DELETE` | `/api/files/<file_id>/permissions/<user_id>` | Owner only | Revoke that user's access |

An owner cannot create a redundant permission for themselves, and a user
cannot manage or remove permissions on somebody else's file. Repeating the
same grant returns `409 Conflict`.

## Authorization model

For each download, the server loads the authenticated session and permits the
request only when one of these database-backed conditions is true:

1. `file.owner_id == current_user.id`; or
2. a `FilePermission(file_id, current_user.id)` row exists.

Creating a new permission requires the recipient's current email to be
verified. Once created, the explicit permission remains authoritative until the
owner revokes it; this preserves pre-migration grants without pretending that a
legacy email address was verified.

An unrelated user receives `403 Forbidden` from the download endpoint even if
they know the exact UUID. Private files are absent from their list, and the
metadata endpoint responds as not found to avoid exposing file existence. Only
the owner can inspect or mutate grants and delete the file.

## Example workflow

The following abbreviated requests illustrate the intended flow. Replace IDs
and tokens with values returned by the API.

1. Alice and Bob register and verify their email addresses using the links
   delivered by the configured mail backend.

   ```bash
   curl -X POST http://127.0.0.1:5000/api/auth/register \
     -H 'Content-Type: application/json' \
     -d '{"username":"alice","email":"alice@example.com","password":"a-long-password"}'

   curl -X POST http://127.0.0.1:5000/api/auth/register \
     -H 'Content-Type: application/json' \
     -d '{"username":"bob","email":"bob@example.com","password":"another-long-password"}'
   ```

2. Alice logs in and uploads `report.pdf`.

   ```bash
   curl -X POST http://127.0.0.1:5000/api/auth/login \
     -H 'Content-Type: application/json' \
     -d '{"identifier":"alice","password":"a-long-password"}'

   curl -X POST http://127.0.0.1:5000/api/files \
     -H 'Authorization: Bearer <ALICE_TOKEN>' \
     -F 'file=@report.pdf'
   ```

3. Alice authorizes Bob (assume the returned file ID is `<FILE_ID>` and Bob's
   account ID is `2`).

   ```bash
   curl -X POST http://127.0.0.1:5000/api/files/<FILE_ID>/permissions \
     -H 'Authorization: Bearer <ALICE_TOKEN>' \
     -H 'Content-Type: application/json' \
     -d '{"user_id":2}'
   ```

4. Bob logs in and downloads the file.

   ```bash
   curl -X POST http://127.0.0.1:5000/api/auth/login \
     -H 'Content-Type: application/json' \
     -d '{"identifier":"bob","password":"another-long-password"}'

   curl http://127.0.0.1:5000/api/files/<FILE_ID>/download \
     -H 'Authorization: Bearer <BOB_TOKEN>' \
     --output report.pdf
   ```

5. Alice removes Bob's permission. Bob's next download receives `403`.

   ```bash
   curl -X DELETE http://127.0.0.1:5000/api/files/<FILE_ID>/permissions/2 \
     -H 'Authorization: Bearer <ALICE_TOKEN>'
   ```

This is the complete intended sequence: Alice registers, Bob registers, Alice
logs in, Alice uploads, Alice authorizes Bob, Bob logs in and downloads, Alice
revokes Bob, and Bob can no longer download.

## Security considerations

- Passwords are hashed with Werkzeug's scrypt configuration and are never
  returned by the API. Newly established passwords require at least 15
  characters and are checked as complete values against offline compromised-
  password digests; existing shorter credentials continue to authenticate
  until their owner replaces them.
- Session and CSRF values are generated from cryptographically secure
  randomness; only digests are persisted. Browser session credentials are
  HttpOnly and every unsafe cookie-authenticated operation requires the
  session-bound CSRF cookie value in a header. Authentication rejects malformed,
  unknown, expired, cross-transport, and revoked credentials.
- Email verification and password recovery use separate, purpose-bound HMAC
  digests under `ACCOUNT_TOKEN_PEPPER`. Usable tokens are never persisted,
  returned by the API, placed in query strings, or logged by application code.
  They are expiring, single-use, replacement-invalidated, and rate-limited.
- Security-email requests are durable, secret-free database jobs. Production
  SMTP runs only in a separate leased worker with encrypted transport, bounded
  retries, and no message body, recipient snapshot, or usable token in the job
  table. Password changes cancel pending recovery jobs transactionally.
- Registration, both login transports, email verification, password recovery,
  uploads, and downloads have server-side fixed-window limits. Login combines
  a broad peer-IP ceiling with failed-only peer and target-only credential
  buckets across short and long windows. Recovery and verification likewise
  combine peer limits with email, user, or challenge targets, so rotating IPs
  cannot bypass the long-window bucket. These finite target cooldowns trade a
  bounded availability risk for distributed-guessing resistance; successful
  authentication does not consume the failure allowance and there is no
  permanent account-lock flag. Authenticated file limits combine user, session,
  and file-resource buckets; separate peer limits run before session lookup so
  unauthenticated upload/download floods are bounded too.
- Bucket identifiers are HMAC-SHA-256 values under the dedicated
  `RATE_LIMIT_KEY_SECRET`; Redis never receives raw email addresses, usernames,
  user IDs, session IDs, file IDs, or action tokens. Limits use
  `request.remote_addr` and deliberately ignore client-supplied
  `X-Forwarded-For`. A trusted edge must supply the actual socket peer through
  the deployment server rather than accepting arbitrary forwarding headers.
- A rejected request returns JSON with status `429`, a finite `Retry-After`,
  and standard `X-RateLimit-*` headers. Production has no in-memory fallback
  and does not swallow Redis errors.
- Upload names are validated as plain basenames. Path separators, traversal
  segments, control characters, empty names, and unusable names are rejected.
- Stored filenames are application-generated UUID values. Files are created
  without overwrite and with restrictive permissions inside a canonical,
  private storage root. Downloads use an already-opened, no-follow file
  descriptor that is checked as a regular file before it is served.
- The configured upload directory cannot be Flask's public static directory.
  Uploaded content is never imported or executed and is served only through
  the authorized download route.
- The global request limit and a streaming file-size check enforce the
  configured maximum while cleaning up partial uploads.
- SQLAlchemy ORM queries avoid SQL construction from client input. Database
  uniqueness and foreign-key constraints reinforce service-layer checks.
- Permission responses identify authorized accounts by ID and username without
  disclosing their email addresses.
- UUIDs reduce guessability but are not authorization. Every read, download,
  permission change, and deletion applies an explicit access policy.
- Error responses do not contain storage paths, SQL details, credentials, or
  production stack traces.

Production operators should additionally enforce TLS, complementary edge
request limits, per-user storage/session quotas, secure logging, backups,
malware/content scanning appropriate to their threat model, monitoring, and
regular dependency updates. Large installations should also paginate list
endpoints and run periodic storage/database reconciliation.

## Tests

Run the full suite from the repository root:

```bash
pytest
```

Run the same local quality and security checks used by CI with:

```bash
ruff check .
bandit -q -c pyproject.toml -r app
pip-audit -r requirements-dev.txt
detect-secrets-hook --baseline .secrets.baseline $(git ls-files)
```

CI runs the tests on Python 3.12, 3.13, and 3.14, including fresh migration,
legacy-schema adoption, drift rejection, repeat-upgrade, email-job leasing,
retry, and secret-persistence tests. It also runs Ruff, Bandit, dependency
vulnerability auditing, and secret detection.
The secret baseline contains only reviewed example/test false positives and
excludes the bundled compromised-password digest set; do not regenerate it to
silence an unexplained finding.

The tests use a fresh temporary SQLite database and upload directory. They
cover registration uniqueness, password hashing, minimum-length and
compromised-password rejection, legacy-password compatibility, login and token
revocation, rate-limit retry headers, peer and HMAC bucket isolation, finite
login backoff, bearer/cookie enforcement, protected endpoints, upload
validation and traversal rejection, maximum size, metadata persistence,
private listings, owner download/deletion, physical cleanup, invalid IDs,
permission uniqueness, and the complete Alice/Bob/Charlie authorization
lifecycle. Negative account tests also cover CSRF rejection, verification
expiry/reuse, resend invalidation, unverified-recipient rejection, generic
reset responses, reset expiry/reuse, queued-reset cancellation, weak-password
rollback, session revocation, distributed-source limits, and safe migration
behavior.

## Roadmap status

This release implements Phase 0 and the requested Priority 1 foundation:
repository reconciliation, reviewed migrations, CI/security checks, secure
browser cookies with CSRF, bearer-client compatibility, rate limits, the
15-character compromised-password policy, verified email, password recovery,
and an asynchronous production security-email outbox.

MFA/passkeys remain deliberately deferred until the Priority 2 account-settings
work can provide safe enrollment, recent re-authentication, recovery, session
management, and security notifications as one coherent flow. Random public
sharing identifiers, access-code shares, quarantine/scanning, SHA-256 file
integrity, encryption at rest, audit history, and digital signatures are also
not part of this stage. An access code, future file-integrity fingerprint, and
future document signature remain three separately labelled concepts.
