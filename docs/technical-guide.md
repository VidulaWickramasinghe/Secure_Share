# Secure Share — Technical guide

[Back to the repository overview](../README.md)

![Secure Share — Private files. Explicit permissions. Owner-controlled access.](assets/secure-share-banner.png)

Secure Share is a Flask REST API with a responsive browser interface for sharing
files between registered users. An owner uploads a file, grants a verified
recipient access, and can revoke that permission later. Every download checks
the current session and database permissions before opening the stored file.

> **A file ID identifies a file; it never authorizes access.** Files are private
> by default and are not published as static assets or anonymous download links.

**Implementation status:** the core sharing workflow and the Phase 0 / Priority 1
security foundation are implemented. Production operation still requires the
infrastructure and controls described below; full Vercel compatibility and the
Priority 2 features are not complete.

## Contents

- [Project background](#project-background)
- [Completed capabilities](#completed-capabilities)
- [Architecture and data model](#architecture)
- [Technology stack](#technology-stack)
- [Local setup](#local-setup)
- [Vercel deployment status](#vercel-deployment-status)
- [Database migrations](#database-migrations)
- [Browser walkthrough](#browser-walkthrough)
- [Configuration and production operations](#configuration-and-production-operations)
- [Authentication and account recovery](#authentication-and-account-recovery)
- [API reference](#api-reference)
- [Authorization model](#authorization-model)
- [End-to-end sharing example](#end-to-end-sharing-example)
- [Security controls and boundaries](#security-controls-and-boundaries)
- [Testing and quality checks](#testing-and-quality-checks)
- [Delivery status and future work](#delivery-status-and-future-work)

## Project background

### The problem

Sharing a URL or a filename does not establish who should be allowed to retrieve
a document. Secure Share addresses that distinction with an identity-based
workflow: the sender retains ownership, recipients receive explicit grants,
and the server decides access on each request.

### The implemented solution

The project brings account registration, email verification, private upload and
download, permission management, password recovery, and a browser dashboard into
one application. The REST API also supports non-browser clients through opaque
bearer sessions. Both interfaces use the same server-side authorization rules.

![Concept illustration of private documents: an approved account is connected to the file tray, while an account without permission has no active connection.](assets/private-sharing-illustration.png)

*Concept artwork for permission-based sharing, not an application screenshot.
The technical diagrams below describe the implemented behavior.*

| Participant | Responsibility | Boundary |
| --- | --- | --- |
| File owner | Upload, download, grant/revoke access, and delete their files | Cannot manage another owner's files |
| Verified recipient | Receive an explicit grant and download the shared file | Cannot grant onward access through the API or delete the owner's file |
| Other registered user | Manage their own uploads | Cannot list or download unrelated private files |
| Deployment operator | Maintain storage, database, email delivery, TLS, and backups | Infrastructure access is outside the application's per-user authorization boundary |

Revocation blocks later download requests after the permission is removed. It
does not erase copies already downloaded or recall a response whose access check
has already succeeded. This is server-controlled access, not digital rights
management or end-to-end encryption.

## Completed capabilities

| Area | Implemented outcome |
| --- | --- |
| Accounts | Registration, normalized unique identities, scrypt password hashes, and a 15-character new-password policy with offline compromised-password checks |
| Sessions | Expiring, database-backed bearer tokens and HttpOnly browser cookies; CSRF protection for unsafe cookie-authenticated requests |
| Email and recovery | Single-use verification/reset links, generic recovery responses, session revocation, and password-change alerts |
| Private files | Validated uploads, UUID storage names, size limits, protected downloads, and owner-only deletion |
| Sharing | Verified-recipient grants, duplicate-grant prevention, permission listing, and owner-controlled revocation |
| Browser experience | Registration/login, verification/recovery pages, upload dashboard, My Files, Shared With Me, and access management |
| Abuse controls | Layered rate limits, HMAC-protected bucket identifiers, and shared Redis counters in production |
| Reliability | Alembic migrations, strict legacy-schema adoption, and durable security-email jobs with leases and bounded retries |
| Engineering checks | Automated tests, a Python 3.12–3.14 CI matrix, lint/security scans, and locked deployment dependency checks |

These are implementation capabilities, not a claim of an independent security
audit, a live production deployment, or completion of every roadmap item.

## Architecture

### Request path and infrastructure

The application factory in `app/__init__.py` wires together routes, security
helpers, business services, and the database. The diagram shows the production
shape: Redis and SMTP are external dependencies, and email processing runs in a
separate supervised worker. Local development substitutes SQLite, in-memory
rate counters, and inline file-based email delivery.

```mermaid
flowchart TB
    accTitle: Secure Share application architecture
    accDescr: Browser and API clients enter Flask guards and services. SQL stores records, private storage holds bytes, Redis limits requests, and a separate worker delivers email.
    browser["Browser interface"] -->|"HttpOnly cookie + CSRF"| webApp
    apiClient["API client"] -->|"Bearer token"| webApp

    subgraph application ["Flask application"]
        webApp["Routes and request guards"] --> services["Authentication, file, and permission services"]
    end

    webApp -->|"Rate-limit counters"| redis[("Shared Redis")]
    services -->|"Metadata and access records"| database[("SQL database")]
    services -->|"File bytes"| storage[("Private persistent storage")]
    database -.->|"Leased email jobs"| worker["Security-email worker"]
    worker -.->|"Encrypted SMTP"| mail["Email provider"]
```

Uploaded bytes live in private storage; the SQL database holds file metadata,
not file contents. No client connects directly to that storage through the
application. Route-level guards authenticate requests; service-layer checks
enforce file access and ownership.

### Repository structure

```text
Secure_Share/
├── app/
│   ├── models/       Users, sessions, action tokens, email jobs, files, grants
│   ├── routes/       REST endpoints and server-rendered web entry points
│   ├── services/     Authentication, email, storage, and permission rules
│   ├── templates/    Flask page templates
│   ├── static/       CSS, favicon, and modular vanilla JavaScript
│   ├── utils/        Authentication and CSRF helpers
│   ├── data/         Bundled development password-blocklist digests
│   ├── config.py     Environment-backed settings and production validation
│   ├── database.py   Migration bootstrap and legacy-schema validation
│   ├── rate_limits.py
│   └── extensions.py
├── migrations/       Reviewed Alembic revisions
├── tests/            Functional, security, migration, and deployment tests
├── storage/          Default private upload directory; not a public asset path
├── .github/workflows/ci.yml
├── .env.example      Safe configuration template
├── .python-version   Deployment Python version
├── pyproject.toml    Runtime dependencies, tooling, and WSGI entrypoint
├── requirements.txt
├── requirements-dev.txt
├── uv.lock           Locked deployment dependencies
└── run.py            WSGI application entrypoint
```

### Data model

One user can own many files and hold many grants on other users' files. Sessions,
account-action tokens, and security-email jobs also belong to a user. The
diagram uses the actual table names and a selected set of fields; it is not a
complete schema dump.

```mermaid
erDiagram
    direction LR
    accTitle: Secure Share database relationships
    accDescr: Users own files and have sessions, action tokens, and email jobs. File permissions join recipients to files, with one grant per file and user pair.
    users ||--o{ files : owns
    users ||--o{ file_permissions : receives
    files ||--o{ file_permissions : permits
    users ||--o{ auth_sessions : authenticates
    users ||--o{ account_action_tokens : verifies_or_recovers
    users ||--o{ security_email_jobs : receives_email

    users {
        integer id PK
        string username UK
        string email UK
        string password_hash
        datetime email_verified_at
    }
    files {
        string id PK
        integer owner_id FK
        string stored_filename UK
        string original_filename
        bigint file_size
    }
    file_permissions {
        integer id PK
        string file_id FK
        integer user_id FK
    }
    auth_sessions {
        integer id PK
        integer user_id FK
        string token_hash UK
        string csrf_token_hash
        datetime expires_at
    }
    account_action_tokens {
        string id PK
        integer user_id FK
        string purpose
        string token_hash UK
        datetime expires_at
    }
    security_email_jobs {
        string id PK
        integer user_id FK
        string kind
        integer attempts
        datetime lease_expires_at
    }
```

`PK` = primary key, `FK` = foreign key, `UK` = unique key; each relationship is
one-to-zero-or-many. `file_permissions` additionally has a composite unique
constraint on `(file_id, user_id)`. Foreign keys cascade permission deletion
when its file or user is removed. The schema uses database-neutral SQLAlchemy
types and constraints for SQLite and PostgreSQL.

The diagrams are editable Mermaid source and render in GitHub Markdown. See
[GitHub's diagram documentation](https://docs.github.com/en/get-started/writing-on-github/working-with-advanced-formatting/creating-diagrams)
if your local Markdown viewer shows code instead of a graph.

## Technology stack

| Layer | Technology |
| --- | --- |
| Runtime and HTTP | Python 3.12+, Flask 3.x, Werkzeug |
| Persistence | SQLAlchemy 2.x, Flask-SQLAlchemy, SQLite locally, PostgreSQL via psycopg in production |
| Schema lifecycle | Flask-Migrate and Alembic |
| Browser client | Flask/Jinja templates, CSS, modular vanilla JavaScript |
| Authentication | Werkzeug scrypt, opaque server-side sessions, CSRF tokens |
| Abuse prevention | Flask-Limiter 4.x and shared Redis in production |
| Security email | SQL-backed outbox, supervised Flask CLI worker, encrypted SMTP |
| Configuration | Environment variables and python-dotenv |
| Quality checks | pytest, Ruff, Bandit, pip-audit, detect-secrets, GitHub Actions |

## Local setup

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

Create local configuration from the safe example. If `.env` already exists,
keep it and merge any missing settings instead of overwriting it.

```bash
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Run the generator separately for `SECRET_KEY`, `ACCOUNT_TOKEN_PEPPER`, and
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

## Vercel deployment status

### Configured: entrypoint and reproducible dependencies

Vercel does not discover `run.py` in its default Flask entrypoint locations.
The repository explicitly selects the existing WSGI application in
`pyproject.toml`, following [Vercel's Flask deployment guide](https://vercel.com/kb/guide/ship-a-flask-app-on-vercel):

```toml
[tool.vercel]
entrypoint = "run:app"
```

Vercel uses `pyproject.toml` as the dependency manifest when it is present, so
it must also contain a complete `[project]` table, not just `[tool.*]` settings.
The project declares all runtime dependencies there and checks that they match
the constraints in `requirements.txt`. `.python-version` selects Python 3.12
for deployment, while `requires-python` retains support for Python 3.12+.
The committed `uv.lock` makes Vercel's dependency installation reproducible.
The app is not installed as a distribution (`tool.uv.package = false`);
Vercel bundles the application source directly.

After changing runtime dependencies, update both manifests and regenerate
the lockfile with `uv lock`. To check the same dependency path Vercel uses,
run these commands in a clean checkout (the sync command replaces `.venv`
contents with production dependencies only):

```bash
python -m pip install uv==0.10.11
uv lock --check
uv sync --frozen --no-dev --no-editable
uv pip check
```

CI runs these checks with Vercel's `uv` version (0.10.11) and imports `run:app`
in that clean environment, separately from the pip-based test environments.

The `run:app` entrypoint imports the `app` object from `run.py`; it does not
start Flask's development server. In the Vercel project settings, use the
repository root as the **Root Directory** and the **Flask** framework preset.
Leave the build command and output directory at their framework defaults;
do not use `python run.py` or `flask run` as a build command. Push the updated
files to the connected deployment branch and deploy that new commit, rather
than redeploying the old commit that lacks this setting.

### Not complete: production hosting compatibility

**These settings cover entrypoint discovery and dependency installation,
not full Vercel production compatibility.**
The current backend requires persistent private filesystem storage and a
separate email worker. Additional changes are needed before hosting real
accounts or files on Vercel:

- **Filesystem and database:** app startup creates `instance/` and creates or
  changes permissions on `UPLOAD_FOLDER`. These operations target the project
  directory by default and fail on Vercel's
  [read-only function filesystem](https://vercel.com/docs/functions/runtimes#file-system-support).
  Use external PostgreSQL, adapt startup to avoid writes to the application
  bundle, and implement durable private object storage for uploaded bytes.
  `/tmp` is temporary scratch space, not persistent upload or SQLite storage.
  Changing environment variables alone does not replace the file service.
- **Security and email:** configure the production variables documented below,
  including independent secrets, shared Redis, SMTP, an HTTPS
  `PUBLIC_BASE_URL`, and the production password blocklist. Run database
  migrations explicitly and run the existing email worker on a separate
  worker host with the same database and security configuration. Do not
  disable production validation to make a deployment start.
- **Static assets:** Vercel's Flask guide requires assets in `public/`.
  Publish the existing `app/static/` assets as `public/static/` to preserve
  the templates' `/static/...` URLs when adding full Vercel support.
- **Upload size:** Vercel limits function request bodies to
  [4.5 MB](https://vercel.com/docs/vercel-blob/server-upload), below this app's
  default 16 MiB limit. Adapt the upload flow or lower the request limit;
  private downloads must continue to enforce current database permissions.

To run the current storage design without that migration, use a WSGI host
with a persistent private volume and a separate supervised email worker.

## Database migrations

`flask --app run.py init-db` is the supported initialization and upgrade
command. It uses the checked-in Alembic revisions and is safe in three cases:

- an empty database is initialized at the latest revision;
- a migration-tracked database is upgraded to the latest revision; and
- the exact four-table schema from releases predating Alembic is validated,
  stamped at the baseline, and then upgraded without replacing its data. This
  also safely recovers an interrupted bootstrap that left an empty
  `alembic_version` table.

An unversioned database with missing, additional, or changed schema objects is
rejected without being stamped. Back up every production database before an
upgrade, investigate the mismatch, and never use `flask db stamp` merely to
bypass validation. SQLite batch migrations preserve dependent rows, restore
foreign-key enforcement, and fail if a foreign-key integrity check finds a
violation. Operators can inspect state with:

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

## Browser walkthrough

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

## Configuration and production operations

### Environment reference

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

### Production configuration skeleton

Replace every placeholder, supply your SMTP credentials as required, and ensure
the directories and password corpus exist before starting the application:

```dotenv
APP_ENV=production
BROWSER_COOKIE_SECURE=1
SECRET_KEY=<random-value-one>
ACCOUNT_TOKEN_PEPPER=<random-value-two>
PUBLIC_BASE_URL=https://share.example.com
DATABASE_URL=postgresql+psycopg://secure_share:password@db.example/secure_share
UPLOAD_FOLDER=/var/lib/secure-share/uploads
RATELIMIT_STORAGE_URI=rediss://redis.example:6379/0
RATE_LIMIT_KEY_SECRET=<random-value-three>
MAIL_BACKEND=smtp
MAIL_FROM_ADDRESS=no-reply@share.example.com
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SECURITY_EMAIL_INLINE_DELIVERY=0
SMTP_USE_STARTTLS=1
SMTP_USE_SSL=0
FLASK_DEBUG=0
PASSWORD_BLOCKLIST_PATH=/etc/secure-share/compromised-passwords.sha256
```

Use a dedicated database role, a persistent private upload volume, and an
absolute `UPLOAD_FOLDER` path not served by the reverse proxy. Do not enable
debug mode in production. Run the WSGI application and this durable mail worker
as separate supervised processes against the same database:

```bash
flask --app run.py email-worker
```

### Durable security-email delivery

Production requests commit secret-free delivery jobs to SQL. A separate worker
claims eligible jobs and contacts the mail provider; SMTP latency is not part of
the account request's response path.

```mermaid
flowchart TB
    accTitle: Durable security-email delivery
    accDescr: Account requests commit jobs and return. A worker leases each job and attempts SMTP delivery, completing it on acceptance or retrying with backoff until attempts are exhausted.
    request["Registration or account-security action"] --> transaction["Commit account changes and email job"]
    transaction --> response["Return API response"]
    transaction -.-> queued[("Durable SQL outbox")]
    queued --> claim["Worker atomically leases a job"]
    claim --> prepare["Resolve account and prepare email"]
    prepare --> send["Send through encrypted SMTP"]
    send -->|"Provider accepts"| complete["Mark job complete"]
    send -->|"Provider failure"| retry{"Attempts remain?"}
    retry -->|"Yes: capped backoff"| queued
    retry -->|"No"| cancel["Cancel exhausted job"]
```

For verification/reset email, the worker creates a usable token in memory and
persists only its purpose-bound digest before sending. The job table stores no
message body, recipient snapshot, or usable token. The local file backend does
write complete `.eml` messages, including their links, to a private development
outbox; protect and do not commit that directory. Provider acceptance does not
guarantee inbox delivery.

`--once`, `--batch-size`, and `--poll-seconds` are available for operations and
testing. Do not run `--once` as the only production delivery process.

Production startup rejects an insecure browser cookie, a reused account-token
key, a non-HTTPS public URL, synchronous security-email delivery, plaintext
SMTP, an unsafe worker lease, a missing or undersized password blocklist, a
non-SMTP mail transport, or process-local rate-limit storage.
Redis failures reject requests rather than falling back to memory or silently
disabling enforcement.

## Authentication and account recovery

### Password policy

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

### API and browser sessions

| Property | API client | Browser client |
| --- | --- | --- |
| Login route | `POST /api/auth/login` | `POST /api/auth/browser-login` |
| Credential transport | `Authorization: Bearer ...` | HttpOnly, SameSite=Lax session cookie |
| Credential visible to JavaScript | Returned to the API caller; not used by the web UI | No |
| Unsafe authenticated requests | Bearer header | Session cookie plus `X-CSRF-Token` |
| Server-side storage | Session-token SHA-256 digest | Session-token and CSRF-token SHA-256 digests |
| Logout | Deletes the current session | Deletes the current session and expires both cookies |

An explicit `Authorization` header takes precedence and never falls back to a
cookie. Bearer and browser sessions cannot be replayed across transports.

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

### Email verification and password recovery

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

## API reference

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

```mermaid
flowchart TD
    accTitle: Download authorization decision
    accDescr: A valid session and existing file are required. Only the owner or an explicitly granted user can receive validated private bytes; all other requests are denied.
    download["Download request"] --> session{"Valid session?"}
    session -->|"No"| unauthorized["401 Unauthorized"]
    session -->|"Yes"| exists{"File exists?"}
    exists -->|"No"| missing["404 Not Found"]
    exists -->|"Yes"| owner{"File owner?"}
    owner -->|"Yes"| openFile["Open and validate private file"]
    owner -->|"No"| grant{"Explicit grant?"}
    grant -->|"No"| forbidden["403 Forbidden"]
    grant -->|"Yes"| openFile
    openFile -->|"Regular file and expected size"| attachment["200 Attachment; no-store"]
    openFile -->|"Unavailable or invalid"| missing
```

This is the file-authorization path. Rate limits can independently reject a
request with `429`; operational failures are not shown. Permission is checked
before opening the private file, not inferred from the dashboard or a UUID.

| Operation | Owner | Explicit recipient | Unrelated user |
| --- | --- | --- | --- |
| See file in listing | Yes | Yes | Omitted |
| Read file metadata | Yes | Yes | `404` |
| Download existing file | Yes | Yes | `403` |
| List, grant, or revoke permissions | Yes | No | No |
| Delete file | Yes | No | No |

Creating a new permission requires the recipient's current email to be
verified. Once created, the explicit permission remains authoritative until the
owner revokes it; this preserves pre-migration grants without pretending that a
legacy email address was verified.

An unrelated user receives `403 Forbidden` from the download endpoint even if
they know the exact UUID. Private files are absent from their list, and the
metadata endpoint responds as not found to avoid exposing file existence. Only
the owner can inspect or mutate grants and delete the file.

## End-to-end sharing example

### Upload, grant, download, revoke

Alice and Bob have registered, verified their email addresses, and signed in.
Alice owns the file; Bob is the recipient. SQL stores the permission, while
private storage holds the bytes.

```mermaid
sequenceDiagram
    accTitle: Owner-controlled sharing and revocation
    accDescr: Alice uploads a file and grants Bob access. Bob downloads it, Alice removes his grant, and Bob's next download is denied after a fresh database check.
    autonumber
    actor alice as Alice (owner)
    participant api as Secure Share API
    participant database as SQL database
    actor bob as Bob (recipient)

    alice->>api: Upload report.pdf
    api->>database: Record file metadata and Alice as owner
    api-->>alice: File ID and safe metadata
    alice->>api: Grant access to Bob's Sharing ID
    api->>database: Check owner and verified recipient, then add grant
    api-->>alice: Grant created
    bob->>api: Download with Bob's session
    api->>database: Check current file permission
    database-->>api: Grant exists
    api-->>bob: Authorized file attachment
    alice->>api: Revoke Bob's access
    api->>database: Delete Bob's grant
    api-->>alice: Revocation confirmed
    bob->>api: Request another download
    api->>database: Check current file permission
    database-->>api: No grant exists
    api-->>bob: 403 Forbidden
```

### API requests

The following abbreviated requests illustrate the intended flow. Replace IDs
and tokens with values returned by the API. Example passwords are for disposable
local accounts only; use unique, strong passwords for real accounts. Verification
links are in `instance/mail-outbox` when using the default development backend.

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
   curl -X POST 'http://127.0.0.1:5000/api/files/<FILE_ID>/permissions' \
     -H 'Authorization: Bearer <ALICE_TOKEN>' \
     -H 'Content-Type: application/json' \
     -d '{"user_id":2}'
   ```

4. Bob logs in and downloads the file.

   ```bash
   curl -X POST http://127.0.0.1:5000/api/auth/login \
     -H 'Content-Type: application/json' \
     -d '{"identifier":"bob","password":"another-long-password"}'

   curl 'http://127.0.0.1:5000/api/files/<FILE_ID>/download' \
     -H 'Authorization: Bearer <BOB_TOKEN>' \
     --output report.pdf
   ```

5. Alice removes Bob's permission. Bob's next download receives `403`.

   ```bash
   curl -X DELETE 'http://127.0.0.1:5000/api/files/<FILE_ID>/permissions/2' \
     -H 'Authorization: Bearer <ALICE_TOKEN>'
   ```

Bob can repeat the download request with `-i` and without `--output` to inspect
the `403` response after revocation. Alice retains access as the owner.

## Security controls and boundaries

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
  digests under `ACCOUNT_TOKEN_PEPPER`. Usable tokens are never persisted in SQL,
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

## Testing and quality checks

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

The suite uses a fresh temporary SQLite database and upload directory. Its
coverage is organized around observable behavior and negative security cases:

| Test module | Principal checks |
| --- | --- |
| `tests/test_auth.py` | Registration uniqueness, password hashing, authentication, session expiry/revocation |
| `tests/test_password_policy.py` | Minimum length, compromised passwords, legacy-password compatibility |
| `tests/test_web.py` | Browser pages, cookie sessions, CSRF, transport isolation |
| `tests/test_account_recovery.py` | Verification, reset expiry/reuse, generic responses, session revocation, rollback |
| `tests/test_files.py` | Upload validation, traversal rejection, size limits, metadata, protected downloads, cleanup |
| `tests/test_permissions.py` | Owner-only grants, uniqueness, verified recipients, Alice/Bob/Charlie access lifecycle |
| `tests/test_rate_limits.py` | Retry headers, distributed-source limits, HMAC bucket isolation, finite cooldowns |
| `tests/test_email_outbox.py` | Durable jobs, leases, retry, cancellation, absence of persisted usable secrets |
| `tests/test_migrations.py` | Fresh install, legacy adoption, drift rejection, repeat upgrade, data preservation |
| `tests/test_deployment.py` | Dependency-manifest agreement and safe import of the WSGI entrypoint |

CI also validates `uv.lock`, installs production-only dependencies in a clean
environment, and smoke-tests `run:app`. SQLite tests and dependency checks do
not replace production integration testing against PostgreSQL, Redis, SMTP,
and persistent storage. No coverage percentage or live CI status is implied by
this table.

## Delivery status and future work

The completed foundation described in this README corresponds to the existing
Phase 0 / Priority 1 scope. The remaining items below are not available features.

| Workstream | Status | Scope |
| --- | --- | --- |
| Core private sharing | Implemented | Upload, explicit grants, protected download, revocation, owner deletion |
| Phase 0 / Priority 1 foundation | Implemented | Repository reconciliation, reviewed migrations, CI/security checks, browser CSRF, bearer compatibility, rate limits, password policy, verification/recovery, durable email outbox |
| Vercel deployment configuration | Partial | Entrypoint, manifests, Python selection, and lockfile checks exist; durable storage and the production hosting adaptations remain |
| Priority 2 account settings | Deferred | MFA/passkeys with safe enrollment, recent re-authentication, recovery, session management, and security notifications |
| Additional sharing modes | Deferred | Random public sharing identifiers and access-code shares |
| File assurance and history | Deferred | Quarantine/scanning, SHA-256 file integrity, application-managed encryption at rest, audit history, and digital signatures |
| Larger-scale operations | Additional work | Pagination, per-user storage/session quotas, reconciliation, and deployment-specific monitoring/backups |

An **access code** would gate a share; a **file-integrity fingerprint** would help
detect changed bytes; a **digital signature** would bind content to a signing
identity. These are different future capabilities. None is supplied by the
current file UUID, session token, or CSRF token.
