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
├── models/       SQLAlchemy users, sessions, files, and permissions
├── routes/       HTTP parsing and REST response handling
├── services/     Authentication, file, and permission business rules
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
User ──< FilePermission >── FileRecord
```

`FilePermission` has a unique constraint on `(file_id, user_id)`, preventing
duplicate grants. Foreign keys cascade permission deletion when a file or user
is removed. The schema uses database-neutral SQLAlchemy types and constraints
that work with both SQLite and PostgreSQL.

## Technologies

- Python 3.12+
- Flask and Flask-SQLAlchemy
- SQLAlchemy 2.x ORM
- SQLite locally; PostgreSQL via psycopg in production
- Werkzeug scrypt password hashing
- Cryptographically random, database-backed bearer sessions
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

Create local configuration from the safe example and replace its development
secret:

```bash
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Paste the generated value into `SECRET_KEY`. The `.env` file and local database
files are ignored by Git; never commit them.

Initialize the database and start the development server:

```bash
flask --app run.py init-db
flask --app run.py run
```

The API is then available at `http://127.0.0.1:5000`. `python run.py` also
starts the development server after the database has been initialized. Flask's
built-in server is for development only; production should use a hardened WSGI
deployment behind HTTPS.

## Environment configuration

| Variable | Purpose | Local default/example |
| --- | --- | --- |
| `SECRET_KEY` | Stable, high-entropy application secret | Random value required in production |
| `DATABASE_URL` | SQLAlchemy database URL | `sqlite:///secure_share.db` in `.env.example` |
| `UPLOAD_FOLDER` | Private directory for uploaded bytes | `storage` |
| `MAX_CONTENT_LENGTH` | Maximum HTTP request size in bytes | `16777216` (16 MiB) |
| `SESSION_LIFETIME_SECONDS` | Bearer-session lifetime | `86400` (24 hours) |
| `FLASK_DEBUG` | Flask development debugging | `0` |

A production PostgreSQL URL looks like:

```dotenv
DATABASE_URL=postgresql+psycopg://secure_share:password@db.example/secure_share
```

Use a dedicated database role, a persistent private upload volume, and an
absolute `UPLOAD_FOLDER` path not served by the reverse proxy. Do not enable
debug mode in production.

## Authentication

Registration stores only a Werkzeug-generated password hash. Login returns a
random opaque token:

```json
{
  "token": "<opaque-session-token>",
  "token_type": "Bearer",
  "expires_at": "2026-08-26T00:00:00+00:00",
  "user": {
    "id": 1,
    "username": "alice",
    "email": "alice@example.com",
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

## API

All endpoints return JSON except a successful download, which returns the file
as an attachment. Expected failures have a consistent `{"error": "..."}`
shape and use `400`, `401`, `403`, `404`, `409`, or `413` as appropriate.
Unexpected production failures return a generic `500` response without a stack
trace.

### Account endpoints

| Method | Endpoint | Authentication | Description |
| --- | --- | --- | --- |
| `POST` | `/api/auth/register` | No | Register with `username`, `email`, and `password` |
| `POST` | `/api/auth/login` | No | Log in with `identifier` (username or email) and `password` |
| `POST` | `/api/auth/logout` | Bearer | Revoke the current session |
| `GET` | `/api/auth/me` | Bearer | Return the current account |
| `PATCH` or `PUT` | `/api/auth/password` | Bearer | Change with `current_password` and `new_password` |

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

An unrelated user receives `403 Forbidden` from the download endpoint even if
they know the exact UUID. Private files are absent from their list, and the
metadata endpoint responds as not found to avoid exposing file existence. Only
the owner can inspect or mutate grants and delete the file.

## Example workflow

The following abbreviated requests illustrate the intended flow. Replace IDs
and tokens with values returned by the API.

1. Alice and Bob register.

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
  returned by the API.
- Bearer values are generated from cryptographically secure randomness; only a
  hash is persisted. Authentication rejects malformed, unknown, and expired
  tokens.
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

Production operators should additionally enforce TLS, reverse-proxy request
and authentication rate limits, per-user storage/session quotas, secure
logging, backups, malware/content scanning appropriate to their threat model,
monitoring, and regular dependency updates. Large installations should also
paginate list endpoints and run periodic storage/database reconciliation.

## Tests

Run the full suite from the repository root:

```bash
pytest
```

The tests use a fresh temporary SQLite database and upload directory. They
cover registration uniqueness, password hashing, login and token revocation,
protected endpoints, upload validation and traversal rejection, maximum size,
metadata persistence, private listings, owner download/deletion, physical
cleanup, invalid IDs, permission uniqueness, and the complete Alice/Bob/Charlie
authorization lifecycle.
