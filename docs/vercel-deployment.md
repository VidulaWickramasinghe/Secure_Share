# Configure Secure Share on Vercel

## Why the setup page appears

The setup page is a real HTTP 503: the application is not ready to accept users.
It replaces a configuration-driven function crash, not the application itself.
Check the runtime logs for the consolidated list of missing/invalid settings.
Only setting names and fixed messages are logged; secret values stay private.

The repository now supports private Vercel Blob uploads and a bounded,
authenticated email-worker endpoint. It no longer rejects Vercel unconditionally.
With valid settings it starts the real application without writing directories
inside the function bundle. Do not switch to development mode or `/tmp` storage
to make the setup page disappear.

## 1. Connect services and set environment variables

Use **Project → Settings → Environment Variables**. Scope values to Production
and, if needed, a separate Preview environment. Do not share production databases
or private Blob stores with untrusted preview branches.

| Setting | Required value |
| --- | --- |
| `APP_ENV` | `production` (also the default on Vercel). |
| `SECRET_KEY` | An independently generated random secret of at least 32 characters, stable across redeployments. |
| `ACCOUNT_TOKEN_PEPPER` | A second independent secret of at least 32 characters. |
| `RATE_LIMIT_KEY_SECRET` | A third independent secret of at least 32 characters. |
| `CRON_SECRET` | A fourth independent secret of at least 32 characters for the scheduler endpoint. |
| `DATABASE_URL` | An external PostgreSQL URL. `postgres://` and `postgresql://` prefixes are normalized to the installed psycopg driver. |
| `RATELIMIT_STORAGE_URI` | A supported Redis connection URI (`rediss://` where supported), not an HTTP/REST endpoint. |
| `PUBLIC_BASE_URL` | `https://secure-share-tau-lilac.vercel.app` for this production site. Preview needs its own trusted canonical HTTPS origin. |
| `FILE_STORAGE_BACKEND` | `vercel_blob` (the Vercel default). |
| `BLOB_READ_WRITE_TOKEN` | Connect a **private** Vercel Blob store to this project. Vercel supplies this credential. A public store is not suitable for private files. |
| `MAIL_BACKEND` | `smtp` (the production default). |
| `SMTP_HOST`, `SMTP_PORT` | Your email provider's SMTP host and TLS port; default port 587. |
| `SMTP_USERNAME`, `SMTP_PASSWORD` | Your provider's SMTP credentials, if required. |
| `MAIL_FROM_ADDRESS` | A sender address verified by your provider. |
| `SMTP_USE_SSL`, `SMTP_USE_STARTTLS` | Exactly one true. Defaults: SSL false, STARTTLS true. |
| `BROWSER_COOKIE_SECURE` | `true` (production default). |
| `SECURITY_EMAIL_INLINE_DELIVERY` | `false` (production default). |

Optional numeric/boolean values may be omitted or left blank for safe defaults.
Do not paste the development `.env.example` wholesale into Vercel: its explicit
filesystem, HTTP, SQLite and development settings are not production settings.
Keep credentials in Vercel or a password manager, never in Git or chat.

`PUBLIC_BASE_URL` may be omitted when Vercel system variables are exposed: it
defaults to the production domain in Production and the deployment URL in Preview.
An explicitly configured value is still validated and takes precedence.

`PASSWORD_BLOCKLIST_PATH` can be omitted in production. The app bundles 10,000
unique common-password SHA-256 digests, with source pin/checksum and MIT
attribution in `app/data/password-blocklist-source.md`. It is a baseline, not a
complete breach corpus. You may override it with a larger maintained digest file.

## 2. Apply database migrations

From a trusted local environment with these service settings, install dependencies
and check static configuration before initializing the database:

```bash
uv sync --frozen --no-dev
VERCEL=1 uv run --no-sync python check_deployment.py
VERCEL=1 uv run --no-sync flask --app run:app init-db
```

The checker does not connect to services or certify that they work. `init-db`
applies migrations to the configured database; run it deliberately, not on every
cold start and not as an unauthenticated HTTP endpoint.

Migration `20260828_0005` adds each file's storage backend. Existing records remain
`filesystem`; no uploaded bytes are moved or deleted. New Vercel uploads use
`vercel_blob`. Existing local files require a separate, verified migration of
their bytes before they can be served on Vercel. Changing the default write
backend never silently reclassifies existing files.

## 3. Schedule security email processing

The existing database outbox retains jobs, leases, retries and token protection.
Invoke this endpoint using **GET or POST**:

```text
https://secure-share-tau-lilac.vercel.app/api/internal/email-worker
Authorization: Bearer <CRON_SECRET>
```

Supply the header through your scheduler's secret settings, not a URL query
parameter. The endpoint processes one job per invocation on Vercel and returns
only aggregate outcome counts. Repeated calls do not resend completed jobs; an
interrupted delivery becomes eligible again after its lease. Set the cadence and
concurrency to match the queue volume and monitor retries/backlog.

Vercel Cron can supply `Authorization: Bearer CRON_SECRET` automatically. For a
plan supporting frequent jobs, merge a `crons` entry into the existing
`vercel.json`, for example:

```json
"crons": [{ "path": "/api/internal/email-worker", "schedule": "* * * * *" }]
```

This is a configuration fragment, not a complete JSON file. Vercel Hobby cron
runs at most once per day, which is unsuitable for prompt verification/reset
email. Use a suitable external scheduler or the CLI worker instead; no scheduler
or paid plan is enabled automatically by this repository. A scheduler calling
the deployment hostname must use a host accepted by `PUBLIC_BASE_URL`/trusted
hosts. Check its HTTP result; do not treat 400/401/503 as successful processing.

The repository configures a 300-second function duration. On Vercel,
`SECURITY_EMAIL_HTTP_BATCH_SIZE=1` and `SMTP_TIMEOUT_SECONDS<=10` keep work bounded.
If you deploy on another host, the supervised CLI `email-worker` remains available.

## 4. Redeploy and verify

Environment changes apply to new deployments. Redeploy after configuration and
migrations, then check **runtime logs**, not just the build status.

- `/` should render the actual login page. A 503 setup page is not success.
- Register an account; verify the scheduler delivers the email and the link works.
- Sign in, upload a file, download the exact bytes, and verify another user cannot
  download it until authorized. Revoke access and verify it is denied again.
- Redeploy and confirm the file survives. Delete it and verify the object and
  metadata are gone. Private Blob URLs and credentials must never reach clients.
- Test password reset and retry behavior. Keep monitoring queue outcomes.

Vercel limits request/response bodies to 4.5 MB. This backend defaults to a 4 MiB
request limit and a file limit 64 KiB smaller to allow multipart framing. Omit the
local 16 MiB `MAX_CONTENT_LENGTH` setting. Larger files need a separately designed
authenticated direct-upload/download flow; they are not silently accepted here.

References: [private Blob storage](https://vercel.com/docs/vercel-blob),
[Python SDK](https://github.com/vercel/vercel-py/tree/main/src/vercel/blob),
[cron security](https://vercel.com/docs/cron-jobs/manage-cron-jobs),
[cron plan limits](https://vercel.com/docs/cron-jobs/usage-and-pricing),
[function limits](https://vercel.com/docs/functions/limitations).
