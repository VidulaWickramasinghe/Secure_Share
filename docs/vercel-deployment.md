# Vercel deployment: startup and remaining requirements

## Current status

The Python dependency manifest and `run:app` entrypoint are configured. That
allows Vercel to build the project; it does **not** make the backend ready.
The observed production crash after those fixes was:

```text
RuntimeError: Production requires a stable high-entropy SECRET_KEY
```

`run.py` now catches known configuration failures and exports a minimal Flask
application that returns **HTTP 503**. All authentication, upload and download
operations remain unavailable. The public response contains no configuration
values, credentials or traceback. Vercel runtime logs contain a consolidated
checklist. Unexpected programming errors still fail visibly for diagnosis.

**A setup page is not a completed deployment.** This repository's filesystem
upload backend and persistent email worker still need a suitable host or a
serverless implementation. Setting `UPLOAD_FOLDER=/tmp`, using SQLite, disabling
production checks or generating a new secret on each cold start is not a fix.

## Check all startup settings

From the repository root, with your intended production settings in the shell
or a private `.env` file, run:

```bash
VERCEL=1 python check_deployment.py
```

The command exits with status 1 and lists problems together. It does not connect
to external services, migrate databases or write upload directories. It prints
setting names and fixed instructions, not values. Do not commit `.env` files or
paste secrets into issues, logs or chat.

Optional numeric and boolean settings may be omitted or left blank to use the
documented defaults. Nonblank malformed values are rejected. On Vercel,
`APP_ENV` must be `production` (an omitted or blank value defaults to production).

## Required production setup

| Setting or service | Requirement |
| --- | --- |
| `SECRET_KEY` | A stable, randomly generated secret of at least 32 characters. |
| `ACCOUNT_TOKEN_PEPPER` | A second independent, stable secret of at least 32 characters. |
| `RATE_LIMIT_KEY_SECRET` | A third independent, stable secret of at least 32 characters. |
| `DATABASE_URL` | An external PostgreSQL connection URL; apply the repository migrations before serving users. |
| `RATELIMIT_STORAGE_URI` | A supported Redis connection URI, shared across instances; an HTTP/REST endpoint is not interchangeable with this URI. |
| `PUBLIC_BASE_URL` | The canonical HTTPS origin, with no credentials, query or application path. |
| `MAIL_BACKEND`, `SMTP_HOST` | `smtp` and a real SMTP server; configure its port, credentials, sender and exactly one TLS mode. |
| `PASSWORD_BLOCKLIST_PATH` | A readable file containing at least 10,000 unique SHA-256 digests of known compromised passwords; do not use fabricated digests. |
| `BROWSER_COOKIE_SECURE` | `true`. |
| `SECURITY_EMAIL_INLINE_DELIVERY` | `false`; run the separate email worker with the same database and secrets. |
| File storage | The current implementation requires a private persistent filesystem. Vercel requires implementing a private object-storage backend before enabling file operations. |

Use your password manager to generate and store the three independent secrets.
Do not rotate existing production keys merely to make a deployment pass; rotation
can invalidate outstanding account links and change rate-limit identifiers.
Changing Vercel environment variables affects **new deployments**, so redeploy
after correcting settings. Check both Preview and Production scopes.

### Hosting choices

To run the current implementation without redesigning file storage, host the
Flask backend on a server/container with a private persistent volume and run
`flask --app run:app email-worker` as a separate supervised process. Configure
HTTPS, PostgreSQL, Redis, SMTP and the blocklist there. Run the configuration
checker without `VERCEL=1`; a successful static check still does not verify
service connectivity or database migrations.

To keep the backend on Vercel, first implement private durable object storage
and deploy the mail worker separately (or implement a secure durable-job
integration). Update the Vercel-specific validation only after those integrations
exist and have end-to-end tests. The current validation deliberately rejects
Vercel's filesystem storage instead of accepting uploads that can disappear.

## Verify a new deployment

1. Inspect **runtime logs**, not only build logs. Configuration messages are
   consolidated under `Deployment configuration is incomplete`.
2. Request `/` and an API endpoint. While setup is incomplete, both must return
   **503**; `/healthz` also returns 503. No API may accept uploads or credentials.
   The setup response is not a readiness success.
3. After the hosting/storage work and configuration are complete, apply database
   migrations once using `flask --app run:app init-db` in a controlled environment.
4. Verify registration, verification email delivery, sign-in, authenticated
   upload/download, access denial for another user, password reset and worker
   retries. Confirm uploaded bytes survive deployment/instance replacement.

Reference: [Flask on Vercel](https://vercel.com/docs/frameworks/backend/flask)
and [Vercel Functions limits](https://vercel.com/docs/functions/limitations).
