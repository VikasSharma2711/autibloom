# AUTIBLOOM Phase 13.3 — Final Production Deployment

## Runtime
- Node.js 20+ (22 recommended)
- PostgreSQL 14+
- HTTPS at the public edge

## IMPORTANT: deploy from ZIP root
The ZIP is intentionally deployable from its root. Your platform's start command should be:

```bash
npm start
```

Do **not** use `node server.js`; the server is under `backend/server.js`.

## Database
Run the cumulative SQL in this order if your database is new:

1. `database/schema.sql`
2. `database/phase6_auth.sql`
3. `database/phase7_schema.sql`
4. `database/phase8_reports.sql`
5. `database/phase9_parent_portal.sql`
6. `database/phase10_clinical_review.sql`
7. `database/phase12_admin_ops.sql`

If `schema.sql` already contains the cumulative definitions, use your migration process to apply only missing objects. Do not blindly re-run destructive migrations against a production database.

## Required environment variables
```text
NODE_ENV=production
DATABASE_URL=<managed PostgreSQL connection string>
PORT=<platform supplied port, if any>
HOST=0.0.0.0
ALLOWED_ORIGINS=https://your-production-domain.example
TRUST_PROXY=true
APP_BASE_URL=https://your-production-domain.example
RESEND_API_KEY=re_xxxxxxxxxxxxxxxxxxxxxxxxx
EMAIL_FROM=AUTIBLOOM <no-reply@your-verified-domain.example>
```

`DATABASE_URL` is mandatory in production.

## Health checks
The application intentionally supports all of these aliases:

- `GET /health`
- `GET /healthz`
- `GET /api/health`
- `GET /api/v1/health`

They return HTTP 200 without requiring a database query, so platform health checks can verify that the web process is alive.

## Routes / 404 handling
- Known frontend files are served from `app/`.
- Common browser routes (`/login`, `/therapist`, `/admin`, `/report-preview`) are mapped to their corresponding HTML files.
- Unknown browser HTML routes fall back to `app/index.html`.
- Unknown `/api/*` routes return a JSON HTTP 404 rather than an HTML page.

## 505 note
HTTP 505 (`HTTP Version Not Supported`) is normally emitted by the hosting proxy/load balancer before the request reaches Express. The application cannot generate a 505 fix for a proxy that rejects the HTTP request. If the platform still reports 505 after deploying this package, check the platform's proxy/runtime settings, custom domain/TLS configuration, and whether it is forwarding HTTP/1.1 correctly to the Node service.

## Recommended platform settings
- Public HTTP port: use the platform-provided `PORT`.
- Internal process: `npm start`.
- Health check: `/health`.
- Health check method: GET.
- Do not configure a separate static-file server in front of this Node app unless it preserves `/api/*` routing.
- If the platform terminates TLS, set `TRUST_PROXY=true`.

## Tests
```bash
npm test
```

The package's Phase 5–11 integrity suite plus Phase 13.2/13.3 authentication integrity tests must pass before release.

## Security
No production secrets, user data, private keys, or populated `.env` files are included.


## Phase 13.2–13.3 authentication setup

This release includes therapist and parent self-registration, email verification, password reset, and secure session handling. Before first production use, apply `database/phase13_2_auth_signup.sql` and `database/phase13_3_email_auth.sql` (or use the cumulative `database/schema.sql` on a new database).

### Email provider
AUTIBLOOM uses the Resend REST API for transactional email. The official Resend API supports sending mail from a Node/Express application through `https://api.resend.com/emails`. urlResend email API documentationturn0search6

Configure these production variables:
- `APP_BASE_URL` — the public HTTPS URL of AUTIBLOOM, with no trailing slash.
- `RESEND_API_KEY` — your Resend API key, stored only as a server environment variable.
- `EMAIL_FROM` — a sender identity on a domain verified with Resend.

### Authentication behavior
- New therapist accounts remain signed out until the email address is verified.
- New parent accounts remain signed out until the email address is verified.
- Verification links expire after 24 hours and are single-use.
- Password-reset links expire after 1 hour and are single-use.
- Resetting a password revokes active sessions for that account.
- Verification/reset requests have a short resend cooldown to reduce email abuse.
- Existing accounts created before Phase 13.3 are marked verified by the migration so the new requirement does not unexpectedly lock out existing users.

### User-facing routes
- Therapist sign in: `/`
- Therapist sign up: `/` → **Create therapist account**
- Therapist forgot password: `/auth.html?mode=forgot&account=therapist`
- Therapist resend verification: `/auth.html?mode=resend&account=therapist`
- Parent portal: `/parent.html`
- Parent forgot password: `/auth.html?mode=forgot&account=parent`
- Parent resend verification: `/auth.html?mode=resend&account=parent`
- Verification/reset links are handled by `/auth.html` automatically.

If Resend is not configured, production registration intentionally returns an email-service configuration error instead of creating an account that cannot be verified.

## Phase 13.5 MFA configuration

ADMIN and THERAPIST accounts are required to enroll in TOTP MFA before receiving an authenticated application session.

Before starting the application in production, generate a persistent 32-byte encryption key:

```bash
openssl rand -hex 32
```

Add the resulting value to the server environment:

```text
MFA_ENCRYPTION_KEY=<64 hex characters>
```

Do not commit this value to GitHub and do not change it after MFA secrets have been enrolled unless you first perform a controlled key migration.

### First therapist/admin login

1. Enter the normal email and password.
2. AUTIBLOOM redirects to the MFA setup page.
3. Install an authenticator app (Google Authenticator, Microsoft Authenticator, or another TOTP-compatible app).
4. Add AUTIBLOOM manually using the displayed secret.
5. Enter the 6-digit code.
6. AUTIBLOOM enables MFA and displays ten recovery codes once.
7. Save the recovery codes securely.
8. Continue to the application.

### Later logins

Email + password is followed by the 6-digit authenticator code. A single unused recovery code can be entered instead if the authenticator device is unavailable.

Parent accounts are not forced to use MFA in Phase 13.5.
