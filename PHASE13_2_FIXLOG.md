# AUTIBLOOM Phase 13.3 — Authentication, Email Verification & Password Reset

## Phase 13.2 retained
- Therapist self-registration at `POST /api/v1/auth/register`.
- Parent self-registration at `POST /api/v1/parent/auth/register`.
- bcrypt password hashing (cost 12).
- Duplicate-email handling and strong password validation.
- Secure HTTP-only session cookies after verified login.
- Therapist Sign Up UI and dedicated Parent Portal.

## Phase 13.3 added
- Email verification for therapist and parent accounts.
- Single-use verification tokens with 24-hour expiry.
- Resend verification flow with cooldown.
- Forgot-password flow for therapist and parent accounts.
- Single-use password-reset tokens with 1-hour expiry.
- Active-session revocation after password reset.
- Dedicated `/auth.html` UI for verification, resend verification, forgot password, and reset password.
- Resend REST API integration using server-side environment variables.
- `email_verified_at` migration for both account types.
- New `email_verification_tokens` and `password_reset_tokens` tables.
- New Phase 13.3 integrity test.

## Production email configuration
Set `APP_BASE_URL`, `RESEND_API_KEY`, and `EMAIL_FROM`. `EMAIL_FROM` must use a sender/domain configured with the email provider. No API key or populated `.env` file is included in this package.

## Compatibility
Existing accounts are marked verified by the migration using their existing creation timestamp, preventing an unexpected production lockout. New accounts must verify email before login.

## Parent privacy
A parent can register and verify an account, but reports remain unavailable until a therapist verifies the parent-to-child link.
