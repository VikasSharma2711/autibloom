# AUTIBLOOM Phase 13.5 — Mandatory MFA

Phase 13.5 adds mandatory multi-factor authentication for ADMIN and THERAPIST accounts.

## Included

- TOTP-based MFA using standard 6-digit, 30-second authenticator codes.
- No third-party MFA runtime dependency; TOTP is implemented with Node's built-in crypto APIs.
- MFA secrets are encrypted at rest with AES-256-GCM using `MFA_ENCRYPTION_KEY`.
- MFA setup is completed before a therapist/admin receives an authenticated session.
- Login creates a short-lived MFA challenge; no application session is created until the MFA code is verified.
- Ten single-use recovery codes are generated during enrollment and shown once.
- Recovery codes are stored as SHA-256 hashes.
- MFA setup/login verification endpoints have dedicated rate limits.
- Existing password-reset session revocation remains in place.
- Parent accounts remain password + email-verification accounts; MFA is not forced on parents in this release.

## Authenticator setup

The enrollment page provides the secret and TOTP parameters for manual setup in an authenticator application:

- Issuer: AUTIBLOOM
- Algorithm: SHA-1
- Digits: 6
- Period: 30 seconds

A QR code is intentionally not generated through a third-party service because the QR payload contains the MFA secret. The secret is displayed only during enrollment over the authenticated setup flow.

## Required production environment variable

Generate a random 32-byte key:

```bash
openssl rand -hex 32
```

Set the resulting 64-character hexadecimal value as:

```text
MFA_ENCRYPTION_KEY=<64 hex characters>
```

Keep this key secret and persistent. **Do not rotate it casually**: existing encrypted MFA secrets cannot be decrypted with a different key.

## Recovery-code policy

Recovery codes are displayed once immediately after MFA enrollment. They should be stored in a secure password manager or another secure offline location. AUTIBLOOM never emails the recovery codes.
