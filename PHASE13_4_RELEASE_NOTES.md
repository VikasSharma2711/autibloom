# AUTIBLOOM Phase 13.4 — Clinical Data Security Hardening

This release hardens the Phase 13.3 authentication and authorization layer for AUTIBLOOM, a sensory evaluation platform for children with special needs.

## Included

- Endpoint-specific authentication rate limiting.
- Anti-account-enumeration behavior for registration and login.
- Session revocation after therapist password changes.
- Parent authentication security audit trail.
- Additional object-level authorization integrity checks.
- Database indexes for therapist/parent authorization paths.
- Token cleanup indexes for email verification and password reset records.
- Updated integrity tests for the hardening changes.

## Existing functionality preserved

- Therapist signup/login/email verification/password reset.
- Parent signup/login/email verification/password reset.
- Child management.
- Sensory assessment workflow.
- Assessment scoring.
- Clinical report generation.
- Therapist report review/release.
- Parent report portal.
- Existing Phase 5–13.3 integrity suite.

## Database

For a **new database**, use `database/schema.sql`.

For an **existing Phase 13.3 database**, apply:

```text
 database/phase13_4_security_hardening.sql
```

Do not apply historical migrations randomly to a production database. Back up the database first and apply the migration appropriate to the installed version.

## Production security status

Phase 13.4 is significantly hardened, but MFA is not included in this release. Do not represent the application as fully security-certified or regulatory-compliant solely because these integrity tests pass.
