# AUTIBLOOM Phase 13 — Final QA & Production Hardening

## Code-level checks
- 121-question clinical assessment matrix.
- Unique question IDs.
- Cumulative clinical/reporting/admin artifacts.
- ADMIN authorization gate.
- Role allow-list.
- Security response headers.
- Production security configuration.
- Final ZIP reopen/integrity verification.
- Obvious private-key material scan.

## Deployment gates
Before public production use, configure HTTPS/TLS, trusted authentication, PostgreSQL with least-privilege credentials, environment/secret management, deployment-boundary rate limiting, privacy/legal review, backups/monitoring and real browser/device acceptance testing.

Code-level QA passing does not by itself certify the deployment environment.

## Phase 13.4 Security Hardening

Phase 13.4 adds clinical-data security hardening before production use:

- Endpoint-specific rate limits for registration, login, verification, resend, password reset, and verification flows.
- Anti-enumeration behavior for therapist/parent registration and login. Existing-account responses are intentionally generic.
- Therapist password changes revoke all active sessions and require re-authentication.
- Parent authentication security events are recorded in `parent_security_audit`.
- Object-level authorization checks are preserved for therapist child/assessment/report access and parent verified-child/released-report access.
- Additional indexes support authorization queries.

Apply `database/schema.sql` for a new database, or apply `database/phase13_4_security_hardening.sql` to an existing Phase 13.3 installation.

**Production note:** Phase 13.4 improves authentication/authorization hardening but does not implement MFA. Admin/therapist MFA remains a recommended next security release before high-risk production deployment.
