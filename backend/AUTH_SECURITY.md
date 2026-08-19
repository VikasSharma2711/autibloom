# AUTIBLOOM — Phase 5 production security contract

1. Passwords: Argon2id preferred; bcrypt with a strong cost is acceptable fallback.
2. Sessions: Secure + HttpOnly + SameSite cookies; never store passwords/tokens in localStorage.
3. MFA: required for therapist/admin accounts before production.
4. Authorization: every child, assessment and report query must enforce ownership.
5. Parent access: only through a verified parent-child relationship; never trust a browser role flag.
6. HTTPS only in production.
7. Secrets only via environment variables/secret manager.
8. Encrypt backups and restrict database access.
9. Audit child-record access, assessment completion and report/export activity.
10. Define retention/deletion procedures before collecting real child data.
11. Add CSRF protection when cookie authentication is used.
12. The Phase 4 localStorage/demo flow is preview-only and must not be used for real clinical records.
