# AUTIBLOOM Phase 6
Production identity foundation:
- PostgreSQL session store with hashed random session tokens
- HttpOnly/SameSite session cookie
- therapist login/logout/me
- password change with bcrypt hashing and session revocation
- authenticated child and assessment endpoints
- therapist ownership enforcement
- audit events
- parent account and parent-child-link schema prepared

Before real clinical launch: add MFA, password reset/email verification, parent login/report authorization, formal role administration, HTTPS/secrets/backups, staging integration and penetration testing. The preview/localStorage flow is not for identifiable clinical data.
