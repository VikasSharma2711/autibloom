# AUTIBLOOM Phase 9 — Parent Portal

Phase 9 adds a parent-facing secure report portal on top of the Phase 8 production package.

## Included
- Parent session login/logout/me endpoints.
- HttpOnly parent session cookie with hashed server-side token.
- Parent-only access to reports marked `Released`.
- Verified `parent_child_links` gate before any report is exposed.
- Parent report view with access audit logging.
- Therapist-issued, short-lived, hashed report delivery tokens.
- Parent-friendly summary, recommendations and home-program display.
- Non-diagnostic disclaimer in the parent view.
- Database tables for parent sessions, delivery tokens and download/audit tracking.

## Production prerequisites
HTTPS, production secrets, authentication rate limiting, password reset/email verification, security testing, privacy/legal review, backup/restore and clinical pilot validation remain required before live deployment.
