# AUTIBLOOM Phase 4 — Product layer

## Included
- Role-aware therapist/parent product flow
- Child profile management
- 121-item assessment
- Draft persistence in demo mode
- Completion and scoring
- Therapist report view
- Parent-friendly summary view
- Assessment history
- Progress comparison by domain
- Print/save-PDF browser workflow
- Backend parent-report route with ownership guard
- Clinical boundary language

## Production boundary
The browser app is a product prototype. In production, replace localStorage/demo login with the secure API and server-side persistence. Parent access must use verified parent-child relationships and must never rely on a client-side role selector.

## Clinical content boundary
The package carries forward the authoritative AUTIBLOOM V1 matrix. No unsupported clinical claims are added to the scoring source.
