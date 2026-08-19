// AUTIBLOOM Phase 13 — production security baseline.
export const SECURITY = Object.freeze({
  allowedRoles: Object.freeze(["ADMIN","THERAPIST","PARENT"]),
  sessionCookie: Object.freeze({httpOnly:true,secure:true,sameSite:"lax"}),
  rateLimit: Object.freeze({windowMs:15*60*1000,maxRequests:120}),
  csrf: Object.freeze({enabled:true,mode:"same-origin-or-allowlisted-origin",header:"origin"})
});
export const isAllowedRole=role=>SECURITY.allowedRoles.includes(role);
