import crypto from "node:crypto";
export const hashSessionToken=t=>crypto.createHash("sha256").update(t).digest("hex");
export const createSessionToken=()=>crypto.randomBytes(32).toString("base64url");
export const sessionExpiry=()=>new Date(Date.now()+7*24*60*60*1000);
export const normalizeEmail=e=>String(e||"").trim().toLowerCase();
export const isValidEmail=e=>/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
export const isStrongPassword=p=>typeof p==='string'&&p.length>=12&&/[A-Z]/.test(p)&&/[a-z]/.test(p)&&/\d/.test(p)&&/[^A-Za-z0-9]/.test(p);
export const safeUser=u=>u&&({id:u.id,email:u.email,display_name:u.display_name,role:String(u.role||'THERAPIST').toUpperCase(),is_active:u.is_active});
