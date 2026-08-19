import crypto from "node:crypto";
export const hashParentSessionToken=t=>crypto.createHash("sha256").update(t).digest("hex");
export const createParentSessionToken=()=>crypto.randomBytes(32).toString("base64url");
export const parentSessionExpiry=()=>new Date(Date.now()+7*24*60*60*1000);
export const createDeliveryToken=()=>crypto.randomBytes(32).toString("base64url");
export const hashDeliveryToken=t=>crypto.createHash("sha256").update(t).digest("hex");
export const deliveryExpiry=()=>new Date(Date.now()+72*60*60*1000);
