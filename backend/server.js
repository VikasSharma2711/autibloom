import express from "express";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";
import bcrypt from "bcryptjs";
import { hashSessionToken, createSessionToken, sessionExpiry, normalizeEmail, isValidEmail, isStrongPassword, safeUser } from "./auth.js";
import { scoreResponses, validateResponses } from "./clinicalScoring.js";

import { buildClinicalDraft, REPORT_VERSION } from "./../clinical/report_engine.js";
import { buildProfessionalReportModel, renderProfessionalReportHtml } from "./report_engine_v11.js";
import { hashParentSessionToken, createParentSessionToken, parentSessionExpiry, createDeliveryToken, hashDeliveryToken, deliveryExpiry } from "./parent_auth.js";
import { createOpaqueToken, hashOpaqueToken, sendVerificationEmail, sendPasswordResetEmail, emailConfigured } from "./email.js";
const app = express();
app.disable("x-powered-by");
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const isProduction = process.env.NODE_ENV === "production";
if (isProduction && !process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL is required in production");
}
app.set("trust proxy", process.env.TRUST_PROXY === "true" ? 1 : false);
app.use(express.json({limit:"1mb"}));
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  max: Number(process.env.DB_POOL_MAX || 10),
  connectionTimeoutMillis: Number(process.env.DB_CONNECTION_TIMEOUT_MS || 10000),
  idleTimeoutMillis: Number(process.env.DB_IDLE_TIMEOUT_MS || 30000),
  query_timeout: Number(process.env.DB_QUERY_TIMEOUT_MS || 30000),
  statement_timeout: Number(process.env.DB_STATEMENT_TIMEOUT_MS || 30000)
});
pool.on("error", err => console.error("AUTIBLOOM PostgreSQL pool error", err));

const AUTIBLOOM_ALLOWED_ROLES = new Set(["ADMIN","THERAPIST","PARENT"]);
function securityHeaders(req,res,next){
  res.setHeader("X-Content-Type-Options","nosniff");
  res.setHeader("X-Frame-Options","DENY");
  res.setHeader("Referrer-Policy","strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy","camera=(), microphone=(), geolocation=()");
  res.setHeader("Cache-Control","no-store");
  if (isProduction) res.setHeader("Strict-Transport-Security","max-age=31536000; includeSubDomains");
  next();
}
function sameOriginGuard(req,res,next){
  if (!["POST","PUT","PATCH","DELETE"].includes(req.method)) return next();
  const origin = req.get("origin");
  if (!origin) return next();
  const allowed = (process.env.ALLOWED_ORIGINS || "").split(",").map(x=>x.trim()).filter(Boolean);
  if (allowed.length && allowed.includes(origin)) return next();
  const expected = `${req.protocol}://${req.get("host")}`;
  if (origin !== expected) return res.status(403).json({error:"CSRF_ORIGIN_REJECTED"});
  next();
}
app.use(securityHeaders);
app.use(sameOriginGuard);
app.use(express.static(path.resolve(__dirname, "../app"), {index:"index.html", dotfiles:"deny"}));

const buckets=new Map();
const WINDOW=15*60*1000, MAX=120;
// Periodically evict stale rate-limit buckets to prevent unbounded memory growth.
setInterval(()=>{
  const cutoff=Math.floor(Date.now()/WINDOW)-1;
  for(const key of buckets.keys()){
    const ts=Number(key.split(":").pop());
    if(!isNaN(ts)&&ts<=cutoff)buckets.delete(key);
  }
},WINDOW).unref();
app.use((req,res,next)=>{
  const key=(req.ip||"unknown")+":"+Math.floor(Date.now()/WINDOW);
  const n=(buckets.get(key)||0)+1; buckets.set(key,n);
  if(n>MAX) return res.status(429).json({error:"RATE_LIMITED"});
  next();
});

const AUTH_LIMITS = {
  register: { windowMs: 60*60*1000, max: 5 },
  login: { windowMs: 15*60*1000, max: 10 },
  forgot: { windowMs: 60*60*1000, max: 5 },
  resend: { windowMs: 60*60*1000, max: 5 },
  reset: { windowMs: 60*60*1000, max: 10 },
  verify: { windowMs: 60*60*1000, max: 20 },
  mfa_setup: { windowMs: 15*60*1000, max: 10 },
  mfa_enable: { windowMs: 15*60*1000, max: 10 },
  mfa_verify: { windowMs: 15*60*1000, max: 10 }
};
const authBuckets = new Map();
setInterval(()=>{
  const now=Date.now();
  for(const [key,b] of authBuckets) if(now-b.startedAt > b.windowMs) authBuckets.delete(key);
}, 15*60*1000).unref();
function authActionFor(req){
  const path=req.path;
  if(path.endsWith('/register')) return 'register';
  if(path.endsWith('/login')) return 'login';
  if(path.endsWith('/forgot-password')) return 'forgot';
  if(path.endsWith('/resend-verification')) return 'resend';
  if(path.endsWith('/reset-password')) return 'reset';
  if(path.endsWith('/verify-email')) return 'verify';
  if(path.endsWith('/mfa/setup')) return 'mfa_setup';
  if(path.endsWith('/mfa/enable')) return 'mfa_enable';
  if(path.endsWith('/mfa/verify')) return 'mfa_verify';
  return null;
}
function authRateLimit(req,res,next){
  const action=authActionFor(req);
  if(!action) return next();
  const limit=AUTH_LIMITS[action];
  const email=normalizeEmail(req.body?.email || req.query?.email || '');
  const ip=req.ip||'unknown';
  const now=Date.now();
  const keys=[`${action}:ip:${ip}`, ...(email ? [`${action}:email:${crypto.createHash('sha256').update(email).digest('hex')}`] : [])];
  for(const key of keys){
    let b=authBuckets.get(key);
    if(!b || now-b.startedAt >= limit.windowMs) b={startedAt:now,count:0,windowMs:limit.windowMs};
    b.count++; authBuckets.set(key,b);
    if(b.count>limit.max) return res.status(429).json({error:'RATE_LIMITED',retry_after_seconds:Math.max(1,Math.ceil((b.startedAt+limit.windowMs-now)/1000))});
  }
  next();
}
app.use('/api/v1/auth', authRateLimit);
app.use('/api/v1/parent/auth', authRateLimit);

function cookie(req){
  const m=(req.headers.cookie||"").match(/(?:^|;\s*)autibloom_session=([^;]+)/);
  return m?decodeURIComponent(m[1]):null;
}
function setCookie(res,t,exp){
  const secure=process.env.NODE_ENV==="production"?" Secure;":"";
  res.setHeader("Set-Cookie",`autibloom_session=${t}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${Math.max(0,Math.floor((exp-Date.now())/1000))};${secure}`);
}
function clearCookie(res){res.setHeader("Set-Cookie","autibloom_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0;");}
async function currentUser(req){
  const t=cookie(req); if(!t) return null;
  const r=await pool.query(
    `SELECT t.id,t.email,t.name AS display_name,t.role,t.is_active,s.id session_id
     FROM user_sessions s JOIN therapists t ON t.id=s.therapist_id
     WHERE s.session_hash=$1 AND s.revoked_at IS NULL AND s.expires_at>now() AND t.is_active=true`,
    [hashSessionToken(t)]
  );
  if(!r.rowCount)return null;
  await pool.query("UPDATE user_sessions SET last_seen_at=now() WHERE id=$1",[r.rows[0].session_id]);
  return {...r.rows[0],role:String(r.rows[0].role||"THERAPIST").toUpperCase()};
}
async function auth(req,res,next){
  try{const u=await currentUser(req);if(!u)return res.status(401).json({error:"AUTHENTICATION_REQUIRED"});req.user=safeUser(u);req.sessionId=u.session_id;if(!AUTIBLOOM_ALLOWED_ROLES.has(req.user.role))return res.status(403).json({error:"INVALID_OR_MISSING_ROLE"});next();}
  catch(e){res.status(500).json({error:"AUTHENTICATION_ERROR"});}
}

const healthResponse = (req,res)=>res.status(200).json({ok:true,service:"autibloom-api",phase:13});
app.get(["/health","/healthz","/api/health","/api/v1/health"], healthResponse);

const EMAIL_NOT_VERIFIED = "EMAIL_NOT_VERIFIED"; // retained as an internal status label; login intentionally returns generic INVALID_CREDENTIALS.
const EMAIL_TOKEN_HOURS = 24;
const RESET_TOKEN_MINUTES = 60;
const verificationExpiry = () => new Date(Date.now() + EMAIL_TOKEN_HOURS * 60 * 60 * 1000);
const resetExpiry = () => new Date(Date.now() + RESET_TOKEN_MINUTES * 60 * 1000);

const MFA_CHALLENGE_MINUTES = 5;
const MFA_SETUP_MINUTES = 15;
const MFA_ISSUER = "AUTIBLOOM";
const MFA_DIGITS = 6;
const MFA_PERIOD = 30;
const MFA_ENCRYPTION_KEY = () => {
  const raw = String(process.env.MFA_ENCRYPTION_KEY || "").trim();
  if (!/^[0-9a-fA-F]{64}$/.test(raw)) throw new Error("MFA_ENCRYPTION_KEY_MISSING_OR_INVALID");
  return Buffer.from(raw, "hex");
};
function base32Encode(buf){
  const alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let bits=0,val=0,out="";
  for(const byte of buf){ val=(val<<8)|byte; bits+=8; while(bits>=5){ out+=alphabet[(val>>>(bits-5))&31]; bits-=5; } }
  if(bits>0) out+=alphabet[(val<<(5-bits))&31];
  return out;
}
function base32Decode(input){
  const alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let bits=0,val=0; const bytes=[];
  for(const c of String(input).replace(/=+$/,'').toUpperCase()){
    const n=alphabet.indexOf(c); if(n<0) throw new Error("INVALID_MFA_SECRET");
    val=(val<<5)|n; bits+=5; if(bits>=8){ bytes.push((val>>>(bits-8))&255); bits-=8; }
  }
  return Buffer.from(bytes);
}
function encryptMfaSecret(secret){
  const iv=crypto.randomBytes(12), cipher=crypto.createCipheriv("aes-256-gcm",MFA_ENCRYPTION_KEY(),iv);
  const enc=Buffer.concat([cipher.update(secret,"utf8"),cipher.final()]);
  return `${iv.toString("base64url")}.${cipher.getAuthTag().toString("base64url")}.${enc.toString("base64url")}`;
}
function decryptMfaSecret(payload){
  const [ivB,tagB,dataB]=String(payload||"").split(".");
  if(!ivB||!tagB||!dataB) throw new Error("INVALID_MFA_SECRET_STORAGE");
  const decipher=crypto.createDecipheriv("aes-256-gcm",MFA_ENCRYPTION_KEY(),Buffer.from(ivB,"base64url"));
  decipher.setAuthTag(Buffer.from(tagB,"base64url"));
  return Buffer.concat([decipher.update(Buffer.from(dataB,"base64url")),decipher.final()]).toString("utf8");
}
function hotp(secretBase32,counter){
  const key=base32Decode(secretBase32), msg=Buffer.alloc(8); msg.writeBigUInt64BE(BigInt(counter));
  const digest=crypto.createHmac("sha1",key).update(msg).digest(); const offset=digest[digest.length-1]&15;
  const code=((digest[offset]&127)<<24)|((digest[offset+1]&255)<<16)|((digest[offset+2]&255)<<8)|(digest[offset+3]&255);
  return String(code%1000000).padStart(6,"0");
}
function verifyTotp(secretBase32,code,window=1){
  const normalized=String(code||"").replace(/\s+/g,""); if(!/^\d{6}$/.test(normalized)) return false;
  const counter=Math.floor(Date.now()/1000/MFA_PERIOD);
  for(let i=-window;i<=window;i++) if(hotp(secretBase32,counter+i)===normalized) return true;
  return false;
}
function otpauthUri(secret,email){
  return `otpauth://totp/${encodeURIComponent(MFA_ISSUER+":"+email)}?secret=${encodeURIComponent(secret)}&issuer=${encodeURIComponent(MFA_ISSUER)}&algorithm=SHA1&digits=6&period=30`;
}
function createMfaSecret(){ return base32Encode(crypto.randomBytes(20)); }
function createRecoveryCodes(){ return Array.from({length:10},()=>crypto.randomBytes(5).toString("hex").toUpperCase().match(/.{1,5}/g).join("-")); }
function hashRecoveryCode(code){ return crypto.createHash("sha256").update(String(code).replace(/-/g,"").toUpperCase()).digest("hex"); }
async function createMfaChallenge({therapistId,type}){
  const token=createOpaqueToken(), exp=new Date(Date.now()+(type==="SETUP"?MFA_SETUP_MINUTES:MFA_CHALLENGE_MINUTES)*60*1000);
  await pool.query("INSERT INTO mfa_challenges(id,therapist_id,token_hash,type,expires_at) VALUES($1,$2,$3,$4,$5)",[crypto.randomUUID(),therapistId,hashOpaqueToken(token),type,exp]);
  return token;
}
async function revokeMfaChallenges(therapistId,type){ await pool.query("UPDATE mfa_challenges SET used_at=COALESCE(used_at,now()) WHERE therapist_id=$1 AND type=$2 AND used_at IS NULL",[therapistId,type]); }
async function issueTherapistSession(res,user){
  const t=createSessionToken(), exp=sessionExpiry();
  await pool.query("INSERT INTO user_sessions(id,therapist_id,session_hash,expires_at) VALUES($1,$2,$3,$4)",[crypto.randomUUID(),user.id,hashSessionToken(t),exp]);
  await pool.query("INSERT INTO audit_log(id,therapist_id,action,entity_type,entity_id) VALUES($1,$2,'LOGIN_SUCCESS','therapist',$2)",[crypto.randomUUID(),user.id]);
  setCookie(res,t,exp); return {user:safeUser(user)};
}

async function issueVerificationEmail({accountType, accountId, email, name}) {
  const recent = await pool.query("SELECT 1 FROM email_verification_tokens WHERE account_type=$1 AND account_id=$2 AND created_at>now()-interval '5 minutes' LIMIT 1", [accountType, accountId]);
  if (recent.rowCount) throw Object.assign(new Error("VERIFICATION_COOLDOWN"), {code:"VERIFICATION_COOLDOWN"});
  const token = createOpaqueToken();
  await pool.query("DELETE FROM email_verification_tokens WHERE account_type=$1 AND account_id=$2 AND used_at IS NULL", [accountType, accountId]);
  await pool.query("INSERT INTO email_verification_tokens(id,account_type,account_id,token_hash,expires_at) VALUES($1,$2,$3,$4,$5)", [crypto.randomUUID(), accountType, accountId, hashOpaqueToken(token), verificationExpiry()]);
  await sendVerificationEmail({to: email, name, token, account: accountType === "PARENT" ? "parent" : "therapist"});
}

async function issuePasswordResetEmail({accountType, accountId, email, name}) {
  const recent = await pool.query("SELECT 1 FROM password_reset_tokens WHERE account_type=$1 AND account_id=$2 AND created_at>now()-interval '5 minutes' LIMIT 1", [accountType, accountId]);
  if (recent.rowCount) throw Object.assign(new Error("RESET_COOLDOWN"), {code:"RESET_COOLDOWN"});
  const token = createOpaqueToken();
  await pool.query("DELETE FROM password_reset_tokens WHERE account_type=$1 AND account_id=$2 AND used_at IS NULL", [accountType, accountId]);
  await pool.query("INSERT INTO password_reset_tokens(id,account_type,account_id,token_hash,expires_at) VALUES($1,$2,$3,$4,$5)", [crypto.randomUUID(), accountType, accountId, hashOpaqueToken(token), resetExpiry()]);
  await sendPasswordResetEmail({to: email, name, token, account: accountType === "PARENT" ? "parent" : "therapist"});
}

if (isProduction && !emailConfigured()) {
  console.warn("AUTIBLOOM email authentication is not fully configured. Set APP_BASE_URL, RESEND_API_KEY and EMAIL_FROM before enabling production signup/password recovery.");
}

app.post("/api/v1/auth/register",async(req,res)=>{
  const name=String(req.body?.name||"").trim();
  const email=normalizeEmail(req.body?.email);
  const password=String(req.body?.password||"");
  if(name.length<2||name.length>120)return res.status(400).json({error:"INVALID_NAME"});
  if(!isValidEmail(email))return res.status(400).json({error:"INVALID_EMAIL"});
  if(!isStrongPassword(password))return res.status(400).json({error:"WEAK_PASSWORD"});
  if(!emailConfigured())return res.status(503).json({error:"EMAIL_SERVICE_NOT_CONFIGURED"});
  try{
    const existing=await pool.query("SELECT id,email,name AS display_name,is_active,email_verified_at FROM therapists WHERE lower(email)=lower($1)",[email]);
    if(existing.rowCount){
      const account=existing.rows[0];
      if(account.is_active && !account.email_verified_at){
        try { await issueVerificationEmail({accountType:"THERAPIST",accountId:account.id,email:account.email,name:account.display_name}); } catch(e) { console.error("THERAPIST_EXISTING_VERIFICATION_FAILED",e); }
      }
      return res.status(202).json({account_created:false,email_verification_required:true,message:"If the account is eligible, verification instructions will be sent to this email address."});
    }
    const hash=await bcrypt.hash(password,12);
    const id=crypto.randomUUID();
    const q=await pool.query(`INSERT INTO therapists(id,name,email,password_hash,role,is_active,email_verified_at) VALUES($1,$2,$3,$4,'THERAPIST',true,NULL) RETURNING id,email,name AS display_name,role,is_active,email_verified_at`,[id,name,email,hash]);
    try {
      await issueVerificationEmail({accountType:"THERAPIST",accountId:id,email,name});
    } catch (mailError) {
      await pool.query("DELETE FROM therapists WHERE id=$1", [id]);
      console.error("THERAPIST_VERIFICATION_EMAIL_FAILED", mailError);
      return res.status(503).json({error:"VERIFICATION_EMAIL_FAILED"});
    }
    await pool.query("INSERT INTO audit_log(id,therapist_id,action,entity_type,entity_id) VALUES($1,$2,'REGISTER_PENDING_EMAIL','therapist',$2)",[crypto.randomUUID(),id]);
    res.status(201).json({account_created:true,email_verification_required:true});
  }catch(e){
    if(e?.code==='23505')return res.status(202).json({account_created:false,email_verification_required:true,message:"If the account is eligible, verification instructions will be sent to this email address."});
    console.error("THERAPIST_REGISTER_FAILED",e);
    res.status(500).json({error:"REGISTRATION_FAILED"});
  }
});

app.post("/api/v1/auth/resend-verification",async(req,res)=>{
  const email=normalizeEmail(req.body?.email);
  if(!isValidEmail(email))return res.status(400).json({error:"INVALID_EMAIL"});
  try{
    const q=await pool.query("SELECT id,email,name AS display_name,email_verified_at,is_active FROM therapists WHERE lower(email)=lower($1)",[email]);
    if(q.rowCount && q.rows[0].is_active && !q.rows[0].email_verified_at && emailConfigured()) {
      try { await issueVerificationEmail({accountType:"THERAPIST",accountId:q.rows[0].id,email:q.rows[0].email,name:q.rows[0].display_name}); } catch(e) { console.error("THERAPIST_RESEND_VERIFICATION_FAILED",e); }
    }
    res.json({sent:true});
  }catch(e){res.status(500).json({error:"VERIFICATION_RESEND_FAILED"});}
});

app.get("/api/v1/auth/verify-email",async(req,res)=>{
  const token=String(req.query?.token||"");
  if(!token)return res.status(400).json({error:"INVALID_VERIFICATION_TOKEN"});
  const client=await pool.connect();
  try{
    await client.query("BEGIN");
    const q=await client.query("SELECT id,account_id FROM email_verification_tokens WHERE account_type='THERAPIST' AND token_hash=$1 AND used_at IS NULL AND expires_at>now() FOR UPDATE",[hashOpaqueToken(token)]);
    if(!q.rowCount){await client.query("ROLLBACK");return res.status(400).json({error:"INVALID_OR_EXPIRED_VERIFICATION_TOKEN"});}
    const accountId=q.rows[0].account_id;
    const user=await client.query("UPDATE therapists SET email_verified_at=COALESCE(email_verified_at,now()) WHERE id=$1 AND is_active=true RETURNING id,email,name AS display_name,role,is_active",[accountId]);
    if(!user.rowCount){await client.query("ROLLBACK");return res.status(400).json({error:"ACCOUNT_UNAVAILABLE"});}
    await client.query("UPDATE email_verification_tokens SET used_at=now() WHERE id=$1",[q.rows[0].id]);
    await client.query("INSERT INTO audit_log(id,therapist_id,action,entity_type,entity_id) VALUES($1,$2,'EMAIL_VERIFIED','therapist',$2)",[crypto.randomUUID(),accountId]);
    await client.query("COMMIT");
    res.json({verified:true,user:safeUser(user.rows[0])});
  }catch(e){await client.query("ROLLBACK");res.status(500).json({error:"EMAIL_VERIFICATION_FAILED"});}finally{client.release();}
});

app.post("/api/v1/auth/forgot-password",async(req,res)=>{
  const email=normalizeEmail(req.body?.email);
  if(!isValidEmail(email))return res.status(400).json({error:"INVALID_EMAIL"});
  try{
    const q=await pool.query("SELECT id,email,name AS display_name,is_active,email_verified_at FROM therapists WHERE lower(email)=lower($1)",[email]);
    if(q.rowCount && q.rows[0].is_active && q.rows[0].email_verified_at && emailConfigured()) {
      try { await issuePasswordResetEmail({accountType:"THERAPIST",accountId:q.rows[0].id,email:q.rows[0].email,name:q.rows[0].display_name}); } catch(e) { console.error("THERAPIST_PASSWORD_RESET_EMAIL_FAILED",e); }
    }
    res.json({sent:true});
  }catch(e){res.status(500).json({error:"PASSWORD_RESET_REQUEST_FAILED"});}
});

app.post("/api/v1/auth/reset-password",async(req,res)=>{
  const token=String(req.body?.token||"");
  const next=String(req.body?.new_password||"");
  if(!token)return res.status(400).json({error:"INVALID_RESET_TOKEN"});
  if(!isStrongPassword(next))return res.status(400).json({error:"WEAK_PASSWORD"});
  const client=await pool.connect();
  try{
    await client.query("BEGIN");
    const q=await client.query("SELECT id,account_id FROM password_reset_tokens WHERE account_type='THERAPIST' AND token_hash=$1 AND used_at IS NULL AND expires_at>now() FOR UPDATE",[hashOpaqueToken(token)]);
    if(!q.rowCount){await client.query("ROLLBACK");return res.status(400).json({error:"INVALID_OR_EXPIRED_RESET_TOKEN"});}
    const accountId=q.rows[0].account_id;
    const hash=await bcrypt.hash(next,12);
    const user=await client.query("UPDATE therapists SET password_hash=$1 WHERE id=$2 AND is_active=true AND email_verified_at IS NOT NULL RETURNING id",[hash,accountId]);
    if(!user.rowCount){await client.query("ROLLBACK");return res.status(400).json({error:"ACCOUNT_UNAVAILABLE"});}
    await client.query("UPDATE password_reset_tokens SET used_at=now() WHERE id=$1",[q.rows[0].id]);
    await client.query("UPDATE user_sessions SET revoked_at=now() WHERE therapist_id=$1 AND revoked_at IS NULL",[accountId]);
    await client.query("INSERT INTO audit_log(id,therapist_id,action,entity_type,entity_id) VALUES($1,$2,'PASSWORD_RESET','therapist',$2)",[crypto.randomUUID(),accountId]);
    await client.query("COMMIT");
    res.json({reset:true});
  }catch(e){await client.query("ROLLBACK");res.status(500).json({error:"PASSWORD_RESET_FAILED"});}finally{client.release();}
});

app.post("/api/v1/auth/login",async(req,res)=>{
  try{
    const email=normalizeEmail(req.body?.email), password=req.body?.password;
    if(!isValidEmail(email)||typeof password!=="string")return res.status(401).json({error:"INVALID_CREDENTIALS"});
    const r=await pool.query("SELECT id,email,name AS display_name,password_hash,is_active,role,email_verified_at FROM therapists WHERE lower(email)=lower($1)",[email]);
    if(!r.rowCount)return res.status(401).json({error:"INVALID_CREDENTIALS"});
    const u=r.rows[0];
    if(!u.is_active || !(await bcrypt.compare(password,u.password_hash)))return res.status(401).json({error:"INVALID_CREDENTIALS"});
    if(!u.email_verified_at)return res.status(401).json({error:"INVALID_CREDENTIALS"});
    const m=await pool.query("SELECT enabled FROM mfa_methods WHERE therapist_id=$1",[u.id]);
    const mfaEnabled=Boolean(m.rows[0]?.enabled);
    if(!mfaEnabled){
      await revokeMfaChallenges(u.id,"SETUP");
      const setupToken=await createMfaChallenge({therapistId:u.id,type:"SETUP"});
      await pool.query("INSERT INTO audit_log(id,therapist_id,action,entity_type,entity_id) VALUES($1,$2,'MFA_SETUP_REQUIRED','therapist',$2)",[crypto.randomUUID(),u.id]);
      return res.status(403).json({error:"MFA_SETUP_REQUIRED",setup_token:setupToken,role:String(u.role||"THERAPIST").toUpperCase()});
    }
    const challengeToken=await createMfaChallenge({therapistId:u.id,type:"LOGIN"});
    res.status(200).json({mfa_required:true,challenge_token:challengeToken});
  }catch(e){console.error(e);res.status(500).json({error:"LOGIN_FAILED"});}
});

app.post("/api/v1/auth/mfa/setup",async(req,res)=>{
  try{
    const token=String(req.body?.setup_token||""); if(!token)return res.status(400).json({error:"INVALID_MFA_SETUP_TOKEN"});
    const q=await pool.query(`SELECT c.*,t.email,t.name AS display_name,t.role,t.is_active,t.email_verified_at FROM mfa_challenges c JOIN therapists t ON t.id=c.therapist_id WHERE c.token_hash=$1 AND c.type='SETUP' AND c.used_at IS NULL AND c.expires_at>now()`,[hashOpaqueToken(token)]);
    if(!q.rowCount)return res.status(400).json({error:"INVALID_OR_EXPIRED_MFA_SETUP_TOKEN"});
    const u=q.rows[0]; if(!u.is_active||!u.email_verified_at)return res.status(400).json({error:"ACCOUNT_UNAVAILABLE"});
    let m=await pool.query("SELECT secret_encrypted FROM mfa_methods WHERE therapist_id=$1",[u.therapist_id]);
    let secret;
    if(m.rowCount) secret=decryptMfaSecret(m.rows[0].secret_encrypted);
    else { secret=createMfaSecret(); await pool.query("INSERT INTO mfa_methods(id,therapist_id,secret_encrypted,enabled) VALUES($1,$2,$3,false)",[crypto.randomUUID(),u.therapist_id,encryptMfaSecret(secret)]); }
    res.json({email:u.email,secret,otpauth_uri:otpauthUri(secret,u.email),account_role:String(u.role).toUpperCase(),expires_in_seconds:MFA_SETUP_MINUTES*60});
  }catch(e){console.error(e);res.status(500).json({error:"MFA_SETUP_FAILED"});}
});

app.post("/api/v1/auth/mfa/enable",async(req,res)=>{
  try{
    const token=String(req.body?.setup_token||""), code=String(req.body?.code||"");
    const q=await pool.query(`SELECT c.*,t.email,t.name AS display_name,t.role,t.is_active,t.email_verified_at,m.secret_encrypted FROM mfa_challenges c JOIN therapists t ON t.id=c.therapist_id JOIN mfa_methods m ON m.therapist_id=t.id WHERE c.token_hash=$1 AND c.type='SETUP' AND c.used_at IS NULL AND c.expires_at>now()`,[hashOpaqueToken(token)]);
    if(!q.rowCount)return res.status(400).json({error:"INVALID_OR_EXPIRED_MFA_SETUP_TOKEN"});
    const u=q.rows[0]; if(!u.is_active||!u.email_verified_at)return res.status(400).json({error:"ACCOUNT_UNAVAILABLE"});
    const secret=decryptMfaSecret(u.secret_encrypted); if(!verifyTotp(secret,code))return res.status(400).json({error:"INVALID_MFA_CODE"});
    const codes=createRecoveryCodes();
    const client=await pool.connect();
    try{
      await client.query("BEGIN");
      await client.query("UPDATE mfa_methods SET enabled=true,enabled_at=now(),last_used_at=now(),updated_at=now() WHERE therapist_id=$1",[u.therapist_id]);
      await client.query("DELETE FROM mfa_recovery_codes WHERE therapist_id=$1",[u.therapist_id]);
      for(const c of codes) await client.query("INSERT INTO mfa_recovery_codes(id,therapist_id,code_hash) VALUES($1,$2,$3)",[crypto.randomUUID(),u.therapist_id,hashRecoveryCode(c)]);
      await client.query("UPDATE mfa_challenges SET used_at=now() WHERE id=$1",[u.id]);
      await client.query("INSERT INTO audit_log(id,therapist_id,action,entity_type,entity_id) VALUES($1,$2,'MFA_ENABLED','therapist',$2)",[crypto.randomUUID(),u.therapist_id]);
      await client.query("COMMIT");
    }catch(e){await client.query("ROLLBACK");throw e}finally{client.release()}
    const result=await issueTherapistSession(res,u); res.json({...result,mfa_enabled:true,recovery_codes:codes});
  }catch(e){console.error(e);res.status(500).json({error:"MFA_ENABLE_FAILED"});}
});

app.post("/api/v1/auth/mfa/verify",async(req,res)=>{
  try{
    const token=String(req.body?.challenge_token||""), code=String(req.body?.code||"").trim();
    const q=await pool.query(`SELECT c.*,t.id therapist_id,t.email,t.name AS display_name,t.role,t.is_active,t.email_verified_at,m.secret_encrypted FROM mfa_challenges c JOIN therapists t ON t.id=c.therapist_id JOIN mfa_methods m ON m.therapist_id=t.id WHERE c.token_hash=$1 AND c.type='LOGIN' AND c.used_at IS NULL AND c.expires_at>now() AND m.enabled=true`,[hashOpaqueToken(token)]);
    if(!q.rowCount)return res.status(400).json({error:"INVALID_OR_EXPIRED_MFA_CHALLENGE"});
    const u=q.rows[0]; if(!u.is_active||!u.email_verified_at)return res.status(401).json({error:"INVALID_CREDENTIALS"});
    let ok=false,usedRecovery=false;
    if(/^\d{6}$/.test(code)) ok=verifyTotp(decryptMfaSecret(u.secret_encrypted),code);
    if(!ok){
      const h=hashRecoveryCode(code); const rc=await pool.query("SELECT id FROM mfa_recovery_codes WHERE therapist_id=$1 AND code_hash=$2 AND used_at IS NULL",[u.therapist_id,h]);
      if(rc.rowCount){ok=true;usedRecovery=true;await pool.query("UPDATE mfa_recovery_codes SET used_at=now() WHERE id=$1",[rc.rows[0].id]);}
    }
    if(!ok)return res.status(401).json({error:"INVALID_MFA_CODE"});
    await pool.query("UPDATE mfa_challenges SET used_at=now() WHERE id=$1",[u.id]);
    await pool.query("UPDATE mfa_methods SET last_used_at=now(),updated_at=now() WHERE therapist_id=$1",[u.therapist_id]);
    await pool.query("INSERT INTO audit_log(id,therapist_id,action,entity_type,entity_id) VALUES($1,$2,$3,'therapist',$2)",[crypto.randomUUID(),u.therapist_id,usedRecovery?'MFA_RECOVERY_CODE_USED':'MFA_VERIFIED']);
    const result=await issueTherapistSession(res,u); res.json({...result,mfa_verified:true,recovery_code_used:usedRecovery});
  }catch(e){console.error(e);res.status(500).json({error:"MFA_VERIFY_FAILED"});}
});

app.get("/api/v1/auth/mfa/status",auth,async(req,res)=>{try{const q=await pool.query("SELECT enabled,enabled_at,last_used_at FROM mfa_methods WHERE therapist_id=$1",[req.user.id]);res.json({required:true,enabled:Boolean(q.rows[0]?.enabled),enabled_at:q.rows[0]?.enabled_at||null,last_used_at:q.rows[0]?.last_used_at||null});}catch(e){res.status(500).json({error:"MFA_STATUS_FAILED"});}});

app.post("/api/v1/auth/logout",async(req,res)=>{
  try{
    const t=cookie(req);
    if(t){
      const r=await pool.query("UPDATE user_sessions SET revoked_at=now() WHERE session_hash=$1 AND revoked_at IS NULL RETURNING therapist_id",[hashSessionToken(t)]);
      if(r.rowCount)await pool.query("INSERT INTO audit_log(id,therapist_id,action,entity_type,entity_id) VALUES($1,$2,'LOGOUT','therapist',$2)",[crypto.randomUUID(),r.rows[0].therapist_id]);
    }
  }finally{clearCookie(res);res.json({logged_out:true});}
});
app.get("/api/v1/auth/me",auth,(req,res)=>res.json({user:req.user}));

app.post("/api/v1/auth/change-password",auth,async(req,res)=>{
  try{
    const current=String(req.body?.current_password||"");
    const next=String(req.body?.new_password||"");
    if(!isStrongPassword(next)) return res.status(400).json({error:"WEAK_PASSWORD"});
    const q=await pool.query("SELECT password_hash FROM therapists WHERE id=$1 AND is_active=true",[req.user.id]);
    if(!q.rowCount || !(await bcrypt.compare(current,q.rows[0].password_hash)))
      return res.status(401).json({error:"INVALID_CURRENT_PASSWORD"});
    const hash=await bcrypt.hash(next,12);
    await pool.query("UPDATE therapists SET password_hash=$1 WHERE id=$2",[hash,req.user.id]);
    await pool.query("UPDATE user_sessions SET revoked_at=now() WHERE therapist_id=$1 AND revoked_at IS NULL",[req.user.id]);
    await pool.query("INSERT INTO audit_log(id,therapist_id,action,entity_type,entity_id) VALUES($1,$2,'PASSWORD_CHANGED','therapist',$2)",[crypto.randomUUID(),req.user.id]);
    clearCookie(res);
    res.json({changed:true,reauthentication_required:true});
  }catch(e){res.status(500).json({error:"CHANGE_PASSWORD_FAILED"});}
});


const requirePhase6Auth = auth;

app.get("/api/v1/children",auth,async(req,res)=>{
  const r=await pool.query(
    `SELECT c.id,c.name,c.date_of_birth,c.caregiver_name,c.primary_concern,c.created_at,
            COUNT(a.id)::int AS assessment_count,
            COUNT(a.id) FILTER(WHERE a.status='Completed')::int AS completed_count
     FROM children c LEFT JOIN assessments a ON a.child_id=c.id
     WHERE c.therapist_id=$1 GROUP BY c.id ORDER BY c.created_at DESC`,
    [req.user.id]);
  res.json({children:r.rows});
});
app.post("/api/v1/children",auth,async(req,res)=>{
  const name=String(req.body?.name||"").trim();
  if(name.length<2||name.length>120)return res.status(400).json({error:"INVALID_CHILD_NAME"});
  const id=crypto.randomUUID();
  const r=await pool.query(
    `INSERT INTO children(id,therapist_id,name,date_of_birth,caregiver_name,primary_concern)
     VALUES($1,$2,$3,$4,$5,$6) RETURNING id,name,date_of_birth,caregiver_name,primary_concern,created_at`,
    [id,req.user.id,name,req.body?.date_of_birth||null,req.body?.caregiver_name||null,req.body?.primary_concern||null]);
  await pool.query("INSERT INTO audit_log(id,therapist_id,action,entity_type,entity_id) VALUES($1,$2,'CHILD_CREATED','child',$3)",[crypto.randomUUID(),req.user.id,id]);
  res.status(201).json({child:r.rows[0]});
});

app.get("/api/v1/assessments",auth,async(req,res)=>{
  const r=await pool.query(
    `SELECT a.id,a.child_id,a.instrument_version,a.status,a.started_at,a.completed_at,c.name child_name,
            (SELECT COUNT(*)::int FROM responses r WHERE r.assessment_id=a.id) answered_count
     FROM assessments a JOIN children c ON c.id=a.child_id
     WHERE a.therapist_id=$1 ORDER BY a.started_at DESC`,
    [req.user.id]);
  res.json({assessments:r.rows});
});
app.post("/api/v1/assessments",auth,async(req,res)=>{
  const child=await pool.query("SELECT id FROM children WHERE id=$1 AND therapist_id=$2",[req.body?.child_id,req.user.id]);
  if(!child.rowCount)return res.status(404).json({error:"CHILD_NOT_FOUND"});
  const id=crypto.randomUUID();
  const r=await pool.query(
    `INSERT INTO assessments(id,child_id,instrument_version,status,therapist_id)
     VALUES($1,$2,'AUTIBLOOM_V1','Draft',$3) RETURNING *`,
    [id,req.body.child_id,req.user.id]);
  await pool.query("INSERT INTO audit_log(id,therapist_id,action,entity_type,entity_id) VALUES($1,$2,'ASSESSMENT_CREATED','assessment',$3)",[crypto.randomUUID(),req.user.id,id]);
  res.status(201).json({assessment:r.rows[0]});
});
app.get("/api/v1/assessments/:id/resume",auth,async(req,res)=>{
  const a=await pool.query(
    `SELECT a.*,c.name child_name FROM assessments a JOIN children c ON c.id=a.child_id
     WHERE a.id=$1 AND a.therapist_id=$2`,[req.params.id,req.user.id]);
  if(!a.rowCount)return res.status(404).json({error:"ASSESSMENT_NOT_FOUND"});
  const r=await pool.query("SELECT question_id,response_value FROM responses WHERE assessment_id=$1",[req.params.id]);
  const responses={}; for(const x of r.rows)responses[x.question_id]=x.response_value===null?"na":Number(x.response_value);
  res.json({assessment:a.rows[0],responses,answered_count:Object.keys(responses).length,total_questions:121});
});
/* PHASE5_RESPONSE_ROUTE */
app.patch("/api/v1/assessments/:id/responses",auth,async(req,res)=>{
  const q=String(req.body?.question_id||""), v=req.body?.response_value;
  if(!/^[A-Z]{2}-[A-Z]{2}-\d{3}$/.test(q))return res.status(400).json({error:"INVALID_QUESTION_ID"});
  if(!([0,1,2,3,4].includes(v)||v==="na"))return res.status(400).json({error:"INVALID_RESPONSE"});
  const r=await pool.query(
    `INSERT INTO responses(id,assessment_id,question_id,response_value)
     SELECT $1,a.id,$2,$3 FROM assessments a
     WHERE a.id=$4 AND a.therapist_id=$5 AND a.status IN('Draft','In Progress')
     ON CONFLICT(assessment_id,question_id) DO UPDATE SET response_value=EXCLUDED.response_value
     RETURNING question_id,response_value`,
    [crypto.randomUUID(),q,v==="na"?null:v,req.params.id,req.user.id]);
  if(!r.rowCount)return res.status(404).json({error:"ASSESSMENT_NOT_FOUND_OR_LOCKED"});
  await pool.query("UPDATE assessments SET status='In Progress' WHERE id=$1 AND status='Draft'",[req.params.id]);
  res.json({saved:true,question_id:q,response_value:v});
});
/* PHASE5_COMPLETE_ROUTE */
app.post("/api/v1/assessments/:id/complete",auth,async(req,res)=>{
  const client=await pool.connect();
  try{
    await client.query("BEGIN");
    const a=await client.query("SELECT * FROM assessments WHERE id=$1 AND therapist_id=$2 FOR UPDATE",[req.params.id,req.user.id]);
    if(!a.rowCount)throw Object.assign(new Error("NOT_FOUND"),{status:404});
    if(a.rows[0].status==="Completed")throw Object.assign(new Error("ALREADY_COMPLETED"),{status:409});
    const rr=await client.query("SELECT question_id,response_value FROM responses WHERE assessment_id=$1",[req.params.id]);
    const responses={};for(const x of rr.rows)responses[x.question_id]=x.response_value===null?"na":Number(x.response_value);
    if(!validateResponses(responses))throw Object.assign(new Error("ALL_121_RESPONSES_REQUIRED"),{status:400});
    const scoring=scoreResponses(responses);
    await client.query("DELETE FROM assessment_scores WHERE assessment_id=$1",[req.params.id]);
    for(const [type,vals] of Object.entries({domain:scoring.domain,pattern:scoring.pattern,functional_area:scoring.functional_area}))
      for(const [label,value] of Object.entries(vals))
        await client.query("INSERT INTO assessment_scores(id,assessment_id,score_type,label,score) VALUES($1,$2,$3,$4,$5)",[crypto.randomUUID(),req.params.id,type,label,value]);
    await client.query("UPDATE assessments SET status='Completed',completed_at=now() WHERE id=$1",[req.params.id]);
    await client.query("INSERT INTO audit_log(id,therapist_id,action,entity_type,entity_id) VALUES($1,$2,'ASSESSMENT_COMPLETED','assessment',$3)",[crypto.randomUUID(),req.user.id,req.params.id]);
    await client.query("COMMIT");
    res.json({status:"Completed",assessment_id:req.params.id,scores:scoring});
  }catch(e){await client.query("ROLLBACK");res.status(e.status||500).json({error:e.message});}
  finally{client.release();}
});
app.get("/api/v1/assessments/:id",auth,async(req,res)=>{
  const a=await pool.query("SELECT a.*,c.name child_name FROM assessments a JOIN children c ON c.id=a.child_id WHERE a.id=$1 AND a.therapist_id=$2",[req.params.id,req.user.id]);
  if(!a.rowCount)return res.status(404).json({error:"ASSESSMENT_NOT_FOUND"});
  const r=await pool.query("SELECT question_id,response_value FROM responses WHERE assessment_id=$1",[req.params.id]);
  const scores=await pool.query("SELECT score_type,label,score FROM assessment_scores WHERE assessment_id=$1 ORDER BY score_type,label",[req.params.id]);
  const responses={};for(const x of r.rows)responses[x.question_id]=x.response_value===null?"na":Number(x.response_value);
  res.json({assessment:a.rows[0],responses,scores:scores.rows});
});
app.get("/api/v1/dashboard",auth,async(req,res)=>{
  const c=await pool.query("SELECT COUNT(*)::int n FROM children WHERE therapist_id=$1",[req.user.id]);
  const a=await pool.query("SELECT COUNT(*)::int n,COUNT(*) FILTER(WHERE status='Completed')::int completed,COUNT(*) FILTER(WHERE status!='Completed')::int draft FROM assessments WHERE therapist_id=$1",[req.user.id]);
  res.json({children:c.rows[0].n,assessments:a.rows[0].n,completed:a.rows[0].completed,draft:a.rows[0].draft});
});



/* PHASE8_REPORT_DRAFT */
app.post("/api/v1/assessments/:id/report/draft", requirePhase6Auth, async (req,res)=>{
 const client=await pool.connect();
 try{
   await client.query("BEGIN");
   const a=await client.query(`SELECT a.id,a.child_id,a.therapist_id,a.status,a.completed_at,c.name,c.date_of_birth FROM assessments a JOIN children c ON c.id=a.child_id WHERE a.id=$1 AND a.therapist_id=$2 FOR UPDATE`,[req.params.id,req.user.id]);
   if(!a.rowCount){await client.query("ROLLBACK");return res.status(404).json({error:"ASSESSMENT_NOT_FOUND"});}
   if(a.rows[0].status!=="Completed"){await client.query("ROLLBACK");return res.status(409).json({error:"ASSESSMENT_NOT_COMPLETED"});}
   const sc=await client.query(`SELECT score_type,label,score FROM assessment_scores WHERE assessment_id=$1 ORDER BY score_type,label`,[req.params.id]);
   const draft=buildClinicalDraft({child:a.rows[0],assessment:a.rows[0],scores:sc.rows});
   const ex=await client.query(`SELECT id FROM clinical_reports WHERE assessment_id=$1 FOR UPDATE`,[req.params.id]); let report;
   if(ex.rowCount){report=(await client.query(`UPDATE clinical_reports SET clinical_summary=$1,updated_at=now() WHERE id=$2 RETURNING *`,[JSON.stringify(draft.score_summary),ex.rows[0].id])).rows[0];}
   else{report=(await client.query(`INSERT INTO clinical_reports(id,assessment_id,therapist_id,report_version,status,clinical_summary) VALUES($1,$2,$3,$4,'Draft',$5) RETURNING *`,[crypto.randomUUID(),req.params.id,req.user.id,REPORT_VERSION,JSON.stringify(draft.score_summary)])).rows[0];}
   await client.query(`INSERT INTO report_access_log(id,report_id,actor_type,actor_id,action) VALUES($1,$2,'therapist',$3,'DRAFT_GENERATED')`,[crypto.randomUUID(),report.id,req.user.id]);
   await client.query("COMMIT");
   res.status(201).json({report,draft});
 }catch(e){await client.query("ROLLBACK");res.status(500).json({error:"REPORT_DRAFT_FAILED"});}
 finally{client.release();}
});
/* PHASE8_REPORT_GET */
app.get("/api/v1/assessments/:id/report", requirePhase6Auth, async (req,res)=>{
 try{const q=await pool.query(`SELECT r.*,a.child_id,a.status AS assessment_status,c.name AS child_name,c.date_of_birth FROM clinical_reports r JOIN assessments a ON a.id=r.assessment_id JOIN children c ON c.id=a.child_id WHERE r.assessment_id=$1 AND r.therapist_id=$2`,[req.params.id,req.user.id]);if(!q.rowCount)return res.status(404).json({error:"REPORT_NOT_FOUND"});await pool.query(`INSERT INTO report_access_log(id,report_id,actor_type,actor_id,action) VALUES($1,$2,'therapist',$3,'VIEWED')`,[crypto.randomUUID(),q.rows[0].id,req.user.id]);res.json({report:q.rows[0]})}catch(e){res.status(500).json({error:"REPORT_GET_FAILED"})}
});
/* PHASE8_REPORT_UPDATE */
app.patch("/api/v1/assessments/:id/report", requirePhase6Auth, async (req,res)=>{
 try{const q=await pool.query(`SELECT id,status FROM clinical_reports WHERE assessment_id=$1 AND therapist_id=$2`,[req.params.id,req.user.id]);if(!q.rowCount)return res.status(404).json({error:"REPORT_NOT_FOUND"});if(q.rows[0].status==="Released")return res.status(409).json({error:"REPORT_ALREADY_RELEASED"});const b=req.body||{};const u=await pool.query(`UPDATE clinical_reports SET clinical_summary=COALESCE($1,clinical_summary),parent_summary=COALESCE($2,parent_summary),recommendations=COALESCE($3,recommendations),home_program=COALESCE($4,home_program),clinician_notes=COALESCE($5,clinician_notes),status='Draft',updated_at=now() WHERE id=$6 AND therapist_id=$7 RETURNING *`,[b.clinical_summary===undefined?null:JSON.stringify(b.clinical_summary),b.parent_summary===undefined?null:JSON.stringify(b.parent_summary),b.recommendations===undefined?null:JSON.stringify(b.recommendations),b.home_program===undefined?null:JSON.stringify(b.home_program),b.clinician_notes===undefined?null:String(b.clinician_notes),q.rows[0].id,req.user.id]);res.json({report:u.rows[0]})}catch(e){res.status(500).json({error:"REPORT_UPDATE_FAILED"})}
});
/* PHASE8_REPORT_REVIEW */
app.post("/api/v1/assessments/:id/report/review", requirePhase6Auth, async (req,res)=>{
 try{const q=await pool.query(`UPDATE clinical_reports SET status='Reviewed',reviewed_at=now(),updated_at=now() WHERE assessment_id=$1 AND therapist_id=$2 AND status='Draft' RETURNING *`,[req.params.id,req.user.id]);if(!q.rowCount)return res.status(409).json({error:"REPORT_NOT_IN_DRAFT"});res.json({report:q.rows[0]})}catch(e){res.status(500).json({error:"REPORT_REVIEW_FAILED"})}
});
/* PHASE8_REPORT_RELEASE */
app.post("/api/v1/assessments/:id/report/release", requirePhase6Auth, async (req,res)=>{
 try{const q=await pool.query(`UPDATE clinical_reports SET status='Released',released_at=now(),updated_at=now() WHERE assessment_id=$1 AND therapist_id=$2 AND status='Reviewed' RETURNING *`,[req.params.id,req.user.id]);if(!q.rowCount)return res.status(409).json({error:"REPORT_MUST_BE_REVIEWED_FIRST"});res.json({report:q.rows[0]})}catch(e){res.status(500).json({error:"REPORT_RELEASE_FAILED"})}
});


/* ================= PHASE 9: PARENT PORTAL ================= */
function parentCookie(req){const m=(req.headers.cookie||"").match(/(?:^|;\s*)autibloom_parent_session=([^;]+)/);return m?decodeURIComponent(m[1]):null;}
function setParentCookie(res,t,exp){const secure=process.env.NODE_ENV==="production"?" Secure;":"";res.setHeader("Set-Cookie",`autibloom_parent_session=${t}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${Math.floor((exp-Date.now())/1000)};${secure}`);}
function clearParentCookie(res){res.setHeader("Set-Cookie","autibloom_parent_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0;");}
async function currentParent(req){const t=parentCookie(req);if(!t)return null;const r=await pool.query(`SELECT p.id,p.email,p.display_name,s.id session_id FROM parent_sessions s JOIN parent_users p ON p.id=s.parent_id WHERE s.session_hash=$1 AND s.revoked_at IS NULL AND s.expires_at>now() AND p.is_active=true`,[hashParentSessionToken(t)]);if(!r.rowCount)return null;await pool.query("UPDATE parent_sessions SET last_seen_at=now() WHERE id=$1",[r.rows[0].session_id]);return r.rows[0];}
async function parentAuth(req,res,next){try{const p=await currentParent(req);if(!p)return res.status(401).json({error:"PARENT_AUTHENTICATION_REQUIRED"});req.parent=p;next();}catch(e){res.status(500).json({error:"PARENT_AUTHENTICATION_ERROR"});}}

app.post("/api/v1/parent/auth/register",async(req,res)=>{
  const email=normalizeEmail(req.body?.email),password=String(req.body?.password||""),displayName=String(req.body?.display_name||"").trim();
  if(!isValidEmail(email))return res.status(400).json({error:"INVALID_EMAIL"});
  if(displayName.length<2||displayName.length>120)return res.status(400).json({error:"INVALID_NAME"});
  if(!isStrongPassword(password))return res.status(400).json({error:"WEAK_PASSWORD"});
  if(!emailConfigured())return res.status(503).json({error:"EMAIL_SERVICE_NOT_CONFIGURED"});
  try{
    const existing=await pool.query("SELECT id,email,display_name,is_active,email_verified_at FROM parent_users WHERE lower(email)=lower($1)",[email]);
    if(existing.rowCount){
      const account=existing.rows[0];
      if(account.is_active && !account.email_verified_at){
        try { await issueVerificationEmail({accountType:"PARENT",accountId:account.id,email:account.email,name:account.display_name}); } catch(e) { console.error("PARENT_EXISTING_VERIFICATION_FAILED",e); }
      }
      return res.status(202).json({account_created:false,email_verification_required:true,message:"If the account is eligible, verification instructions will be sent to this email address."});
    }
    const hash=await bcrypt.hash(password,12),id=crypto.randomUUID();
    await pool.query("INSERT INTO parent_users(id,email,password_hash,display_name,is_active,email_verified_at) VALUES($1,$2,$3,$4,true,NULL)",[id,email,hash,displayName]);
    await pool.query("INSERT INTO parent_security_audit(id,parent_id,action,metadata) VALUES($1,$2,'REGISTER_PENDING_EMAIL',$3)",[crypto.randomUUID(),id,JSON.stringify({account_type:'PARENT'})]);
    try { await issueVerificationEmail({accountType:"PARENT",accountId:id,email,name:displayName}); }
    catch(e){ await pool.query("DELETE FROM parent_users WHERE id=$1",[id]); console.error("PARENT_VERIFICATION_EMAIL_FAILED",e); return res.status(503).json({error:"VERIFICATION_EMAIL_FAILED"}); }
    res.status(201).json({account_created:true,email_verification_required:true});
  }catch(e){if(e?.code==='23505')return res.status(202).json({account_created:false,email_verification_required:true,message:"If the account is eligible, verification instructions will be sent to this email address."});res.status(500).json({error:"PARENT_REGISTRATION_FAILED"});}
});

app.post("/api/v1/parent/auth/resend-verification",async(req,res)=>{
  const email=normalizeEmail(req.body?.email);
  if(!isValidEmail(email))return res.status(400).json({error:"INVALID_EMAIL"});
  try{
    const q=await pool.query("SELECT id,email,display_name,is_active,email_verified_at FROM parent_users WHERE lower(email)=lower($1)",[email]);
    if(q.rowCount && q.rows[0].is_active && !q.rows[0].email_verified_at && emailConfigured()) {
      try { await issueVerificationEmail({accountType:"PARENT",accountId:q.rows[0].id,email:q.rows[0].email,name:q.rows[0].display_name}); } catch(e) { console.error("PARENT_RESEND_VERIFICATION_FAILED",e); }
    }
    res.json({sent:true});
  }catch(e){res.status(500).json({error:"VERIFICATION_RESEND_FAILED"});}
});

app.get("/api/v1/parent/auth/verify-email",async(req,res)=>{
  const token=String(req.query?.token||"");
  if(!token)return res.status(400).json({error:"INVALID_VERIFICATION_TOKEN"});
  const client=await pool.connect();
  try{
    await client.query("BEGIN");
    const q=await client.query("SELECT id,account_id FROM email_verification_tokens WHERE account_type='PARENT' AND token_hash=$1 AND used_at IS NULL AND expires_at>now() FOR UPDATE",[hashOpaqueToken(token)]);
    if(!q.rowCount){await client.query("ROLLBACK");return res.status(400).json({error:"INVALID_OR_EXPIRED_VERIFICATION_TOKEN"});}
    const accountId=q.rows[0].account_id;
    const user=await client.query("UPDATE parent_users SET email_verified_at=COALESCE(email_verified_at,now()) WHERE id=$1 AND is_active=true RETURNING id,email,display_name,is_active",[accountId]);
    if(!user.rowCount){await client.query("ROLLBACK");return res.status(400).json({error:"ACCOUNT_UNAVAILABLE"});}
    await client.query("UPDATE email_verification_tokens SET used_at=now() WHERE id=$1",[q.rows[0].id]);
    await client.query("INSERT INTO parent_security_audit(id,parent_id,action,metadata) VALUES($1,$2,'EMAIL_VERIFIED',$3)",[crypto.randomUUID(),accountId,JSON.stringify({account_type:'PARENT'})]);
    await client.query("COMMIT");
    res.json({verified:true,parent:user.rows[0]});
  }catch(e){await client.query("ROLLBACK");res.status(500).json({error:"EMAIL_VERIFICATION_FAILED"});}finally{client.release();}
});

app.post("/api/v1/parent/auth/forgot-password",async(req,res)=>{
  const email=normalizeEmail(req.body?.email);
  if(!isValidEmail(email))return res.status(400).json({error:"INVALID_EMAIL"});
  try{
    const q=await pool.query("SELECT id,email,display_name,is_active,email_verified_at FROM parent_users WHERE lower(email)=lower($1)",[email]);
    if(q.rowCount && q.rows[0].is_active && q.rows[0].email_verified_at && emailConfigured()) {
      try { await issuePasswordResetEmail({accountType:"PARENT",accountId:q.rows[0].id,email:q.rows[0].email,name:q.rows[0].display_name}); } catch(e) { console.error("PARENT_PASSWORD_RESET_EMAIL_FAILED",e); }
    }
    res.json({sent:true});
  }catch(e){res.status(500).json({error:"PASSWORD_RESET_REQUEST_FAILED"});}
});

app.post("/api/v1/parent/auth/reset-password",async(req,res)=>{
  const token=String(req.body?.token||""),next=String(req.body?.new_password||"");
  if(!token)return res.status(400).json({error:"INVALID_RESET_TOKEN"});
  if(!isStrongPassword(next))return res.status(400).json({error:"WEAK_PASSWORD"});
  const client=await pool.connect();
  try{
    await client.query("BEGIN");
    const q=await client.query("SELECT id,account_id FROM password_reset_tokens WHERE account_type='PARENT' AND token_hash=$1 AND used_at IS NULL AND expires_at>now() FOR UPDATE",[hashOpaqueToken(token)]);
    if(!q.rowCount){await client.query("ROLLBACK");return res.status(400).json({error:"INVALID_OR_EXPIRED_RESET_TOKEN"});}
    const accountId=q.rows[0].account_id,hash=await bcrypt.hash(next,12);
    const user=await client.query("UPDATE parent_users SET password_hash=$1,updated_at=now() WHERE id=$2 AND is_active=true AND email_verified_at IS NOT NULL RETURNING id",[hash,accountId]);
    if(!user.rowCount){await client.query("ROLLBACK");return res.status(400).json({error:"ACCOUNT_UNAVAILABLE"});}
    await client.query("UPDATE password_reset_tokens SET used_at=now() WHERE id=$1",[q.rows[0].id]);
    await client.query("UPDATE parent_sessions SET revoked_at=now() WHERE parent_id=$1 AND revoked_at IS NULL",[accountId]);
    await client.query("INSERT INTO parent_security_audit(id,parent_id,action,metadata) VALUES($1,$2,'PASSWORD_RESET',$3)",[crypto.randomUUID(),accountId,JSON.stringify({account_type:'PARENT'})]);
    await client.query("COMMIT");
    res.json({reset:true});
  }catch(e){await client.query("ROLLBACK");res.status(500).json({error:"PASSWORD_RESET_FAILED"});}finally{client.release();}
});

app.post("/api/v1/parent/auth/login",async(req,res)=>{try{const email=String(req.body?.email||"").trim().toLowerCase(),password=String(req.body?.password||"");const q=await pool.query("SELECT id,email,display_name,password_hash,is_active,email_verified_at FROM parent_users WHERE lower(email)=lower($1)",[email]);if(!q.rowCount)return res.status(401).json({error:"INVALID_CREDENTIALS"});const p=q.rows[0];if(!p.is_active||!(await bcrypt.compare(password,p.password_hash)))return res.status(401).json({error:"INVALID_CREDENTIALS"});if(!p.email_verified_at)return res.status(401).json({error:"INVALID_CREDENTIALS"});const t=createParentSessionToken(),exp=parentSessionExpiry();await pool.query("INSERT INTO parent_sessions(id,parent_id,session_hash,expires_at) VALUES($1,$2,$3,$4)",[crypto.randomUUID(),p.id,hashParentSessionToken(t),exp]);await pool.query("INSERT INTO parent_security_audit(id,parent_id,action,metadata) VALUES($1,$2,'LOGIN_SUCCESS',$3)",[crypto.randomUUID(),p.id,JSON.stringify({account_type:'PARENT'})]);setParentCookie(res,t,exp);res.json({parent:{id:p.id,email:p.email,display_name:p.display_name}});}catch(e){res.status(500).json({error:"PARENT_LOGIN_FAILED"});}});
app.post("/api/v1/parent/auth/logout",async(req,res)=>{try{const t=parentCookie(req);if(t){const r=await pool.query("UPDATE parent_sessions SET revoked_at=now() WHERE session_hash=$1 AND revoked_at IS NULL RETURNING parent_id",[hashParentSessionToken(t)]);if(r.rowCount)await pool.query("INSERT INTO parent_security_audit(id,parent_id,action,metadata) VALUES($1,$2,'LOGOUT',$3)",[crypto.randomUUID(),r.rows[0].parent_id,JSON.stringify({account_type:'PARENT'})]);}}finally{clearParentCookie(res);res.json({logged_out:true});}});
app.get("/api/v1/parent/auth/me",parentAuth,(req,res)=>res.json({parent:{id:req.parent.id,email:req.parent.email,display_name:req.parent.display_name}}));
app.get("/api/v1/parent/reports",parentAuth,async(req,res)=>{try{const q=await pool.query(`SELECT r.id,r.assessment_id,r.report_version,r.status,r.updated_at,c.id child_id,c.name child_name FROM clinical_reports r JOIN assessments a ON a.id=r.assessment_id JOIN children c ON c.id=a.child_id JOIN parent_child_links pcl ON pcl.child_id=c.id WHERE pcl.parent_id=$1 AND pcl.verified_at IS NOT NULL AND r.status='Released' ORDER BY r.updated_at DESC`,[req.parent.id]);res.json({reports:q.rows});}catch(e){res.status(500).json({error:"PARENT_REPORT_LIST_FAILED"});}});
app.get("/api/v1/parent/reports/:id",parentAuth,async(req,res)=>{try{const q=await pool.query(`SELECT r.id,r.assessment_id,r.report_version,r.status,r.clinical_summary,r.parent_summary,r.recommendations,r.home_program,r.released_at,c.id child_id,c.name child_name,c.date_of_birth FROM clinical_reports r JOIN assessments a ON a.id=r.assessment_id JOIN children c ON c.id=a.child_id JOIN parent_child_links pcl ON pcl.child_id=c.id WHERE r.id=$1 AND pcl.parent_id=$2 AND pcl.verified_at IS NOT NULL AND r.status='Released'`,[req.params.id,req.parent.id]);if(!q.rowCount)return res.status(404).json({error:"REPORT_NOT_FOUND"});await pool.query(`INSERT INTO report_access_log(id,report_id,actor_type,actor_id,action) VALUES($1,$2,'parent',$3,'VIEWED')`,[crypto.randomUUID(),q.rows[0].id,req.parent.id]);res.json({report:q.rows[0]});}catch(e){res.status(500).json({error:"PARENT_REPORT_GET_FAILED"});}});
app.post("/api/v1/assessments/:id/report/delivery-token",requirePhase6Auth,async(req,res)=>{try{const parentId=req.body?.parent_id;if(!parentId)return res.status(400).json({error:"PARENT_ID_REQUIRED"});const r=await pool.query(`SELECT cr.id,cr.status FROM clinical_reports cr JOIN assessments a ON a.id=cr.assessment_id WHERE a.id=$1 AND a.therapist_id=$2`,[req.params.id,req.user.id]);if(!r.rowCount)return res.status(404).json({error:"REPORT_NOT_FOUND"});if(r.rows[0].status!=="Released")return res.status(409).json({error:"REPORT_NOT_RELEASED"});const link=await pool.query(`SELECT 1 FROM parent_child_links pcl JOIN assessments a ON a.child_id=pcl.child_id WHERE a.id=$1 AND pcl.parent_id=$2 AND pcl.verified_at IS NOT NULL`,[req.params.id,parentId]);if(!link.rowCount)return res.status(403).json({error:"PARENT_NOT_VERIFIED_FOR_CHILD"});const token=createDeliveryToken(),exp=deliveryExpiry();await pool.query(`INSERT INTO report_delivery_tokens(id,report_id,parent_id,token_hash,expires_at) VALUES($1,$2,$3,$4,$5)`,[crypto.randomUUID(),r.rows[0].id,parentId,hashDeliveryToken(token),exp]);res.status(201).json({token,expires_at:exp,report_id:r.rows[0].id});}catch(e){res.status(500).json({error:"DELIVERY_TOKEN_FAILED"});}});


/* AUTIBLOOM PHASE 10 — THERAPIST CLINICAL REVIEW */
app.get("/api/v1/therapist/dashboard", requirePhase6Auth, async (req,res)=>{
 try{const q=await pool.query(`SELECT r.id,r.assessment_id,r.report_version,r.status,r.updated_at,r.released_at,c.id AS child_id,c.name AS child_name FROM clinical_reports r JOIN assessments a ON a.id=r.assessment_id JOIN children c ON c.id=a.child_id WHERE r.therapist_id=$1 ORDER BY r.updated_at DESC`,[req.user.id]);res.json({reports:q.rows})}
 catch(e){res.status(500).json({error:"THERAPIST_DASHBOARD_FAILED"})}
});
app.get("/api/v1/therapist/reports/:id", requirePhase6Auth, async (req,res)=>{
 try{const q=await pool.query(`SELECT r.*,c.id AS child_id,c.name AS child_name,c.date_of_birth,a.created_at AS assessment_created_at FROM clinical_reports r JOIN assessments a ON a.id=r.assessment_id JOIN children c ON c.id=a.child_id WHERE r.id=$1 AND r.therapist_id=$2`,[req.params.id,req.user.id]);if(!q.rowCount)return res.status(404).json({error:"REPORT_NOT_FOUND"});const h=await pool.query(`SELECT action,note,created_at FROM clinical_report_reviews WHERE report_id=$1 ORDER BY created_at ASC`,[req.params.id]);res.json({report:q.rows[0],review_history:h.rows})}
 catch(e){res.status(500).json({error:"THERAPIST_REPORT_GET_FAILED"})}
});
app.post("/api/v1/therapist/reports/:id/review", requirePhase6Auth, async (req,res)=>{
 const action=String(req.body?.action||""),note=String(req.body?.note||"").trim(),allowed=new Set(["DRAFT_SAVED","SUBMITTED_FOR_REVIEW","APPROVED","RETURNED"]);
 if(!allowed.has(action))return res.status(400).json({error:"INVALID_REVIEW_ACTION"});
 const map={DRAFT_SAVED:"Draft",SUBMITTED_FOR_REVIEW:"In Review",APPROVED:"Approved",RETURNED:"Draft"};
 const client=await pool.connect();
 try{
   const q=await client.query(`SELECT id FROM clinical_reports WHERE id=$1 AND therapist_id=$2`,[req.params.id,req.user.id]);
   if(!q.rowCount){return res.status(404).json({error:"REPORT_NOT_FOUND"});}
   await client.query("BEGIN");
   await client.query(`UPDATE clinical_reports SET status=$1,updated_at=now() WHERE id=$2`,[map[action],req.params.id]);
   await client.query(`INSERT INTO clinical_report_reviews(id,report_id,therapist_id,action,note) VALUES($1,$2,$3,$4,$5)`,[crypto.randomUUID(),req.params.id,req.user.id,action,note||null]);
   await client.query("COMMIT");
   res.json({ok:true,status:map[action]});
 }catch(e){try{await client.query("ROLLBACK")}catch(_){}res.status(500).json({error:"REPORT_REVIEW_FAILED"});}
 finally{client.release();}
});
app.post("/api/v1/therapist/reports/:id/release", requirePhase6Auth, async (req,res)=>{
 const client=await pool.connect();
 try{
   const q=await client.query(`SELECT id,status FROM clinical_reports WHERE id=$1 AND therapist_id=$2`,[req.params.id,req.user.id]);
   if(!q.rowCount)return res.status(404).json({error:"REPORT_NOT_FOUND"});
   if(!["Approved","In Review"].includes(q.rows[0].status))return res.status(409).json({error:"REPORT_NOT_READY_FOR_RELEASE"});
   await client.query("BEGIN");
   await client.query(`UPDATE clinical_reports SET status='Released',released_at=now(),updated_at=now() WHERE id=$1`,[req.params.id]);
   await client.query(`INSERT INTO clinical_report_reviews(id,report_id,therapist_id,action,note) VALUES($1,$2,$3,'RELEASED',$4)`,[crypto.randomUUID(),req.params.id,req.user.id,String(req.body?.note||"").trim()||null]);
   await client.query(`INSERT INTO clinical_report_release_log(id,report_id,therapist_id,release_channel) VALUES($1,$2,$3,'PARENT_PORTAL')`,[crypto.randomUUID(),req.params.id,req.user.id]);
   await client.query("COMMIT");
   res.json({ok:true,status:"Released"});
 }catch(e){try{await client.query("ROLLBACK")}catch(_){}res.status(500).json({error:"REPORT_RELEASE_FAILED"});}
 finally{client.release();}
});


/* AUTIBLOOM_PHASE11_REPORTING */
function p11Sections(r){
  const cs=r.clinical_summary||{};
  return [
    {title:'Clinical Summary',body:r.parent_summary?.text||r.parent_summary||''},
    {title:'Sensory Processing Overview',body:cs.overview||cs.sensory_overview||''},
    {title:'Functional Impact',body:cs.functional_impact||''},
    {title:'Clinical Recommendations',body:r.recommendations||[]},
    {title:'Home Program',body:r.home_program||[]},
    {title:'Clinician Notes',body:r.clinician_notes||''}
  ];
}
app.get('/api/v1/therapist/reports/:id/html',auth,async(req,res)=>{
  try{const q=await pool.query(`SELECT r.*,c.name child_name,c.date_of_birth,a.created_at assessment_created_at FROM clinical_reports r JOIN assessments a ON a.id=r.assessment_id JOIN children c ON c.id=a.child_id WHERE r.id=$1 AND r.therapist_id=$2`,[req.params.id,req.user.id]);if(!q.rowCount)return res.status(404).json({error:'REPORT_NOT_FOUND'});const r=q.rows[0];const m=buildProfessionalReportModel({report_id:r.id,report_version:r.report_version,child:{name:r.child_name,date_of_birth:r.date_of_birth},assessment:{date:r.assessment_created_at,assessor:req.user.display_name},sections:p11Sections(r)});res.type('html').send(renderProfessionalReportHtml(m));}catch(e){res.status(500).json({error:'REPORT_HTML_GENERATION_FAILED'});}
});
app.get('/api/v1/parent/reports/:id/html',parentAuth,async(req,res)=>{
  try{const q=await pool.query(`SELECT r.*,c.name child_name,c.date_of_birth,a.created_at assessment_created_at FROM clinical_reports r JOIN assessments a ON a.id=r.assessment_id JOIN children c ON c.id=a.child_id JOIN parent_child_links pcl ON pcl.child_id=c.id WHERE r.id=$1 AND pcl.parent_id=$2 AND pcl.verified_at IS NOT NULL AND r.status='Released'`,[req.params.id,req.parent.id]);if(!q.rowCount)return res.status(404).json({error:'REPORT_NOT_FOUND'});const r=q.rows[0];const m=buildProfessionalReportModel({report_id:r.id,report_version:r.report_version,child:{name:r.child_name,date_of_birth:r.date_of_birth},assessment:{date:r.assessment_created_at,assessor:'AUTIBLOOM Clinical Team'},sections:p11Sections(r)});res.type('html').send(renderProfessionalReportHtml(m));}catch(e){res.status(500).json({error:'PARENT_REPORT_HTML_FAILED'});}
});


/* AUTIBLOOM PHASE 12 */
function requireAdmin(req,res,next){const role=req.user?.role||req.user?.role_key;if(role!=="ADMIN")return res.status(403).json({error:"ADMIN_REQUIRED"});next();}
app.get("/api/v1/admin/dashboard",requirePhase6Auth,requireAdmin,async(req,res)=>{try{const q=await pool.query(`SELECT (SELECT COUNT(*) FROM children) children,(SELECT COUNT(*) FROM assessments) assessments,(SELECT COUNT(*) FROM clinical_reports) reports,(SELECT COUNT(*) FROM clinical_reports WHERE status='Released') released_reports,(SELECT COUNT(*) FROM therapists) therapists`);res.json({metrics:q.rows[0]});}catch(e){res.status(500).json({error:"ADMIN_DASHBOARD_FAILED"});}});
app.get("/api/v1/admin/audit",requirePhase6Auth,requireAdmin,async(req,res)=>{try{const q=await pool.query(`SELECT * FROM admin_audit_log ORDER BY created_at DESC LIMIT 100`);res.json({entries:q.rows});}catch(e){res.status(500).json({error:"ADMIN_AUDIT_FAILED"});}});
app.get("/api/v1/admin/analytics",requirePhase6Auth,requireAdmin,async(req,res)=>{try{const q=await pool.query(`SELECT * FROM analytics_daily_snapshot ORDER BY snapshot_date DESC LIMIT 90`);res.json({snapshots:q.rows});}catch(e){res.status(500).json({error:"ADMIN_ANALYTICS_FAILED"});}});
app.get("/api/v1/admin/operations",requirePhase6Auth,requireAdmin,async(req,res)=>{try{const q=await pool.query(`SELECT * FROM operational_events ORDER BY created_at DESC LIMIT 100`);res.json({events:q.rows});}catch(e){res.status(500).json({error:"ADMIN_OPERATIONS_FAILED"});}});

/* AUTIBLOOM_PHASE13_SECURITY_BASELINE */
// API 404s must remain JSON; browser navigation gets the SPA entry point.
app.use("/api", (req,res)=>res.status(404).json({error:"API_ROUTE_NOT_FOUND",path:req.originalUrl}));
app.get(["/login","/therapist","/therapist-dashboard","/admin","/admin-dashboard","/report-preview","/auth","/mfa"], (req,res)=>{
  const map={
    "/login":"index.html",
    "/therapist":"therapist-dashboard.html",
    "/therapist-dashboard":"therapist-dashboard.html",
    "/admin":"admin-dashboard.html",
    "/admin-dashboard":"admin-dashboard.html",
    "/report-preview":"report-preview.html",
    "/auth":"auth.html",
    "/mfa":"mfa.html"
  };
  res.sendFile(path.resolve(__dirname,"../app",map[req.path] || "index.html"));
});
app.use((req,res,next)=>{
  if ((req.method === "GET" || req.method === "HEAD") && req.accepts("html")) {
    return res.sendFile(path.resolve(__dirname,"../app/index.html"));
  }
  return res.status(404).json({error:"NOT_FOUND",path:req.originalUrl});
});
app.use((err,req,res,next)=>{
  console.error("AUTIBLOOM request error", err);
  if (res.headersSent) return next(err);
  const status = Number(err.status || err.statusCode || 500);
  res.status(status >= 400 && status < 600 ? status : 500).json({error:"INTERNAL_SERVER_ERROR"});
});

const port = Number(process.env.PORT || 3000);
const host = process.env.HOST || "0.0.0.0";
const server = app.listen(port,host,()=>console.log(`AUTIBLOOM API running on http://${host}:${port}`));
server.keepAliveTimeout = Number(process.env.KEEP_ALIVE_TIMEOUT_MS || 65000);
server.headersTimeout = Number(process.env.HEADERS_TIMEOUT_MS || 66000);
server.requestTimeout = Number(process.env.REQUEST_TIMEOUT_MS || 120000);

async function shutdown(signal){
  console.log(`AUTIBLOOM ${signal}: shutting down`);
  server.close(async()=>{
    try { await pool.end(); } finally { process.exit(0); }
  });
  setTimeout(()=>process.exit(1),10000).unref();
}
process.on("SIGTERM",()=>shutdown("SIGTERM"));
process.on("SIGINT",()=>shutdown("SIGINT"));
