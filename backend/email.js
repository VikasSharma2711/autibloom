import crypto from "node:crypto";

const apiKey = () => String(process.env.RESEND_API_KEY || "").trim();
const from = () => String(process.env.EMAIL_FROM || "").trim();
const baseUrl = () => String(process.env.APP_BASE_URL || "").trim().replace(/\/$/, "");

export function emailConfigured() {
  return Boolean(apiKey() && from() && baseUrl());
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>\"']/g, c => ({
    "&":"&amp;", "<":"&lt;", ">":"&gt;", "\"":"&quot;", "'":"&#039;"
  }[c]));
}

export function createOpaqueToken() {
  return crypto.randomBytes(32).toString("base64url");
}

export function hashOpaqueToken(token) {
  return crypto.createHash("sha256").update(String(token)).digest("hex");
}

async function sendEmail({to, subject, html}) {
  if (!emailConfigured()) throw new Error("EMAIL_PROVIDER_NOT_CONFIGURED");
  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${apiKey()}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({from: from(), to: [to], subject, html})
  });
  const body = await response.text();
  if (!response.ok) {
    console.error("RESEND_EMAIL_FAILED", response.status, body.slice(0, 500));
    throw new Error("EMAIL_SEND_FAILED");
  }
  return body ? JSON.parse(body) : {};
}

function layout(title, intro, buttonText, buttonUrl, footer) {
  return `<!doctype html><html><body style="margin:0;background:#f6f8fb;font-family:Arial,sans-serif;color:#172033"><div style="max-width:600px;margin:40px auto;padding:28px;background:#fff;border:1px solid #e5eaf1;border-radius:16px"><h1 style="margin-top:0">AUTIBLOOM</h1><h2>${escapeHtml(title)}</h2><p>${escapeHtml(intro)}</p><p style="margin:28px 0"><a href="${escapeHtml(buttonUrl)}" style="display:inline-block;padding:12px 18px;background:#172033;color:#fff;text-decoration:none;border-radius:10px;font-weight:700">${escapeHtml(buttonText)}</a></p><p style="font-size:13px;color:#64748b">If the button does not work, copy and paste this link into your browser:</p><p style="font-size:12px;word-break:break-all;color:#475569">${escapeHtml(buttonUrl)}</p><hr style="border:0;border-top:1px solid #e5eaf1;margin:28px 0"><p style="font-size:12px;color:#64748b">${escapeHtml(footer)}</p></div></body></html>`;
}

export async function sendVerificationEmail({to, name, token, account}) {
  const url = `${baseUrl()}/auth.html?mode=verify&account=${encodeURIComponent(account)}&token=${encodeURIComponent(token)}`;
  return sendEmail({
    to,
    subject: "Verify your AUTIBLOOM email address",
    html: layout(
      "Verify your email address",
      `Hello ${name || "there"}, please verify your email address to activate your AUTIBLOOM account.`,
      "Verify email",
      url,
      "This verification link expires in 24 hours. If you did not create this account, you can safely ignore this email."
    )
  });
}

export async function sendPasswordResetEmail({to, name, token, account}) {
  const url = `${baseUrl()}/auth.html?mode=reset&account=${encodeURIComponent(account)}&token=${encodeURIComponent(token)}`;
  return sendEmail({
    to,
    subject: "Reset your AUTIBLOOM password",
    html: layout(
      "Reset your password",
      `Hello ${name || "there"}, we received a request to reset your AUTIBLOOM password.`,
      "Reset password",
      url,
      "This password-reset link expires in 1 hour and can be used only once. If you did not request this, you can safely ignore this email."
    )
  });
}
