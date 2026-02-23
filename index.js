require("dotenv").config();
const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const nodemailer = require("nodemailer");
const crypto = require("crypto");

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: false,
});

// Create/migrate table on startup
pool.query(`
  CREATE TABLE IF NOT EXISTS users (
    id                   SERIAL PRIMARY KEY,
    email                VARCHAR(255) UNIQUE NOT NULL,
    password_hash        VARCHAR(255) NOT NULL,
    verified             BOOLEAN NOT NULL DEFAULT FALSE,
    verification_token   VARCHAR(255),
    reset_token          VARCHAR(255),
    reset_token_expires  TIMESTAMP,
    created_at           TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )
`).then(async () => {
  // Add new columns if they don't exist (migration for existing tables)
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token VARCHAR(255)`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token_expires TIMESTAMP`);
  console.log("DB ready");
}).catch(e => console.error("DB init error:", e.message));

function makeTransporter() {
  const port = Number(process.env.SMTP_PORT) || 465;
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port,
    secure: port === 465,          // 465 = SSL, 587 = STARTTLS
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
    tls: { rejectUnauthorized: false },
  });
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

async function sendVerificationEmail(email, token) {
  const link = `${process.env.APP_URL}/api/verify-email?token=${token}`;
  await makeTransporter().sendMail({
    from: `"Cardium Boss" <${process.env.SMTP_USER}>`,
    to: email,
    subject: "Verify your Cardium Boss account",
    html: `
      <div style="font-family:'Open Sans',Arial,sans-serif;max-width:480px;margin:0 auto;padding:32px;background:#f0f8ff;border-radius:8px;">
        <h2 style="color:#1a4a90;margin-bottom:8px;">Welcome to Cardium Boss</h2>
        <p style="color:#2a5a80;font-size:15px;line-height:1.6;">
          Thanks for registering. Click the button below to verify your email address and activate your account.
        </p>
        <a href="${link}" style="display:inline-block;margin:24px 0;padding:14px 32px;background:linear-gradient(135deg,#1a5a9a,#2a90e8);color:#fff;text-decoration:none;border-radius:6px;font-size:15px;font-weight:600;">
          Verify Email Address
        </a>
        <p style="color:#6a8aa8;font-size:12px;">
          This link expires in 24 hours. If you didn't create an account, you can safely ignore this email.
        </p>
      </div>
    `,
  });
}

async function sendPasswordResetEmail(email, token) {
  const link = `${process.env.APP_URL}/api/reset-password-page?token=${token}`;
  await makeTransporter().sendMail({
    from: `"Cardium Boss" <${process.env.SMTP_USER}>`,
    to: email,
    subject: "Reset your Cardium Boss password",
    html: `
      <div style="font-family:'Open Sans',Arial,sans-serif;max-width:480px;margin:0 auto;padding:32px;background:#f0f8ff;border-radius:8px;">
        <h2 style="color:#1a4a90;margin-bottom:8px;">Password Reset</h2>
        <p style="color:#2a5a80;font-size:15px;line-height:1.6;">
          You requested a password reset for your Cardium Boss account. Click below to set a new password.
        </p>
        <a href="${link}" style="display:inline-block;margin:24px 0;padding:14px 32px;background:linear-gradient(135deg,#1a5a9a,#2a90e8);color:#fff;text-decoration:none;border-radius:6px;font-size:15px;font-weight:600;">
          Reset Password
        </a>
        <p style="color:#6a8aa8;font-size:12px;">
          This link expires in 1 hour. If you didn't request a reset, you can safely ignore this email.
        </p>
      </div>
    `,
  });
}

// GET /api/smtp-test  (debug — remove after confirming)
app.get("/api/smtp-test", async (req, res) => {
  try {
    await makeTransporter().verify();
    res.json({ ok: true, host: process.env.SMTP_HOST, user: process.env.SMTP_USER });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message, host: process.env.SMTP_HOST, user: process.env.SMTP_USER });
  }
});

// POST /api/resend-verification
app.post("/api/resend-verification", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email is required." });

  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (result.rows.length === 0) return res.status(404).json({ error: "No account found with that email." });

    const user = result.rows[0];
    if (user.verified) return res.status(400).json({ error: "This account is already verified. Please sign in." });

    const token = crypto.randomBytes(32).toString("hex");
    await pool.query("UPDATE users SET verification_token = $1 WHERE id = $2", [token, user.id]);
    await sendVerificationEmail(email, token);

    res.json({ message: "Verification email resent. Check your inbox." });
  } catch (err) {
    console.error("Resend error:", err.message);
    res.status(500).json({ error: "Server error: " + err.message });
  }
});

// POST /api/register
app.post("/api/register", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !EMAIL_RE.test(email)) {
    return res.status(400).json({ error: "Invalid email address." });
  }
  if (!password || password.length < 6) {
    return res.status(400).json({ error: "Password must be at least 6 characters." });
  }

  try {
    const existing = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: "An account with that email already exists." });
    }

    const hash = await bcrypt.hash(password, 10);
    const token = crypto.randomBytes(32).toString("hex");

    await pool.query(
      "INSERT INTO users (email, password_hash, verified, verification_token) VALUES ($1, $2, FALSE, $3)",
      [email, hash, token]
    );

    await sendVerificationEmail(email, token);
    res.status(201).json({ message: "Account created. Check your email to verify your address." });
  } catch (err) {
    console.error("Register error:", err.message);
    res.status(500).json({ error: "Server error: " + err.message });
  }
});

// POST /api/login
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required." });
  }

  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Invalid email or password." });
    }

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ error: "Invalid email or password." });
    }

    if (!user.verified) {
      return res.status(403).json({ error: "Please verify your email address before signing in. Check your inbox." });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.json({ token, email: user.email });
  } catch (err) {
    console.error("Login error:", err.message);
    res.status(500).json({ error: "Server error. Please try again." });
  }
});

// POST /api/forgot-password
app.post("/api/forgot-password", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email is required." });

  try {
    const result = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
    // Always return success to prevent email enumeration
    if (result.rows.length === 0) {
      return res.json({ message: "If an account exists for that email, a reset link has been sent." });
    }

    const token = crypto.randomBytes(32).toString("hex");
    const expires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    await pool.query(
      "UPDATE users SET reset_token = $1, reset_token_expires = $2 WHERE email = $3",
      [token, expires, email]
    );

    await sendPasswordResetEmail(email, token);
    res.json({ message: "If an account exists for that email, a reset link has been sent." });
  } catch (err) {
    console.error("Forgot-password error:", err.message);
    res.status(500).json({ error: "Server error: " + err.message });
  }
});

// GET /api/reset-password-page?token=xxx  (served as HTML form)
app.get("/api/reset-password-page", async (req, res) => {
  const { token } = req.query;
  if (!token) return res.send(resetPage("Invalid Link", null, "No reset token provided."));

  try {
    const result = await pool.query(
      "SELECT id FROM users WHERE reset_token = $1 AND reset_token_expires > NOW()",
      [token]
    );
    if (result.rows.length === 0) {
      return res.send(resetPage("Link Expired", null, "This reset link is invalid or has expired. Please request a new one."));
    }
    res.send(resetPage("Reset Password", token, null));
  } catch (err) {
    console.error("Reset-page error:", err.message);
    res.send(resetPage("Error", null, "Something went wrong. Please try again."));
  }
});

// POST /api/reset-password  (form submission)
app.post("/api/reset-password", express.urlencoded({ extended: true }), async (req, res) => {
  const { token, password, confirm } = req.body;

  if (!token || !password || password.length < 6) {
    return res.send(resetPage("Reset Password", token, "Password must be at least 6 characters."));
  }
  if (password !== confirm) {
    return res.send(resetPage("Reset Password", token, "Passwords do not match."));
  }

  try {
    const result = await pool.query(
      "SELECT id FROM users WHERE reset_token = $1 AND reset_token_expires > NOW()",
      [token]
    );
    if (result.rows.length === 0) {
      return res.send(resetPage("Link Expired", null, "This reset link is invalid or has expired. Please request a new one."));
    }

    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      "UPDATE users SET password_hash = $1, reset_token = NULL, reset_token_expires = NULL WHERE id = $2",
      [hash, result.rows[0].id]
    );

    res.send(verifyPage("Password Reset!", "Your password has been updated. You can now sign in with your new password.", true));
  } catch (err) {
    console.error("Reset-password error:", err.message);
    res.send(resetPage("Reset Password", token, "Server error. Please try again."));
  }
});

// GET /api/verify-email?token=xxx
app.get("/api/verify-email", async (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).send(verifyPage("Invalid Link", "No verification token was provided.", false));

  try {
    const result = await pool.query(
      "SELECT id FROM users WHERE verification_token = $1 AND verified = FALSE",
      [token]
    );
    if (result.rows.length === 0) {
      return res.status(400).send(verifyPage("Already Verified or Invalid", "This link has already been used or is invalid. You can sign in now.", false));
    }

    await pool.query(
      "UPDATE users SET verified = TRUE, verification_token = NULL WHERE id = $1",
      [result.rows[0].id]
    );

    res.send(verifyPage("Email Verified!", "Your account is now active. You can close this tab and sign in.", true));
  } catch (err) {
    console.error("Verify-email error:", err.message);
    res.status(500).send(verifyPage("Error", "Something went wrong. Please try again.", false));
  }
});

function verifyPage(title, message, success) {
  const color = success ? "#1a7a40" : "#b91c1c";
  const bg = success ? "#e0f7ea" : "#fef2f2";
  const icon = success ? "✓" : "✗";
  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>${title} — Cardium Boss</title>
<link href="https://fonts.googleapis.com/css2?family=Open+Sans:wght@400;700&display=swap" rel="stylesheet">
<style>body{margin:0;font-family:'Open Sans',sans-serif;background:radial-gradient(ellipse at 40% 20%,#c8e8f8 0%,#a0d0ec 60%,#80b8e0 100%);min-height:100vh;display:flex;align-items:center;justify-content:center;}</style>
</head><body>
<div style="background:${bg};border:1.5px solid ${color};border-radius:10px;padding:40px 48px;text-align:center;max-width:400px;box-shadow:0 8px 32px rgba(30,80,160,0.12);">
  <div style="font-size:48px;color:${color};margin-bottom:16px;">${icon}</div>
  <h2 style="color:#1a4a90;margin:0 0 12px;">${title}</h2>
  <p style="color:#2a5a80;font-size:15px;line-height:1.6;margin:0 0 24px;">${message}</p>
  <p style="color:#1a4a90;font-weight:700;font-size:18px;margin:0;">Cardium Boss</p>
</div>
</body></html>`;
}

function resetPage(title, token, errorMsg) {
  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>${title} — Cardium Boss</title>
<link href="https://fonts.googleapis.com/css2?family=Open+Sans:wght@400;700&display=swap" rel="stylesheet">
<style>
  body{margin:0;font-family:'Open Sans',sans-serif;background:radial-gradient(ellipse at 40% 20%,#c8e8f8 0%,#a0d0ec 60%,#80b8e0 100%);min-height:100vh;display:flex;align-items:center;justify-content:center;}
  .card{background:#fff;border-radius:10px;padding:40px 48px;max-width:400px;width:100%;box-shadow:0 8px 32px rgba(30,80,160,0.12);}
  h2{color:#1a4a90;margin:0 0 20px;text-align:center;}
  input{width:100%;box-sizing:border-box;padding:11px 14px;font-size:15px;border:1.5px solid #b0cce4;border-radius:6px;font-family:'Open Sans',sans-serif;margin-bottom:12px;}
  button{width:100%;padding:14px;background:linear-gradient(135deg,#1a5a9a,#2a90e8);color:#fff;border:none;border-radius:6px;font-size:15px;font-family:'Open Sans',sans-serif;cursor:pointer;text-transform:uppercase;letter-spacing:0.1em;}
  .error{color:#b91c1c;background:#fef2f2;border:1px solid #fca5a5;border-radius:6px;padding:10px 14px;font-size:14px;margin-bottom:12px;}
  .brand{text-align:center;color:#1a4a90;font-weight:700;font-size:16px;margin-top:20px;}
</style>
</head><body>
<div class="card">
  <h2>${title}</h2>
  ${errorMsg && !token ? `<div class="error">${errorMsg}</div>` : ""}
  ${token ? `
  ${errorMsg ? `<div class="error">${errorMsg}</div>` : ""}
  <form method="POST" action="/api/reset-password">
    <input type="hidden" name="token" value="${token}">
    <input type="password" name="password" placeholder="New password (min 6 characters)" required>
    <input type="password" name="confirm" placeholder="Confirm new password" required>
    <button type="submit">Set New Password</button>
  </form>` : ""}
  <div class="brand">Cardium Boss</div>
</div>
</body></html>`;
}

// GET /api/verify  (JWT token check)
app.get("/api/verify", (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "No token provided." });
  }

  const token = authHeader.slice(7);
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    res.json({ email: payload.email });
  } catch {
    res.status(401).json({ error: "Invalid or expired token." });
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
