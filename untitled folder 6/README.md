# SecureAuth — Secure Registration & Authentication Prototype

A Flask-based prototype demonstrating secure system design for the Advanced Cyber Security module assignment.

## Features implemented

| Feature | Detail |
|---|---|
| Registration UI | Username + password, fully responsive, animated dark UI |
| Password strength | Live, server-validated scoring (length, character variety, entropy, common-password & sequence blocklist) |
| CAPTCHA | Server-rendered distorted-text image CAPTCHA, session-bound, single-use |
| Password hashing | Argon2id via `argon2-cffi`, automatic per-password salt |
| Password history | Last 5 password hashes stored; reuse is rejected |
| Account lockout | 5 failed attempts → 15 minute lockout (brute-force mitigation) |
| Multi-factor authentication | Mandatory TOTP (RFC 6238) via `pyotp`, QR enrollment via `qrcode`, plus an email one-time-code (OTP) backup method |
| Email OTP | 6-digit code emailed on request, hashed at rest, single-use, 10-minute expiry, rate-limited resend, max 5 verify attempts |
| Password expiry | 90-day rotation policy, surfaced on the dashboard |
| Secure Note Vault | Multi-user isolated note repository protecting against IDOR / access bypass |
| CSRF protection | Per-session token validated on every state-changing POST |
| Admin Panel CRUD | Separate interface to Create, Read, Update, and Delete user records directly from the database |
| Security headers | `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Cache-Control: no-store` |
| Generic auth errors | Login errors never reveal whether the username exists |

## Setup
```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py

Then open **http://127.0.0.1:5000** in your browser.

The SQLite database (`secureauth.db`) is created automatically on first run.

Administrative Master Credentials Configuration
Before running the application, make sure your .env file contains your master admin credentials used to access the database management dashboard:
ADMIN_EMAIL=admin@secureauth.local
ADMIN_PASSWORD=Admin123

### Email delivery (optional)

Email OTP works out of the box in development: if no SMTP server is
configured, the code is printed to the server console instead of being
emailed, so you can still test the flow locally. To send real emails, set
these environment variables before running the app:


export SMTP_HOST=smtp.example.com
export SMTP_PORT=465
export SMTP_USERNAME=you@example.com
export SMTP_PASSWORD=your-app-password
export SMTP_USE_TLS=true
export MAIL_FROM="SecureAuth <no-reply@example.com>"

```

## Usage flow

1. **Register** at `/register` — choose a username, email address, and
   password (watch the live strength meter and shield gauge), solve the
   CAPTCHA.
2. **Set up MFA** — scan the QR code with an authenticator app (Google
   Authenticator, Authy, Microsoft Authenticator, 1Password, etc.), or tap
   "Can't scan?" to add the account manually using the displayed key, then
   confirm with the current 6-digit code (codes refresh every 30 seconds).
3. **Log in** at `/login` — enter your username/password, then verify with
   either your authenticator app's current code, or switch to the "Email
   code" tab to receive a one-time code by email instead.
4. **Dashboard** — view your account's security posture (MFA status,
   password age, history count).
5. **Manage Protected Notes** at /notes — Once securely authenticated with MFA, access your private vault 
   container to create, view, or manage personal notes.
6. **Change password** from the dashboard — old password reuse and weak
   passwords are rejected.
7. **Administrative Database Management (CRUD)** at `/admin/login`:
   - To test administrative capabilities, navigate directly to `/admin/login`.
   - Log in using the master administrator configuration values declared in your local `.env` file (`ADMIN_EMAIL` and `ADMIN_PASSWORD`).
   - Once authenticated, you can audit the user registry (Read), provision new users manually (Create), reset passwords or lift brute-force lockouts (Update), and permanently wipe profiles from the SQLite storage layer (Delete).

## Project structure

```
secureauth/
├── app.py              # Routes, sessions, admin CRUD/notes controllers, CSRF, security headers
├── models.py            # SQLAlchemy models (User, Note, PasswordHistory)
├── security.py           # Hashing, password strength, lockout, email OTP logic
├── captcha.py            # CAPTCHA generation & validation
├── mailer.py              # Email OTP delivery (SMTP, with console fallback)
├── requirements.txt
├── .env
├── templates/             # Jinja2 templates
│   ├── base.html
│   ├── change_password.html
│   ├── mfa_setup.html
│   ├── mfa_verify.html
│   ├── register.html
│   ├── login.html
│   ├── dashboard.html
│   ├── notes.html
│   ├── admin_login.html
│   └── admin_dashboard.html
└── static/
    ├── css/style.css       # Design system + animations
    └── js/                # main.js, strength.js
```

## Notes for the report / demonstration

- All password-strength rules are evaluated **server-side**
  (`/api/password-strength`); the client only renders what the server
  returns, so the rules cannot be bypassed by disabling JavaScript.
- The CAPTCHA answer is stored only in the server-side session and is
  cleared after each verification attempt — it is never exposed in the
  page's HTML/DOM.
- The Admin Panel runs within a strictly validated server-side session boundary 
  (`session.get("is_admin") == True`). This blocks horizontal or vertical privilege 
  escalation and prevents standard users from accessing administrative actions by 
  guessing or force-browsing URLs.
- The Secure Note Vault (`/notes`) enforces context-based data isolation by loading records 
  tied exclusively to the active user's session identifier (e.g., `user_id = session['user_id']`). 
  This completely mitigates Insecure Direct Object Reference (IDOR) vulnerabilities, as 
  tampering with request parameters cannot expose notes belonging to other users.
- For a production deployment, the TOTP secret should additionally be
  encrypted at rest, HTTPS should be enforced via `SESSION_COOKIE_SECURE`
  and HSTS, and rate limiting should be added at the network layer
  (e.g. Flask-Limiter / reverse proxy) in addition to the application-level
  lockout implemented here.
- **Brute-Force & Lockout:** Account lockout triggers after 5 consecutive failed login attempts, applying a persistent 15-minute cooldown that survives application restarts.
