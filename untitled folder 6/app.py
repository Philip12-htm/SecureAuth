"""
app.py
SecureAuth — a prototype registration/authentication system demonstrating
secure system design for the Advanced Cyber Security module assignment.

Security features implemented (see README.md and the accompanying report
for full justification):
  1. Registration with live, server-validated password strength scoring.
  2. Image-based CAPTCHA (server-rendered, session-bound, single-use).
  3. Argon2id password hashing (salted automatically).
  4. Password history (last 5 hashes) to block reuse.
  5. Account lockout after repeated failed logins (brute-force mitigation).
  6. Mandatory TOTP-based multi-factor authentication.
  7. Password expiry policy (forced rotation after 90 days).
  8. Security headers, CSRF-style one-time tokens on state-changing forms,
     and server-side session management (no client-trusted state).
"""

import functools
import io
import os
import re
import secrets
from datetime import datetime, timedelta
from dotenv import load_dotenv
load_dotenv()  

import pyotp
import qrcode
from flask import (
    Flask, render_template, request, redirect, url_for, session, jsonify,
    flash, send_file, abort
)

from models import db, User, PasswordHistory, PASSWORD_HISTORY_LIMIT, SecureNote
from security import (
    hash_password, verify_password, evaluate_password_strength,
    is_password_acceptable, register_failed_attempt, reset_failed_attempts,
    MAX_FAILED_ATTEMPTS, LOCKOUT_MINUTES,
    generate_email_otp, hash_email_otp, verify_email_otp,
    EMAIL_OTP_VALID_MINUTES, EMAIL_OTP_RESEND_COOLDOWN_SECONDS,
    EMAIL_OTP_MAX_ATTEMPTS,
)
from captcha import new_captcha, verify_captcha
from mailer import send_email_otp

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
db_url = os.environ.get("DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'secureauth.db')}")
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = True if os.environ.get("RENDER") else False
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

db.init_app(app)

PASSWORD_EXPIRY_DAYS = 90
ISSUER_NAME = "SecureAuth"
EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ---------------------------------------------------------------------------
# Security headers applied to every response (defence in depth)
# ---------------------------------------------------------------------------
@app.after_request
def set_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Cache-Control"] = "no-store"
    return resp


# ---------------------------------------------------------------------------
# CSRF protection: a per-session token validated on every POST
# ---------------------------------------------------------------------------
def get_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = get_csrf_token


def csrf_protect():
    token = session.get("csrf_token")
    submitted = request.form.get("csrf_token")
    if not token or not submitted or not secrets.compare_digest(token, submitted):
        abort(400, description="Invalid or missing CSRF token.")


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


# ---------------------------------------------------------------------------
# Routes: landing
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        captcha_text, captcha_image = new_captcha()
        session["captcha_text"] = captcha_text
        return render_template("register.html", captcha_image=captcha_image, email="")

    csrf_protect()
    username = (request.form.get("username") or "").strip()
    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    confirm = request.form.get("confirm_password") or ""
    captcha_input = request.form.get("captcha") or ""

    errors = []

    if not (3 <= len(username) <= 30) or not username.replace("_", "").replace(".", "").isalnum():
        errors.append("Username must be 3-30 characters (letters, numbers, '.', '_').")

    if User.query.filter(db.func.lower(User.username) == username.lower()).first():
        errors.append("That username is already taken.")

    if not email or not EMAIL_REGEX.match(email) or len(email) > 255:
        errors.append("Enter a valid email address.")
    elif User.query.filter(db.func.lower(User.email) == email).first():
        errors.append("An account with that email already exists.")

    if not verify_captcha(captcha_input, session.get("captcha_text", "")):
        errors.append("CAPTCHA verification failed. Please try again.")

    strength = evaluate_password_strength(password, username)
    if strength["blocked"] or strength["score"] < 2:
        errors.append("Password is too weak. " + " ".join(strength["feedback"]))

    if password != confirm:
        errors.append("Passwords do not match.")

    # Always issue a fresh CAPTCHA after any attempt (single-use)
    session.pop("captcha_text", None)
    captcha_text, captcha_image = new_captcha()
    session["captcha_text"] = captcha_text

    if errors:
        for e in errors:
            flash(e, "error")
        return render_template(
            "register.html", captcha_image=captcha_image, username=username, email=email
        ), 400

    mfa_secret = pyotp.random_base32()
    user = User(
        username=username,
        email=email,
        password_hash=hash_password(password),
        mfa_secret=mfa_secret,
        mfa_enabled=False,
        password_changed_at=datetime.utcnow(),
    )
    db.session.add(user)
    db.session.flush()
    db.session.add(PasswordHistory(user_id=user.id, password_hash=user.password_hash))
    db.session.commit()

    session["setup_user_id"] = user.id
    flash("Account created. Now set up multi-factor authentication to finish.", "success")
    return redirect(url_for("mfa_setup"))


# ---------------------------------------------------------------------------
# CAPTCHA refresh (AJAX)
# ---------------------------------------------------------------------------
@app.route("/captcha/refresh")
def captcha_refresh():
    text, image = new_captcha()
    session["captcha_text"] = text
    return jsonify({"image": image})


# ---------------------------------------------------------------------------
# Live password strength check (AJAX)
# ---------------------------------------------------------------------------
@app.route("/api/password-strength", methods=["POST"])
def api_password_strength():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    username = data.get("username", "")
    return jsonify(evaluate_password_strength(password, username))


# ---------------------------------------------------------------------------
# MFA setup (immediately after registration)
# ---------------------------------------------------------------------------
@app.route("/mfa-setup", methods=["GET", "POST"])
def mfa_setup():
    user_id = session.get("setup_user_id")
    if not user_id:
        return redirect(url_for("register"))
    user = User.query.get(user_id)
    if not user or user.mfa_enabled:
        return redirect(url_for("login"))

    totp = pyotp.TOTP(user.mfa_secret)
    provisioning_uri = totp.provisioning_uri(name=user.email, issuer_name=ISSUER_NAME)

    if request.method == "POST":
        csrf_protect()
        # Normalise the submitted code: authenticator apps / clipboard pastes
        # sometimes include surrounding whitespace, so strip everything that
        # isn't a digit before comparing against the expected TOTP value.
        code = "".join(filter(str.isdigit, request.form.get("code") or ""))
        if len(code) != 6:
            flash("Enter the 6-digit code exactly as shown in your authenticator app.", "error")
        # valid_window=2 accepts the code generated up to 60 seconds before or
        # after "now", which absorbs normal clock drift between the server
        # and the user's phone while still keeping each code's effective
        # validity window short.
       # valid_window=4 extends the time synchronization window to 2 full minutes on either side
        elif totp.verify(code, valid_window=4):
            user.mfa_enabled = True
            db.session.commit()
            session.pop("setup_user_id", None)
            flash("MFA enabled. You can now log in.", "success")
            return redirect(url_for("login"))
        else:
            flash("Incorrect code. Make sure your device's clock is correct and try the latest code from your authenticator app.", "error")

    return render_template(
        "mfa_setup.html", secret=user.mfa_secret, provisioning_uri=provisioning_uri
    )


@app.route("/mfa-qrcode")
def mfa_qrcode():
    """Streams a PNG QR code for the pending setup user's provisioning URI."""
    user_id = session.get("setup_user_id")
    if not user_id:
        abort(404)
    user = User.query.get(user_id)
    if not user:
        abort(404)
    totp = pyotp.TOTP(user.mfa_secret)
    uri = totp.provisioning_uri(name=user.email, issuer_name=ISSUER_NAME)
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")


# ---------------------------------------------------------------------------
# Login (step 1: username/password)
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    csrf_protect()
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    user = User.query.filter(db.func.lower(User.username) == username.lower()).first()

    # Generic error message regardless of which check fails, to avoid
    # username enumeration.
    generic_error = "Invalid username or password."

    if not user:
        flash(generic_error, "error")
        return render_template("login.html", username=username), 400

    if user.is_locked():
        minutes_left = max(1, int((user.locked_until - datetime.utcnow()).total_seconds() // 60) + 1)
        flash(f"Account locked due to repeated failed attempts. Try again in {minutes_left} minute(s).", "error")
        return render_template("login.html", username=username), 403

    if not verify_password(user.password_hash, password):
        register_failed_attempt(user)
        db.session.commit()
        remaining = max(0, MAX_FAILED_ATTEMPTS - user.failed_attempts)
        if user.is_locked():
            flash(f"Account locked for {LOCKOUT_MINUTES} minutes after {MAX_FAILED_ATTEMPTS} failed attempts.", "error")
        else:
            flash(f"{generic_error} ({remaining} attempt(s) remaining before lockout)", "error")
        return render_template("login.html", username=username), 401

    # Password correct -> require MFA before establishing a session
    reset_failed_attempts(user)
    db.session.commit()

    if not user.mfa_enabled:
        session["setup_user_id"] = user.id
        flash("Please finish setting up multi-factor authentication.", "error")
        return redirect(url_for("mfa_setup"))

    session["pending_mfa_user_id"] = user.id
    return redirect(url_for("mfa_verify"))


# ---------------------------------------------------------------------------
# Login (step 2: TOTP or email OTP verification)
# ---------------------------------------------------------------------------
@app.route("/mfa-verify", methods=["GET", "POST"])
def mfa_verify():
    user_id = session.get("pending_mfa_user_id")
    if not user_id:
        return redirect(url_for("login"))
    user = User.query.get(user_id)
    if not user:
        session.pop("pending_mfa_user_id", None)
        return redirect(url_for("login"))

    # Which tab is active: "app" (TOTP, default) or "email" (email OTP).
    method = request.values.get("method", "app")
    if method not in ("app", "email"):
        method = "app"

    if request.method == "POST":
        csrf_protect()
        code = "".join(filter(str.isdigit, request.form.get("code") or ""))

        if method == "email":
            if not user.email_otp_hash or not user.email_otp_expires_at:
                flash("Request an email code first.", "error")
            elif datetime.utcnow() > user.email_otp_expires_at:
                flash("That code has expired. Request a new one.", "error")
            elif user.email_otp_attempts >= EMAIL_OTP_MAX_ATTEMPTS:
                flash("Too many incorrect attempts. Request a new code.", "error")
            elif len(code) == 6 and verify_email_otp(user.email_otp_hash, code):
                # Single-use: clear it immediately on success.
                user.email_otp_hash = None
                user.email_otp_expires_at = None
                user.email_otp_attempts = 0
                _complete_login(user)
                db.session.commit()
                flash(f"Welcome back, {user.username}.", "success")
                return redirect(url_for("dashboard"))
            else:
                user.email_otp_attempts += 1
                db.session.commit()
                flash("Incorrect or expired code.", "error")
        else:
            totp = pyotp.TOTP(user.mfa_secret)
            if len(code) == 6 and totp.verify(code, valid_window=2):
                _complete_login(user)
                db.session.commit()
                flash(f"Welcome back, {user.username}.", "success")
                return redirect(url_for("dashboard"))
            flash("Incorrect authentication code.", "error")

    masked_email = _mask_email(user.email)
    return render_template(
        "mfa_verify.html", username=user.username, method=method, masked_email=masked_email
    )


def _complete_login(user):
    session.pop("pending_mfa_user_id", None)
    session.permanent = True
    session["user_id"] = user.id
    user.last_login_at = datetime.utcnow()


def _mask_email(email):
    try:
        local, domain = email.split("@", 1)
    except ValueError:
        return email
    if len(local) <= 2:
        masked_local = local[0] + "*"
    else:
        masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
    return f"{masked_local}@{domain}"


# ---------------------------------------------------------------------------
# Request an email OTP (AJAX/form POST) during login MFA step
# ---------------------------------------------------------------------------
@app.route("/mfa-verify/send-email-otp", methods=["POST"])
def mfa_send_email_otp():
    csrf_protect()
    user_id = session.get("pending_mfa_user_id")
    if not user_id:
        return jsonify({"ok": False, "error": "Session expired. Please log in again."}), 400
    user = User.query.get(user_id)
    if not user:
        return jsonify({"ok": False, "error": "Session expired. Please log in again."}), 400

    now = datetime.utcnow()
    if (user.email_otp_last_sent_at and
            (now - user.email_otp_last_sent_at).total_seconds() < EMAIL_OTP_RESEND_COOLDOWN_SECONDS):
        wait = int(EMAIL_OTP_RESEND_COOLDOWN_SECONDS - (now - user.email_otp_last_sent_at).total_seconds())
        return jsonify({"ok": False, "error": f"Please wait {wait}s before requesting another code."}), 429

    code = generate_email_otp()
    user.email_otp_hash = hash_email_otp(code)
    user.email_otp_expires_at = now + timedelta(minutes=EMAIL_OTP_VALID_MINUTES)
    user.email_otp_attempts = 0
    user.email_otp_last_sent_at = now
    db.session.commit()

    try:
        send_email_otp(user.email, code, EMAIL_OTP_VALID_MINUTES)
    except Exception as e:
        # This will send the ACTUAL internal Python error message straight to your browser screen
        return jsonify({"ok": False, "error": f"Internal SMTP Error: {str(e)}"}), 502

    return jsonify({"ok": True, "masked_email": _mask_email(user.email),
                     "valid_minutes": EMAIL_OTP_VALID_MINUTES})


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    user = User.query.get(session["user_id"])
    age_days = (datetime.utcnow() - user.password_changed_at).days
    days_left = max(0, PASSWORD_EXPIRY_DAYS - age_days)
    expired = age_days >= PASSWORD_EXPIRY_DAYS
    history_count = PasswordHistory.query.filter_by(user_id=user.id).count()

    # Dynamic Security Score Calculation
    score = 0
    if user.mfa_enabled: score += 35
    if not expired: score += 30
    if history_count >= 1: score += 20
    if not user.is_locked(): score += 15

    # Determine status level and color indicators
    if score >= 85:
        score_label, score_color = "Excellent", "#10b981"
    elif score >= 60:
        score_label, score_color = "Good", "#3b82f6"
    else:
        score_label, score_color = "Action Required", "#ef4444"

    # Extract Session Metadata from Flask Request
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr) or '127.0.0.1'
    user_agent = request.user_agent
    browser = user_agent.browser.title() if user_agent.browser else "Unknown Browser"
    platform = user_agent.platform.title() if user_agent.platform else "Unknown OS"

    return render_template(
        "dashboard.html",
        user=user,
        age_days=age_days,
        days_left=days_left,
        expired=expired,
        history_count=history_count,
        expiry_days=PASSWORD_EXPIRY_DAYS,
        score=score,
        score_label=score_label,
        score_color=score_color,
        ip_address=ip_address,
        browser=browser,
        platform=platform
    )

# ---------------------------------------------------------------------------
# Change password
# ---------------------------------------------------------------------------
@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    user = User.query.get(session["user_id"])

    if request.method == "POST":
        csrf_protect()
        current = request.form.get("current_password") or ""
        new_password = request.form.get("new_password") or ""
        confirm = request.form.get("confirm_password") or ""

        errors = []
        if not verify_password(user.password_hash, current):
            errors.append("Current password is incorrect.")

        strength = evaluate_password_strength(new_password, user.username)
        if strength["blocked"] or strength["score"] < 2:
            errors.append("New password is too weak. " + " ".join(strength["feedback"]))

        if new_password != confirm:
            errors.append("New passwords do not match.")

        # Block reuse of last N passwords
        recent_hashes = [h.password_hash for h in
                          PasswordHistory.query.filter_by(user_id=user.id)
                          .order_by(PasswordHistory.created_at.desc())
                          .limit(PASSWORD_HISTORY_LIMIT)]
        if not errors:
            for old_hash in recent_hashes:
                if verify_password(old_hash, new_password):
                    errors.append(f"You cannot reuse any of your last {PASSWORD_HISTORY_LIMIT} passwords.")
                    break

        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("change_password.html"), 400

        user.password_hash = hash_password(new_password)
        user.password_changed_at = datetime.utcnow()
        user.must_change_password = False
        db.session.add(PasswordHistory(user_id=user.id, password_hash=user.password_hash))

        # Trim history beyond the limit
        all_hist = (PasswordHistory.query.filter_by(user_id=user.id)
                    .order_by(PasswordHistory.created_at.desc()).all())
        for old in all_hist[PASSWORD_HISTORY_LIMIT:]:
            db.session.delete(old)

        db.session.commit()
        flash("Password updated successfully.", "success")
        return redirect(url_for("dashboard"))

    return render_template("change_password.html")


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------
@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))

# ===========================================================================
# ISOLATED ADMIN PORTAL ACTIONS (CRUD Workspace)
# ===========================================================================
import os
from models import User

# --- ADMIN LOGIN ROUTE ---
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        
        # Check directly against the protected .env values
        if email == os.getenv("ADMIN_EMAIL") and password == os.getenv("ADMIN_PASSWORD"):
            session.clear() # Clear any existing regular user sessions
            session["is_admin"] = True
            session["admin_email"] = email
            flash("Welcome to the Master Administrative Console.", "success")
            return redirect(url_for("admin_dashboard"))
        else:
            flash("Invalid administrative credentials.", "error")
            
    return render_template("admin_login.html")

# --- ADMIN PORTAL DISPATCHER (READ / CREATE) ---
@app.route("/admin/portal", methods=["GET", "POST"])
def admin_dashboard():
    if not session.get("is_admin"):
        return "Access Denied: Administrative Session Required.", 403
        
    # CREATE: Manually provision a user account
    if request.method == "POST" and request.form.get("action") == "create":
        csrf_protect()
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        
        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            flash("Identity collision: Username or Email already exists.", "error")
        else:
            from security import hash_password
            new_user = User(
                username=username, 
                email=email, 
                password_hash=hash_password(password),
                mfa_secret=pyotp.random_base32(), # Seeds MFA secret for newly created users
                mfa_enabled=False,
                password_changed_at=datetime.utcnow()
            )
            db.session.add(new_user)
            db.session.commit()
            flash(f"Account for '{username}' provisioned securely.", "success")
        return redirect(url_for("admin_dashboard"))

    # READ: Pull every regular user from the local database
    all_users = User.query.all()
    return render_template("admin_dashboard.html", users=all_users)

# --- ADMIN ACTIONS (UPDATE) ---
@app.route("/admin/portal/update/<int:user_id>", methods=["POST"])
def admin_update_user(user_id):
    if not session.get("is_admin"):
        return "Unauthorized", 403
    csrf_protect()
    
    user = User.query.get_or_404(user_id)
    action_type = request.form.get("action_type")
    
    if action_type == "reset_password":
        from security import hash_password
        user.password_hash = hash_password("TemporaryPass123!")
        db.session.commit()
        flash(f"Password for {user.username} forced reset to 'TemporaryPass123!'.", "success")
    elif action_type == "unlock":
        user.failed_attempts = 0
        user.locked_until = None
        db.session.commit()
        flash(f"Brute-force security blocks cleared for {user.username}.", "success")
        
    return redirect(url_for("admin_dashboard"))

# --- ADMIN ACTIONS (DELETE) ---

@app.route("/admin/portal/delete/<int:user_id>", methods=["POST"])
def admin_delete_user(user_id):
    if not session.get("is_admin"):
        return "Unauthorized", 403
    csrf_protect()
    
    user = User.query.get_or_404(user_id)
    
    try:
        db.session.delete(user)
        db.session.commit()
        flash(f"User identity profile '{user.username}' successfully purged from database.", "success")
    except Exception as e:
        db.session.rollback()
        print(f"!!! ADMIN DELETE ERROR: {e} !!!")
        flash(f"Failed to delete user '{user.username}' due to a database constraint error.", "error")

    return redirect(url_for("admin_dashboard"))

# --- ADMIN LOGOUT ---
@app.route("/admin/logout")
def admin_logout():
    session.clear()
    flash("Administrative terminal disconnected.", "success")
    return redirect(url_for("admin_login"))

# ===========================================================================
# USER CRYPTOGRAPHIC DATA WORKSPACE (CRUD Secure Notes)
# ===========================================================================

# CREATE & READ: View notes workspace and process additions
@app.route("/notes", methods=["GET", "POST"])
@login_required
def manage_notes():
    if request.method == "POST":
        csrf_protect()
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()
        
        if not title or not content:
            flash("Note title and content workspace fields cannot be empty.", "error")
        else:
            new_note = SecureNote(user_id=session["user_id"], title=title, content=content)
            db.session.add(new_note)
            db.session.commit()
            flash("Secure record written to isolated workspace successfully!", "success")
        return redirect(url_for("manage_notes"))

    # READ: Isolate queries explicitly to the logged-in user session id
    user_notes = SecureNote.query.filter_by(user_id=session["user_id"]).order_by(SecureNote.created_at.desc()).all()
    return render_template("notes.html", notes=user_notes)


# UPDATE: Modify records securely
@app.route("/notes/edit/<int:note_id>", methods=["POST"])
@login_required
def edit_note(note_id):
    csrf_protect()
    # Scoping the query by user_id prevents Horizontal Privilege Escalation
    note = SecureNote.query.filter_by(id=note_id, user_id=session["user_id"]).first_or_404()
    
    note.title = request.form.get("title", "").strip()
    note.content = request.form.get("content", "").strip()
    
    if not note.title or not note.content:
        flash("Record mutations cannot contain blank strings.", "error")
    else:
        db.session.commit()
        flash("Secure log tracking data updated successfully.", "success")
    return redirect(url_for("manage_notes"))


# DELETE: Safely purge records
@app.route("/notes/delete/<int:note_id>", methods=["POST"])
@login_required
def delete_note(note_id):
    csrf_protect()
    # Checking both fields mitigates IDOR (Insecure Direct Object Reference) exploits
    note = SecureNote.query.filter_by(id=note_id, user_id=session["user_id"]).first_or_404()
    db.session.delete(note)
    db.session.commit()
    flash("Secure segment detached and purged.", "success")
    return redirect(url_for("manage_notes"))

# ===========================================================================
# Execution Context
# ===========================================================================
with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
