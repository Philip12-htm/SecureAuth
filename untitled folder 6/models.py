"""
models.py
SQLAlchemy models for SecureAuth.

Design notes (for report justification):
- Passwords are NEVER stored in plaintext. Only Argon2id hashes are persisted.
- A PasswordHistory table stores the last N hashes per user so we can block
  password reuse without ever storing old passwords in recoverable form.
- Account lockout state (failed_attempts / locked_until) is stored on the
  user row so brute-force protection survives server restarts.
- MFA secret is a TOTP base32 secret used with pyotp. In a production system
  this field should additionally be encrypted at rest (e.g. via Fernet) —
  noted as a future-work item in the report.
"""

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

# How many previous password hashes we remember per user to block reuse.
PASSWORD_HISTORY_LIMIT = 5


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)

    # --- MFA (TOTP) ---
    mfa_secret = db.Column(db.String(64), nullable=False)
    mfa_enabled = db.Column(db.Boolean, default=False, nullable=False)

    # --- MFA (Email OTP) ---
    email_otp_hash = db.Column(db.String(255), nullable=True)
    email_otp_expires_at = db.Column(db.DateTime, nullable=True)
    email_otp_attempts = db.Column(db.Integer, default=0, nullable=False)
    email_otp_last_sent_at = db.Column(db.DateTime, nullable=True)

    # --- Brute-force protection ---
    failed_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)

    # --- Password policy ---
    password_changed_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    must_change_password = db.Column(db.Boolean, default=False, nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login_at = db.Column(db.DateTime, nullable=True)

    # --- Relationships with Cascade Delete ---
    history = db.relationship(
        "PasswordHistory",
        backref="user",
        lazy=True,
        order_by="PasswordHistory.created_at.desc()",
        cascade="all, delete-orphan",
    )

    # ADDED: Cascade delete for user notes to fix ForeignKeyViolation when deleting users
    notes = db.relationship(
        "SecureNote",
        backref="owner",
        lazy=True,
        cascade="all, delete-orphan",
    )

    def is_locked(self):
        return self.locked_until is not None and self.locked_until > datetime.utcnow()


class PasswordHistory(db.Model):
    __tablename__ = "password_history"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class SecureNote(db.Model):
    __tablename__ = "secure_notes"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
