"""
mailer.py
Minimal email-sending helper used to deliver one-time passcodes (email OTP)
as an alternative second factor to TOTP.
"""

import os
import smtplib
import ssl
from email.message import EmailMessage

SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "true").lower() != "false"
MAIL_FROM = os.environ.get("MAIL_FROM", "")


def send_email_otp(to_email: str, code: str, minutes_valid: int) -> None:
    subject = "Your SecureAuth Verification Code"
    
    # Text-only fallback for older email clients
    text_body = (
        f"Hello,\n\n"
        f"Your one-time verification code is: {code}\n\n"
        f"This code expires in {minutes_valid} minute(s). "
        f"If you did not request this code, you can safely ignore this email."
    )

    # High-end, clean professional HTML layout matching dark/green theme
    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #090d16; color: #f8fafc; margin: 0; padding: 0; }}
            .container {{ max-width: 500px; margin: 40px auto; background: #111c30; border: 1px solid #22314d; border-radius: 12px; padding: 32px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); }}
            .logo {{ font-size: 20px; font-weight: bold; color: #10b981; margin-bottom: 24px; text-transform: uppercase; letter-spacing: 0.05em; }}
            h2 {{ color: #ffffff; font-size: 22px; margin-top: 0; }}
            p {{ color: #94a3b8; font-size: 15px; line-height: 1.6; }}
            .code-box {{ background: #090d16; border: 1px solid #22314d; color: #10b981; font-size: 32px; font-weight: bold; text-align: center; padding: 16px; border-radius: 8px; margin: 28px 0; font-family: monospace; letter-spacing: 4px; }}
            .footer {{ font-size: 12px; color: #64748b; margin-top: 32px; border-top: 1px solid #22314d; padding-top: 16px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="logo">SecureAuth</div>
            <h2>Verify Your Identity</h2>
            <p>Hi there,</p>
            <p>Use the following secure one-time passcode (OTP) to finalize your multi-factor verification checkpoint layer:</p>
            <div class="code-box">{code}</div>
            <p>This dynamic code is valid for <strong>{minutes_valid} minutes</strong>. For system integrity, do not share this challenge string with anyone.</p>
            <div class="footer">
                If you didn't initiate this request, someone may be attempting to access your profile parameters. You can safely disregard this warning notice.
            </div>
        </div>
    </body>
    </html>
    """

    # If variables aren't active in the environment yet, display inside terminal nicely
    if not SMTP_USERNAME or not SMTP_PASSWORD:
        print("=" * 60)
        print(f"[DEV MODE - Missing SMTP Credentials] Email OTP for {to_email}")
        print(f"Code: {code}")
        print("=" * 60)
        return

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = MAIL_FROM if MAIL_FROM else SMTP_USERNAME
    msg["To"] = to_email
    
    msg.set_content(text_body)
    msg.add_alternative(html_body, subtype="html")

    context = ssl.create_default_context()
    try:
        # Port 465 uses direct SSL
        if SMTP_PORT == 465:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context, timeout=15) as server:
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.send_message(msg)
        else:
            # Port 587 uses explicit STARTTLS handshaking (Optimal for Render)
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
                server.ehlo()
                if SMTP_USE_TLS:
                    server.starttls(context=context)
                    server.ehlo()
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.send_message(msg)
    except Exception as e:
        print(f"\n!!! SMTP ERROR OCCURRED: {e} !!!\n")
        raise e
