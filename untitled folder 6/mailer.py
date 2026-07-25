"""
mailer.py
Delivers one-time passcodes (email OTP) via Brevo's HTTPS API.
Uses Port 443 (HTTPS) to bypass Render outbound SMTP network blocks.
"""

import os
import requests

BREVO_API_KEY = os.environ.get("BREVO_API_KEY", os.environ.get("SMTP_PASSWORD", ""))
SENDER_EMAIL = os.environ.get("MAIL_FROM", "phonehtet.2020myat@gmail.com")


def send_email_otp(to_email: str, code: str, minutes_valid: int) -> None:
    subject = "Your SecureAuth Verification Code"

    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #090d16; color: #f8fafc; margin: 0; padding: 0; }}
            .container {{ max-width: 500px; margin: 40px auto; background: #111c30; border: 1px solid #22314d; border-radius: 12px; padding: 32px; }}
            .logo {{ font-size: 20px; font-weight: bold; color: #10b981; margin-bottom: 24px; text-transform: uppercase; }}
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
            <p>This dynamic code is valid for <strong>{minutes_valid} minutes</strong>.</p>
            <div class="footer">If you didn't initiate this request, you can safely disregard this notice.</div>
        </div>
    </body>
    </html>
    """

    if not BREVO_API_KEY:
        print("=" * 60)
        print(f"[DEV MODE - Missing BREVO_API_KEY] Email OTP for {to_email}")
        print(f"Code: {code}")
        print("=" * 60)
        return

    url = "https://api.brevo.com/v3/smtp/email"
    
    headers = {
        "accept": "application/json",
        "api-key": BREVO_API_KEY,
        "content-type": "application/json"
    }

    # Extract clean email address if MAIL_FROM contains display name like "SecureAuth <email@domain.com>"
    clean_sender = SENDER_EMAIL
    if "<" in SENDER_EMAIL and ">" in SENDER_EMAIL:
        clean_sender = SENDER_EMAIL.split("<")[1].split(">")[0]

    payload = {
        "sender": {
            "name": "SecureAuth",
            "email": clean_sender
        },
        "to": [
            {
                "email": to_email
            }
        ],
        "subject": subject,
        "htmlContent": html_body
    }

    response = requests.post(url, json=payload, headers=headers, timeout=10)

    if response.status_code not in (200, 201, 202):
        print(f"\n!!! BREVO API ERROR ({response.status_code}): {response.text} !!!\n")
        raise Exception(f"Brevo API Error ({response.status_code}): {response.text}")
