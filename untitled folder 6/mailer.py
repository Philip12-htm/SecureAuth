"""
mailer.py
Delivers one-time passcodes (email OTP) via Resend API or console fallback.
"""

import os
import resend

RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
# resend.dev is allowed during testing; update to your domain once verified
MAIL_FROM = os.environ.get("MAIL_FROM", "SecureAuth <onboarding@resend.dev>")


def send_email_otp(to_email: str, code: str, minutes_valid: int) -> None:
    subject = "Your SecureAuth Verification Code"

    # Clean HTML layout matching the dark/green theme
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

    # Terminal log fallback if API key is not present
    if not RESEND_API_KEY:
        print("=" * 60)
        print(f"[DEV MODE - Missing RESEND_API_KEY] Email OTP for {to_email}")
        print(f"Code: {code}")
        print("=" * 60)
        return

    resend.api_key = RESEND_API_KEY

    try:
        resend.Emails.send({
            "from": MAIL_FROM,
            "to": [to_email],
            "subject": subject,
            "html": html_body,
        })
    except Exception as e:
        print(f"\n!!! RESEND API ERROR OCCURRED: {e} !!!\n")
        raise e
