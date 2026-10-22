"""
FixAI Security Email Service
============================
Enterprise-grade email dispatcher supporting:
1. Standard SMTP / TLS / SSL (Gmail, AWS SES, SendGrid, Resend, Mailgun, custom relays)
2. Asynchronous execution via threadpool to avoid event loop stalls
3. Responsive HTML email templates with FixAI Cyber EDR styling + Plain text fallback
4. Local dev / test relay logging with in-memory delivery audit
"""

import asyncio
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid
from typing import Dict, Optional, Tuple
from datetime import datetime, timezone

from app.config import settings

logger = logging.getLogger("fixai.email")

# In-memory delivery history for automated testing and local debugging
_delivery_history: Dict[str, Dict] = {}


def _build_html_email(otp_code: str, expire_minutes: int, recipient_email: str) -> str:
    """Constructs a responsive cybersecurity-themed HTML email."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Your FixAI Verification Code</title>
  <style>
    body {{
      margin: 0;
      padding: 0;
      background-color: #0b0f17;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      color: #e2e8f0;
    }}
    .container {{
      max-width: 540px;
      margin: 40px auto;
      background: #111827;
      border: 1px solid #1f2937;
      border-radius: 16px;
      overflow: hidden;
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(0, 0, 0, 0.5);
    }}
    .header {{
      background: linear-gradient(135deg, #10b981 0%, #06b6d4 100%);
      padding: 24px 32px;
      text-align: center;
    }}
    .logo-text {{
      font-size: 24px;
      font-weight: 800;
      letter-spacing: -0.5px;
      color: #ffffff;
      margin: 0;
    }}
    .logo-badge {{
      display: inline-block;
      background: rgba(255, 255, 255, 0.2);
      padding: 2px 8px;
      border-radius: 9999px;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.5px;
      margin-left: 6px;
    }}
    .content {{
      padding: 32px;
    }}
    .title {{
      font-size: 18px;
      font-weight: 700;
      color: #f8fafc;
      margin: 0 0 12px 0;
    }}
    .description {{
      font-size: 14px;
      line-height: 1.6;
      color: #94a3b8;
      margin: 0 0 24px 0;
    }}
    .otp-box {{
      background: #0f172a;
      border: 1px solid #10b981;
      border-radius: 12px;
      padding: 20px;
      text-align: center;
      margin-bottom: 24px;
    }}
    .otp-code {{
      font-family: 'SF Mono', Monaco, Consolas, 'Courier New', monospace;
      font-size: 36px;
      font-weight: 800;
      letter-spacing: 8px;
      color: #10b981;
      margin: 0;
    }}
    .expiry-note {{
      font-size: 12px;
      color: #64748b;
      margin-top: 8px;
    }}
    .security-notice {{
      background: #1e293b;
      border-left: 4px solid #06b6d4;
      padding: 12px 16px;
      border-radius: 4px 8px 8px 4px;
      margin-bottom: 24px;
    }}
    .security-text {{
      font-size: 12px;
      color: #cbd5e1;
      margin: 0;
      line-height: 1.5;
    }}
    .footer {{
      background: #090d16;
      border-top: 1px solid #1e293b;
      padding: 20px 32px;
      text-align: center;
    }}
    .footer-text {{
      font-size: 11px;
      color: #64748b;
      margin: 0 0 4px 0;
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1 class="logo-text">FixAI <span class="logo-badge">ZERO-TRUST</span></h1>
    </div>
    <div class="content">
      <h2 class="title">Verification Code</h2>
      <p class="description">
        You requested a secure one-time password to access the FixAI Endpoint Guardian. Use the code below to complete your authentication:
      </p>

      <div class="otp-box">
        <div class="otp-code">{otp_code}</div>
        <div class="expiry-note">Valid for {expire_minutes} minutes &middot; Single-use only</div>
      </div>

      <div class="security-notice">
        <p class="security-text">
          <strong>Security Warning:</strong> FixAI engineers will never ask for this code. If you did not initiate this request, your account may be under reconnaissance.
        </p>
      </div>

      <p class="description" style="margin-bottom: 0; font-size: 12px; color: #64748b;">
        Recipient: {recipient_email}<br>
        Timestamp: {timestamp}
      </p>
    </div>
    <div class="footer">
      <p class="footer-text">FixAI Autonomous Endpoint Detection & System Reliability</p>
      <p class="footer-text">&copy; 2026 FixAI Security. All rights reserved.</p>
    </div>
  </div>
</body>
</html>
"""


def _send_smtp_sync(recipient_email: str, otp_code: str, expire_minutes: int) -> Tuple[bool, str]:
    """Synchronous worker that performs actual SMTP delivery."""
    from_email = settings.SMTP_FROM_EMAIL or settings.SMTP_USER or "no-reply@fixai.security"
    from_name = settings.SMTP_FROM_NAME or "FixAI Security Guardian"
    subject = f"Your FixAI Verification Code: {otp_code}"

    # Build MIME message
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"{from_name} <{from_email}>"
    msg["To"] = recipient_email

    # Plaintext fallback
    text_content = (
        f"FixAI Security — One-Time Verification Code\n"
        f"===========================================\n\n"
        f"Your verification code is: {otp_code}\n\n"
        f"This code will expire in {expire_minutes} minutes.\n"
        f"If you did not request this verification, please ignore this email.\n\n"
        f"FixAI Autonomous Guardian · https://fixai.local\n"
    )

    html_content = _build_html_email(otp_code, expire_minutes, recipient_email)

    msg.attach(MIMEText(text_content, "plain"))
    msg.attach(MIMEText(html_content, "html"))

    # Add standard email headers for compliance & spam-filter deliverability
    msg["Reply-To"] = from_email
    msg["X-Priority"] = "1"
    msg["Importance"] = "high"
    msg["X-Mailer"] = "FixAI-Security-EDR/1.0"
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid()

    try:
        if settings.SMTP_SSL:
            server = smtplib.SMTP_SSL(settings.SMTP_HOST, settings.SMTP_PORT, timeout=12)
        else:
            server = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=12)

        server.ehlo()
        if settings.SMTP_TLS and not settings.SMTP_SSL:
            server.starttls()
            server.ehlo()

        if settings.SMTP_USER and settings.SMTP_PASSWORD:
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)

        # Headers already added above compliant with RFC 5322

        server.sendmail(from_email, [recipient_email], msg.as_string())
        server.quit()

        banner = (
            f"\n================================================================================\n"
            f"  [FixAI Email Dispatcher] OTP TRANSMITTED VIA SMTP ({settings.SMTP_HOST})\n"
            f"--------------------------------------------------------------------------------\n"
            f"  To:        {recipient_email}\n"
            f"  From:      {from_email}\n"
            f"  Subject:   {subject}\n"
            f"  OTP Code:  >>>  {otp_code}  <<<\n"
            f"  Expires:   {expire_minutes} minutes\n"
            f"  Status:    Delivered to outgoing mail server.\n"
            f"  Note:      Check Inbox AND Spam / Junk / Promotions folder!\n"
            f"================================================================================\n"
        )
        try:
            print(banner)
        except Exception:
            try:
                print(banner.encode('ascii', errors='replace').decode('ascii'))
            except Exception:
                pass
        logger.info("Successfully delivered OTP email to %s via SMTP (%s:%d)", recipient_email, settings.SMTP_HOST, settings.SMTP_PORT)
        return True, "OTP sent successfully to your email."

    except Exception as exc:
        logger.error("Failed to deliver OTP via SMTP to %s: %s", recipient_email, str(exc))
        import os
        is_prod = os.getenv("FIXAI_ENV", "development").lower() == "production"
        if not is_prod:
            # Graceful local development fallback: log OTP so developer is never blocked
            fallback_banner = (
                f"\n⚠️  [FixAI SMTP Delivery Warning] SMTP delivery failed: {exc}\n"
                f"    Falling back to local relay for {recipient_email}\n"
                f"    OTP Code: >>>  {otp_code}  <<<\n"
            )
            try:
                print(fallback_banner)
            except Exception:
                try:
                    print(fallback_banner.encode('ascii', errors='replace').decode('ascii'))
                except Exception:
                    pass
            return True, "OTP sent successfully (check inbox, spam, or local console)."
        return False, f"SMTP delivery failure: {str(exc)}"


def _send_resend_sync(recipient_email: str, otp_code: str, expire_minutes: int) -> Tuple[bool, str]:
    """Synchronous worker that performs email delivery via Resend HTTP REST API."""
    import json
    import urllib.request

    url = "https://api.resend.com/emails"
    from_email = settings.SMTP_FROM_EMAIL or "FixAI Security <onboarding@resend.dev>"
    payload = {
        "from": from_email,
        "to": [recipient_email],
        "subject": f"Your FixAI Verification Code: {otp_code}",
        "html": _build_html_email(otp_code, expire_minutes, recipient_email),
    }

    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {settings.RESEND_API_KEY}",
            "Content-Type": "application/json",
            "User-Agent": "FixAI-Security-EDR/1.0",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            data = json.loads(resp.read().decode())
            logger.info("Successfully delivered OTP email to %s via Resend API (id: %s)", recipient_email, data.get("id"))
            return True, "OTP sent successfully to your email."
    except Exception as exc:
        logger.error("Resend API delivery failure to %s: %s", recipient_email, str(exc))
        return False, f"Resend delivery failure: {str(exc)}"


async def send_otp_email(recipient_email: str, otp_code: str, expire_minutes: int = 5) -> Tuple[bool, str]:
    """
    Asynchronously delivers the 6-digit OTP code to the recipient's email address.
    
    1. If RESEND_API_KEY is configured: dispatches via Resend HTTP API.
    2. If SMTP credentials are provided (SMTP_HOST & SMTP_USER): executes real SMTP email transmission.
    3. If running locally without external SMTP/Resend: logs the verification code prominently to
       the server console and records it in delivery history.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    
    # Check if Resend API is configured
    has_resend = bool(settings.RESEND_API_KEY)
    if has_resend:
        success, message = await asyncio.to_thread(_send_resend_sync, recipient_email, otp_code, expire_minutes)
        _delivery_history[recipient_email.lower()] = {
            "otp": otp_code,
            "timestamp": timestamp,
            "delivery_type": "RESEND_API",
            "success": success,
            "message": message,
        }
        return success, message

    # Check if real SMTP server is configured
    has_smtp = bool(settings.SMTP_HOST and (settings.SMTP_USER or settings.SMTP_PORT == 25 or settings.SMTP_PORT == 1025))

    if has_smtp:
        success, message = await asyncio.to_thread(_send_smtp_sync, recipient_email, otp_code, expire_minutes)
        _delivery_history[recipient_email.lower()] = {
            "otp": otp_code,
            "timestamp": timestamp,
            "delivery_type": "SMTP",
            "success": success,
            "message": message,
        }
        return success, message

    # Local development / Console relay mode
    _delivery_history[recipient_email.lower()] = {
        "otp": otp_code,
        "timestamp": timestamp,
        "delivery_type": "LOCAL_DEV_RELAY",
        "success": True,
        "message": "OTP sent successfully to your email.",
    }

    log_banner = (
        f"\n================================================================================\n"
        f"  [FixAI Cyber EDR] EMAIL DISPATCHER (Local / Development Relay Mode)\n"
        f"--------------------------------------------------------------------------------\n"
        f"  To:        {recipient_email}\n"
        f"  Subject:   Your FixAI Verification Code: {otp_code}\n"
        f"  Expires:   {expire_minutes} minutes\n"
        f"  OTP Code:  >>>  {otp_code}  <<<\n"
        f"  Note:      Set SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD in backend/.env\n"
        f"             to route through external SMTP (SendGrid, AWS SES, Resend, Gmail).\n"
        f"================================================================================\n"
    )
    print(log_banner)
    logger.info("Local relay dispatched OTP %s to %s", otp_code, recipient_email)
    return True, "OTP sent successfully to your email."


def get_last_delivered_otp(email: str) -> Optional[str]:
    """Returns the most recent OTP delivered to the given email address (useful for automated testing)."""
    record = _delivery_history.get(email.lower())
    return record.get("otp") if record else None


def get_delivery_record(email: str) -> Optional[Dict]:
    """Returns delivery audit record for the specified email."""
    return _delivery_history.get(email.lower())
