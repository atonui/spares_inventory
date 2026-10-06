"""Email helpers for user-facing account workflows."""

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from fastapi import HTTPException


def send_password_reset_email(
    *,
    email: str,
    token: str,
    frontend_url: str,
    smtp_server: str,
    smtp_port: int,
    smtp_username: str,
    smtp_password: str,
    logger,
):
    reset_link = f"{frontend_url}/reset_password.html?token={token}"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Password Reset Request - Inventory System"
    msg["From"] = smtp_username
    msg["To"] = email

    html = f"""
    <html>
      <body style="font-family: Arial, sans-serif; padding: 20px;">
        <div style="max-width: 600px; margin: 0 auto; background: #f8f9fa; padding: 30px; border-radius: 8px;">
            <h2 style="color: #333;">Password Reset Request</h2>
            <p>You requested to reset your password for the Inventory Management System.</p>
            <p>Click the button below to reset your password:</p>
            <div style="text-align: center; margin: 30px 0;">
                <a href="{reset_link}"
                   style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                          color: white;
                          padding: 12px 30px;
                          text-decoration: none;
                          border-radius: 8px;
                          display: inline-block;">
                    Reset Password
                </a>
            </div>
            <p style="color: #666; font-size: 14px;">
                Or copy and paste this link into your browser:<br>
                <a href="{reset_link}">{reset_link}</a>
            </p>
            <p style="color: #666; font-size: 14px;">
                This link will expire in 1 hour.<br>
                If you didn't request this, please ignore this email.
            </p>
        </div>
      </body>
    </html>
    """

    msg.attach(MIMEText(html, "html"))

    try:
        if logger:
            logger.info(f"Attempting to send password reset email to {email}")
        with smtplib.SMTP(smtp_server, smtp_port, timeout=10) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.send_message(msg)
        if logger:
            logger.info(f"Password reset email sent successfully to {email}")
    except smtplib.SMTPAuthenticationError as e:
        if logger:
            logger.error(f"SMTP Authentication failed: {e}")
        raise HTTPException(
            status_code=500,
            detail="Email configuration error. Please contact administrator.",
        )
    except smtplib.SMTPException as e:
        if logger:
            logger.error(f"SMTP error sending email: {e}")
        raise HTTPException(status_code=500, detail="Failed to send reset email.")
    except Exception as e:
        if logger:
            logger.error(f"Unexpected error sending email: {e}")
        raise HTTPException(status_code=500, detail="Failed to send reset email.")
