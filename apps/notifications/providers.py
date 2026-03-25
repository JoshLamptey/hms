import logging
import requests
import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException
from decouple import config

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
# ARKESEL SMS PROVIDER
# ──────────────────────────────────────────────

class ArkeselProvider:
    """
    Handles all SMS sending via Arkesel's SMS API.
    Docs: https://sms.arkesel.com/docs
    """

    BASE_URL = config("ARKESEL_BASE_URL", )


    def __init__(self):
        self.api_key = config("ARKESEL_API_KEY")
        self.sender_id = config("ARKESEL_SENDER_ID", default="HMS")

    def _build_url(self, phone_number: str, message: str, scheduled_time: str = None) -> str:
        url = (
            f"{self.BASE_URL}"
            f"?action=send-sms"
            f"&api_key={self.api_key}"
            f"&from={self.sender_id}"
            f"&to={phone_number}"
            f"&sms={message}"
        )
        if scheduled_time:
            url += f"&schedule={scheduled_time}"
        return url

    def send(self, phone_number: str, message: str) -> dict:
        """
        Send a single SMS immediately.
        Returns: {"success": bool, "message": str, "raw": dict}
        """
        try:
            url = self._build_url(phone_number, message)
            response = requests.get(url, timeout=10)
            data = response.json()

            success = data.get("code") == "ok"
            return {
                "success": success,
                "message": data.get("message", ""),
                "raw": data,
            }

        except requests.exceptions.Timeout:
            logger.error(f"Arkesel timeout sending to {phone_number}")
            return {"success": False, "message": "Request timed out", "raw": {}}

        except Exception as e:
            logger.error(f"Arkesel error sending to {phone_number}: {e}")
            return {"success": False, "message": str(e), "raw": {}}

    def send_bulk(self, phone_numbers: list[str], message: str) -> dict:
        """
        Send the same SMS to multiple recipients.
        Arkesel accepts comma-separated numbers in a single request.
        Returns: {"success": bool, "message": str, "raw": dict}
        """
        try:
            recipients = ",".join(phone_numbers)
            url = self._build_url(recipients, message)
            response = requests.get(url, timeout=15)
            data = response.json()

            success = data.get("code") == "ok"
            return {
                "success": success,
                "message": data.get("message", ""),
                "raw": data,
            }

        except requests.exceptions.Timeout:
            logger.error("Arkesel timeout on bulk send")
            return {"success": False, "message": "Request timed out", "raw": {}}

        except Exception as e:
            logger.error(f"Arkesel bulk send error: {e}")
            return {"success": False, "message": str(e), "raw": {}}

    def send_otp(self, phone_number: str, otp: str, expires_in_minutes: int = 10) -> dict:
        """
        Send an OTP via SMS.
        Formats a clean message and sends it immediately.
        Returns: {"success": bool, "message": str, "raw": dict}
        """
        app_name = "HMS"
        message = (
            f"Your {app_name} OTP is: {otp}. "
            f"Valid for {expires_in_minutes} minutes. "
            f"Do not share this code with anyone."
        )
        return self.send(phone_number=phone_number, message=message)

    def send_temporary_password(self, phone_number: str, password: str) -> dict:
        """
        Send a system-generated temporary password via SMS.
        Used by the send_reset_password auth flow.
        Returns: {"success": bool, "message": str, "raw": dict}
        """
        app_name = "HMS"
        message = (
            f"Your {app_name} temporary password is: {password}. "
            f"Please log in and change it immediately."
        )
        return self.send(phone_number=phone_number, message=message)

    def send_scheduled(self, phone_number: str, message: str, scheduled_time: str) -> dict:
        """
        Schedule an SMS for a future time.
        scheduled_time format: "2025-12-01 08:00 AM" (Arkesel's expected format)
        Returns: {"success": bool, "message": str, "raw": dict}
        """
        try:
            url = self._build_url(phone_number, message, scheduled_time)
            response = requests.get(url, timeout=10)
            data = response.json()

            success = data.get("code") == "ok"
            return {
                "success": success,
                "message": data.get("message", ""),
                "raw": data,
            }

        except Exception as e:
            logger.error(f"Arkesel scheduled send error: {e}")
            return {"success": False, "message": str(e), "raw": {}}


# ──────────────────────────────────────────────
# RESEND EMAIL PROVIDER
# ──────────────────────────────────────────────

# HTML templates for each email type.
# Since we don't have a custom domain yet we're using onboarding@resend.dev.
# These are inline HTML strings — swap for a template engine later if needed.

def _base_template(title: str, body_html: str) -> str:
    """
    Wraps any email body in a clean, minimal base layout.
    """
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
        <title>{title}</title>
        <style>
            body {{ font-family: Arial, sans-serif; background: #f4f4f4; margin: 0; padding: 0; }}
            .wrapper {{ max-width: 600px; margin: 40px auto; background: #ffffff; border-radius: 8px;
                        padding: 40px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
            .header {{ font-size: 22px; font-weight: bold; color: #1a1a1a; margin-bottom: 24px; }}
            .body {{ font-size: 15px; color: #444444; line-height: 1.6; }}
            .highlight {{ background: #f0f4ff; border-left: 4px solid #4f6ef7;
                          padding: 12px 16px; border-radius: 4px; margin: 20px 0;
                          font-size: 18px; font-weight: bold; color: #1a1a1a; letter-spacing: 2px; }}
            .footer {{ margin-top: 32px; font-size: 12px; color: #999999; }}
        </style>
    </head>
    <body>
        <div class="wrapper">
            <div class="header">{title}</div>
            <div class="body">{body_html}</div>
            <div class="footer">
                This email was sent automatically. Please do not reply to this email.
            </div>
        </div>
    </body>
    </html>
    """


def _login_credentials_template(full_name: str, email: str, password: str, app_name: str) -> str:
    body = f"""
        <p>Hi <strong>{full_name}</strong>,</p>
        <p>Your account has been created on <strong>{app_name}</strong>. Here are your login credentials:</p>
        <p><strong>Email:</strong> {email}</p>
        <div class="highlight">{password}</div>
        <p>Please log in and change your password immediately.</p>
        <p>If you did not expect this email, please contact your administrator.</p>
    """
    return _base_template(f"Welcome to {app_name}", body)


def _otp_template(full_name: str, otp:str, expires_in_minutes: int, app_name: str)->str:
    body = f"""
    <p>Hi <strong>{full_name}</strong>,</p>
        <p>Your one-time password (OTP) for <strong>{app_name}</strong> is:</p>
        <div class="highlight">{otp}</div>
        <p>This code expires in <strong>{expires_in_minutes} minutes</strong>.</p>
        <p>If you did not request this, you can safely ignore this email.</p>
    """
    return _base_template(f"Your OTP -- {app_name}", body)


def _temporary_password_template(full_name: str, password: str, app_name: str)->str:
    body = f"""
        <p>Hi <strong>{full_name}</strong>,</p>
        <p>A password reset was requested for your <strong>{app_name}</strong> account.</p>
        <p>Your temporary password is:</p>
        <div class="highlight">{password}</div>
        <p>This password expires in <strong>3 days</strong>. Please log in and change it immediately.</p>
        <p>If you did not request this, please contact your administrator right away !</p>
    """
    return _base_template(f"Your Temporary Password — {app_name}", body)

def _campaign_email_template(subject: str, body: str, sender_name: str, app_name: str) -> str:
    """
    Boilerplate for admin-written campaign emails.
    The body is whatever the admin typed — rendered as-is inside the layout.
    """
    formatted_body = "".join(f"<p>{line}</p>" for line in body.strip().splitlines() if line.strip())
    html_body = f"""
        <p>From <strong>{sender_name}</strong> at <strong>{app_name}</strong>:</p>
        <hr style="border: none; border-top: 1px solid #eeeeee; margin: 20px 0;" />
        {formatted_body}
    """
    return _base_template(subject, html_body)

class BrevoProvider:
    """
    Handles all email sending via Brevo (formerly Sendinblue).
    Free tier: 300 emails/day, no domain required.
    Docs: https://developers.brevo.com/docs
 
    .env vars needed:
        BREVO_API_KEY   — from Brevo dashboard → Settings → API Keys
        BREVO_FROM_EMAIL — the sender address you verified in Brevo
        BREVO_FROM_NAME  — display name for the sender (e.g. "HMS App")
        APP_NAME         — used inside email templates
    """
    def __init__(self):
        self.app_name = config("APP_NAME", default="HMS")
        self.from_email = config("BREVO_FROM_EMAIL")
        self.from_name = config("BREVO_FROM_NAME", default= self.app_name)
        
        
        # Configure the Brevo SDK with your API key
        configuration = sib_api_v3_sdk.Configuration()
        configuration.api_key["api-key"] = config("BREVO_API_KEY")
        self._api = sib_api_v3_sdk.TransactionalEmailsApi(
            sib_api_v3_sdk.ApiClient(configuration)
        )
        
    
    def _send(self, to:str | list[str], subject:str, html:str)->dict:
        """
        Core send method. All public methods call this.
        Returns: {"success": bool, "id": str|None, "message": str}
 
        Brevo expects recipients as a list of {"email": "..."} dicts.
        """
        try:
            recipients = [to] if isinstance(to,str) else to
            to_list = [{"email": addr} for addr in recipients]
            
            send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
                to=to_list,
                sender={"email" : self.from_email, "name":self.from_name},
                subject=subject,
                html_content=html,
            )
            
            response = self._api.send_transac_email(send_smtp_email)
            return {
                "success" : True,
                "id" : getattr(response, "message_id", None),
                "message" : "Email sent successfully"
            }
            
        except ApiException as e:
            logger.error(f"Brevo API error sending to {to}: {e} ")
            return{
                "success" : False,
                "id" : None,
                "message" : str(e)
            }
        
        except Exception as e:
            logger.error(f"Brevo unexpected error sending to {to} : {e}")
            return {
                "success" : False,
                "id" : None,
                "message" : str(e)
            }
            
    
    def send_login_credentials(self, to:str, full_name:str, email:str, password:str)->dict:
        """Send account credentials to a newly created user."""
        html = _login_credentials_template(full_name, email, password, self.app_name)
        return self._send(to, f"Welcome to {self.app_name}, These are your Account Details", html)
    
    
    def send_otp(self, to:str, full_name:str, otp:str, expires_in_minutes:int=10)->dict:
        """Send a one-time password."""
        html = _otp_template(full_name, otp, expires_in_minutes, self.app_name)
        return self._send(to, f"Your OTP-- {self.app_name}", html)
    
    
    def send_temporary_password(self, to:str, full_name:str, password:str)->dict:
        """Send a system-generated temporary password. Used by the forgot-password flow."""
        html = _temporary_password_template(full_name, password, self.app_name)
        
        return self._send(to, f"Your Temporary Password --{self.app_name}",  html)
    
    
    def send_campaign_email(self, to:str |list[str], subject:str, body:str, sender_name:str)->dict:
        """
        Send an admin-written campaign email.
        `body` is plain text — gets wrapped in the base HTML layout.
        """
        html = _campaign_email_template(subject, body, sender_name, self.app_name)
        
        return self._send(to, subject, html)