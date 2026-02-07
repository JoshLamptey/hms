import logging
from celery import shared_task
from apps.users.services import send_sendgrid_email, render_email

logger = logging.getLogger(__name__)


@shared_task(
    bind=True,
    autoretry_for=(Exception,),
    retry_kwargs={"max_retries": 3, "countdown": 60},
)
def send_notification(self, recipient: str, context: dict):
    """
    context = {
        "template": "otp",
        "subject": "Your OTP Code",
        "context": {...}
    }
    """

    logger.info(
        f"Preparing to send notification to {recipient} with context: {context}"
    )
    html, text = render_email(
        template=context["template"],
        context=context["context"],
    )

    try:
        send_sendgrid_email(
            recipient=recipient,
            subject=context["subject"],
            html_content=html,
            text_content=text,
        )
    except Exception as e:
        logger.error(f"Failed to send notification to {recipient}: {str(e)}")
        self.retry(exc=e)

    logger.info(f"Notification sent to {recipient}")


@shared_task
def send_login_credentials(email, password):
    context = {
        "template": "login-credentials",
        "subject": "Login Credentials",
        "context": {
            "email": email,
            "password": password,
        },
    }

    send_notification.delay(
        recipient=email,
        context=context,
    )
