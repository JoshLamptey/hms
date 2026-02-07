import logging
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Email, To, Content
from decouple import config
from django.template.loader import render_to_string

logger = logging.getLogger(__name__)


def send_sendgrid_email(
    recipient: str, subject: str, html_content: str, text_content: str | None = None
):
    """
    Send email via SendGrid Web API
    """
    message = Mail(
        from_email=Email(config("DEFAULT_FROM_EMAIL")),
        to_emails=To(recipient),
        subject=subject,
        html_content=html_content,
    )

    if text_content:
        message.add_content(Content("text/plain", text_content))

    try:
        sg = SendGridAPIClient(config("SENDGRID_API_KEY"))
        response = sg.send(message)

        logger.info(
            f"Email sent to {recipient} with status code {response.status_code}"
        )
    except Exception as e:
        logger.error(f"Failed to send email to {recipient}: {str(e)}")
        raise


def render_email(template: str, context: dict) -> tuple[str, str]:
    """
    Returns (html, text)
    """

    html = render_to_string(f"emails/{template}.html", context)

    try:
        text = render_to_string(f"emails/{template}.txt", context)
    except Exception as e:
        logger.warning(f"Text template for {template} not found: {str(e)}")
        text = ""

    return html, text
