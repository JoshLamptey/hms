import logging
from django.utils import timezone
from apps.notifications.models import Notification
from apps.notifications.providers import ArkeselProvider, BrevoProvider

logger = logging.getLogger(__name__)

sms = ArkeselProvider()
email = BrevoProvider()


class NotificationService:

    # ──────────────────────────────────────────────
    # AUTH NOTIFICATIONS
    # ──────────────────────────────────────────────

    def send_login_credentials(
        self,
        to: str,
        full_name: str,
        password: str,
        email_address: str = None,
        phone_number: str = None,
    ) -> None:
        try:
            if email_address or "@" in to:
                address = email_address or to
                email.send_login_credentials(
                    to=address,
                    full_name=full_name,
                    email=address,
                    password=password,
                )
            elif phone_number or to.startswith("+"):
                number = phone_number or to
                sms.send_temporary_password(
                    phone_number=number,
                    password=password,
                )
        except Exception as e:
            logger.error(f"send_login_credentials error: {e}")

    def send_otp(
        self,
        full_name: str,
        otp: str,
        expires_in_minutes: int = 10,
        email_address: str = None,
        phone_number: str = None,
    ) -> None:
        try:
            if email_address:
                email.send_otp(
                    to=email_address,
                    full_name=full_name,
                    otp=otp,
                    expires_in_minutes=expires_in_minutes,
                )
            elif phone_number:
                sms.send_otp(
                    phone_number=phone_number,
                    otp=otp,
                    expires_in_minutes=expires_in_minutes,
                )
        except Exception as e:
            logger.error(f"send_otp error: {e}")

    def send_password_reset_otp(
        self,
        to: str,
        full_name: str,
        otp: str,
        expires_in_minutes: int = 10,
    ) -> None:
        try:
            if "@" in to:
                email.send_otp(
                    to=to,
                    full_name=full_name,
                    otp=otp,
                    expires_in_minutes=expires_in_minutes,
                )
            else:
                sms.send_otp(
                    phone_number=to,
                    otp=otp,
                    expires_in_minutes=expires_in_minutes,
                )
        except Exception as e:
            logger.error(f"send_password_reset_otp error: {e}")

    def send_temporary_password(
        self,
        full_name: str,
        password: str,
        email_address: str = None,
        phone_number: str = None,
    ) -> None:
        try:
            if email_address:
                email.send_temporary_password(
                    to=email_address,
                    full_name=full_name,
                    password=password,
                )
            elif phone_number:
                sms.send_temporary_password(
                    phone_number=phone_number,
                    password=password,
                )
        except Exception as e:
            logger.error(f"send_temporary_password error: {e}")

    # ──────────────────────────────────────────────
    # LICENSE NOTIFICATIONS
    # ──────────────────────────────────────────────

    def send_license_expiry_notice(
        self,
        to: str,
        full_name: str,
        expiration_date,
        license_name: str,
    ) -> None:
        try:
            email._send(
                to=to,
                subject="License Expiry Notice",
                html=f"""
                    <p>Hi <strong>{full_name}</strong>,</p>
                    <p>Your <strong>{license_name}</strong> license is expiring on
                    <strong>{expiration_date}</strong>.</p>
                    <p>Please contact your administrator to renew it before it expires.</p>
                """,
            )
        except Exception as e:
            logger.error(f"send_license_expiry_notice error: {e}")

    # ──────────────────────────────────────────────
    # CAMPAIGN NOTIFICATIONS
    # ──────────────────────────────────────────────

    def send_campaign(
        self,
        campaign,
        recipients: list,
        sender_name: str,
    ) -> None:
        for recipient in recipients:
            notification = Notification.objects.create(
                campaign=campaign,
                recipient=recipient if hasattr(recipient, "id") else None,
                channel=campaign.channel,
                subject=campaign.subject,
                message=campaign.message,
                recipient_address=getattr(recipient, "email", None)
                or getattr(recipient, "phone_number", None)
                or str(recipient),
            )

            try:
                if campaign.channel == Notification.Channel.EMAIL:
                    result = email.send_campaign_email(
                        to=notification.recipient_address,
                        subject=campaign.subject or campaign.name,
                        body=campaign.message,
                        sender_name=sender_name,
                    )
                elif campaign.channel == Notification.Channel.SMS:
                    result = sms.send(
                        phone_number=notification.recipient_address,
                        message=campaign.message,
                    )
                else:
                    notification.status = Notification.Status.PENDING
                    notification.save(update_fields=["status"])
                    continue

                if result.get("success"):
                    notification.status = Notification.Status.SENT
                    notification.sent_at = timezone.now()
                else:
                    notification.status = Notification.Status.FAILED
                    notification.failure_reason = result.get("message", "Unknown error")

            except Exception as e:
                logger.error(f"Campaign send error for {notification.recipient_address}: {e}")
                notification.status = Notification.Status.FAILED
                notification.failure_reason = str(e)

            notification.save(update_fields=["status", "sent_at", "failure_reason"])

    # ──────────────────────────────────────────────
    # IN-APP NOTIFICATIONS
    # ──────────────────────────────────────────────

    def send_in_app(
        self,
        recipient,
        message: str,
        subject: str = None,
        sender=None,
        campaign=None,
    ) -> Notification:
        try:
            notification = Notification.objects.create(
                campaign=campaign,
                recipient=recipient,
                sender=sender,
                channel=Notification.Channel.IN_APP,
                subject=subject,
                message=message,
                status=Notification.Status.SENT,
                sent_at=timezone.now(),
                recipient_address=recipient.email,
            )
            from apps.notifications.realtime import notify_notification_created

            notify_notification_created(notification)
            return notification
        except Exception as e:
            logger.error(f"send_in_app error: {e}")
            return None
