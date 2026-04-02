import logging
from django.utils import timezone
from django.db import transaction

from .models import Campaign, Notification
from .providers import ArkeselProvider, BrevoProvider

logger = logging.getLogger(__name__)

sms = ArkeselProvider()
email = BrevoProvider()


class NotificationService:
    """
    Central service for all notification logic.
    Views and tasks call this — never the providers directly.

    Public methods:
        - create_campaign()        → create + dispatch a bulk campaign
        - notify_user()            → send a direct in-app notification to a user
        - send_login_credentials() → transactional email (no campaign/notification record)
        - send_otp()               → transactional email (no campaign/notification record)
        - send_password_reset()    → transactional email (no campaign/notification record)
        - dispatch_notification()  → used by Celery tasks to send a single Notification record
        - mark_all_read()          → mark all in-app notifications as read for a user
    """

    # ──────────────────────────────────────────────
    # CAMPAIGN FLOW
    # ──────────────────────────────────────────────

    def create_campaign(
        self,
        data: dict,
        created_by,
        recipient_users: list,
        org_slug: str,
    ) -> Campaign:
        """
        Creates a Campaign and fans out one Notification record per recipient.
        Kicks off Celery tasks to do the actual sending.

        Args:
            data:            Validated data from CampaignCreateSerializer
            created_by:      The request.user (admin)
            recipient_users: List of User objects resolved by the view
            org_slug:        Tenant schema slug

        Returns:
            The created Campaign instance
        """
        from .tasks import dispatch_campaign_task

        # Pop write-only fields that don't live on Campaign
        data.pop("customers", None)  
        data.pop("staff", None)

        with transaction.atomic():
            campaign = Campaign.objects.create(
                **data,
                created_by=created_by,
                org_slug=org_slug
            )
            
            notifications = []
            if campaign.target_type == "contact_upload":
                
                # Recipients come from the contact JSON field, not User records
                for contact in (campaign.contact or []):
                    address = contact.get("email") if campaign.channel else contact.get("phone_number")
                    notifications.append(
                        Notification(
                            campaign=campaign,
                            recipient=None,
                            sender = created_by,
                            channel= campaign.channel,
                            subject=campaign.subject,
                            message=campaign.message,
                            status="pending",
                            recipient_address=address
                        )
                    )
            else:
                for user in recipient_users:
                    address = self._resolve_address(user, campaign.channel)
                    notifications.append(
                        Notification(
                            campaign=campaign,
                            recipient=user,
                            sender=created_by,
                            channel=campaign.channel,
                            subject=campaign.subject,
                            message=campaign.message,
                            status="pending",
                            recipient_address=address,
                        )
                    )
            
            Notification.objects.bulk_create(notifications)
            
            
        # Kick off sending — scheduled campaigns are handled by Celery beat
        if not campaign.is_scheduled:
            dispatch_campaign_task.delay(campaign.id)
        else:
            from .tasks import dispatch_scheduled_campaign_task
            dispatch_scheduled_campaign_task.apply_async(
                args=[campaign.id],
                eta=campaign.scheduled_time,
            )

        return campaign

    # ──────────────────────────────────────────────
    # DIRECT IN-APP NOTIFICATION
    # ──────────────────────────────────────────────

    def notify_user(
        self,
        sender,
        recipient,
        message: str,
        subject: str = None,
    ) -> Notification:
        """
        Send a direct in-app notification from one user to another.
        No campaign needed. Fires the WebSocket push immediately.

        Args:
            sender:    The User triggering the notification (admin/staff)
            recipient: The User receiving the notification
            message:   Notification text
            subject:   Optional subject/title

        Returns:
            The created Notification instance
        """
        from .tasks import push_in_app_notification_task

        notification = Notification.objects.create(
            campaign=None,
            recipient=recipient,
            sender=sender,
            channel="in_app",
            subject=subject,
            message=message,
            status="sent",
            sent_at=timezone.now(),
        )
        
        result = self._push_in_app(notification)
        
        if not result["success"]:
            logger.warning(f"Websocket push failed for notification {notification.uid}: {result['message']}")

        
        return notification

    # ──────────────────────────────────────────────
    # DISPATCH — called by Celery tasks per notification
    # ──────────────────────────────────────────────

    def dispatch_notification(self, notification: Notification) -> bool:
        """
        Sends a single Notification record via its channel.
        Updates status to 'sent' or 'failed' with a reason.
        Called by Celery tasks — not the view directly.

        Returns:
            True if successful, False if failed
        """
        try:
            if notification.channel == "sms":
                result = self._send_sms(notification)
            elif notification.channel == "email":
                result = self._send_email(notification)
            elif notification.channel == "in_app":
                result = self._push_in_app(notification)
            else:
                logger.error(f"Unknown channel: {notification.channel}")
                return False

            if result["success"]:
                notification.status = "sent"
                notification.sent_at = timezone.now()
                notification.failure_reason = None
            else:
                notification.status = "failed"
                notification.failure_reason = result.get("message", "Unknown error")

            notification.save(update_fields=["status", "sent_at", "failure_reason"])
            return result["success"]

        except Exception as e:
            logger.error(f"dispatch_notification error for {notification.uid}: {e}")
            notification.status = "failed"
            notification.failure_reason = str(e)
            notification.save(update_fields=["status", "failure_reason"])
            return False

    # ──────────────────────────────────────────────
    # TRANSACTIONAL EMAILS (no Notification record)
    # ──────────────────────────────────────────────

    def send_login_credentials(self, to: str, full_name: str, password: str) -> bool:
        """
        Send login credentials to a newly created user.
        Called directly (e.g. from the users app) — no Campaign or Notification record.
        """
        result = email.send_login_credentials(
            to=to,
            full_name=full_name,
            email=to,
            password=password,
        )
        if not result["success"]:
            logger.error(f"Failed to send login credentials to {to}: {result['message']}")
        return result["success"]

    def send_otp(
        self,
        full_name: str,
        otp: str,
        expires_in_minutes: int = 10,
        email_address: str = None,
        phone_number: str = None,
    ) -> bool:
        """
        Send a one-time password via email, SMS, or both.
        At least one of email_address or phone_number must be provided.
        Called directly from auth flows — no Campaign or Notification record.
        """
        if not email_address and not phone_number:
            logger.error("send_otp called with no email or phone number")
            return False

        success = True

        if email_address:
            result = email.send_otp(
                to=email_address,
                full_name=full_name,
                otp=otp,
                expires_in_minutes=expires_in_minutes,
            )
            if not result["success"]:
                logger.error(f"Failed to send OTP email to {email_address}: {result['message']}")
                success = False

        if phone_number:
            result = sms.send_otp(
                phone_number=phone_number,
                otp=otp,
                expires_in_minutes=expires_in_minutes,
            )
            if not result["success"]:
                logger.error(f"Failed to send OTP SMS to {phone_number}: {result['message']}")
                success = False

        return success

    def send_temporary_password(
        self,
        full_name: str,
        password: str,
        email_address: str = None,
        phone_number: str = None,
    ) -> bool:
        """
        Send a system-generated temporary password via email, SMS, or both.
        Called directly from the forgot-password auth flow.
        No Campaign or Notification record created.
        """
        if not email_address and not phone_number:
            logger.error("send_temporary_password called with no email or phone number")
            return False

        success = True

        if email_address:
            result = email.send_temporary_password(
                to=email_address,
                full_name=full_name,
                password=password,
            )
            if not result["success"]:
                logger.error(f"Failed to send temp password email to {email_address}: {result['message']}")
                success = False

        if phone_number:
            result = sms.send_temporary_password(
                phone_number=phone_number,
                password=password,
            )
            if not result["success"]:
                logger.error(f"Failed to send temp password SMS to {phone_number}: {result['message']}")
                success = False

        return success

    # ──────────────────────────────────────────────
    # IN-APP UTILS
    # ──────────────────────────────────────────────

    def mark_all_read(self, user) -> int:
        """
        Mark all unread in-app notifications as read for a user.
        Returns the number of notifications updated.
        """
        updated = Notification.objects.filter(
            recipient=user,
            channel="in_app",
            is_read=False,
        ).update(is_read=True, status="read")
        return updated

    # ──────────────────────────────────────────────
    # PRIVATE HELPERS
    # ──────────────────────────────────────────────

    def _resolve_address(self, user, channel: str) -> str | None:
        """
        Snapshot the recipient's contact address at the time of campaign creation.
        Stored on the Notification record so it's accurate even if user updates later.
        """
        if channel == "email":
            return getattr(user, "email", None)
        elif channel == "sms":
            return getattr(user, "phone_number", None)
        return None

    def _send_sms(self, notification: Notification) -> dict:
        phone = notification.recipient_address
        if not phone:
            return {"success": False, "message": "No phone number on record"}
        return sms.send(phone_number=phone, message=notification.message)

    def _send_email(self, notification: Notification) -> dict:
        to = notification.recipient_address
        if not to:
            return {"success": False, "message": "No email address on record"}

        sender_name = "System"
        if notification.sender:
            sender_name = notification.sender.get_full_name() or notification.sender.username

        return email.send_campaign_email(
            to=to,
            subject=notification.subject or "(No Subject)",
            body=notification.message,
            sender_name=sender_name,
        )

    def _push_in_app(self, notification: Notification) -> dict:
        """
        Sends a WebSocket push to the recipient's channel group.
        The consumer handles delivery to the connected client.
        """
        from channels.layers import get_channel_layer
        from asgiref.sync import async_to_sync

        channel_layer = get_channel_layer()
        if not channel_layer:
            logger.error("Channel layer not configured — cannot push in-app notification")
            return {"success": False, "message": "Channel layer not configured"}

        group_name = f"notify_{notification.recipient.id}"

        payload = {
            "type": "send_notification",
            "data": {
                "id": notification.id,
                "uid": str(notification.uid),
                "message": notification.message,
                "subject": notification.subject,
                "is_read": notification.is_read,
                "timestamp": notification.created_at.isoformat(),
                "sender": (
                    {
                        "id": notification.sender.id,
                        "uid": str(notification.sender.uid),
                        "full_name": (
                            notification.sender.get_full_name()
                            or notification.sender.username
                        ),
                    }
                    if notification.sender
                    else None
                ),
            },
        }

        try:
            async_to_sync(channel_layer.group_send)(group_name, payload)
            return {"success": True, "message": "Push sent"}
        except Exception as e:
            logger.error(f"WebSocket push failed for notification {notification.uid}: {e}")
            return {"success": False, "message": str(e)}