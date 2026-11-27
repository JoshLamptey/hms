import logging
import arrow
from celery import shared_task
from django.utils import timezone
from apps.notifications.models import Campaign, Notification
from apps.notifications.service import NotificationService

logger = logging.getLogger(__name__)
service = NotificationService()

def _resolve_recipients(campaign) -> list:
    from apps.users.models import User as UserModel

    target = campaign.target_type

    if target == Campaign.TargetType.STAFF:
        return list(
            UserModel.objects.filter(
                org_slug=campaign.org_slug,
            ).exclude(id=campaign.created_by_id)
        )

    elif target == Campaign.TargetType.CUSTOMERS:
        contacts = campaign.contact or []
        return contacts

    elif target == Campaign.TargetType.CONTACT_UPLOAD:
        contacts = campaign.contact or []
        return contacts

    elif target == Campaign.TargetType.INDIVIDUAL:
        contacts = campaign.contact or []
        if not contacts:
            logger.warning(f"Campaign {campaign.id} has no contacts for INDIVIDUAL target.")
        return contacts

    return []


@shared_task(bind=True, max_retries=3)
def send_campaign_task(self, campaign_id: int) -> None:
    try:
        campaign = Campaign.objects.prefetch_related("notifications").get(id=campaign_id)

        if campaign.is_sent:
            logger.warning(f"Campaign {campaign_id} already sent. Skipping.")
            return

        recipients = _resolve_recipients(campaign)

        if not recipients:
            logger.warning(f"Campaign {campaign_id} has no recipients. Skipping.")
            return

        sender_name = (
            campaign.created_by.get_full_name()
            if campaign.created_by
            else "System"
        )

        service.send_campaign(
            campaign=campaign,
            recipients=recipients,
            sender_name=sender_name,
        )

        campaign.is_sent = True
        campaign.sent_at = timezone.now()
        campaign.save(update_fields=["is_sent", "sent_at"])

        logger.info(f"Campaign {campaign_id} sent successfully.")

    except Campaign.DoesNotExist:
        logger.error(f"Campaign {campaign_id} does not exist.")

    except Exception as e:
        logger.error(f"Campaign {campaign_id} send failed: {e}")
        raise self.retry(exc=e, countdown=60 * 5)


@shared_task(bind=True, max_retries=3)
def send_scheduled_campaigns(self) -> None:
    try:
        now = timezone.now()
        campaigns = Campaign.objects.filter(
            is_scheduled=True,
            is_sent=False,
            scheduled_time__lte=now,
        )

        for campaign in campaigns:
            send_campaign_task.delay(campaign.id)

        logger.info(f"Queued {campaigns.count()} scheduled campaigns.")

    except Exception as e:
        logger.error(f"send_scheduled_campaigns error: {e}")
        raise self.retry(exc=e, countdown=60 * 5)


@shared_task(bind=True, max_retries=3)
def send_license_expiry_notices(self) -> None:
    try:
        from apps.clients.models import License

        expiry_threshold = arrow.now().shift(days=5).date()
        expiring_licenses = License.objects.select_related(
            "license_type", "tenant"
        ).prefetch_related("users").filter(
            expiry_date__lte=expiry_threshold,
            status=License.LicenseStatus.ACTIVE,
        )

        for license in expiring_licenses:
            tenant = license.tenant
            service.send_license_expiry_notice(
                to=tenant.email,
                full_name=tenant.name,
                expiration_date=license.expiry_date,
                license_name=license.name,
            )

            admin_users = license.users.filter(role__name="ADMIN")
            for user in admin_users:
                service.send_license_expiry_notice(
                    to=user.email,
                    full_name=user.get_full_name(),
                    expiration_date=license.expiry_date,
                    license_name=license.name,
                )

        logger.info(f"Sent expiry notices for {expiring_licenses.count()} licenses.")

    except Exception as e:
        logger.error(f"send_license_expiry_notices error: {e}")
        raise self.retry(exc=e, countdown=60 * 5)


@shared_task(bind=True, max_retries=3)
def retry_failed_notifications(self) -> None:
    try:
        failed = Notification.objects.filter(
            status=Notification.Status.FAILED,
        ).select_related("campaign", "recipient")

        for notification in failed:
            if not notification.recipient_address:
                continue

            try:
                if notification.channel == Notification.Channel.EMAIL:
                    from apps.notifications.providers import BrevoProvider
                    brevo = BrevoProvider()
                    result = brevo.send_campaign_email(
                        to=notification.recipient_address,
                        subject=notification.subject or "",
                        body=notification.message,
                        sender_name="System",
                    )
                elif notification.channel == Notification.Channel.SMS:
                    from apps.notifications.providers import ArkeselProvider
                    arkesel = ArkeselProvider()
                    result = arkesel.send(
                        phone_number=notification.recipient_address,
                        message=notification.message,
                    )
                else:
                    continue

                if result.get("success"):
                    notification.status = Notification.Status.SENT
                    notification.sent_at = timezone.now()
                    notification.failure_reason = None
                    notification.save(update_fields=["status", "sent_at", "failure_reason"])

            except Exception as e:
                logger.error(f"Retry failed for notification {notification.id}: {e}")

        logger.info(f"Retried {failed.count()} failed notifications.")

    except Exception as e:
        logger.error(f"retry_failed_notifications error: {e}")
        raise self.retry(exc=e, countdown=60 * 5)