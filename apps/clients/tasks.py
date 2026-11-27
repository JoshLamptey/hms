from celery import shared_task
from apps.clients.models import License
from apps.notifications.service import NotificationService
import arrow
import logging

logger = logging.getLogger(__name__)

service = NotificationService()

@shared_task(bind=True)
def send_license_expiry_notice(self):
    try:
        now = arrow.utcnow()
        expiration_threshold = now.shift(days=5)

        expiring_licenses = License.objects.select_related(
            "license_type", "tenant"
        ).prefetch_related("users").filter(
            expiry_date__gte=now.date(),
            expiry_date__lte=expiration_threshold.date(),
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

    except Exception as e:
        logger.error(f"Error in send_license_expiry_notice: {e}")
        self.retry(exc=e, countdown=60 * 5)
