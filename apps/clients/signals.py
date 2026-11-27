import logging
from django.dispatch import receiver
from django.db.models.signals import post_save, post_delete
from apps.clients.models import Tenant, License, LicenseRenewal, LicenseHistory
from apps.clients.utils import create_schema_for_client

logger = logging.getLogger(__name__)


def create_license_history(action, license, tenant):
    try:
        LicenseHistory.objects.create(
            license=license,
            tenant=tenant,
            action=action,
        )
    except Exception as e:
        logger.error(f"Failed to create license history: {e}")


@receiver(post_save, sender=License)
def save_license_history(sender, instance, created, **kwargs):
    action = LicenseHistory.Action.CREATE if created else LicenseHistory.Action.UPDATE
    create_license_history(action, instance, instance.tenant)


@receiver(post_delete, sender=License)
def delete_license_history(sender, instance, **kwargs):
    create_license_history(LicenseHistory.Action.DELETE, instance, instance.tenant)


@receiver(post_save, sender=LicenseRenewal)
def save_renewal_history(sender, instance, created, **kwargs):
    if created:
        create_license_history(
            LicenseHistory.Action.RENEW,
            instance.license,
            instance.license.tenant,
        )


@receiver(post_save, sender=Tenant)
def create_client_schema(sender, instance, created, **kwargs):
    if not created:
        return

    try:
        schema_name = create_schema_for_client(instance)
        logger.info(f"Signal: schema '{schema_name}' ready for '{instance.name}'.")
    except Exception as e:
        logger.error(
            f"Signal: failed to create schema for client '{instance.name}': {e}",
            exc_info=True,
        )
        raise
