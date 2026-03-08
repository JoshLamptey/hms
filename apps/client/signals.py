from django.dispatch import receiver
from django.db.models.signals import post_save, post_delete
from apps.client.models import LicenseHistory, License, LicenseRenewal,Tenant
from apps.client.utils import create_schema_for_client
import logging
logger = logging.getLogger(__name__)



def create_license_history(action, instance, tenant, renewal=None):
    """
    Helper function to create a LicenseHistory record.
    """

    try:
        LicenseHistory.objects.create(
            license=getattr(instance, "license", None),
            renewal=renewal,
            tenant=tenant,
            action=action,
        )

    except Exception as e:
        print(f"Failed to create license history:{e}")


@receiver(post_save, sender=License)
def save_license_history(sender, instance, created, **kwargs):
    """
    Signal to save License history when a License instance is created or updated.
    """
    action = "CREATE" if created else "UPDATE"
    tenant = instance.tenant
    create_license_history(action, instance, tenant)


@receiver(post_delete, sender=License)
def delete_license_history(sender, instance, **kwargs):
    """
    Signal to save License history when a License instance is deleted.
    """
    tenant = instance.tenant
    create_license_history("DELETE", instance, tenant)


@receiver(post_save, sender=LicenseRenewal)
def save_renewal_history(sender, instance, created, **kwargs):
    """
    Signal to save License history when a LicenseRenewal instance is created.
    """
    if created:
        tenant = instance.license.tenant

        create_license_history("RENEW", instance.license, tenant, renewal=instance)



@receiver(post_save, sender=Tenant)
def create_client_schema(sender, instance, created, **kwargs):
    """
    Fires after a Client is saved.
    Only acts on newly created records (not updates).
    """
    print (f"instance {instance}")
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