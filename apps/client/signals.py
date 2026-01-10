from django.dispatch import receiver
from django.db.models.signals import post_save, post_delete
from apps.client.models import LicenseHistory,License,LicenseRenewal



def create_license_history(action, instance, tenant, renewal=None):
    """
    Helper function to create a LicenseHistory record.
    """
    
    try:
        LicenseHistory.objects.create(
            license=getattr(instance, "license", None),
            renewal=renewal,
            tenant = tenant,
            action = action
        )
    
    except Exception as e:
        print(f"Failed to create license history:{e}")
    

@receiver(post_save, sender=License)
def save_license_history(sender, instance,created, **kwargs):
    """
    Signal to save License history when a License instance is created or updated.
    """
    action = "CREATE" if created else "UPDATE"
    tenant = instance.tenant
    create_license_history(action, instance, tenant)
    


@receiver(post_delete, sender=License)
def delele_license_history(sender, instance, **kwargs):
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
        
        create_license_history(
            "RENEW", instance.license, tenant, renewal=instance
        )