#=======update all of this after you set up user and notification management====



from celery import shared_task
from apps.client.models import License
from apps.notifications.notify import Notify
from apps.notifications.utils import create_notification
from apps.users.utils import send_notification
import arrow

notify = Notify()

@shared_task(bind=True)
def send_license_expiry_notice(self):
    try:
        now = arrow.utcnow()
        # Define expiration threshold (e.g., 5 days from now)
        expiration_threshold = now.shift(days=5)
        expiring_licenses = License.objects.select_related(
            "license_type", "organisation"
        ).prefetch_related("users").filter(
            expiry_date__gte=now.datetime,
            expiry_date__lte=expiration_threshold.datetime
        )
        
        for license in expiring_licenses:
            tenant = license.tenant
            message = " Dear License holder, your license is 5 days away from expiry, Please Contact your admin and get it renewed."
            #send both email and sms 
            context = {
                "template": "license-expiration",
                "context": {
                    "tenant": tenant,
                    "license": license,
                    "expiration_date": license.expiry_date,
                },
            }
            send_notification.delay(tenant.email, context)
            notify.send_notification(
                medium='sms',
                recipient=tenant.phone_number,
                message=message
            )
            
            # Send notifications to admin users
            admin_users = license.users.filter(role__name="admin_user")
            for user in admin_users:
                create_notification(
                    sender_user = user,
                    recipient_user = user,
                    message=f"Your license for {org.name} is expiring on {license.expiry_date.strftime('%Y-%m-%d')}.",
                )
            
    except Exception as e:
        print(f"Error in send_license_expiration_notification: {e}")
        self.retry(exc=e, countdown=60*5)# Retry after 5 minutes