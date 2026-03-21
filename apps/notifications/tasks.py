import logging
from celery import shared_task
from django.db import transaction
from django.utils import timezone
from datetime import timedelta


logger = logging.getLogger(__name__)


@shared_task(bind=True,max_retries=3, default_retry_delay=60)
def dispatch_campaign_task(self,campaign_id:int):
    """
    Fan-out task — iterates through all pending Notification records
    for a campaign and dispatches each one via the correct channel.
 
    bind=True         — gives us access to `self` for retries
    max_retries=3     — retries up to 3 times on unexpected failure
    default_retry_delay=60 — waits 60 seconds between retries
 
    Note: individual send failures (SMS/email API errors) are handled
    per-notification inside NotificationService.dispatch_notification()
    and recorded as status="failed" — they do NOT trigger a task retry.
    Task retries are only for unexpected exceptions (DB down, etc).
    """
    from apps.notifications.models import Campaign,Notification
    from apps.notifications.service import NotificationService
    
    service = NotificationService()
    
    try:
        campaign = Campaign.objects.get(id=campaign_id)
    except Campaign.DoesNotExist:
        logger.error(f"dispatch_campaign_task: Campaign {campaign_id} not found")
        return
    # Only process pending notifications — safe to re-run if task is retried
    notifications = Notification.objects.filter(
        campaign=campaign,
        status="pending"
    ).select_related("recipient", "sender")
    
    if not notifications.exists():
        logger.info(f"Campaign {campaign_id} has no pending notifications to dispatch")
        return
    
    
    logger.info(f"Campaign {campaign_id}: dispatching {notifications.count()} notifications")
    
    success_count = 0
    fail_count = 0
    
    for notification in notifications:
        try:
            result = service.dispatch_notification(notification)
            if result:
                success_count += 1
            else:
                fail_count += 1
        
        except Exception as e:
            fail_count += 1 
            logger.error(
                f"Campaign {campaign_id} unexpected error dispatching"
                f"notification {notification.uid} : {e}"
            )
            
    # Mark campaign as sent once all notifications have been processed
    # regardless of individual success/failure — the per-record status
    # tells the full story
    
    with transaction.atomic():
        campaign.is_sent = True
        campaign.sent_at = timezone.now()
        campaign.save(update_fields=["is_sent", "sent_at"])
        
        
    logger.info(
        f"Campaign {campaign_id} complete-"
        f"sent : {success_count}, failed : {fail_count}"
    )
    
    
    

@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def dispatch_scheduled_campaign_task(self, campaign_id:int):
    """
    Triggered by Celery beat at campaign.scheduled_time via apply_async(eta=...).
    Simply delegates to dispatch_campaign_task.
 
    Keeping this as a separate task means scheduled vs immediate sends
    are distinguishable in your Celery logs and monitoring.
    """
    logger.info(f"Scheduled Campaign {campaign_id} triggered - handing off to dispatch")
    
    dispatch_campaign_task.delay(campaign_id)
    
@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def push_in_app_notification_task(self, notification_id:int):
    """
    Sends a WebSocket push for a single in-app notification.
    Called by NotificationService.notify_user() so the view
    doesn't block waiting for the channel layer.
 
    Shorter retry delay (10s) since in-app pushes should be near-instant.
    If the user isn't connected, the push silently fails — that's fine,
    they'll see the notification when they next fetch their list.
    """
    from apps.notifications.models import Notification
    from apps.notifications.service import NotificationService
    
    service = NotificationService()
    
    try:
        notification = Notification.objects.select_related(
            "recipient", "sender"
        ).get(id=notification_id)
        
    except Notification.DoesNotExist:
        logger.error(f"push_in_app_notification_task : Notification {notification_id} not found")
        return
    
    result = service._push_in_app(notification)
    
    if not result["success"]:
        logger.warning(
            f"Websocket push failed for notification {notification.uid}"
            f"{result["message"]} -- user may be offline, skipping retry"
        )
        
        # We deliberately don't retry WebSocket pushes — if the user is
        # offline the push will never land anyway. They'll get it on next fetch
        
        return
    
    logger.info(f"Websocket push sent for notification {notification.uid}")
    

@shared_task
def retry_failed_notifications():
    """
    Periodic task — retries all failed notifications from the last 24 hours.
    Hook this up to Celery beat to run on a schedule (e.g. every hour).
 
    This handles transient failures like SMS gateway timeouts without
    requiring manual intervention.
    """
    from apps.notifications.models import Notification
    from apps.notifications.service import NotificationService
    
    service = NotificationService()
    
    cutoff = timezone.now() - timedelta(hours=24)
    
    failed = Notification.objects.filter(
        status = "failed",
        created_at__gte = cutoff,
        channel__in=["sms", "email"] # only retry external channel failures
    ).select_related("recipient", "sender")
    
    if not failed.exists():
        logger.info("retry_failed_notifications: nothing to retry")
        return
    
    
    logger.info(f"retry_failed_notifications : retrying {failed.count()} notifications")
    
    for notification in failed:
        # Reset to pending so dispatch_notification() will process it
        notification.status = "pending"
        notification.failure_reason = None
        notification.save(update_fields=["status", "failure_reason"])
        service.dispatch_notification(notification)
        