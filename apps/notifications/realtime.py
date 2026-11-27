import logging

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.db import transaction

logger = logging.getLogger(__name__)


def notification_group_name(tenant_id, user_id):
    tenant_key = tenant_id if tenant_id is not None else "shared"
    return f"notifications_{tenant_key}_{user_id}"


def notify_notification_created(notification):
    """Publish a persisted in-app notification after its transaction commits."""
    if notification.channel != "in_app" or notification.recipient_id is None:
        return

    payload = {
        "id": notification.id,
        "uid": str(notification.uid),
        "subject": notification.subject,
        "message": notification.message,
        "channel": notification.channel,
        "status": notification.status,
        "is_read": notification.is_read,
        "sent_at": notification.sent_at.isoformat() if notification.sent_at else None,
        "created_at": notification.created_at.isoformat(),
    }
    group_name = notification_group_name(
        notification.recipient.tenant_id,
        notification.recipient_id,
    )
    transaction.on_commit(lambda: _publish_notification(group_name, payload))


def _publish_notification(group_name, payload):
    try:
        channel_layer = get_channel_layer()
        if channel_layer is None:
            return
        async_to_sync(channel_layer.group_send)(
            group_name,
            {"type": "notification_message", "message": payload},
        )
    except Exception:
        logger.exception("Failed to publish in-app notification over WebSocket.")
