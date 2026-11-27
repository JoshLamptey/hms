import json
import logging
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from apps.notifications.realtime import notification_group_name

logger = logging.getLogger(__name__)


class NotificationConsumer(AsyncWebsocketConsumer):

    async def connect(self):
        if self.scope.get("ticket_auth_failed"):
            await self.accept()
            await self.close(code=self.scope.get("ticket_close_code", 4401))
            return

        self.user = self.scope.get("user")

        if not self.user or not self.user.is_authenticated:
            await self.close(code=4001)
            return

        self.group_name = notification_group_name(
            self.user.tenant_id,
            self.user.id,
        )

        await self.channel_layer.group_add(
            self.group_name,
            self.channel_name,
        )

        await self.accept()
        logger.info(f"WebSocket connected: user {self.user.id}")

    async def disconnect(self, close_code):
        if hasattr(self, "group_name"):
            await self.channel_layer.group_discard(
                self.group_name,
                self.channel_name,
            )
        logger.info(f"WebSocket disconnected: code {close_code}")

    async def receive(self, text_data):
        try:
            data = json.loads(text_data)
            action = data.get("action")

            if action == "mark_read":
                notification_id = data.get("notification_id")
                if notification_id:
                    await self.mark_notification_read(notification_id)

            elif action == "ping":
                await self.send(text_data=json.dumps({"type": "pong"}))

        except json.JSONDecodeError:
            logger.warning(f"Invalid JSON received from user {self.user.id}")
        except Exception as e:
            logger.error(f"WebSocket receive error: {e}")

    async def notification_message(self, event):
        await self.send(text_data=json.dumps(event["message"]))

    @database_sync_to_async
    def mark_notification_read(self, notification_id):
        try:
            from apps.notifications.models import Notification
            notification = Notification.objects.filter(
                id=notification_id,
                recipient=self.user,
                channel="in_app",
            ).first()
            if notification:
                notification.mark_as_read()
        except Exception as e:
            logger.error(f"mark_notification_read error: {e}")
