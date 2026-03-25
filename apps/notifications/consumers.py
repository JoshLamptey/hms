import json
import logging
from channels.generic.websocket import AsyncJsonWebsocketConsumer
from django.contrib.auth.models import AnonymousUser


logger = logging.getLogger(__name__)

class NotificationConsumer(AsyncJsonWebsocketConsumer):
    """
    WebSocket consumer for real-time in-app notifications.
 
    Flow:
        1. Client connects to ws://host/ws/notifications/?token=<jwt>
        2. JWTWebSocketMiddleware authenticates and sets scope["user"]
        3. Consumer joins the user's personal group: notify_<user_id>
        4. When a notification is created, the service calls
           channel_layer.group_send() to this group
        5. Consumer receives it and forwards to the client over WebSocket
 
    Each user has their own isolated group so pushes are always targeted.
    """
    
    async def connect(self):
        user = self.scope.get("user")
        
        # Reject unauthenticated connections immediately
        if not user or isinstance(user, AnonymousUser):
            logger.warning("Rejected unauthenticated websocket connection")
            await self.close(code=4001)
            return
        
        # Each user gets their own group keyed by their integer PK
        # Using user.id (integer) rather than uid (UUID) keeps group names short
        
        self.group_name = f"notify_{user.id}"
        self.user = user
        
        
        # Join the group — this is what allows group_send() to reach this consumer
        await self.channel_layer.group_add(
            self.group_name,
            self.channel_name
        )
        
        await self.accept()
        
        logger.info(f"Websocket connected: user={user.id} group={self.group_name}")
        
        # Send a confirmation so the client knows it's live
        await self.send(text_data=json.dumps({
            "type" : "connection.established",
            "message" : "Connected to notification stream"
        }))
        
    
    async def disconnect(self, close_code):
        # Leave the group on disconnect so stale channels don't pile up
        if hasattr (self, "group_name"):
            await self.channel_layer.group_discard(
                self.group_name,
                self.channel_name
            )
            logger.info(
                f"Websocket disconnected : user={self.user.id}"
                f"group={self.group_name} code={close_code}"
            )
            
    async def recieve(self, text_data=None, bytes_data=None):
        """
        Handle messages sent FROM the client TO the server.
 
        Currently supports:
            - mark_read: mark a specific notification as read
            - ping: keepalive check
 
        The client sends JSON: {"type": "mark_read", "uid": "<notification_uid>"}
        """
        if not text_data:
            return
        
        try:
            data = json.loads(text_data)
            message_type= data.get("type")
            
            if message_type == "ping":
                await self.send(text_data=json.dumps({"type" : "pong"}))
                
            elif message_type == "mark_read":
                uid = data.get("uid")
                if uid:
                    await self._mark_notification_read(uid)
                
            else :
                logger.warning(f"Unknown websocket message type: {message_type}")
        
        except json.JSONDecodeError:
            logger.warning("Recieved invalid JSON over websocket")
            
    
    
    # ──────────────────────────────────────────────
    # GROUP MESSAGE HANDLERS
    # These methods are called when channel_layer.group_send()
    # is used from the service/tasks. The "type" field in the
    # group_send payload maps to the method name (dots → underscores).
    # ──────────────────────────────────────────────
    
    
    async def send_notification(self, event):
        """
        Receives a notification from the channel layer and forwards it
        to the connected WebSocket client.
 
        Called when type="send_notification" is used in group_send().
        The "data" key contains the payload the client receives.
        """
        
        await self.send(text_data=json.dumps({
            "type" : "notification.new",
            "data" : event["data"]
        }))
        
    # ──────────────────────────────────────────────
    # PRIVATE HELPERS
    # ──────────────────────────────────────────────
    
    @staticmethod
    async def _mark_notification_read(uid:str):
        """
        Marks a notification as read when the client sends a mark_read event.
        Runs the DB update in a thread pool since Django ORM is synchronous.
        """
        from channels.db import database_sync_to_async
        from apps.notifications.models import Notification
        
        @database_sync_to_async
        def _update(uid):
            Notification.objects.filter(uid=uid).update(
                is_read=True,
                status = "read"
            )
            
        await _update(uid)
        logger.info(f"Notification {uid} marked as read via Websocket")