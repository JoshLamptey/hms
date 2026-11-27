from django.urls import re_path
from apps.notifications import consumers

websocket_urlpatterns = [
    # ws://yourhost/ws/notifications/
    # The ASGI middleware authenticates a short-lived, one-time ticket.
    re_path(r"^ws/notifications/$", consumers.NotificationConsumer.as_asgi()),
]
