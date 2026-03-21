from django.urls import re_path
from apps.notifications import consumers

websocket_urlpatterns = [
    # ws://yourhost/ws/notifications/
    # The consumer handles auth via the JWTWebSocketMiddleware —
    # by the time the connection reaches here, request.user is already set.
    re_path(r"^ws/notifications/$", consumers.NotificationConsumer.as_asgi()),
]