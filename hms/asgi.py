"""
ASGI config for hms project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.1/howto/deployment/asgi/
"""

import os

from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter,URLRouter

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "hms.settings")

# Initialize Django ASGI application early to ensure apps are loaded
# before importing consumers or routing modules.
django_asgi_app = get_asgi_application()

from apps.notifications.routing import websocket_urlpatterns
from apps.notifications.middleware import JWTWebSocketMiddleWare

application = ProtocolTypeRouter({
    "http": django_asgi_app,
    "websocket": JWTWebSocketMiddleWare(
        URLRouter(websocket_urlpatterns)
    ),
})