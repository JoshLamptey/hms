"""
ASGI config for hms project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.1/howto/deployment/asgi/
"""

import os

from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter,URLRouter
from channels.security.websocket import AllowedHostsOriginValidator

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "hms.settings")

# Initialize Django ASGI application early to ensure apps are loaded
# before importing consumers or routing modules.
django_asgi_app = get_asgi_application()

from apps.notifications.routing import websocket_urlpatterns
from apps.notifications.middleware import JWTWebSocketMiddleWare

application = ProtocolTypeRouter(
    {
        # All standard HTTP requests go through Django as normal
        "http" : django_asgi_app,
        
        # WebSocket connections go through Channels
        # AllowedHostsOriginValidator ensures only requests from ALLOWED_HOSTS
        # can open a WebSocket — protects against cross-site WebSocket hijacking
        "websocket": AllowedHostsOriginValidator(
            JWTWebSocketMiddleWare(
                URLRouter(websocket_urlpatterns)
            )
        ),
    }
)
