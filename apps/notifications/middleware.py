import logging
from urllib.parse import parse_qs

from channels.db import database_sync_to_async
from channels.middleware import BaseMiddleware
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser

from apps.notifications.tickets import consume_ticket

logger = logging.getLogger(__name__)


@database_sync_to_async
def _consume_ticket(ticket):
    return consume_ticket(ticket)


@database_sync_to_async
def _load_user(user_id, tenant_id):
    User = get_user_model()
    try:
        user = User.objects.select_related("tenant").get(
            pk=user_id,
            tenant_id=tenant_id,
        )
    except User.DoesNotExist:
        return None

    if (
        not user.is_active
        or user.is_blocked
        or not user.login_enabled
        or user.status != User.Status.ACTIVE
        or (user.tenant_id is not None and not user.tenant.is_active)
    ):
        return None
    return user


class TicketAuthMiddleware(BaseMiddleware):
    async def __call__(self, scope, receive, send):
        scope = dict(scope)
        scope["user"] = AnonymousUser()
        scope["ticket_auth_failed"] = True
        scope["ticket_close_code"] = 4401

        query = parse_qs(scope.get("query_string", b"").decode())
        ticket_values = query.get("ticket", [])
        if "token" in query or len(ticket_values) != 1:
            logger.warning("WebSocket ticket rejected: missing or invalid ticket parameter.")
            return await super().__call__(scope, receive, send)

        headers = dict(scope.get("headers", []))
        origin = headers.get(b"origin", b"").decode()
        allowed_origins = getattr(settings, "WS_ALLOWED_ORIGINS", [])
        if origin and origin not in allowed_origins:
            logger.warning("WebSocket ticket rejected: origin not allowed.")
            scope["ticket_close_code"] = 4403
            return await super().__call__(scope, receive, send)

        try:
            claims = await _consume_ticket(ticket_values[0])
        except Exception:
            logger.exception("WebSocket ticket store unavailable.")
            scope["ticket_close_code"] = 4500
            return await super().__call__(scope, receive, send)

        if not claims:
            logger.warning("WebSocket ticket rejected: expired or already consumed.")
        elif origin != claims.get("origin"):
            logger.warning("WebSocket ticket rejected: origin mismatch.")
            scope["ticket_close_code"] = 4403
        else:
            try:
                user = await _load_user(claims["user_id"], claims["tenant_id"])
            except Exception:
                logger.exception("WebSocket ticket user lookup failed.")
                scope["ticket_close_code"] = 4500
            else:
                if user:
                    scope["user"] = user
                    scope["tenant_id"] = user.tenant_id
                    scope["ticket_auth_failed"] = False
                else:
                    logger.warning("WebSocket ticket rejected: user is unavailable.")

        return await super().__call__(scope, receive, send)
