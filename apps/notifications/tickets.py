import json
import secrets
from functools import lru_cache

from django.conf import settings
from redis import Redis

TICKET_TTL_SECONDS = 60
_TICKET_KEY_PREFIX = "websocket_ticket:"
_CONSUME_SCRIPT = """
local value = redis.call('GET', KEYS[1])
if value then
    redis.call('DEL', KEYS[1])
end
return value
"""


@lru_cache(maxsize=1)
def _redis_client():
    return Redis.from_url(
        settings.CACHES["default"]["LOCATION"],
        decode_responses=True,
    )


def issue_ticket(user, origin):
    client = _redis_client()
    for _ in range(3):
        ticket = secrets.token_urlsafe(32)
        claims = json.dumps({
            "user_id": user.pk,
            "tenant_id": user.tenant_id,
            "origin": origin,
        })
        if client.set(
            f"{_TICKET_KEY_PREFIX}{ticket}",
            claims,
            ex=TICKET_TTL_SECONDS,
            nx=True,
        ):
            return ticket
    raise RuntimeError("Could not allocate a unique WebSocket ticket.")


def consume_ticket(ticket):
    raw_claims = _redis_client().eval(
        _CONSUME_SCRIPT,
        1,
        f"{_TICKET_KEY_PREFIX}{ticket}",
    )
    return json.loads(raw_claims) if raw_claims else None
