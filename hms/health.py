"""Liveness and readiness endpoints for container health checks."""

from django.core.cache import cache
from django.db import connection
from django.http import JsonResponse


def live(request):
    return JsonResponse({"status": "live"})


def ready(request):
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
    except Exception:
        return JsonResponse({"status": "not_ready", "dependency": "database"}, status=503)

    try:
        cache.set("health:ready", "ok", timeout=5)
        if cache.get("health:ready") != "ok":
            raise RuntimeError("cache miss")
    except Exception:
        return JsonResponse({"status": "not_ready", "dependency": "cache"}, status=503)

    return JsonResponse({"status": "ready"})
