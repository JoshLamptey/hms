from django.db import connection
from functools import wraps
from apps.clients.models import Tenant
from django.core.cache import cache
from rest_framework.exceptions import PermissionDenied, APIException
import logging

logger = logging.getLogger(__name__)

def with_schema(view_func):
    @wraps(view_func)
    def wrapper(self, request, *args, **kwargs):
        

        user = getattr(request, "user", None)
        org_slug = None

        if user and user.is_authenticated:
            org_slug = cache.get(f"org_slug:{user.id}")

        if not org_slug:
            logger.info("Org slug missing in cache for user %s", user)
            raise PermissionDenied("Organization context missing.")

        try:
            tenant = Tenant.objects.only("schema_name").get(org_slug=org_slug)
            request.tenant = tenant

        except Tenant.DoesNotExist:
            raise PermissionDenied("Invalid organization context.")

        try:
            with connection.cursor() as cursor:
                cursor.execute(f"SET search_path TO {tenant.schema_name},public")
        

                return view_func(self, request, *args, **kwargs)

        except Exception as e:
            
            raise APIException("Database error occurred.")

    return wrapper