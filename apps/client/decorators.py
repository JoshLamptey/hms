from django.db import connection
from functools import wraps
from apps.client.models import Tenant
from django.core.cache import cache
from rest_framework.exceptions import PermissionDenied, APIException


def with_schema(view_func):
    @wraps(view_func)
    def wrapper(self, request, *args, **kwargs):
        print("\n=== START with_schema decorator ===")

        user = getattr(request, "user", None)
        org_slug = None

        if user and user.is_authenticated:
            org_slug = cache.get(f"org_slug:{user.id}")
            print(f"Org slug from cache:{org_slug}")

        if not org_slug:
            print("Org slug missing in cache for user %s", user)
            raise PermissionDenied("Organization context missing.")

        try:
            tenant = Tenant.objects.only("schema_name").get(org_slug=org_slug)
            request.tenant = tenant
            print(f"Tenant found: {tenant.schema_name}")

        except Tenant.DoesNotExist:
            raise PermissionDenied("Invalid organization context.")

        try:
            print(f"Setting search_path to schema: {tenant.schema_name}")
            with connection.cursor() as cursor:
                cursor.execute(f"SET search_path TO {tenant.schema_name},public")
                print("Search path set successfully.")

                return view_func(self, request, *args, **kwargs)

        except Exception as e:
            print(f"Error setting search_path: {str(e)}")
            raise APIException("Database error occurred.")

    return wrapper
