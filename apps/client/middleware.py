#======Use this middleware only if you are using a multi-tenant architecture with separate schemas per tenant. and every tenant has all their information stored in their schema and there is no need for a public schema======#


# from django.db import connection
# from django.core.cache import cache
# from apps.client.models import Tenant

# class TenantMiddleware:
#     def __init__(self, get_response):
#         self.get_response = get_response

#     def __call__(self, request):
#         user = getattr(request, "user", None)

#         if user and user.is_authenticated:
#             org_slug = cache.get(f"org_slug:{user.id}")

#             if org_slug:
#                 try:
#                     tenant = Tenant.objects.only("schema_name").get(slug=org_slug)
#                     request.tenant = tenant

#                     with connection.cursor() as cursor:
#                         cursor.execute(
#                             f"SET search_path TO {tenant.schema_name}, public"
#                         )

#                 except Tenant.DoesNotExist:
#                     request.tenant = None

#         return self.get_response(request)
