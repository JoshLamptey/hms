from django.contrib import admin
from apps.client.models import (
    Tenant,
    LicenseType,
    License,
    LicenseHistory,
    LicenseRenewal,
)


class BaseAdmin(admin.ModelAdmin):
    readonly_fields = ("created_at", "updated_at")

    def get_list_display(self, request):
        return tuple(field.name for field in self.model._meta.fields)


class BaseAdminWithoutTimestamps(admin.ModelAdmin):
    # For models without created_at/updated_at
    def get_list_display(self, request):
        return tuple(field.name for field in self.model._meta.fields)


# Register each model with appropriate admin class
@admin.register(Tenant)
class TenantAdmin(BaseAdmin):
    pass


@admin.register(License)
class LicenseAdmin(BaseAdmin):
    pass


@admin.register(LicenseType)
class LicenseTypeAdmin(BaseAdmin):
    pass


@admin.register(LicenseHistory)
class LicenseHistoryAdmin(BaseAdminWithoutTimestamps):  # If no timestamps
    pass


@admin.register(LicenseRenewal)
class LicenseRenewalAdmin(BaseAdmin):
    pass
