from django.contrib import admin
from apps.clients.models import (
    Tenant,
    LicenseType,
    License,
    LicenseRenewal,
    LicenseHistory,
)


@admin.register(Tenant)
class TenantAdmin(admin.ModelAdmin):
    list_display = [
        "name",
        "org_slug",
        "schema_name",
        "email",
        "phone_number",
        "is_active",
        "created_at",
    ]
    list_filter = ["is_active"]
    search_fields = ["name", "email", "org_slug", "schema_name"]
    ordering = ["-created_at"]
    readonly_fields = ["uid", "schema_name", "org_slug", "created_at", "updated_at"]

    fieldsets = (
        (None, {"fields": ("uid", "name", "email", "phone_number", "address", "logo")}),
        ("Schema", {"fields": ("schema_name", "org_slug")}),
        ("Status", {"fields": ("is_active",)}),
        ("Timestamps", {"fields": ("created_at", "updated_at")}),
    )


@admin.register(LicenseType)
class LicenseTypeAdmin(admin.ModelAdmin):
    list_display = [
        "name",
        "sub_name",
        "duration",
        "max_users",
        "created_at",
    ]
    search_fields = ["name", "sub_name"]
    ordering = ["-created_at"]
    readonly_fields = ["uid", "created_at", "updated_at"]

    fieldsets = (
        (None, {"fields": ("uid", "name", "sub_name", "description", "coverage")}),
        ("Limits", {"fields": ("duration", "max_users")}),
        ("Timestamps", {"fields": ("created_at", "updated_at")}),
    )


@admin.register(License)
class LicenseAdmin(admin.ModelAdmin):
    list_display = [
        "tenant",
        "license_type",
        "status",
        "quantity",
        "issue_date",
        "expiry_date",
        "created_at",
    ]
    list_filter = ["status", "license_type"]
    search_fields = ["tenant__name", "tenant__org_slug", "license_key"]
    ordering = ["-created_at"]
    readonly_fields = [
        "uid",
        "license_key",
        "issue_date",
        "created_at",
        "updated_at",
    ]
    filter_horizontal = ["users"]

    fieldsets = (
        (None, {"fields": ("uid", "tenant", "license_type", "license_key")}),
        ("Terms", {"fields": ("quantity", "status", "issue_date", "expiry_date")}),
        ("Users", {"fields": ("users",)}),
        ("Timestamps", {"fields": ("created_at", "updated_at")}),
    )


@admin.register(LicenseRenewal)
class LicenseRenewalAdmin(admin.ModelAdmin):
    list_display = [
        "license",
        "quantity",
        "renewal_date",
        "expiration_date",
        "created_at",
    ]
    search_fields = ["license__tenant__name", "license__license_key"]
    ordering = ["-created_at"]
    readonly_fields = ["uid", "renewal_date", "created_at", "updated_at"]

    fieldsets = (
        (None, {"fields": ("uid", "license", "quantity")}),
        ("Dates", {"fields": ("renewal_date", "expiration_date")}),
        ("Timestamps", {"fields": ("created_at", "updated_at")}),
    )


@admin.register(LicenseHistory)
class LicenseHistoryAdmin(admin.ModelAdmin):
    list_display = [
        "license",
        "tenant",
        "action",
        "timestamp",
    ]
    list_filter = ["action"]
    search_fields = ["license__tenant__name", "tenant__name"]
    ordering = ["-timestamp"]
    readonly_fields = ["uid", "license", "tenant", "action", "timestamp"]

    fieldsets = (
        (None, {"fields": ("uid", "license", "tenant", "action")}),
        ("Timestamps", {"fields": ("timestamp",)}),
    )
