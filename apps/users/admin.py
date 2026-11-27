from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from apps.users.models import User, UserRole, UserGroup, RefreshToken, UserRateLimitFlag


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = [
        "username",
        "email",
        "first_name",
        "last_name",
        "role",
        "tenant",
        "status",
        "is_blocked",
        "login_enabled",
        "created_at",
    ]
    list_filter = ["role", "tenant", "status", "is_blocked", "gender"]
    search_fields = ["username", "email", "first_name", "last_name", "phone_number"]
    ordering = ["-created_at"]
    readonly_fields = ["created_at", "updated_at", "last_login", "password_expiry"]

    fieldsets = (
        (None, {"fields": ("username", "password")}),
        (
            "Personal Info",
            {
                "fields": (
                    "first_name",
                    "middle_name",
                    "last_name",
                    "email",
                    "phone_number",
                    "gender",
                    "image",
                )
            },
        ),
        ("Organisation", {"fields": ("tenant", "org_slug", "role")}),
        (
            "Account Status",
            {"fields": ("status", "is_blocked", "blocked_at", "login_enabled")},
        ),
        ("Password", {"fields": ("password_changed", "password_expiry")}),
        ("Timestamps", {"fields": ("created_at", "updated_at", "last_login")}),
    )

    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": (
                    "username",
                    "email",
                    "first_name",
                    "last_name",
                    "phone_number",
                    "role",
                    "tenant",
                    "password1",
                    "password2",
                ),
            },
        ),
    )


@admin.register(UserRole)
class UserRoleAdmin(admin.ModelAdmin):
    list_display = ["name", "uid", "created_at"]
    search_fields = ["name"]
    ordering = ["-created_at"]
    readonly_fields = ["uid", "created_at", "updated_at"]


@admin.register(UserGroup)
class UserGroupAdmin(admin.ModelAdmin):
    list_display = ["name", "tenant", "is_global", "created_at"]
    list_filter = ["is_global", "tenant"]
    search_fields = ["name"]
    ordering = ["-created_at"]
    readonly_fields = ["uid", "created_at", "updated_at"]
    filter_horizontal = ["users", "permissions"]


@admin.register(RefreshToken)
class RefreshTokenAdmin(admin.ModelAdmin):
    list_display = ["user", "jti", "is_revoked", "expires_at", "created_at"]
    list_filter = ["is_revoked"]
    search_fields = ["user__username", "user__email"]
    ordering = ["-created_at"]
    readonly_fields = ["jti", "token", "created_at", "expires_at", "last_used_at"]


@admin.register(UserRateLimitFlag)
class UserRateLimitFlagAdmin(admin.ModelAdmin):
    list_display = ["user", "reason", "count", "is_blocked", "last_flagged_at"]
    list_filter = ["is_blocked"]
    search_fields = ["user__username", "user__email", "reason"]
    ordering = ["-last_flagged_at"]
    readonly_fields = ["uid", "last_flagged_at"]
