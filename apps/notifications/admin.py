from django.contrib import admin

# Register your models here.

from django.contrib import admin
from apps.notifications.models import Campaign, Notification


@admin.register(Campaign)
class CampaignAdmin(admin.ModelAdmin):
    list_display = [
        "name",
        "channel",
        "target_type",
        "org_slug",
        "is_scheduled",
        "is_sent",
        "sent_at",
        "created_at",
    ]
    list_filter = ["channel", "target_type", "is_scheduled", "is_sent"]
    search_fields = ["name", "org_slug", "created_by__email", "created_by__username"]
    ordering = ["-created_at"]
    readonly_fields = [
        "uid",
        "org_slug",
        "is_sent",
        "sent_at",
        "created_at",
        "updated_at",
        "total_recipients",
        "sent_count",
        "failed_count",
    ]

    fieldsets = (
        (None, {"fields": ("uid", "name", "channel", "target_type", "created_by", "org_slug")}),
        ("Content", {"fields": ("subject", "message", "contact")}),
        ("Schedule", {"fields": ("is_scheduled", "scheduled_time")}),
        ("Status", {"fields": ("is_sent", "sent_at")}),
        ("Stats", {"fields": ("total_recipients", "sent_count", "failed_count")}),
        ("Timestamps", {"fields": ("created_at", "updated_at")}),
    )


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = [
        "channel",
        "recipient",
        "sender",
        "status",
        "is_read",
        "sent_at",
        "created_at",
    ]
    list_filter = ["channel", "status", "is_read"]
    search_fields = [
        "recipient__email",
        "recipient__username",
        "sender__email",
        "sender__username",
        "recipient_address",
    ]
    ordering = ["-created_at"]
    readonly_fields = [
        "uid",
        "campaign",
        "recipient",
        "sender",
        "channel",
        "status",
        "is_read",
        "sent_at",
        "recipient_address",
        "failure_reason",
        "created_at",
    ]

    fieldsets = (
        (None, {"fields": ("uid", "campaign", "channel")}),
        ("Parties", {"fields": ("recipient", "sender", "recipient_address")}),
        ("Content", {"fields": ("subject", "message")}),
        ("Status", {"fields": ("status", "is_read", "sent_at", "failure_reason")}),
        ("Timestamps", {"fields": ("created_at",)}),
    )