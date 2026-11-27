from rest_framework import serializers
from apps.notifications.models import Campaign, Notification


class NotificationListSerializer(serializers.ModelSerializer):
    recipient = serializers.SerializerMethodField()
    sender = serializers.SerializerMethodField()
    campaign = serializers.SerializerMethodField()

    def get_recipient(self, obj):
        if obj.recipient:
            return {
                "id": obj.recipient.id,
                "uid": str(obj.recipient.uid),
                "full_name": obj.recipient.get_full_name(),
                "email": obj.recipient.email,
            }
        return None

    def get_sender(self, obj):
        if obj.sender:
            return {
                "id": obj.sender.id,
                "uid": str(obj.sender.uid),
                "full_name": obj.sender.get_full_name(),
            }
        return None

    def get_campaign(self, obj):
        if obj.campaign:
            return {
                "id": obj.campaign.id,
                "uid": str(obj.campaign.uid),
                "name": obj.campaign.name,
            }
        return None

    class Meta:
        model = Notification
        fields = [
            "id",
            "uid",
            "campaign",
            "recipient",
            "sender",
            "channel",
            "subject",
            "message",
            "status",
            "is_read",
            "sent_at",
            "failure_reason",
            "recipient_address",
            "created_at",
        ]


class CampaignCreateUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Campaign
        fields = [
            "name",
            "channel",
            "subject",
            "message",
            "target_type",
            "is_scheduled",
            "scheduled_time",
            "contact",
        ]


class CampaignListSerializer(serializers.ModelSerializer):
    created_by = serializers.SerializerMethodField()
    total_recipients = serializers.SerializerMethodField()
    sent_count = serializers.SerializerMethodField()
    failed_count = serializers.SerializerMethodField()

    def get_created_by(self, obj):
        if obj.created_by:
            return {
                "id": obj.created_by.id,
                "uid": str(obj.created_by.uid),
                "full_name": obj.created_by.get_full_name(),
            }
        return None

    def get_total_recipients(self, obj):
        return obj.notifications.count()

    def get_sent_count(self, obj):
        return obj.notifications.filter(status="sent").count()

    def get_failed_count(self, obj):
        return obj.notifications.filter(status="failed").count()

    class Meta:
        model = Campaign
        fields = [
            "id",
            "uid",
            "name",
            "channel",
            "subject",
            "message",
            "target_type",
            "org_slug",
            "created_by",
            "is_scheduled",
            "scheduled_time",
            "is_sent",
            "sent_at",
            "total_recipients",
            "sent_count",
            "failed_count",
            "created_at",
            "updated_at",
        ]