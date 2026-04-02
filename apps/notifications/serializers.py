from rest_framework import serializers
from apps.notifications.models import Campaign, Notification
from django.utils import timezone

class NotificationListSerializer(serializers.ModelSerializer):
    """
    Used for reading notifications (list + retrieve).
    Expands sender/recipient to readable names instead of raw IDs.
    """
    sender = serializers.SerializerMethodField()
    recipient = serializers.SerializerMethodField()
    campaign_name = serializers.SerializerMethodField()
    
    class Meta:
        model = Notification
        fields = [
            "uid",
            "campaign",
            "campaign_name",
            "recipient",
            "sender",
            "channel",
            "subject",
            "message",
            "status",
            "is_read",
            "recipient_address",
            "failure_reason",
            "sent_at",
            "created_at",
        ]
        read_only_fields = fields
        
    def get_recipient(self, obj):
        if not obj.recipient:
            return None
        return {
            "id" : obj.recipient.id,
            "uid" : obj.recipient.uid,
            "full_name" : obj.recipient.get_full_name(),
            "email" : obj.recipient.email,
        }
    
    
    def get_sender(self, obj):
        if not obj.sender:
            return None
        return {
            "id" : obj.sender.id,
            "uid" : obj.sender.uid,
            "full_name" : obj.sender.get_full_name(),
            "email" : obj.sender.email,
        }
        
    
    def get_campaign_name(self, obj):
        if not obj.campaign:
            return None
        return obj.campaign.name
    

class NotificationCreateSerializer(serializers.ModelSerializer):
    """
    Used when creating a direct/task notification (no campaign).
    The sender is always set from request.user in the view — not accepted from input.
    """
    
    class Meta:
        model = Notification
        fields = [
            "recipient",
            "channel",
            "subject",
            "message",
        ]
        
    def validate_channel(self, value):
        # Direct notifications only make sense as in-app
        # SMS/email direct sends go through a Campaign
        if value != "in_app":
            raise serializers.ValidationError(
                "Direct notifications must use the 'in_app' channel. "
                "Use a Campaign to send SMS or email."
            )
        return value
    
    
class CampaignListSerializer(serializers.ModelSerializer):
    """
    Used for reading campaigns (list + retrieve).
    Includes progress stats and creator info.
    """
    created_by = serializers.SerializerMethodField()
    total_recipients = serializers.IntegerField(read_only=True)
    sent_count = serializers.IntegerField(read_only=True)
    failed_count = serializers.IntegerField(read_only=True)
    
    
    class Meta:
        model = Campaign
        fields = [
            "uid",
            "name",
            "channel",
            "subject",
            "message",
            "target_type",
            "created_by",
            "org_slug",
            "is_scheduled",
            "scheduled_time",
            "is_sent",
            "sent_at",
            "contact",
            "total_recipients",
            "sent_count",
            "failed_count",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields
        
    def get_total_recipients(self, obj):
        return obj.notifications.count()
    
    def get_sent_count(self, obj):
        return obj.notifications.filter(status="sent").count()
    
    def get_sent_failed(Self, obj):
        return obj.notifications.filter(status="failed").coount()
        
    def get_created_by(self, obj):
        if not obj.created_by:
            return None
        return {
            "id": obj.created_by.id,
            "uid": str(obj.created_by.uid),
            "full_name": obj.created_by.get_full_name() or obj.created_by.username,
            "email": obj.created_by.email,
        }
        
    

class CampaignCreateSerializer(serializers.ModelSerializer):
    """
    Used when creating a campaign.

    The view is responsible for:
    - Setting created_by from request.user
    - Setting org_slug from request.user.org_slug
    - Validating and resolving members/ministries/contact_file
    - Kicking off the Celery task after save

    This serializer only validates the raw input fields.
    """
    # Accept member IDs or ministry IDs as lists — handled in the service layer,
    # not stored on the Campaign model directly (they fan out to Notification records)
    
    staff = serializers.ListField(
        child=serializers.IntegerField(),
        required=False,
        write_only=True,
    )
    customers = serializers.ListField(
        child=serializers.IntegerField(),
        required=False,
        write_only=True,
    )
    
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
            # write-only resolution fields
            "customers",
            "staff",
        ]
        
    def validate(self, data):
        channel = data.get("channel")
        target_type = data.get("target_type")
        is_scheduled = data.get("is_scheduled", False)
        scheduled_time = data.get("scheduled_time")
        
        # Subject is required for email campaigns
        if channel == "email" and not data.get("subject"):
            raise serializers.ValidationError(
                {
                    "subject": "Subject is required for email campaigns."
                }
            )
        
        if is_scheduled and not scheduled_time:
            raise serializers.ValidationError({
                "scheduled_time": "Scheduled time is required when is_scheduled is True."
            })
        
        if target_type == "staff" and not data.get("staff"):
            raise serializers.ValidationError({
                "staff" : "Staff list is required when target_type is staff."
            })
            
        if target_type == "customers" and not data.get("customers"):
            raise serializers.ValidationError({
                "customers" : "Customers list is required when target_type is customers."
            })
            
        if target_type == "contact_upload" and not data.get("contact"):
            raise serializers.ValidationError({
                "contact" : "Contact file is required when target_type is contact_upload."
            })
        
        return data
    
    
    def validate_scheduled_time(self, value):
        if value and value <= timezone.now():
            raise serializers.ValidationError("Scheduled time must be in the future.")
        return value
    

class CampaignUpdateSerializer(serializers.ModelSerializer):
    """
    Used for partial updates on a campaign.
    Only allows updating fields that make sense to change after creation.
    Sent campaigns cannot be edited — enforced in the view.
    """
    
    class Meta:
        model = Campaign
        fields = [
            "name",
            "subject",
            "message",
            "is_scheduled",
            "scheduled_time",
        ]
    
    def validate_scheduled_time(self, value):
        if value and value <= timezone.now():
            raise serializers.ValidationError("Scheduled time must be in the future.")
        return value
    
    