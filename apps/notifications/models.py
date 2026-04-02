import uuid
from django.db import models

class Campaign(models.Model):
    """
    Represents a bulk notification send initiated by an admin.
    One Campaign can have many Notification records (one per recipient).
    """
    CHANNEL_CHOICES = [
        ("sms", "SMS"),
        ("email", "Email"),
        ("in_app", "In-App")
    ]
    
    TARGET_TYPE_CHOICES = [
        ("staff", "STAFF"),
        ("customers", "CUSTOMERS"),
        ("contact_upload", "CONTACT_UPLOAD"),
        ("individual", "INDIVIDUAL")
    ]
    uid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    name = models.CharField(max_length=255)
    channel = models.CharField(max_length=10, choices=CHANNEL_CHOICES)
    subject = models.CharField(max_length=255, blank=True, null=True)#email only
    message = models.TextField()
    target_type = models.CharField(max_length=20, choices=TARGET_TYPE_CHOICES)
    created_by = models.ForeignKey("users.User", on_delete=models.SET_NULL, null=True, blank=True, related_name='campaigns')
    org_slug = models.CharField(max_length=255, blank=True, null=True)
    is_scheduled = models.BooleanField(default=False)
    scheduled_time = models.DateTimeField(null=True, blank=True)
    is_sent = models.BooleanField(default=False)
    sent_at = models.DateTimeField(null=True, blank=True)
    # For contact_upload target type — stores the raw contact list
    # Format: [{"name": "John", "phone_number": "0201234567"}, ...]
    contact = models.JSONField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    
    class Meta:
        ordering = ['-created_at']
        
    def __str__(self):
        return f"{self.name} ({self.channel}) - {self.created_at.date()}"
    
    @property
    def total_recipients(self):
        return self.notifications.count()

    @property
    def sent_count(self):
        return self.notifications.filter(status="sent").count()

    @property
    def failed_count(self):
        return self.notifications.filter(status="failed").count()


class Notification(models.Model):
    """
    One record per recipient per send.
    Covers SMS, email, and in-app notifications.
    When campaign is null, it's a direct/task notification between users.
    """
    
    CHANNEL_CHOICES = [
        ("sms", "SMS"),
        ("email", "Email"),
        ("in_app", "In-App")
    ]
    
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("sent", "Sent"),
        ("failed", "Failed"),
        ("read", "Read"),  # in-app only
    ]
    
    uid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    
     # Link to campaign — null means this is a direct/task notification
    campaign = models.ForeignKey(Campaign,on_delete=models.CASCADE,null=True,blank=True,related_name="notifications",)
    # The user receiving this notification
    recipient = models.ForeignKey("users.User", on_delete=models.CASCADE, related_name="notifications_recieved", null=True, blank=True)
     # The user who triggered this (null for system-generated)
    sender = models.ForeignKey("users.User",on_delete=models.SET_NULL,null=True,blank=True,related_name="notifications_sent",)
    channel = models.CharField(max_length=10, choices=CHANNEL_CHOICES)
    subject = models.CharField(max_length=255, blank=True, null=True)#email only
    message = models.TextField()
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default="pending")
    is_read = models.BooleanField(default=False)
    sent_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    failure_reason = models.TextField(blank=True, null=True)
    recipient_address = models.CharField(max_length=255,blank=True,null=True,help_text="Email address or phone number used at time of send",)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.channel.upper()} to {self.recipient} [{self.status}]"

    def mark_as_read(self):
        """Mark in-app notification as read."""
        if self.channel == "in_app" and not self.is_read:
            self.is_read = True
            self.status = "read"
            self.save(update_fields=["is_read", "status"])