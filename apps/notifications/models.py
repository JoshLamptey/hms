from django.db import models

# Create your models here.
import uuid
from django.db import models


class Campaign(models.Model):

    class Channel(models.TextChoices):
        SMS = "sms", "SMS"
        EMAIL = "email", "Email"
        IN_APP = "in_app", "In-App"

    class TargetType(models.TextChoices):
        STAFF = "staff", "Staff"
        CUSTOMERS = "customers", "Customers"
        CONTACT_UPLOAD = "contact_upload", "Contact Upload"
        INDIVIDUAL = "individual", "Individual"

    uid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    name = models.CharField(max_length=255)
    channel = models.CharField(max_length=10, choices=Channel.choices)
    subject = models.CharField(max_length=255, blank=True, null=True)
    message = models.TextField()
    target_type = models.CharField(max_length=20, choices=TargetType.choices)
    created_by = models.ForeignKey(
        "users.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="campaigns",
    )
    org_slug = models.CharField(max_length=255, blank=True, null=True)
    is_scheduled = models.BooleanField(default=False)
    scheduled_time = models.DateTimeField(null=True, blank=True)
    is_sent = models.BooleanField(default=False)
    sent_at = models.DateTimeField(null=True, blank=True)
    contact = models.JSONField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

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

    class Channel(models.TextChoices):
        SMS = "sms", "SMS"
        EMAIL = "email", "Email"
        IN_APP = "in_app", "In-App"

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        SENT = "sent", "Sent"
        FAILED = "failed", "Failed"
        READ = "read", "Read"

    uid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    campaign = models.ForeignKey(
        Campaign,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="notifications",
    )
    recipient = models.ForeignKey(
        "users.User",
        on_delete=models.CASCADE,
        related_name="notifications_received",
        null=True,
        blank=True,
    )
    sender = models.ForeignKey(
        "users.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="notifications_sent",
    )
    channel = models.CharField(max_length=10, choices=Channel.choices)
    subject = models.CharField(max_length=255, blank=True, null=True)
    message = models.TextField()
    status = models.CharField(
        max_length=10,
        choices=Status.choices,
        default=Status.PENDING,
    )
    is_read = models.BooleanField(default=False)
    sent_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    failure_reason = models.TextField(blank=True, null=True)
    recipient_address = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="Email address or phone number used at time of send",
    )

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.channel.upper()} to {self.recipient} [{self.status}]"

    def mark_as_read(self):
        if self.channel == "in_app" and not self.is_read:
            self.is_read = True
            self.status = self.Status.READ
            self.save(update_fields=["is_read", "status"])