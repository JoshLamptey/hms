import uuid
import arrow
from django.db import models
from django.contrib.auth.models import AbstractUser, Permission
from django.utils.translation import gettext_lazy as t
from django.utils import timezone
from phonenumber_field.modelfields import PhoneNumberField

from apps.notifications.service import NotificationService

service = NotificationService()


class UserRole(models.Model):
    class Role(models.TextChoices):
        SUPER_ADMIN = "SUPER_ADMIN", t("Super Admin")
        ADMIN = "ADMIN", t("Admin")
        MANAGER = "MANAGER", t("Manager")
        STAFF = "STAFF", t("Staff")
        CLIENT = "CLIENT", t("Client")

    uid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    name = models.CharField(max_length=20, choices=Role.choices, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = t("User Role")
        verbose_name_plural = t("User Roles")
        ordering = ["-created_at"]

    def __str__(self):
        return self.name


class UserGroup(models.Model):
    uid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    name = models.CharField(max_length=150, null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    users = models.ManyToManyField(
        "users.User", verbose_name="user_perm_group", blank=True
    )
    permissions = models.ManyToManyField(
        Permission, blank=True, related_name="user_groups"
    )
    tenant = models.ForeignKey(
        "clients.Tenant",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="user_groups",
    )
    is_global = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = t("User Group")
        verbose_name_plural = t("User Groups")
        ordering = ["-created_at"]

    def __str__(self):
        return self.name or str(self.uid)


class User(AbstractUser):
    class Gender(models.TextChoices):
        MALE = "MALE", t("Male")
        FEMALE = "FEMALE", t("Female")
        OTHER = "OTHER", t("Other")

    class Status(models.TextChoices):
        ACTIVE = "ACTIVE", t("Active")
        INACTIVE = "INACTIVE", t("Inactive")
        SUSPENDED = "SUSPENDED", t("Suspended")

    uid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    username = models.CharField(max_length=150, unique=True)
    middle_name = models.CharField(max_length=150, null=True, blank=True)
    role = models.ForeignKey(
        UserRole, on_delete=models.SET_NULL, related_name="users", null=True, blank=True
    )
    phone_number = PhoneNumberField()
    gender = models.CharField(
        max_length=10, choices=Gender.choices, default=Gender.OTHER
    )
    status = models.CharField(
        max_length=20, choices=Status.choices, default=Status.ACTIVE
    )
    org_slug = models.CharField(max_length=150, null=True, blank=True)
    tenant = models.ForeignKey(
        "clients.Tenant",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="users",
    )
    image = models.ImageField(upload_to="users/", null=True, blank=True)
    password = models.CharField(max_length=128, null=True, blank=True)
    is_blocked = models.BooleanField(default=False)
    blocked_at = models.DateTimeField(null=True, blank=True)
    password_changed = models.BooleanField(default=False)
    password_expiry = models.DateTimeField(null=True, blank=True)
    login_enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = t("User")
        verbose_name_plural = t("Users")
        ordering = ["-created_at"]

    def generate_temporary_password(self):
        return uuid.uuid4().hex[:12]

    def save(self, *args, **kwargs):
        temp_password = None

        if not self.password:
            temp_password = self.generate_temporary_password()
            self.set_password(temp_password)
            self.password_changed = False
            self.password_expiry = (
                arrow.now().shift(days=+7).datetime
            )  # Password expires in 7 days

        super().save(*args, **kwargs)

        if temp_password and self.email:
            service.send_login_credentials(
                to=self.email,
                password=temp_password,
                full_name=self.get_full_name(),
            )

    def is_password_expired(self):
        if self.password_expiry and timezone.now() > self.password_expiry:
            return True
        return False

    def __str__(self):
        return self.username

    def delete(self, *args, **kwargs):
        self.status = self.Status.INACTIVE
        self.save(update_fields=["status"])


class RefreshToken(models.Model):
    jti = models.UUIDField(unique=True)
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="refresh_tokens"
    )
    token = models.TextField()
    expires_at = models.DateTimeField()
    last_used_at = models.DateTimeField(null=True, blank=True)
    is_revoked = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Refresh Token"
        verbose_name_plural = "Refresh Tokens"
        ordering = ["-created_at"]

    def is_expired(self):
        return arrow.utcnow().datetime > self.expires_at

    def __str__(self):
        return f"{self.user.username} - {self.jti}"


class UserRateLimitFlag(models.Model):
    uid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="rate_limit_flags",
    )
    reason = models.TextField(max_length=500, db_index=True)
    count = models.IntegerField(default=0)
    last_flagged_at = models.DateTimeField(auto_now=True)
    is_blocked = models.BooleanField(default=False)

    class Meta:
        unique_together = ("user", "reason")
        verbose_name = "User Rate Limit Flag"
        verbose_name_plural = "User Rate Limit Flags"

    def __str__(self):
        return f"{self.user.username} - {self.reason}"
