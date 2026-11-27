import uuid
import secrets
from datetime import timedelta
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import get_user_model
from django_countries.fields import CountryField
from phonenumber_field.modelfields import PhoneNumberField
from apps.clients.utils import generate_schema_name
from timezone_field import TimeZoneField
from django.utils.text import slugify
User = get_user_model()


class Tenant(models.Model):
    uid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    name = models.CharField(max_length=150, unique=True, null=True, blank=True)
    address = models.CharField(max_length=150, null=True, blank=True)
    schema_name = models.CharField(max_length=63, unique=True)
    is_active = models.BooleanField(default=True)
    org_slug = models.SlugField(max_length=255, unique=True)
    logo = models.ImageField(
        verbose_name=_("Tenant Logo"),
        default="tenant_logo/tenant_logo.png",
        upload_to="tenant/logo",
        blank=True,
        null=True,
    )
    timezone = TimeZoneField(default='Africa/Accra')
    country = CountryField(default='GH', blank=True)
    email = models.EmailField(verbose_name=_("Tenant Email"), unique=True)
    phone_number = PhoneNumberField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _("Tenant")
        verbose_name_plural = _("Tenants")
        ordering = ["-created_at"]
        
    

    def save(self, *args, **kwargs):
        if not self.schema_name and self.name:
            self.schema_name = generate_schema_name(self.name)
        if not self.org_slug and self.name:
            base_slug = slugify(self.name)
            slug = base_slug
            counter = 1
            while Tenant.objects.filter(org_slug=slug).exclude(pk=self.pk).exists():
                slug = f"{base_slug}-{counter}"
                counter += 1
            self.org_slug = slug
        super().save(*args, **kwargs)
        
    def __str__(self):
        return self.name or str(self.uid)


class LicenseType(models.Model):
    uid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    name = models.CharField(max_length=150, unique=True)
    coverage = models.TextField(null=True, blank=True)
    sub_name = models.CharField(max_length=150, blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    duration = models.IntegerField(default=0)
    max_users = models.PositiveIntegerField(default=10)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _("License Type")
        verbose_name_plural = _("License Types")
        ordering = ["-created_at"]

    def __str__(self):
        return self.full_text
    

    @property
    def full_text(self):
        return f"{self.name} | {self.sub_name}" if self.sub_name else self.name


class License(models.Model):
    class LicenseStatus(models.TextChoices):
        PENDING = "pending", _("Pending")
        ACTIVE = "active", _("Active")
        EXPIRED = "expired", _("Expired")
        REVOKED = "revoked", _("Revoked")

    uid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    license_type = models.ForeignKey(
        LicenseType,
        on_delete=models.CASCADE,
        related_name="licenses",
    )
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.CASCADE,
        related_name="licenses",
    )
    users = models.ManyToManyField(
        User,
        verbose_name=_("Users"),
        related_name="user_licenses",
        blank=True,
    )
    issue_date = models.DateField(verbose_name=_("Issue Date"), auto_now_add=True)
    expiry_date = models.DateField(verbose_name=_("Expiry Date"), null=True, blank=True)
    quantity = models.PositiveIntegerField(verbose_name=_("License Qty"), default=1)
    status = models.CharField(
        max_length=20,
        choices=LicenseStatus.choices,
        default=LicenseStatus.PENDING,
    )
    license_key = models.CharField(
        max_length=255,
        unique=True,
        editable=False,
        verbose_name=_("License Key"),
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _("License")
        verbose_name_plural = _("Licenses")
        constraints = [
            models.UniqueConstraint(
                fields=["license_key", "tenant"],
                name="unique_license_key_per_tenant",
            )
        ]
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.tenant.name} - {self.name}"

    @property
    def name(self):
        return self.license_type.full_text

    @property
    def remaining_slots(self):
        return self.quantity - self.users.count()

    @property
    def is_active(self):
        if not self.expiry_date:
            return False
        return (
            self.status == self.LicenseStatus.ACTIVE
            and timezone.now().date() < self.expiry_date
        )

    def generate_license_key(self):
        while True:
            key = secrets.token_hex(16)
            if not License.objects.filter(license_key=key).exists():
                return key

    def save(self, **kwargs):
        if not self.expiry_date:
            self.expiry_date = timezone.now().date() + timedelta(
                days=self.license_type.duration
            )

        if self.quantity > self.license_type.max_users:
            self.quantity = self.license_type.max_users

        if not self.license_key:
            self.license_key = self.generate_license_key()

        if (
            self.status == self.LicenseStatus.ACTIVE
            and timezone.now().date() >= self.expiry_date
        ):
            self.status = self.LicenseStatus.EXPIRED

        super().save(**kwargs)


class LicenseRenewal(models.Model):
    uid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    license = models.ForeignKey(
        License,
        on_delete=models.CASCADE,
        related_name="renewals",
    )
    quantity = models.PositiveIntegerField(default=1)
    renewal_date = models.DateField(auto_now_add=True)
    expiration_date = models.DateField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _("License Renewal")
        verbose_name_plural = _("License Renewals")
        ordering = ["-created_at"]

    def __str__(self):
        return f"Renewal for {self.license} on {self.renewal_date}"

    def save(self, **kwargs):
        if not self.expiration_date:
            self.expiration_date = (
                self.renewal_date + timedelta(days=self.license.license_type.duration)
                if self.renewal_date
                else (
                    timezone.now().date()
                    + timedelta(days=self.license.license_type.duration)
                )
            )

        if self.quantity > self.license.license_type.max_users:
            self.quantity = self.license.license_type.max_users

        if self.quantity == 0:
            self.quantity = self.license.quantity
        else:
            self.license.quantity = self.quantity

        self.license.expiry_date = self.expiration_date
        self.license.status = self.license.LicenseStatus.ACTIVE
        self.license.save(update_fields=["expiry_date", "quantity", "status"])

        super().save(**kwargs)


class LicenseHistory(models.Model):
    class Action(models.TextChoices):
        CREATE = "CREATE", _("Create")
        UPDATE = "UPDATE", _("Update")
        DELETE = "DELETE", _("Delete")
        RENEW = "RENEW", _("Renew")

    uid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    license = models.ForeignKey(
        License,
        on_delete=models.CASCADE,
        related_name="history",
    )
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.CASCADE,
        related_name="license_history",
    )
    action = models.CharField(max_length=10, choices=Action.choices)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _("License History")
        verbose_name_plural = _("License Histories")
        ordering = ["-timestamp"]

    def __str__(self):
        return f"{self.action} on {self.license} at {self.timestamp}"
