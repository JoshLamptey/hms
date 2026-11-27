import arrow
from rest_framework import serializers
from timezone_field.rest_framework import TimeZoneSerializerField
from django_countries.serializer_fields import CountryField as CountrySerializerField
from apps.clients.models import (
    Tenant,
    License,
    LicenseType,
    LicenseRenewal,
    LicenseHistory,
)

class TenantCreateUpdateSerializer(serializers.ModelSerializer):
    timezone = TimeZoneSerializerField(required=False)
    country = CountrySerializerField(required=False)
    
    class Meta:
        model = Tenant
        fields = [
            "name",
            "address",
            "email",
            "phone_number",
            "logo",
            "is_active",
            "timezone",
            "country"
        ]


class TenantListSerializer(serializers.ModelSerializer):
    logo = serializers.SerializerMethodField()
    timezone = TimeZoneSerializerField()

    def get_logo(self, obj):
        request = self.context.get("request")
        if obj.logo and request:
            return request.build_absolute_uri(obj.logo.url)
        return None

    class Meta:
        model = Tenant
        fields = [
            "id",
            "uid",
            "name",
            "address",
            "org_slug",
            "schema_name",
            "email",
            "phone_number",
            "logo",
            "is_active",
            "timezone",
            "country",
            "created_at",
            "updated_at",
        ]
        
        
class LicenseTypeCreateUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = LicenseType
        fields = [
            "name",
            "sub_name",
            "coverage",
            "description",
            "duration",
            "max_users",
        ]


class LicenseTypeListSerializer(serializers.ModelSerializer):
    class Meta:
        model = LicenseType
        fields = [
            "id",
            "uid",
            "name",
            "sub_name",
            "coverage",
            "description",
            "duration",
            "max_users",
            "created_at",
            "updated_at",
        ]


class LicenseCreateUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = License
        fields = [
            "tenant",
            "license_type",
            "expiry_date",
            "quantity",
            "status",
            "users",
        ]


class LicenseListSerializer(serializers.ModelSerializer):
    license_type = serializers.SerializerMethodField()
    tenant = serializers.SerializerMethodField()
    users = serializers.SerializerMethodField()
    days_till_expiry = serializers.SerializerMethodField()
    is_active = serializers.SerializerMethodField()

    def get_license_type(self, obj):
        if obj.license_type:
            return {
                "id": obj.license_type.id,
                "uid": str(obj.license_type.uid),
                "name": obj.license_type.name,
                "sub_name": obj.license_type.sub_name,
            }
        return None

    def get_tenant(self, obj):
        if obj.tenant:
            return {
                "id": obj.tenant.id,
                "uid": str(obj.tenant.uid),
                "name": obj.tenant.name,
                "org_slug": obj.tenant.org_slug,
            }
        return None

    def get_users(self, obj):
        return [
            {
                "id": user.id,
                "uid": str(user.uid),
                "full_name": user.get_full_name(),
                "email": user.email,
            }
            for user in obj.users.all()
        ]

    def get_days_till_expiry(self, obj):
        if not obj.expiry_date:
            return None
        expiry = arrow.get(obj.expiry_date)
        now = arrow.now()
        if expiry < now:
            return "Expired"
        return expiry.humanize(now)

    def get_is_active(self, obj):
        return obj.is_active

    class Meta:
        model = License
        fields = [
            "id",
            "uid",
            "tenant",
            "license_type",
            "license_key",
            "issue_date",
            "expiry_date",
            "quantity",
            "status",
            "is_active",
            "remaining_slots",
            "users",
            "days_till_expiry",
            "created_at",
            "updated_at",
        ]


class LicenseRenewalCreateUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = LicenseRenewal
        fields = [
            "license",
            "quantity",
            "expiration_date",
        ]


class LicenseRenewalListSerializer(serializers.ModelSerializer):
    license = serializers.SerializerMethodField()

    def get_license(self, obj):
        if obj.license:
            return {
                "id": obj.license.id,
                "uid": str(obj.license.uid),
                "name": obj.license.name,
            }
        return None

    class Meta:
        model = LicenseRenewal
        fields = [
            "id",
            "uid",
            "license",
            "quantity",
            "renewal_date",
            "expiration_date",
            "created_at",
            "updated_at",
        ]


class LicenseHistoryListSerializer(serializers.ModelSerializer):
    license = serializers.SerializerMethodField()
    tenant = serializers.SerializerMethodField()

    def get_license(self, obj):
        if obj.license:
            return {
                "id": obj.license.id,
                "uid": str(obj.license.uid),
                "name": obj.license.name,
            }
        return None

    def get_tenant(self, obj):
        if obj.tenant:
            return {
                "id": obj.tenant.id,
                "uid": str(obj.tenant.uid),
                "name": obj.tenant.name,
            }
        return None

    class Meta:
        model = LicenseHistory
        fields = [
            "id",
            "uid",
            "license",
            "tenant",
            "action",
            "timestamp",
        ]
