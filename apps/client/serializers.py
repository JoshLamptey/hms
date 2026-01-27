from rest_framework import serializers
from decouple import config
from apps.client.models import (
    Tenant,
    License,
    LicenseHistory,
    LicenseRenewal,
    LicenseType,
)
import arrow


class TenantCreateUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tenant
        fields = [
            "name",
            "schema_name",
            "is_active",
            "org_slug",
            "logo",
            "email",
        ]


class TenantListSerializer(serializers.ModelSerializer):
    logo = serializers.SerializerMethodField()

    def get_logo(self, obj):
        if obj.logo:
            return config("BASE_URL") + obj.logo.url
        return None

    class Meta:
        model = Tenant
        fields = [
            "uid",
            "name",
            "schema_name",
            "is_active",
            "org_slug",
            "logo",
            "email",
            "created_at",
            "updated_at",
        ]


class LicenseTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = LicenseType
        fields = [
            "uid",
            "name",
            "coverage",
            "sub_name",
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
            "issue_date",
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

    def get_days_till_expiry(self, obj):
        expiry_date = arrow.get(obj.expiry_date)
        now = arrow.now()

        if expiry_date < now:
            return "Expired"
        else:
            return expiry_date.humanize(now)

    def get_license_type(self, obj):
        if obj.license_type:
            return {
                "uid": str(obj.license_type.uid),
                "name": obj.license_type.name,
                "sub_name": obj.license_type.sub_name,
            }
        else:
            return None

    def get_tenant(self, obj):
        if obj.tenant:
            return {
                "id": obj.tenant.id,
                "uid": str(obj.tenant.uid),
                "name": obj.tenant.name,
            }
        else:
            return None

    def get_users(self, obj):
        print("users in this license")
        if obj.users:
            users = obj.users.all()
            user_list = []
            for user in users:
                user_list.append(
                    {
                        "id": user.id,
                        "username": user.username,
                        "full_name": f"{user.first_name} {user.last_name}",
                        "email": user.email,
                    }
                )
            return user_list

    class Meta:
        model = License
        fields = [
            "uid",
            "tenant",
            "license_type",
            "issue_date",
            "expiry_date",
            "quantity",
            "status",
            "users",
            "created_at",
            "updated_at",
        ]


# this shouldn't have a create update serializer since you will create
# them in the respective create and update methods
class LicenseHistoryListSerializer(serializers.ModelSerializer):
    license = serializers.SerializerMethodField()
    tenant = serializers.SerializerMethodField()

    def get_license(self, obj):
        if obj.license:
            return {"uid": str(obj.license.uid), "name": obj.license.name}

    def get_tenant(self, obj):
        if obj.tenant:
            return {"uid": str(obj.tenant.uid), "name": obj.license.name}

    class Meta:
        model = LicenseHistory
        fields = [
            "license",
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
            return {"uid": str(obj.license.uid), "name": obj.license.name}

    class Meta:
        model = LicenseRenewal
        fields = ["license", "quantity", "expiration_date", "created_at", "updated_at"]
