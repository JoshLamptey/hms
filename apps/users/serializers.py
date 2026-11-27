from rest_framework import serializers
from apps.users.models import User, UserGroup, UserRole


class UserRoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserRole
        fields = ["id", "uid", "name", "created_at", "updated_at"]


class UserGroupCreateUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserGroup
        fields = [
            "id",
            "uid",
            "name",
            "description",
            "users",
            "permissions",
            "tenant",
            "is_global",
            "created_at",
            "updated_at",
        ]


class UserGroupListSerializer(serializers.ModelSerializer):
    permissions = serializers.SerializerMethodField()
    users = serializers.SerializerMethodField()
    tenant = serializers.SerializerMethodField()

    def get_permissions(self, obj):
        request = self.context.get("request")
        user = getattr(request, "user", None)

        perms = obj.permissions.select_related("content_type")

        if user and user.role and user.role.name == "SUPER_ADMIN":
            return [
                {
                    "id": perm.id,
                    "codename": perm.codename,
                    "name": perm.name,
                }
                for perm in perms
            ]

        return [
            {
                "id": perm.id,
                "codename": perm.codename,
                "name": perm.name,
            }
            for perm in perms
            if perm.content_type.app_label != "clients"
        ]

    def get_users(self, obj):

        return [
            {"id": user.id, "uid": str(user.uid), "full_name": user.get_full_name()}
            for user in obj.users.all()
        ]

    def get_tenant(self, obj):
        if obj.tenant:
            return {
                "id": obj.tenant.id,
                "uid": str(obj.tenant.uid),
                "name": obj.tenant.name,
            }
        return None

    class Meta:
        model = UserGroup
        fields = [
            "id",
            "uid",
            "name",
            "description",
            "is_global",
            "permissions",
            "users",
            "tenant",
            "created_at",
            "updated_at",
        ]


class UserCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            "username",
            "first_name",
            "middle_name",
            "last_name",
            "email",
            "phone_number",
            "gender",
            "image",
            "role",
            "status",
            "is_blocked",
            "login_enabled",
            "org_slug",
            "tenant",
            "password",
            "password_changed",
            "password_expiry",
        ]


class UserSelfUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            "first_name",
            "last_name",
            "middle_name",
            "phone_number",
            "gender",
            "image",
        ]


class UserAdminUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            "role",
            "status",
            "login_enabled",
            "is_blocked",
        ]


class UserListSerializer(serializers.ModelSerializer):
    role = serializers.SerializerMethodField()
    tenant = serializers.SerializerMethodField()
    groups = serializers.SerializerMethodField()

    def get_role(self, obj):
        if obj.role:
            return {
                "id": obj.role.id,
                "uid": str(obj.role.uid),
                "name": obj.role.name,
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

    def get_groups(self, obj):
        user_groups = UserGroup.objects.filter(users=obj).prefetch_related(
            "permissions"
        )

        if user_groups.exists():
            return [
                {
                    "id": group.id,
                    "uid": str(group.uid),
                    "name": group.name,
                    "permissions": [perm.codename for perm in group.permissions.all()],
                }
                for group in user_groups
            ]
        return None

    class Meta:
        model = User
        fields = [
            "id",
            "uid",
            "first_name",
            "last_name",
            "middle_name",
            "email",
            "image",
            "phone_number",
            "role",
            "tenant",
            "groups",
            "status",
            "gender",
            "last_login",
            "is_blocked",
            "login_enabled",
            "password_changed",
            "created_at",
            "updated_at",
        ]
