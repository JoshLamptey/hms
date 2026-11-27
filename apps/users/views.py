import re
import logging
import arrow
import jwt
from django.conf import settings
from django.core.cache import cache
from django.db.models import Q
from django.http import Http404
from django.contrib.auth.models import Permission
from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.exceptions import PermissionDenied
from rest_framework.throttling import ScopedRateThrottle, UserRateThrottle
from django.utils import timezone
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.hashers import check_password, make_password
from django.core.exceptions import ValidationError
from decouple import config
from apps.clients.models import Tenant, License
from apps.users.auth import Authenticator
from apps.users.models import User, UserGroup, UserRole, RefreshToken
from apps.users.perms import TenantPermission, LicenseGuard
from apps.users.serializers import (
    UserRoleSerializer,
    UserCreateSerializer,
    UserAdminUpdateSerializer,
    UserSelfUpdateSerializer,
    UserListSerializer,
    UserGroupCreateUpdateSerializer,
    UserGroupListSerializer,
)
from apps.users.pagination import FetchDataPagination
from apps.users.integrations import mark_attendance_on_login


auth = Authenticator()
logger = logging.getLogger(__name__)

EXCLUDED_APPS = [
    "admin",
    "auth",
    "contenttypes",
    "sessions",
    "staticfiles",
    "rest_framework",
    "drf_spectacular",
    "post_office",
    "django_celery_results",
    "django_celery_beat",
]

CLIENT_EXCLUDED_APPS = [
    "clients",
]

ALL_EXCLUDED_APPS = EXCLUDED_APPS + CLIENT_EXCLUDED_APPS


def is_privileged(user):
    return user.is_superuser or (user.role and user.role.name == "SUPER_ADMIN")


class UserRoleViewSet(viewsets.ModelViewSet):
    content_model = UserRole
    queryset = UserRole.objects.all()
    serializer_class = UserRoleSerializer
    permission_classes = [TenantPermission]
    lookup_field = "uid"

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        serializer = self.get_serializer(queryset, many=True)
        return Response(
            {"success": True, "data": serializer.data}, status=status.HTTP_200_OK
        )

    def retrieve(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
        except Http404:
            return Response(
                {"success": False, "message": "Role not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        serializer = self.get_serializer(instance)
        return Response(
            {"success": True, "data": serializer.data}, status=status.HTTP_200_OK
        )

    def create(self, request, *args, **kwargs):
        try:
            if not is_privileged(request.user):
                return Response(
                    {"success": False, "data": "Unauthorized request."},
                    status=status.HTTP_403_FORBIDDEN,
                )

            data = request.data
            name = data.get("name")

            if not name:
                return Response(
                    {"success": False, "message": "Name is required"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if UserRole.objects.filter(name=name).exists():
                return Response(
                    {"success": False, "message": "Role already exists"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            serializer = self.get_serializer(data=data)
            serializer.is_valid(raise_exception=True)
            serializer.save()

            return Response(
                {"success": True, "message": "Role created successfully"},
                status=status.HTTP_201_CREATED,
            )

        except Exception as e:
            logger.error(f"Error creating role: {e}")
            return Response(
                {"success": False, "message": "Failed to create role"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class PermissionViewset(viewsets.ViewSet):

    def list(self, request, *args, **kwargs):
        perms = Permission.objects.select_related("content_type")
        grouped_permissions = {}

        user = request.user

        for perm in perms:
            app_label = perm.content_type.app_label

            if app_label in ALL_EXCLUDED_APPS:
                continue

            if not is_privileged(user) and app_label in CLIENT_EXCLUDED_APPS:
                continue

            model_name = perm.content_type.model
            grouped_permissions.setdefault(model_name, []).append(
                {
                    "id": perm.id,
                    "name": perm.name,
                    "codename": perm.codename,
                }
            )

        return Response(
            {
                "success": True,
                "data": grouped_permissions,
            },
            status=status.HTTP_200_OK,
        )


class UserGroupViewSet(viewsets.ModelViewSet):
    content_model = UserGroup
    queryset = UserGroup.objects.prefetch_related("permissions", "users").all()
    permission_classes = [TenantPermission]
    lookup_field = "uid"

    def get_serializer_class(self):
        if self.action in ["update", "create", "partial_update"]:
            return UserGroupCreateUpdateSerializer
        return UserGroupListSerializer

    def get_queryset(self):
        user = self.request.user
        qs = self.queryset

        if is_privileged(user):
            return qs.filter(is_global=True)

        return qs.filter(
            is_global=False,
            tenant=user.tenant,
        )

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        serializer = self.get_serializer(queryset, many=True)

        return Response(
            {"success": True, "data": serializer.data}, status=status.HTTP_200_OK
        )

    def retrieve(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
        except Http404:
            return Response(
                {"success": False, "message": "User group not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        serializer = self.get_serializer(instance)
        return Response(
            {"success": True, "data": serializer.data}, status=status.HTTP_200_OK
        )

    def create(self, request, *args, **kwargs):
        try:
            data = request.data
            name = data.get("name")
            group_permissions = data.get("permissions", [])
            tenant = request.user.tenant

            if not name:
                return Response(
                    {"success": False, "message": "Name is required"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            group_filter = UserGroup.objects.filter(name=name)
            if tenant:
                group_filter = group_filter.filter(tenant=tenant)
            else:
                group_filter = group_filter.filter(tenant__isnull=True)

            if group_filter.exists():
                return Response(
                    {"success": False, "message": "User group already exists."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            group_data = {"name": name}
            if tenant:
                group_data["tenant"] = tenant

            if is_privileged(request.user):
                group_data["is_global"] = True

            group = UserGroup.objects.create(**group_data)

            if group_permissions:
                valid_permissions = Permission.objects.filter(id__in=group_permissions)
                group.permissions.set(valid_permissions)

            return Response(
                {"success": True, "message": "User group created successfully."},
                status=status.HTTP_201_CREATED,
            )

        except Exception as e:
            logger.error(f"Error creating user group : {e}")
            return Response(
                {"success": False, "message": "Failed to create user group"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    @action(detail=False, methods=["post"], url_path="assign-user-group")
    def assign_user_group(self, request, *args, **kwargs):
        try:
            data = request.data
            group_uid = data.get("group_uid")
            users = data.get("users", [])

            if not group_uid:
                return Response(
                    {"success": False, "message": "Group uid is required"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if not isinstance(users, list):
                return Response(
                    {"success": False, "message": "Users must be a list"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            user_group = UserGroup.objects.filter(uid=group_uid).first()

            if not user_group:
                return Response(
                    {"success": False, "message": "User group does not exist"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            user_group.users.add(*users)

            return Response(
                {"success": True, "message": "User(s) assigned to group successfully."},
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error(f"Error assigning user to group :  {e}")
            return Response(
                {"success": False, "message": "Failed to assign user group."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    @action(detail=False, methods=["post"], url_path="remove-user-group")
    def remove_user_group(self, request, *args, **kwargs):
        try:
            data = request.data
            group_uid = data.get("group_uid")
            users = data.get("users", [])

            if not group_uid:
                return Response(
                    {"success": False, "message": "Group uid is required"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if not isinstance(users, list):
                return Response(
                    {"success": False, "message": "Users must be a list"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            user_group = UserGroup.objects.filter(uid=group_uid).first()

            if not user_group:
                return Response(
                    {"success": False, "message": "User group does not exist"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            user_group.users.remove(*users)

            return Response(
                {"success": True, "message": "User(s) removed from group successfully."},
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error(f"Error removing user group: {e}")
            return Response(
                {
                    "success": False,
                    "message": "Failed to remove user group.",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class UserViewSet(viewsets.ModelViewSet):
    content_model = User
    queryset = User.objects.select_related("role", "tenant").all()
    permission_classes = [TenantPermission]
    lookup_field = "uid"
    pagination_class = FetchDataPagination
    throttle_classes = [ScopedRateThrottle, UserRateThrottle]

    def get_serializer_class(self):
        if self.action == "create":
            return UserCreateSerializer
        if self.action in ["update", "partial_update"]:
            obj = self.get_object()
            if obj.id == self.request.user.id:
                return UserSelfUpdateSerializer
            return UserAdminUpdateSerializer

        return UserListSerializer

    def get_queryset(self):
        user = self.request.user
        queryset = User.objects.filter(status=User.Status.ACTIVE).select_related("role", "tenant").all()

        if not is_privileged(user):
            queryset = queryset.filter(tenant=user.tenant)

        tenant = self.request.query_params.get("tenant")
        role = self.request.query_params.get("role")
        user_status = self.request.query_params.get("status")
        name = self.request.query_params.get("name")

        if tenant and is_privileged(user):
            queryset = queryset.filter(tenant__org_slug=tenant)
        if role:
            queryset = queryset.filter(role__name__iexact=role)
        if user_status:
            queryset = queryset.filter(status__iexact=user_status)
        if name:
            queryset = queryset.filter(
                Q(first_name__icontains=name)
                | Q(last_name__icontains=name)
                | Q(middle_name__icontains=name)
            )

        return queryset



    def list(self, request, *args, **kwargs):
        if not is_privileged(request.user):
                return Response(
                    {"success": False, "message": "Unauthorized request."},
                    status=status.HTTP_403_FORBIDDEN,
                )

        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)

        if page is not None:
            serializer = self.get_serializer(page, many=True)
            data = self.get_paginated_response(serializer.data).data
            return Response(
                {
                    "success": True,
                    "data": data["results"],
                    "meta": {
                        "count": data["count"],
                        "next": data["next"],
                        "previous": data["previous"],
                    },
                },
                status=status.HTTP_200_OK,
            )

        serializer = self.get_serializer(queryset, many=True)
        return Response(
            {"success": True, "data": serializer.data}, status=status.HTTP_200_OK
        )

    def retrieve(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
        except Http404:
            return Response(
                {"success": False, "message": "User not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        serializer = self.get_serializer(instance)
        return Response(
            {"success": True, "data": serializer.data}, status=status.HTTP_200_OK
        )

    @action(detail=False, methods=["get"], url_path="me")
    def me(self, request):
        serializer = UserListSerializer(request.user)
        return Response(
            {"success": True, "data": serializer.data},
            status=status.HTTP_200_OK,
        )


    def create(self, request, *args, **kwargs):
        try:
            data = request.data.copy()

            required_fields = [
                "first_name",
                "last_name",
                "role",
                "email",
                "phone_number",
                "gender",
            ]

            for field in required_fields:
                if not data.get(field):
                    return Response(
                        {"success": False, "message": f"{field} is required"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            if is_privileged(request.user):
                tenant = Tenant.objects.filter(id=data.get("tenant")).first()
                if not tenant:
                    return Response(
                        {"success": False, "message": "Tenant does not exist"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                data["org_slug"] = tenant.org_slug

            else:
                data["tenant"] = request.user.tenant.id
                data["org_slug"] = request.user.tenant.org_slug



            if not is_privileged(request.user):
                active_license = License.objects.filter(
                    tenant=request.user.tenant,
                    status=License.LicenseStatus.ACTIVE,
                    expiry_date__gt=timezone.now().date(),
                ).select_related('license_type').first()

                if not active_license:
                    return Response({
                        'success': False,
                        'message': 'No active license found for this organisation.'
                    }, status=status.HTTP_403_FORBIDDEN)

                current_user_count = User.objects.filter(
                    org_slug=data['org_slug'],
                    is_active=True
                ).count()

                if current_user_count >= active_license.quantity:
                    return Response({
                        'success': False,
                        'message': f'User limit reached. Your {active_license.name} license allows a maximum of {active_license.quantity} users.'
                    }, status=status.HTTP_403_FORBIDDEN)

            if User.objects.filter(
                Q(email=data.get("email")) | Q(phone_number=data.get("phone_number")),
                org_slug=data["org_slug"],status=User.Status.ACTIVE,
            ).exists():
                return Response(
                    {
                        "success": False,
                        "message": " A user with this email or phone number already exists.",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if not data.get("username"):
                base = f"{data.get('first_name', '').lower()}_{data.get('last_name', '').lower()}"
                username = base
                counter = 1

                while User.objects.filter(username=username).exists():
                    username = f"{base}_{counter}"
                    counter += 1

                data["username"] = username

            if data.get("password"):
                try:
                    plain_password = data.get("password")
                    validate_password(plain_password)
                    data["password"] = make_password(plain_password)
                except ValidationError as e:
                    return Response(
                        {
                            "success": False,
                            "message": e.messages,
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            serializer = self.get_serializer(data=data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)

            return Response(
                {"success": True, "message": "User created successfully."},
                status=status.HTTP_201_CREATED,
            )

        except Exception as e:
            logger.exception(f"User create failed: {str(e)}")
            return Response(
                {"success": False, "message": "Failed to create user."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)
        try:
            instance = self.get_object()
        except Http404:
            return Response(
                {"success": False, "message": "User not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)

        forbidden_fields = {"tenant", "org_slug"}
        if forbidden_fields & set(serializer.validated_data.keys()):
            raise PermissionDenied("Organisation fields cannot be modified.")

        if instance.id == request.user.id:
            forbidden_self_fields = {"role", "status", "is_blocked", "login_enabled"}
            if forbidden_self_fields & set(serializer.validated_data.keys()):
                raise PermissionDenied("You cannot modify administrative fields.")

        self.perform_update(serializer)

        return Response(
            {
                "success": True,
                "message": "User updated successfully.",
            },
            status=status.HTTP_200_OK,
        )

    @action(
        detail=False,
        methods=["post"],
        url_path="update-password",
    )
    def update_password(self, request):
        data = request.data
        password = data.get("password")
        confirm_password = data.get("confirm_password")
        user = request.user

        if not password:
            return Response(
                {"success": False, "message": "Password is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not confirm_password:
            return Response(
                {"success": False, "message": "Confirm password is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if password != confirm_password:
            return Response(
                {"success": False, "message": "Passwords do not match."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            validate_password(password, user=user)
            user.set_password(password)
        except ValidationError as e:
            return Response(
                {"success": False, "message": e.messages},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user.password_changed = True
        user.login_enabled = True
        user.save(update_fields=["password", "password_changed", "login_enabled"])

        RefreshToken.objects.filter(user=user).update(is_revoked=True)

        auth_header = request.headers.get("Authorization")

        if auth_header:
            try:
                prefix, token = auth_header.split(" ")
                payload = jwt.decode(
                    token,
                    config("SECRET_KEY"),
                    algorithms=["HS256"],
                    options={"verify_exp": False},
                )
                jti = payload.get("jti")
                exp = payload.get("exp")
                if jti and exp:
                    ttl = exp - int(arrow.utcnow().timestamp())
                    if ttl > 0:
                        cache.set(f"blacklist:access:{jti}", "blacklisted", timeout=ttl)

            except Exception as e:
                logger.error(f"Error blacklisting access token : {e}")

        return Response(
            {
                "success": True,
                "data": "Password updated successfully . Please re-login.",
            },
            status=status.HTTP_200_OK,
        )

    @action(
        detail=False,
        methods=["post"],
        permission_classes=[permissions.AllowAny],
        url_path="forgot-password",
        throttle_classes=[ScopedRateThrottle],
    )
    def forgot_password(self, request):
        data = request.data
        field = data.get("field")

        if not field:
            return Response(
                {"success": False, "message": "Field is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = User.objects.filter(Q(email=field) | Q(phone_number=field)).first()

        if not user:
            return Response(
                {"success": True, "message": f"OTP sent successfully to  {field}"},
                status=status.HTTP_200_OK,
            )

        full_name = user.get_full_name()

        try:
            if "@" in field:
                if not re.match(r"[^@]+@[^@]+\.[^@]+", field):
                    return Response(
                        {"success": False, "message": "Invalid email format"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                auth.send_otp(email=field, full_name=full_name)

            elif re.match(r"^\+?\d{7,15}$", field):
                auth.send_otp(phone=field, full_name=full_name)
            else:
                return Response(
                    {"success": False, "message": "Invalid phone number format"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            return Response(
                {"success": True, "message": f"OTP sent successfully to {field}"},
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error(f"Error sending OTP: {e}")
            return Response(
                {"success": False, "message": "Failed to send OTP."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    forgot_password.throttle_scope = "forgot_password"

    @action(
        detail=False,
        methods=["post"],
        permission_classes=[permissions.AllowAny],
        url_path="verify-otp",
    )
    def verify_otp(self, request):
        data = request.data
        field = data.get("field")
        otp = data.get("otp")

        if not field:
            return Response(
                {"success": False, "message": "Field is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not otp:
            return Response(
                {"success": False, "message": "OTP is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if "@" in field:
            verify = auth.verify_otp(email=field, user_entered_otp=otp)
        else:
            verify = auth.verify_otp(phone=field, user_entered_otp=otp)

        if verify:
            user = User.objects.filter(Q(email=field) | Q(phone_number=field)).first()

            temp_token = auth.generate_reset_token(user, identifier=field)
            return Response(
                {
                    "success": True,
                    "message": "OTP verified successfully.",
                    "temp_token": temp_token,
                },
                status=status.HTTP_200_OK,
            )

        return Response(
            {
                "success": False,
                "message": "OTP verification failed. Please re-check your OTP and try again.",
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    @action(
        detail=False,
        methods=["post"],
        permission_classes=[permissions.AllowAny],
        url_path="reset-password",
        throttle_classes=[ScopedRateThrottle],
    )
    def reset_password(self, request):
        data = request.data
        field = data.get("field")
        reset_token = data.get("reset_token")
        password = data.get("password")
        confirm_password = data.get("confirm_password")

        if not field:
            return Response(
                {"success": False, "message": "Field is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not reset_token:
            return Response(
                {"success": False, "message": "Reset token is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not password:
            return Response(
                {"success": False, "message": "Password is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not confirm_password:
            return Response(
                {"success": False, "message": "Confirm password is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if password != confirm_password:
            return Response(
                {"success": False, "message": "Passwords do not match."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            payload = jwt.decode(
                reset_token,
                config("SECRET_KEY"),
                algorithms=["HS256"],
            )
        except jwt.ExpiredSignatureError:
            return Response(
                {"success": False, "message": "Reset token has expired."},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        except jwt.InvalidTokenError:
            return Response(
                {"success": False, "message": "Invalid reset token."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        if payload.get("type") != "password_reset":
            return Response(
                {"success": False, "message": "Invalid token type"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        identifier = payload.get("identifier")
        cached_token = cache.get(f"reset_token:{identifier}")

        if isinstance(cached_token, bytes):
            cached_token = cached_token.decode("utf-8")

        if not cached_token or cached_token != reset_token:
            return Response(
                {"success": False, "message": "Reset token is invalid or already used."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        user = User.objects.filter(
            Q(email=identifier) | Q(phone_number=identifier)
        ).first()

        if not user:
            return Response(
                {"success": False, "message": "User not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        if field != identifier:
            return Response(
                {"success": False, "message": "Field does not match the reset token."},
                status=status.HTTP_403_FORBIDDEN,
            )

        try:
            validate_password(password, user=user)
        except ValidationError as e:
            return Response(
                {"success": False, "message": e.messages},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user.set_password(password)
        user.password_changed = True
        user.login_enabled = True
        user.save(update_fields=["password", "password_changed", "login_enabled"])

        cache.delete(f"reset_token:{identifier}")
        RefreshToken.objects.filter(user=user).update(is_revoked=True)

        return Response(
            {"success": True, "message": "Password reset successfully."},
            status=status.HTTP_200_OK,
        )

    reset_password.throttle_scope = "reset_password"

    @action(
        detail=False,
        methods=["post"],
        permission_classes=[permissions.AllowAny],
        url_path="login",
        throttle_classes=[ScopedRateThrottle],
    )
    def login(self, request):
        data = request.data
        field = data.get("field")
        password = data.get("password")
        latitude = data.get("latitude")
        longitude = data.get("longitude")

        if not field:
            return Response(
                {"success": False, "message": "Field is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not password:
            return Response(
                {"success": False, "message": "Password is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = (
            User.objects.select_related("role", "tenant")
            .filter(Q(email=field) | Q(phone_number=field))
            .first()
        )

        if not user:
            return Response(
                {"success": False, "message": "Invalid credentials"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not check_password(password, user.password):
            return Response(
                {"success": False, "message": "Invalid credentials"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        now = arrow.now().datetime

        if not is_privileged(user):
            if (
                not user.password_changed
                and user.password_expiry
                and user.password_expiry <= now
            ):
                return Response(
                    {
                        "success": False,
                        "message": "Password expired. Please contact your administrator.",
                    },
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            if not user.login_enabled:
                return Response(
                    {
                        "success": False,
                        "message": "Login disabled. Please contact your administrator.",
                    },
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            if user.is_blocked:
                return Response(
                    {
                        "success": False,
                        "message": "Your account is blocked. Please contact your administrator.",
                    },
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            license = (
                tenant.licenses.filter(status=License.LicenseStatus.ACTIVE).first()
                if (tenant := getattr(user, "tenant", None))
                else None
            )

            if not license or not license.is_active:
                return Response(
                    {
                        "success": False,
                        "message": "Your organisation's license is inactive.",
                    },
                    status=status.HTTP_401_UNAUTHORIZED,
                )

        user.last_login = now
        user.save(update_fields=["last_login"])

        access_token = auth.generate_access_token(user)
        refresh_token = auth.generate_refresh_token(user)

        attendance_result = mark_attendance_on_login(user=user, latitude=latitude, longitude=longitude)

        response_data = {
            "success": True,
            "message": "User logged in successfully.",
            "password_changed": user.password_changed,
            "access_token": access_token,
            "role": user.role.name if user.role else None,
        }

        if attendance_result is not None:
            response_data["attendance"] = {
                "marked": attendance_result["marked"],
                "reason": attendance_result["reason"],
            }

        response = Response(response_data, status=status.HTTP_200_OK)
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            secure= not settings.DEBUG,
            samesite="Lax",
            max_age=60 * 60 * 12,
            path="/",
        )
        return response


    login.throttle_scope = "login"

    @action(
        detail=False,
        methods=["post"],
        permission_classes=[permissions.AllowAny],
        url_path="passwordless-login",
        throttle_classes=[ScopedRateThrottle],
    )
    def login_without_password(self, request):
        try:
            data = request.data
            field = data.get("field")

            if not field:
                return Response(
                    {"success": False, "message": "Field is required."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            user = (
                User.objects.select_related("role", "tenant")
                .filter(Q(email=field) | Q(phone_number=field))
                .first()
            )

            if not user:
                return Response(
                    {"success": True, "message": f"OTP sent successfully to {field}."},
                    status=status.HTTP_200_OK,
                )

            if not is_privileged(user):
                license = (
                    tenant.licenses.filter(status=License.LicenseStatus.ACTIVE).first()
                    if (tenant := getattr(user, "tenant", None))
                    else None
                )

                if not license or not license.is_active:
                    return Response(
                        {"success": True, "message": f"OTP sent successfully to {field}."},
                        status=status.HTTP_200_OK,
                    )

            full_name = user.get_full_name()

            if "@" in field:
                if not re.match(r"[^@]+@[^@]+\.[^@]+", field):
                    return Response(
                        {"success": False, "message": "Invalid email format."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                auth.send_otp(email=field, full_name=full_name)

            elif re.match(r"^\+?\d{7,15}$", field):
                auth.send_otp(phone=field, full_name=full_name)

            else:
                return Response(
                    {"success": False, "message": "Invalid email or phone number format."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            return Response(
                {"success": True, "message": f"OTP sent successfully to {field}."},
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error(f"Error sending OTP: {e}")
            return Response(
                {"success": False, "message": "Failed to send OTP."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    login_without_password.throttle_scope = "passwordless_login"

    @action(
        detail=False,
        methods=["post"],
        permission_classes=[permissions.AllowAny],
        url_path="passwordless-login-verify-otp",
    )
    def verify_passwordless_otp(self, request):
        try:
            data = request.data
            field = data.get("field")
            otp = data.get("otp")
            latitude = data.get("latitude")
            longitude = data.get("longitude")

            if not field:
                return Response(
                    {"success": False, "message": "Field is required."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if not otp:
                return Response(
                    {"success": False, "message": "OTP is required."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            user = (
                User.objects.select_related("role", "tenant")
                .filter(Q(email=field) | Q(phone_number=field))
                .first()
            )

            if not user:
                return Response(
                    {"success": False, "message": "Invalid email or phone number."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if "@" in field:
                verify = auth.verify_otp(email=field, user_entered_otp=otp)
            else:
                verify = auth.verify_otp(phone=field, user_entered_otp=otp)

            if not verify:
                return Response(
                    {
                        "success": False,
                        "message": "OTP verification failed. Please re-check your OTP and try again.",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if not user.password_changed:
                return Response(
                    {
                        "success": False,
                        "message": "Please change your password to continue.",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            access_token = auth.generate_access_token(user)
            refresh_token = auth.generate_refresh_token(user)

            attendance_result = mark_attendance_on_login(user=user, latitude=latitude, longitude=longitude)

            response_data = {
                "success": True,
                "message": "User logged in successfully.",
                "password_changed": user.password_changed,
                "access_token": access_token,
                "role": user.role.name if user.role else None,
            }

            if attendance_result is not None:
                response_data["attendance"] = {
                    "marked": attendance_result["marked"],
                    "reason": attendance_result["reason"],
                }

            response = Response(response_data, status=status.HTTP_200_OK)
            response.set_cookie(
                key="refresh_token",
                value=refresh_token,
                httponly=True,
                secure= not settings.DEBUG,
                samesite="Lax",
                max_age=60 * 60 * 12,
                path="/",
            )
            return response
        except Exception as e:
            logger.error(f"Error verifying OTP: {e}")
            return Response(
                {"success": False, "message": "Failed to verify OTP."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    @action(
        detail=False,
        methods=["post"],
        url_path="refresh-token",
        permission_classes=[permissions.AllowAny],
        throttle_classes=[ScopedRateThrottle],
    )
    def refresh_token(self, request):
        refresh_token = request.COOKIES.get("refresh_token")

        if not refresh_token:
            return Response(
                {"success": False, "message": "Refresh token is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            payload = jwt.decode(
                refresh_token, config("SECRET_KEY"), algorithms=["HS256"]
            )

            refresh_jti = payload.get("jti")

            if cache.get(f"blacklist:refresh:{refresh_jti}"):
                return Response(
                    {
                        "success": False,
                        "message": "Refresh token has been blacklisted. Please login again.",
                    },
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            if payload.get("type") != "refresh":
                return Response(
                    {"success": False, "message": "Invalid token type."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            token_obj = RefreshToken.objects.filter(
                jti=refresh_jti, is_revoked=False
            ).first()

            if not token_obj:
                return Response(
                    {
                        "success": False,
                        "message": "Refresh token not found or already revoked.",
                    },
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            if token_obj.is_expired():
                return Response(
                    {
                        "success": False,
                        "message": "Refresh token has expired. Please login again.",
                    },
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            token_obj.last_used_at = arrow.utcnow().datetime
            token_obj.save(update_fields=["last_used_at"])

            access_token = auth.generate_access_token(token_obj.user)

            return Response(
                {
                    "success": True,
                    "message": "Token refreshed successfully.",
                    "access_token": access_token,
                },
                status=status.HTTP_200_OK,
            )

        except jwt.ExpiredSignatureError:
            return Response(
                {
                    "success": False,
                    "message": "Refresh token has expired. Please login again.",
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )
        except jwt.InvalidTokenError:
            return Response(
                {"success": False, "message": "Invalid refresh token."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

    refresh_token.throttle_scope = "refresh_token"

    @action(detail=False, methods=["post"], url_path="logout")
    def logout(self, request):
        refresh_token = request.COOKIES.get("refresh_token")

        if not refresh_token:
            return Response(
                {"success": False, "message": "Refresh token is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            payload = jwt.decode(
                refresh_token,
                config("SECRET_KEY"),
                algorithms=["HS256"],
                options={"verify_exp": False},
            )

            refresh_jti = payload.get("jti")
            exp = payload.get("exp")

            if refresh_jti and exp:
                ttl = exp - int(arrow.utcnow().timestamp())
                if ttl > 0:
                    cache.set(
                        f"blacklist:refresh:{refresh_jti}",
                        "blacklisted",
                        timeout=ttl,
                    )

            RefreshToken.objects.filter(jti=refresh_jti).update(is_revoked=True)

        except jwt.InvalidTokenError:
            logger.error("Invalid refresh token provided for logout.")

        auth_header = request.headers.get("Authorization")
        if auth_header:
            try:
                prefix, token = auth_header.split(" ")
                payload = jwt.decode(
                    token,
                    config("SECRET_KEY"),
                    algorithms=["HS256"],
                    options={"verify_exp": False},
                )
                jti = payload.get("jti")
                exp = payload.get("exp")
                if jti and exp:
                    ttl = exp - int(arrow.utcnow().timestamp())
                    if ttl > 0:
                        cache.set(f"blacklist:access:{jti}", "blacklisted", timeout=ttl)
            except Exception as e:
                logger.error(f"Error blacklisting access token: {e}")

        response = Response(
        {"success": True, "message": "Logged out successfully."},
        status=status.HTTP_200_OK,
        )
        response.delete_cookie(
            key="refresh_token",
            path="/",
        )
        return response

    @action(
        detail=False,
        methods=["get"],
        url_path="users-by-organization/(?P<uid>[^/.]+)",
    )
    def users_by_organization(self, request, uid=None):
        try:
            if not is_privileged(request.user):
                return Response(
                    {"success": False, "message": "Unauthorized request."},
                    status=status.HTTP_403_FORBIDDEN,
                )

            if not uid:
                return Response(
                    {"success": False, "message": "Organization UID is required."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            tenant = Tenant.objects.filter(org_slug=uid).first()

            if not tenant:
                return Response(
                    {"success": False, "message": "Organization does not exist."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            users = User.objects.filter(tenant=tenant).select_related("role", "tenant")
            serializer = UserListSerializer(users, many=True)
            return Response(
                {"success": True, "data": serializer.data},
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error(f"Error fetching users by organization: {e}")
            return Response(
                {"success": False, "data": "Failed to fetch users by organization."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class FetchOrgUsers(viewsets.ReadOnlyModelViewSet):
    content_model = User
    permission_classes = [TenantPermission]
    serializer_class = UserListSerializer
    pagination_class = FetchDataPagination

    def get_queryset(self):
        return (
            User.objects.select_related("role", "tenant")
            .filter(org_slug=self.request.user.org_slug, status=User.Status.ACTIVE)
            .order_by("id")
        )

    def list(self, request, *args, **kwargs):
        try:
            role = request.query_params.get("role")
            user_status = request.query_params.get("status")
            name = request.query_params.get("name")

            users = self.get_queryset()

            if role:
                users = users.filter(role__name=role)
            if user_status:
                users = users.filter(status=user_status)
            if name:
                users = users.filter(
                    Q(first_name__icontains=name)
                    | Q(last_name__icontains=name)
                    | Q(middle_name__icontains=name)
                )

            page = self.paginate_queryset(users)
            if page is not None:
                serializer = self.get_serializer(page, many=True)
                data = self.get_paginated_response(serializer.data).data
                return Response(
                    {
                        "success": True,
                        "data": data["results"],
                        "meta": {
                            "count": data["count"],
                            "next": data["next"],
                            "previous": data["previous"],
                        },
                    },
                    status=status.HTTP_200_OK,
                )

            serializer = self.get_serializer(users, many=True)
            return Response(
                {"success": True, "data": serializer.data},
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error(f"Error fetching org users: {str(e)}", exc_info=True)
            return Response(
                {"success": False, "message": "Failed to fetch organisation users."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class FetchOrgUserGroups(viewsets.ReadOnlyModelViewSet):
    content_model = UserGroup
    permission_classes = [TenantPermission]
    serializer_class = UserGroupListSerializer

    def get_queryset(self):
        return (
            UserGroup.objects.filter(tenant=self.request.user.tenant)
            .prefetch_related("permissions", "users")
            .order_by("-created_at")
        )

    def list(self, request, *args, **kwargs):
        try:
            queryset = self.get_queryset()
            serializer = self.get_serializer(queryset, many=True)
            return Response(
                {"success": True, "data": serializer.data}, status=status.HTTP_200_OK
            )

        except Exception as e:
            logger.error(f"Error fetching org user groups: {str(e)}")
            return Response(
                {"success": False, "message": "Failed to fetch organisation user groups."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
