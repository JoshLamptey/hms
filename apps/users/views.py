import random
import re
import string
import logging
import arrow
import os
import jwt
from django.conf import settings
from django.core.cache import cache
from rest_framework.decorators import action
from django.db.models import Q
from django.contrib.auth.models import Permission
from django.http import FileResponse, Http404
from apps.client.models import License, Tenant, RefreshToken
from apps.client.serializers import LicenseListSerializer
from apps.users.auth import Authenticator
from rest_framework import viewsets, status, permissions
from rest_framework.response import Response
from django.core.exceptions import ObjectDoesNotExist
from apps.users.models import UserGroup, UserRole
from apps.users.perms import CustomPermission
from apps.users.serializers import (
    UserRoleSerializer,
    UserCreateSerializer,
    UserAdminUpdateSerializer,
    UserSelfUpdateSerializer,
    UserListSerializer,
    UserGroupCreateUpdateSerializer,
    UserGroupListSerializer,
)
from apps.users.utils import send_login_credentials
from decouple import config
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model

auth = Authenticator()
logger = logging.getLogger(__name__)
User = get_user_model()


class UserRoleViewset(viewsets.ModelViewSet):
    content_model = UserRole
    queryset = UserRole.objects.all()
    serializer_class = UserRoleSerializer
    permission_classes = [CustomPermission]
    lookup_field = "uid"

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        serializer = self.get_serializer(queryset, many=True)
        return Response(
            {
                "success": True,
                "info": serializer.data,
            }
        )

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)

        return Response(
            {
                "success": True,
                "info": serializer.data,
            }
        )

    def create(self, request, *args, **kwargs):
        try:
            data = request.data
            name = data.get("name")

            if not name:
                return Response(
                    {
                        "success": False,
                        "info": "Name is required.",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            role = UserRole.objects.filter(name=name)

            if role.exists():
                return Response(
                    {
                        "success": False,
                        "info": "Role already exists.",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            serializer = self.get_serializer(data=data)
            serializer.is_valid(raise_exception=True)
            serializer.save()

            return Response(
                {
                    "success": True,
                    "info": "Role created successfully.",
                },
                status=status.HTTP_201_CREATED,
            )

        except Exception as e:
            logger.error(f"Error creating role: {e}")
            return Response(
                {
                    "success": False,
                    "info": "Failed to create role.",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


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
    "client",
]


ALL_EXCLUDED_APPS = EXCLUDED_APPS + CLIENT_EXCLUDED_APPS


class PermissionViewset(viewsets.ViewSet):
    """
    ViewSet to list all available permissions in the system.
    """

    def list(self, request, *args, **kwargs):
        permissions = Permission.objects.select_related("content_type")
        grouped_permissions = {}

        user = request.user
        is_super_admin = (
            user.is_authenticated
            and getattr(user, "role", None)
            and user.role.name == "super_admin"
        )

        for perm in permissions:
            app_label = perm.content_type.app_label

            if app_label in ALL_EXCLUDED_APPS:
                continue

            if not is_super_admin and app_label in CLIENT_EXCLUDED_APPS:
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
                    "info": grouped_permissions,
                },
                status=status.HTTP_200_OK,
            )

    # I don't understand this yet i will touch it tomorrow
    # @action(detail=False, methods=["get"], url_path="fetch-organization-permissions")
    # def fetch_organization_permissions(self, request):
    #     try:
    #         permissions = Permission.objects.select_related("content_type").all()
    #         grouped_permissions = {}

    #         for perm in permissions:
    #             if perm.content_type.app_label in ALL_EXCLUDED_APPS:
    #                 continue

    #             model_name = perm.content_type.model  # Get model name

    #             if model_name not in grouped_permissions:
    #                 grouped_permissions[model_name] = []

    #             grouped_permissions[model_name].append(
    #                 {"id": perm.id, "codename": perm.codename, "name": perm.name}
    #             )

    #         return Response(
    #             {"success": True, "info": grouped_permissions},
    #             status=status.HTTP_200_OK,
    #         )

    #     except Exception as e:
    #         logger.warning(str(e))
    #         return Response(
    #             {
    #                 "success": False,
    #                 "info": "An error occurred while fetching permissions",
    #             },
    #             status=status.HTTP_500_INTERNAL_SERVER_ERROR,
    #         )


class UserGroupViewset(viewsets.ModelViewSet):
    content_model = UserGroup
    queryset = UserGroup.objects.prefetch_related("permissions").all()
    permission_classes = [CustomPermission]
    lookup_field = "uid"

    def get_serializer_class(self):
        if self.action in ["create", "update", "partial_update"]:
            return UserGroupCreateUpdateSerializer
        return UserGroupListSerializer

    def get_queryset(self):
        user = self.request.user
        qs = self.queryset

        if user.role == UserRole.Role.SUPER_ADMIN:
            return qs.filter(is_global=True)

        return qs.filter(
            is_global=False,
            tenant__org_slug=user.org_slug,
        )

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        serializer = self.get_serializer(queryset, many=True)
        return Response(
            {
                "success": True,
                "info": serializer.data,
            },
            status=status.HTTP_200_OK,
        )

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)

        return Response(
            {
                "success": True,
                "info": serializer.data,
            },
            status=status.HTTP_200_OK,
        )

    def create(self, request, *args, **kwargs):
        try:
            data = request.data
            name = data.get("name")
            permissions = data.get("permissions", [])

            tenant = request.user.tenant

            if not name:
                return Response(
                    {
                        "success": False,
                        "info": "Name is required.",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Check if group already exists with or without organization
            group_filter = UserGroup.objects.filter(name=name)
            if tenant:
                group_filter = group_filter.filter(tenant=tenant)
            else:
                group_filter = group_filter.filter(tenant__isnull=True)

            if group_filter.exists():
                return Response(
                    {
                        "success": False,
                        "info": " User Group already exists.",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Create the group with or without organization

            group_data = {"name": name}
            if tenant:
                group_data["tenant"] = tenant

            if request.user.role == UserRole.Role.SUPER_ADMIN:
                group_data["is_global"] = True

            group = UserGroup.objects.create(**group_data)

            # Assign permissions to the group
            if permissions:
                valid_permissions = Permission.objects.filter(id__in=permissions)
                group.permissions.set(valid_permissions)

            return Response(
                {
                    "success": True,
                    "info": "User Group created successfully.",
                },
                status=status.HTTP_201_CREATED,
            )

        except Exception as e:
            logger.error(f"Error creating user group: {e}")
            return Response(
                {
                    "success": False,
                    "info": "Failed to create user group.",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    @action(
        detail=False,
        methods=["post"],
        url_path="assign-user-group",
    )
    def assign_user_group(self, request, *args, **kwargs):
        try:
            data = request.data
            group_id = data.get("group_id")
            users = data.get("users", [])

            if not group_id:
                return Response(
                    {
                        "success": False,
                        "info": "Group ID is required.",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if not isinstance(users, list):
                return Response(
                    {"success": False, "info": "users should be a list"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            user_group = UserGroup.objects.filter(id=group_id).first()

            if not user_group:
                return Response(
                    {
                        "success": False,
                        "info": "User Group does not exist.",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            for user in users:
                user_group.users.add(user)

            user_group.save()

            return Response(
                {
                    "success": True,
                    "info": "User Group assigned successfully.",
                },
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error(f"Error assigning user group: {e}")
            return Response(
                {
                    "success": False,
                    "info": "Failed to assign user group.",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    @action(
        detail=False,
        methods=["post"],
        url_path="remove-user-group",
    )
    def remove_user_group(self, request, *args, **kwargs):
        try:
            data = request.data
            group_id = data.get("group_id")
            users = data.get("users", [])

            if not group_id:
                return Response(
                    {
                        "success": False,
                        "info": "Group ID is required.",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if not isinstance(users, list):
                return Response(
                    {
                        "success": False,
                        "info": "users should be a list",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            user_group = UserGroup.objects.filter(id=group_id).first()

            if not user_group:
                return Response(
                    {
                        "success": False,
                        "info": "User Group does not exist.",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            user_group.users.remove(*users)

            return Response(
                {
                    "success": True,
                    "info": "User Group removed successfully.",
                },
                status=status.HTTP_410_GONE,
            )

        except Exception as e:
            logger.error(f"Error removing user group: {e}")
            return Response(
                {
                    "success": False,
                    "info": "Failed to remove user group.",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
