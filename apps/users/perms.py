import logging
from django.db.models import Q
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth.models import Permission
from rest_framework.permissions import BasePermission
from rest_framework import exceptions
from apps.users.models import UserGroup

logger = logging.getLogger(__name__)

def is_admin(user):
    return bool(user.role and user.role.name in ["ADMIN", "MANAGER"])


class TenantPermission(BasePermission):

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        if request.user.is_superuser:
            return True

        if request.user.role and request.user.role.name == "SUPER_ADMIN":
            return True

        if request.user.is_blocked:
            raise exceptions.PermissionDenied(
                "Your account has been blocked, Please contact your administrator."
            )

        if not request.user.login_enabled:
            raise exceptions.PermissionDenied(
                "Login is disabled for this account, Please contact your administrator."
            )

        if not hasattr(view, "content_model") or view.content_model is None:
            return False

        model_name = view.content_model._meta.model_name

        permission_map = {
            "create": f"add_{model_name}",
            "update": f"change_{model_name}",
            "partial_update": f"change_{model_name}",
            "destroy": f"delete_{model_name}",
            "retrieve": f"view_{model_name}",
            "list": f"view_{model_name}",
        }

        required_permission = permission_map.get(view.action)

        if required_permission:
            content_type = ContentType.objects.get_for_model(view.content_model)

            if not Permission.objects.filter(
                codename=required_permission,
                content_type=content_type,
            ).exists():
                return False

            user_has_group_permission = UserGroup.objects.filter(
                Q(users=request.user)
                & Q(permissions__codename=required_permission)
                & Q(permissions__content_type=content_type)
                & (Q(tenant=request.user.tenant) | Q(is_global=True))
            ).exists()

            if not user_has_group_permission:
                if not request.user.has_perm(
                    f"{content_type.app_label}.{required_permission}"
                ):
                    return False

        if (
            hasattr(view, "check_organization_context")
            and view.check_organization_context
        ):
            if not self._check_organization_context(request, view):
                return False

        return True

    def _check_organization_context(self, request, view):
        user_org = getattr(request.user, "org_slug", None)

        if not user_org:
            return False
        return True


class LicenseGuard(BasePermission):

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        if request.user.is_superuser:
            return True

        if request.user.role and request.user.role.name == "SUPER_ADMIN":
            return True

        tenant = getattr(request.user, "tenant", None)
        if tenant is None:
            raise exceptions.PermissionDenied(
                "No organisation assigned to this account, Please contact your admin"
            )

        license = getattr(tenant, "license", None)
        if license is None or not license.is_active:
            raise exceptions.PermissionDenied(
                "Your organisation's license is inactive, Please contact your admin"
            )

        return True
