from django.urls import path, include
from rest_framework.routers import DefaultRouter
from apps.users.views import (
    UserRoleViewSet,
    UserGroupViewSet,
    UserViewSet,
    PermissionViewset,
    FetchOrgUserGroups,
    FetchOrgUsers,
)

router = DefaultRouter()

router.register(r"user-role", UserRoleViewSet, basename="user-roles")
router.register(r"user-group", UserGroupViewSet, basename="user-groups")
router.register(r"users", UserViewSet, basename="users")
router.register(r"permissions", PermissionViewset, basename="permissions")
router.register(r"fetch-org-users", FetchOrgUsers, basename="fetch-org-users")
router.register(
    r"fetch-org-user-groups", FetchOrgUserGroups, basename="fetch-org-user-groups"
)

urlpatterns = [
    path("", include(router.urls)),
]
