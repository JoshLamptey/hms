from django.urls import path, include
from rest_framework.routers import DefaultRouter
from apps.users.views import(
    UserRoleViewset,
    UserGroupViewset,
    UserViewset,
    PermissionViewset,
    FetchOrgUserGroups,
    FetchOrgUsers,
    SystemLogsViewset
)

router = DefaultRouter()

router.register(r"user-role", UserRoleViewset, basename="user-roles")
router.register(r"user-group", UserGroupViewset, basename="user-groups")
router.register(r"users", UserViewset, basename="users")
router.register(r"permissions", PermissionViewset, basename="permissions")
router.register(r"system-logs", SystemLogsViewset, basename="system-logs")
router.register(r"fetch-org-users", FetchOrgUsers, basename="fetch-org-users")
router.register(r"fetch-org-user-groups", FetchOrgUserGroups, basename="fetch-org-user-groups")

urlpatterns = [
    path("", include(router.urls)),
]