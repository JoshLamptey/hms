import json
import arrow
from rest_framework.decorators import action, permission_classes, api_view
from rest_framework import viewsets, status
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from apps.users.perms import CustomPermission
from django.db.models import Count, Q
from phonenumbers import parse, is_valid_number
from apps.client.models import (
    Tenant,
    License,
    LicenseHistory,
    LicenseRenewal,
    LicenseType,
)
from apps.client.serializers import (
    TenantCreateUpdateSerializer,
    TenantListSerializer,
    LicenseTypeSerializer,
    LicenseCreateUpdateSerializer,
    LicenseListSerializer,
    LicenseHistoryListSerializer,
    LicenseRenewalCreateUpdateSerializer,
    LicenseRenewalListSerializer,
)
from apps.client.decorators import with_schema

User = get_user_model()


# Create your views here.


class TenantViewset(viewsets.ModelViewSet):
    queryset = Tenant.objects.all()
    lookup_field = "uid"
    permission_classes = [CustomPermission]

    def get_serializer_class(self):
        if self.action in ["create", "update", "partial_update"]:
            return TenantCreateUpdateSerializer
        return TenantListSerializer

    def list(self, request, *args, **kwargs):

        if not request.user.is_superuser:
            return Response(
                {"success": False, "info": "Unathorized Request"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(
            {"success": True, "info": serializer.data}, status=status.HTTP_200_OK
        )

    def retrieve(self, request, *args, **kwargs):

        if not request.user.is_superuser:
            return Response(
                {"success": False, "info": "Unathorized Request"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(
            {"success": True, "info": serializer.data}, status=status.HTTP_200_OK
        )

    def create(self, request, *args, **kwargs):
        try:
            data = request.data

            if not request.user.is_superuser:
                return Response(
                    {"success": False, "info": "Unathorized Request"},
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            required_fields = [
                "name",
                "is_active",
                "logo",
                "email",
                "phone_number",
            ]

            for field in required_fields:
                if not data.get(field):
                    return Response(
                        {"success": False, "info": f"{field} is required"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            tenant_name = data.get("name")

            tenant = Tenant.objects.filter(name=tenant_name)

            if tenant.exists():
                return Response(
                    {
                        "success": False,
                        "info": "Sorry, Another organisation with this already exist.",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            phone_number = data.get("phone_number")

            if phone_number:
                phone = parse(phone_number)

                if not is_valid_number(phone):
                    return Response(
                        {"success": False, "info": "Invalid phone number"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            serializer = self.get_serializer(data=data)
            serializer.is_valid(raise_exception=True)
            serializer.save()

            return Response(
                {"success": True, "info": "Organization created successfully"},
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            print(f"Failed to create Tenant :{e}")
            return Response(
                {"success": False, "info": "An unexpected error occurred"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def update(self, request, *args, **kwargs):
        if not request.user.is_superuser:
            return Response(
                {"success": False, "info": "Unathorized Request"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(
            {"success": True, "info": "Organization updated successfully"},
            status=status.HTTP_200_OK,
        )

    def destroy(self, request, *args, **kwargs):
        if not request.user.is_superuser:
            return Response(
                {"success": False, "info": "Unauthorized Request"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        instance = self.get_object()
        instance.delete()

        return Response(
            {"success": True, "info": "Organization deleted successfully"},
            status=status.HTTP_200_OK,
        )

    @action(
        detail=False,
        methods=["get"],
        url_path="fetch-organizations",
        permission_classes=[CustomPermission],
    )
    def fetch_organisations(self, request):
        try:
            tenants = Tenant.objects.filter(id=request.user.tenant.id)
            serializer = TenantListSerializer(tenants, many=True)

            return Response(
                {"success": True, "info": serializer.data}, status=status.HTTP_200_OK
            )

        except Exception as e:
            print(f"Error fetching tenants :{e}")
            return Response(
                {
                    "success": False,
                    "info": "An error occurred while processing your request",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class LicenseTypeViewset(viewsets.ModelViewSet):
    queryset = LicenseType.objects.all()
    permission_classes = [CustomPermission]
    serializer_class = LicenseTypeSerializer
    lookup_field = "uid"

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        serializer = self.get_serializer(queryset, many=True)

        return Response(
            {"success": True, "info": serializer.data}, status=status.HTTP_200_OK
        )

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)

        return Response(
            {"success": True, "info": serializer.data}, status=status.HTTP_200_OK
        )

    def create(self, request, *args, **kwargs):
        try:
            data = request.data

            if not request.user.is_superuser:
                return Response(
                    {"success": False, "info": "Unathorized Request"},
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            required_fields = ["name", "coverage", "duration", "max_users"]

            for field in required_fields:
                if not data.get(field):
                    return Response(
                        {"success": False, "info": f"{field} is required"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            serializer = self.get_serializer(data=data)
            serializer.is_valid(raise_exception=True)
            serializer.save()

            return Response(
                {
                    "success": True,
                    "info": "License Type Created Successfully",
                    "data": serializer.data,
                },
                status=status.HTTP_201_CREATED,
            )

        except Exception as e:
            print(f"creating license failed {e}")
            return Response(
                {
                    "success": False,
                    "info": "An error occured whilst processing your request",
                }
            )

    def update(self, request, *args, **kwargs):
        if not request.user.is_superuser:
            return Response(
                {"success": False, "info": "Unathorized Request"},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        return super().update(request, *args, **kwargs)


class LicenseViewset(viewsets.ModelViewSet):
    queryset = (
        License.objects.prefetch_related("users")
        .select_related("license_type", "tenant")
        .all()
    )
    permission_classes = [CustomPermission]
    lookup_field = "uid"

    def get_serializer_class(self):
        if self.action in ["create", "update", "partial_update"]:
            return LicenseCreateUpdateSerializer
        return LicenseListSerializer

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        serializer = self.get_serializer(queryset, many=True)

        return Response(
            {"success": True, "info": serializer.data}, status=status.HTTP_200_OK
        )

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)

        return Response(
            {"success": True, "info": serializer.data}, status=status.HTTP_200_OK
        )

    def create(self, request, *args, **kwargs):
        try:
            data = request.data

            if not request.user.is_superuser:
                return Response(
                    {"success": False, "info": "Unathorized Request"},
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            required_fields = [
                "license_type",
                "issue_date",
                "expiry_date",
                "quantity",
                "tenant",
            ]

            for field in required_fields:
                if not data.get(field):
                    return Response(
                        {"success": False, "info": f"{field} is required"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            license_type = data.get("license_type")
            tenant = data.get("tenant")

            ltype = LicenseType.objects.filter(id=license_type).first()
            if not ltype:
                return Response(
                    {"success": False, "info": "LicenseType does not exist"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            org = Tenant.objects.filter(id=tenant).filter()
            if not org:
                return Response(
                    {"success": True, "info": "Tenant does not exist"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            serializer = self.get_serializer(data=data)
            serializer.is_valid(raise_exception=True)
            serializer.save()

            return Response(
                {
                    "success": True,
                    "info": "License Created Successfully",
                },
                status=status.HTTP_201_CREATED,
            )

        except Exception as e:
            print(f"license failed to create:{e}")
            return Response(
                {
                    "success": False,
                    "info": "An error occurred while processing your request",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

    def update(self, request, *args, **kwargs):
        if not request.user.is_superuser:
            return Response(
                {"success": False, "info": "Unauthorized Request"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(
            {"success": True, "info": "License updated successfully"},
            status=status.HTTP_200_OK,
        )

    def destroy(self, request, *args, **kwargs):
        if not request.user.is_superuser:
            return Response(
                {"success": False, "info": "Unauthorized Request"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        uid = kwargs.get("uid")
        instance = self.get_object()
        instance.delete()

        return Response(
            {"success": True, "info": "License deleted successfully"},
            status=status.HTTP_200_OK,
        )

    @action(
        detail=False,
        methods=["post"],
        url_path="assign-license-users",
        permission_classes=[CustomPermission],
    )
    def assign_license_users(self, request, *args, **kwargs):
        try:
            data = request.data
            license_id = data.get("license")
            users = data.get("users", [])

            if not license_id:
                return Response(
                    {"success": False, "info": "License is required"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if not users:
                return Response(
                    {"success": False, "info": "Users are required"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            license_obj = License.objects.filter(id=license_id).first()
            if not license_obj:
                return Response(
                    {"success": False, "info": "License not found"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            valid_users = User.objects.filter(id__in=users)
            valid_user_ids = set(valid_users.values_list("id", flat=True))
            num_users_to_assign = len(users)

            if len(valid_user_ids) != num_users_to_assign:
                return Response(
                    {"success": False, "info": "One or more users do not exist"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Check if users are already assigned to another license
            already_in_license = license_obj.users.filter(
                id__in=valid_user_ids
            ).values_list("id", flat=True)

            if already_in_license:
                return Response(
                    {
                        "success": False,
                        "info": f"Some users are already in this license",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # check  license capacity

            current_users_count = license_obj.users.count()
            max_users_allowed = license_obj.quantity
            remaining_slots = license_obj.remaining_slots

            # Check both max capacity and remaining slots for thorough validation
            if num_users_to_assign > remaining_slots:
                return Response(
                    {
                        "success": False,
                        "info": f"Cannot assign {num_users_to_assign} users. Only {remaining_slots} slots remaining.",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if current_users_count + num_users_to_assign > max_users_allowed:
                return Response(
                    {
                        "success": False,
                        "info": f"Cannot assign {num_users_to_assign} users. Would exceed maximum of {max_users_allowed} users.",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            license_obj.users.add(*valid_users)

        except Exception as e:
            print(f"failed to add license users {e}")
            return Response(
                {
                    "success": False,
                    "info": "An error occurred while assigning users to the license",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    @action(
        detail=False,
        methods=["post"],
        url_path="remove-license-users",
        permission_classes=[CustomPermission],
    )
    def remove_license_users(self, request, *args, **kwargs):
        try:
            data = request.data
            license_id = data.get("license")
            users = data.get("users", [])

            if not license_id:
                return Response(
                    {"success": False, "info": "License is required"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if not users:
                return Response(
                    {"success": False, "info": "Users are required"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            license_obj = License.objects.filter(id=license_id).first()

            if not license_obj:
                return Response(
                    {"success": False, "info": "License not found"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # validate Users
            valid_users = User.objects.filter(id__in=users)
            valid_users_ids = set(valid_users.values_list("id", flat=True))

            num_users_to_remove = len(users)

            if len(valid_users_ids) != num_users_to_remove:
                return Response(
                    {"success": False, "info": "One or more users do not exist"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # remove users from the license
            license_obj.users.remove(*valid_users)

            return Response(
                {"success": True, "info": "License users removed successfully"},
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            print(f"failed to remove license users: {e}")
            return Response(
                {
                    "success": False,
                    "info": "An error occured whilst processing your request",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    @action(
        detail=False,
        methods=["get"],
        url_path="fetch-expiring-licenses",
        permission_classes=[CustomPermission],
    )
    def fetch_expiring_licenses(self, request, *args, **kwargs):
        try:
            expiry = arrow.now().shift(days=90).date()
            """Fetch licenses that are expiring in 90 days"""
            licenses = (
                License.objects.filter(expriy_date__lte=expiry)
                .all()
                .order_by("-expiry_date")
            )
            serializer = LicenseListSerializer(licenses, many=True)

            return Response(
                {"success": True, "info": serializer.data}, status=status.HTTP_200_OK
            )

        except Exception as e:
            print(f"failed to fetch expiring licenses: {e}")
            return Response(
                {
                    "success": False,
                    "info": "An error occurred while fetching licenses",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    @action(
        detail=False,
        methods=["get"],
        url_path="retrieve-license-by-org/(?P<uid>[^/.]+)",
        permission_classes=[CustomPermission],
    )
    def get_single_license_by_org(self, request, *args, **kwargs):
        try:
            uid = kwargs.get("uid")
            license = License.objects.filter(
                tenant=request.user.tenant, uid=uid
            ).first()

            if not license:
                return Response(
                    {"success": False, "info": "License not found"},
                    status=status.HTTP_404_NOT_FOUND,
                )
            serializer = LicenseListSerializer(license, many=False)

            return Response(
                {"success": True, "info": serializer.data}, status=status.HTTP_200_OK
            )

        except Exception as e:
            print(f"failed to fetch license {e}")
            return Response(
                {
                    "success": False,
                    "info": "An error occurred whilst processing your request",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class FetchOrgLicense(viewsets.ReadOnlyModelViewSet):
    content_model = License
    permission_classes = [CustomPermission]

    def list(self, request, *args, **kwargs):
        try:
            if not request.user.role.name == "admin_user":
                return Response(
                    {"success": False, "info": "Unauthorized Request"},
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            licenses = License.objects.filter(tenant=request.user.tenant).order_by(
                "-expiry_date"
            )

            serializer = LicenseListSerializer(licenses, many=True)

            return Response(
                {"success": True, "info": serializer.data}, status=status.HTTP_200_OK
            )
        except AttributeError as e:
            print(f"Missing attribute: {str(e)}")
            return Response(
                {
                    "success": False,
                    "info": "Invalid user data",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        except Exception as e:
            print(f"Unexpected error fetching licenses: {str(e)}")
            return Response(
                {
                    "success": False,
                    "info": "An error occurred while fetching licenses",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class LicenseRenewalViewset(viewsets.ModelViewSet):
    queryset = LicenseRenewal.objects.select_related("license").all()
    permission_classes = [CustomPermission]
    lookup_field = "uid"

    def get_serializer_class(self):
        if self.action in ["create", "update", "partial_update"]:
            return LicenseRenewalCreateUpdateSerializer
        LicenseRenewalListSerializer

    def create(self, request, *args, **kwargs):
        try:
            data = request.data

            if not request.user.is_superuser:
                return Response(
                    {"success": False, "info": "Unathorized Request"},
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            required_fields = ["license", "expiry_date", "quantity"]

            for field in required_fields:
                if not data.get(field):
                    return Response(
                        {"success": False, "info": f"{field} is required"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            serializer = self.get_serializer(data=data)
            serializer.is_valid(raise_exception=True)
            serializer.save()

            return Response(
                {"success": True, "info": "License Renewal Successfully"},
                status=status.HTTP_201_CREATED,
            )

        except Exception as e:
            print(e)
            return Response(
                {
                    "success": False,
                    "info": "An error occurred while processing your request",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

    def update(self, request, *args, **kwargs):
        if not request.user.is_superuser:
            return Response(
                {"success": False, "info": "Unathorized Request"},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        return super().update(request, *args, **kwargs)


class LicenseHistoryViewset(viewsets.ViewSet):
    permission_classes = [CustomPermission]

    def list(self, request, *args, **kwargs):
        try:
            history = LicenseHistory.objects.select_related("license").all()
            serializer = LicenseHistoryListSerializer(history, many=True)

            return Response(
                {"success": True, "info": serializer.data}, status=status.HTTP_200_OK
            )

        except Exception as e:
            print(e)
            return Response(
                {
                    "success": False,
                    "info": "An error occurred while fetching permissions",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


api_view(["get"])


@permission_classes([CustomPermission])
def fetch_org_license_plans(request, *args, **kwargs):
    try:
        plans = License.objects.select_related("tenant", "license_type").filter(
            tenant=request.user.tenant
        )

        if not request.user.role.name == "super_admin":
            return Response(
                {"success": False, "info": "Unathorized Request"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        plan_data = []
        for plan in plans:
            plan_data.append(
                {
                    "type": plan.license_type.name,
                    "expiry": arrow.get(plan.expiry_date).date(),
                    "seats": f"{plan.users.count()} / {plan.quantity} Licensing",
                }
            )

        next_90_days = arrow.now().shift(days=90).date()

        expirys = plans.filter(expiry_date__lte=next_90_days)

        expiry_data = []

        for exp in expirys:
            total_days = (
                arrow.get(exp.expiry_date).date() - arrow.get(exp.created_at).date()
            ).days

            elapsed_days = (arrow.now().date() - arrow.get(exp.created_at).date()).days

            remaining_days = (
                arrow.get(exp.expiry_date).date() - arrow.now().date()
            ).days

            progress = (elapsed_days / total_days) * 100 if total_days > 0 else 100

            expiry_data.append(
                {
                    "license": exp.license_type.name,
                    "percentage": "{progress:.2f}".format(progress=progress),
                    "progressText": f"{elapsed_days} of {total_days} days",
                    "remainingText": f"{remaining_days} days remaining until your plan requires update",
                }
            )

            return Response(
                {"success": True, "info": {"plans": plan_data, "expirys": expiry_data}},
                status=status.HTTP_200_OK,
            )

    except Exception as e:
        print(e)
        return Response(
            {
                "success": False,
                "info": "An error occurred while fetching license plans",
            },
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@api_view(["get"])
@permission_classes([CustomPermission])
def fetch_dashboard_card(request, *args, **kwargs):
    """
    Fetch dashboard statistics including organizations, licenses, and users.
    Returns:
        - Organization counts (total, active, inactive)
        - License counts (total, active, expired, types)
        - User counts (total, active, inactive, admin)
    """

    try:
        tenants = Tenant.objects.prefetch_related("license_set"), all()
        licenses = License.objects.select_related("tenant").all()

        tenant_license_status = licenses.values("tenant", "status").annotate(
            count=Count("status")
        )

        active_tenant_ids = {
            item["tenant"]
            for item in tenant_license_status
            if item["status"] == "active"
        }
        expired_tenant_ids = {
            item["tenant"]
            for item in tenant_license_status
            if item["status"] == "expired"
        }

        # license stats
        license_stats = licenses.aggregate(
            total=Count("id"),
            active=Count("id", filter=Q(status="active")),
            expired=Count("id", filter=Q(status="expired")),
            types=Count("license_type", distinct=True),
        )

        # user stats
        user_stats = User.objects.aggregate(
            total=Count("id"),
            active=Count("id", filter=Q(is_active=True)),
            inactive=Count("id", filter=Q(is_active=False)),
            admins=Count("id", filter=Q(is_superuser=True)),
        )

        data = {
            "tenants": {
                "total": tenants.count(),
                "active": len(active_tenant_ids),
                "inactive": len(expired_tenant_ids),
                "with_licenses": len(active_tenant_ids | expired_tenant_ids),
            },
            "licenses": license_stats,
            "users": {
                "total": user_stats["total"],
                "active": user_stats["active"] - user_stats["admins"],
                "inactive": user_stats["inactive"],
                "admins": user_stats["admins"],
            },
        }

        return Response(
            {
                "success": True,
                "info": data,
            },
            status=status.HTTP_200_OK,
        )

    except Exception as e:
        print(e)
        return Response(
            {
                "success": False,
                "data": None,
                "message": "An unexpected error occurred while processing your request",
            },
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@api_view(["GET"])
@permission_classes([CustomPermission])
def fetch_dashboard_pie_charts(request, *args, **kwargs):
    try:
        all_license_types = list(LicenseType.objects.values_list("name", flat=True))

        license_counts = {lt_name: 0 for lt_name in all_license_types}

        licenses_by_type = License.objects.values("licenses_type__name").annotate(
            count=Count("id")
        )

        for item in licenses_by_type:
            lt_name = item["license_by_type"]
            if lt_name in license_counts:
                license_counts[lt_name] = item["count"]

        labels = list(license_counts.keys())
        counts = list(license_counts.values)

        background_colors = [
            "#3B82F6",  # Blue
            "#10B981",  # Emerald
            "#F59E0B",  # Amber
            "#EF4444",  # Red
            "#8B5CF6",  # Violet
            "#EC4899",  # Pink
        ]

        # Rotate colors if more types than colors
        if len(labels) > len(background_colors):
            background_colors *= len(labels) // len(background_colors) + 1

        chart_data = {
            "labels": labels,
            "datasets": [
                {
                    "data": counts,
                    "backgroundColor": background_colors[: len(labels)],
                    "borderWidth": 1,
                }
            ],
        }

        return Response(
            {
                "success": True,
                "info": chart_data,
            },
            status=status.HTTP_200_OK,
        )

    except Exception as e:
        print(e)
        return Response(
            {
                "success": False,
                "data": None,
                "message": "An unexpected error occurred while processing your request",
            },
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@api_view(["GET"])
@permission_classes([CustomPermission])
def fetch_dashboard_bar_chart(request, *args, **kwargs):
    try:
        recent_renewals = (
            LicenseRenewal.objects.select_related("license", "license__tenant")
            .order_by("license__tenant_id", "-renewal_date")
            .distinct("license__tenant_id")[:10]
        )

        chart_data = {
            "labels": [],
            "datasets": [
                {
                    "label": "License Quantity",
                    "data": [],
                    "backgroundColor": "#3B82F6",
                    "borderColor": "#3B82F6",
                    "borderWidth": 1,
                }
            ],
        }

        for renewal in recent_renewals:
            chart_data["labels"].append(renewal.license.tenant.org_slug)
            chart_data["datasets"][0]["data"].append(renewal.license.quantity)

        return Response(
            {
                "success": True,
                "info": chart_data,
                "message": "Bar chart data fetched successfully",
            }
        )

    except Exception as e:
        print(e)
        return Response(
            {
                "success": False,
                "info": None,
                "message": f"Error fetching chart data: {str(e)}",
            },
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
