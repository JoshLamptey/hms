import logging
import arrow
from django.db.models import Count, Q
from django.db import transaction
from django.http import Http404
from django.contrib.auth import get_user_model
from rest_framework import viewsets, status
from rest_framework.decorators import api_view, permission_classes, action
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema, OpenApiResponse, OpenApiExample
from drf_spectacular.types import OpenApiTypes
from phonenumbers import parse, is_valid_number
from apps.users.perms import TenantPermission
from apps.clients.models import (
    Tenant,
    License,
    LicenseType,
    LicenseRenewal,
    LicenseHistory,
)
from apps.clients.serializers import (
    TenantCreateUpdateSerializer,
    TenantListSerializer,
    LicenseTypeCreateUpdateSerializer,
    LicenseTypeListSerializer,
    LicenseCreateUpdateSerializer,
    LicenseListSerializer,
    LicenseHistoryListSerializer,
    LicenseRenewalCreateUpdateSerializer,
    LicenseRenewalListSerializer,
)
from apps.clients.utils import generate_schema_name

User = get_user_model()
logger = logging.getLogger(__name__)


def is_privileged(user):
    return user.is_superuser or (user.role and user.role.name == "SUPER_ADMIN")


class TenantViewset(viewsets.ModelViewSet):
    content_model = Tenant
    queryset = Tenant.objects.all()
    lookup_field = "uid"
    permission_classes = [TenantPermission]

    def get_serializer_class(self):
        if self.action in ["create", "update", "partial_update"]:
            return TenantCreateUpdateSerializer
        return TenantListSerializer

    def list(self, request, *args, **kwargs):
        if not is_privileged(request.user):
            return Response(
                {"success": False, "message": "Unauthorized request."},
                status=status.HTTP_403_FORBIDDEN,
            )

        queryset = self.filter_queryset(self.get_queryset())
        serializer = self.get_serializer(
            queryset, many=True, context={"request": request}
        )
        return Response(
            {"success": True, "data": serializer.data},
            status=status.HTTP_200_OK,
        )

    def retrieve(self, request, *args, **kwargs):
        if not is_privileged(request.user):
            return Response(
                {"success": False, "message": "Unauthorized request."},
                status=status.HTTP_403_FORBIDDEN,
            )

        try:
            instance = self.get_object()
        except Http404:
            return Response(
                {"success": False, "message": "Organisation not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        serializer = self.get_serializer(instance, context={"request": request})
        return Response(
            {"success": True, "data": serializer.data},
            status=status.HTTP_200_OK,
        )

    def create(self, request, *args, **kwargs):
        try:
            if not is_privileged(request.user):
                return Response(
                    {"success": False, "message": "Unauthorized request."},
                    status=status.HTTP_403_FORBIDDEN,
                )

            data = request.data
            required_fields = ["name", "email", "phone_number"]

            for field in required_fields:
                if not data.get(field):
                    return Response(
                        {"success": False, "data": f"{field} is required."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            phone_number = data.get("phone_number")
            email = data.get("email")
            name = data.get("name")

            if Tenant.objects.filter(
                Q(email=email) | Q(phone_number=phone_number)
            ).exists():
                return Response(
                    {
                        "success": False,
                        "message": "An organisation with these contact details already exists.",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if Tenant.objects.filter(name=name).exists():
                return Response(
                    {
                        "success": False,
                        "message": "An organisation with this name already exists.",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if phone_number:
                try:
                    phone = parse(phone_number)
                    if not is_valid_number(phone):
                        return Response(
                            {"success": False, "message": "Invalid phone number."},
                            status=status.HTTP_400_BAD_REQUEST,
                        )
                except Exception:
                    return Response(
                        {"success": False, "message": "Invalid phone number format."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            with transaction.atomic():
                schema_name = generate_schema_name(name)

                # Check schema_name uniqueness explicitly
                if Tenant.objects.filter(schema_name=schema_name).exists():
                    return Response(
                        {"success": False, "message": "An organisation with a similar name already exists."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                serializer = self.get_serializer(data={**data, "schema_name": schema_name})
                serializer.is_valid(raise_exception=True)
                serializer.save()

            return Response(
                {"success": True, "message": "Organisation created successfully."},
                status=status.HTTP_201_CREATED,
            )

        except Exception as e:
            logger.error(f"Failed to create tenant: {e}")
            return Response(
                {"success": False, "message": "An unexpected error occurred."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def update(self, request, *args, **kwargs):
        if not is_privileged(request.user):
            return Response(
                {"success": False, "message": "Unauthorized request."},
                status=status.HTTP_403_FORBIDDEN,
            )

        try:
            instance = self.get_object()
        except Http404:
            return Response(
                {"success": False, "message": "Organisation not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(
            {"success": True, "message": "Organisation updated successfully."},
            status=status.HTTP_200_OK,
        )

    def destroy(self, request, *args, **kwargs):
        if not is_privileged(request.user):
            return Response(
                {"success": False, "message": "Unauthorized request."},
                status=status.HTTP_403_FORBIDDEN,
            )

        try:
            instance = self.get_object()
        except Http404:
            return Response(
                {"success": False, "message": "Organisation not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        instance.delete()

        return Response(
            {"success": True, "message": "Organisation deleted successfully."},
            status=status.HTTP_200_OK,
        )

    @action(detail=False, methods=["get"], url_path="my-organisation")
    def fetch_my_organisation(self, request):
        try:
            tenant = request.user.tenant
            if not tenant:
                return Response(
                    {
                        "success": False,
                        "message": "No organisation assigned to your account.",
                    },
                    status=status.HTTP_404_NOT_FOUND,
                )

            serializer = TenantListSerializer(tenant, context={"request": request})
            return Response(
                {"success": True, "data": serializer.data},
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error(f"Error fetching organisation: {e}")
            return Response(
                {
                    "success": False,
                    "message": "An error occurred while fetching your organisation.",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class LicenseTypeViewset(viewsets.ModelViewSet):
    content_model = LicenseType
    queryset = LicenseType.objects.all()
    permission_classes = [TenantPermission]
    lookup_field = "uid"

    def get_serializer_class(self):
        if self.action in ["create", "update", "partial_update"]:
            return LicenseTypeCreateUpdateSerializer
        return LicenseTypeListSerializer

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        serializer = self.get_serializer(queryset, many=True)
        return Response(
            {"success": True, "data": serializer.data},
            status=status.HTTP_200_OK,
        )

    def retrieve(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
        except Http404:
            return Response(
                {"success": False, "message": "License type not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        serializer = self.get_serializer(instance)
        return Response(
            {"success": True, "data": serializer.data},
            status=status.HTTP_200_OK,
        )

    def create(self, request, *args, **kwargs):
        try:
            if not is_privileged(request.user):
                return Response(
                    {"success": False, "message": "Unauthorized request."},
                    status=status.HTTP_403_FORBIDDEN,
                )

            data = request.data
            required_fields = ["name", "coverage", "duration", "max_users"]

            for field in required_fields:
                if not data.get(field):
                    return Response(
                        {"success": False, "message": f"{field} is required."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            if LicenseType.objects.filter(name=data.get("name")).exists():
                return Response(
                    {
                        "success": False,
                        "message": "A license type with this name already exists.",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            serializer = self.get_serializer(data=data)
            serializer.is_valid(raise_exception=True)
            serializer.save()

            return Response(
                {"success": True, "message": "License type created successfully."},
                status=status.HTTP_201_CREATED,
            )

        except Exception as e:
            logger.error(f"Failed to create license type: {e}")
            return Response(
                {
                    "success": False,
                    "message": "An error occurred whilst processing your request.",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def update(self, request, *args, **kwargs):
        if not is_privileged(request.user):
            return Response(
                {"success": False, "message": "Unauthorized request."},
                status=status.HTTP_403_FORBIDDEN,
            )

        try:
            instance = self.get_object()
        except Http404:
            return Response(
                {"success": False, "message": "License type not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(
            {"success": True, "message": "License type updated successfully."},
            status=status.HTTP_200_OK,
        )

    def destroy(self, request, *args, **kwargs):
        if not is_privileged(request.user):
            return Response(
                {"success": False, "message": "Unauthorized request."},
                status=status.HTTP_403_FORBIDDEN,
            )

        try:
            instance = self.get_object()
        except Http404:
            return Response(
                {"success": False, "message": "License type not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        instance.delete()

        return Response(
            {"success": True, "message": "License type deleted successfully."},
            status=status.HTTP_200_OK,
        )


class LicenseViewset(viewsets.ModelViewSet):
    content_model = License
    queryset = (
        License.objects.prefetch_related("users")
        .select_related("license_type", "tenant")
        .all()
    )
    permission_classes = [TenantPermission]
    lookup_field = "uid"

    def get_serializer_class(self):
        if self.action in ["create", "update", "partial_update"]:
            return LicenseCreateUpdateSerializer
        return LicenseListSerializer

    def list(self, request, *args, **kwargs):
        if not is_privileged(request.user):
            return Response(
                {"success": False, "message": "Unauthorized request."},
                status=status.HTTP_403_FORBIDDEN,
            )

        queryset = self.filter_queryset(self.get_queryset())
        serializer = self.get_serializer(queryset, many=True)
        return Response(
            {"success": True, "data": serializer.data},
            status=status.HTTP_200_OK,
        )

    def retrieve(self, request, *args, **kwargs):
        if not is_privileged(request.user):
                return Response(
                    {"success": False, "message": "Unauthorized request."},
                    status=status.HTTP_403_FORBIDDEN,
                )
        try:
            instance = self.get_object()
        except Http404:
            return Response(
                {"success": False, "message": "License not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        serializer = self.get_serializer(instance)
        return Response(
            {"success": True, "data": serializer.data},
            status=status.HTTP_200_OK,
        )

    def create(self, request, *args, **kwargs):
        try:
            if not is_privileged(request.user):
                return Response(
                    {"success": False, "data": "Unauthorized request."},
                    status=status.HTTP_403_FORBIDDEN,
                )

            data = request.data
            required_fields = ["license_type", "quantity", "tenant"]

            for field in required_fields:
                if not data.get(field):
                    return Response(
                        {"success": False, "message": f"{field} is required."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            if not LicenseType.objects.filter(id=data.get("license_type")).exists():
                return Response(
                    {"success": False, "message": "License type does not exist."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if not Tenant.objects.filter(id=data.get("tenant")).exists():
                return Response(
                    {"success": False, "message": "Tenant does not exist."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            serializer = self.get_serializer(data=data)
            serializer.is_valid(raise_exception=True)
            serializer.save()

            return Response(
                {"success": True, "message": "License created successfully."},
                status=status.HTTP_201_CREATED,
            )

        except Exception as e:
            logger.error(f"Failed to create license: {e}")
            return Response(
                {
                    "success": False,
                    "message": "An error occurred while processing your request.",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def update(self, request, *args, **kwargs):
        if not is_privileged(request.user):
            return Response(
                {"success": False, "message": "Unauthorized request."},
                status=status.HTTP_403_FORBIDDEN,
            )

        try:
            instance = self.get_object()
        except Http404:
            return Response(
                {"success": False, "message": "License not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(
            {"success": True, "message": "License updated successfully."},
            status=status.HTTP_200_OK,
        )

    def destroy(self, request, *args, **kwargs):
        if not is_privileged(request.user):
            return Response(
                {"success": False, "message": "Unauthorized request."},
                status=status.HTTP_403_FORBIDDEN,
            )

        try:
            instance = self.get_object()
        except Http404:
            return Response(
                {"success": False, "message": "License not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        instance.delete()

        return Response(
            {"success": True, "message": "License deleted successfully."},
            status=status.HTTP_200_OK,
        )

    @action(detail=False, methods=["post"], url_path="assign-license-users")
    def assign_license_users(self, request, *args, **kwargs):
        try:
            data = request.data
            license_uid = data.get("license_uid")
            users = data.get("users", [])

            if not license_uid:
                return Response(
                    {"success": False, "message": "License UID is required."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if not users:
                return Response(
                    {"success": False, "message": "Users are required."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if not isinstance(users, list):
                return Response(
                    {"success": False, "message": "Users must be a list."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            license_obj = License.objects.filter(uid=license_uid).first()
            if not license_obj:
                return Response(
                    {"success": False, "message": "License not found."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            valid_users = User.objects.filter(id__in=users)
            if valid_users.count() != len(users):
                return Response(
                    {"success": False, "message": "One or more users do not exist."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            already_assigned = license_obj.users.filter(id__in=users).values_list(
                "id", flat=True
            )
            if already_assigned.exists():
                return Response(
                    {
                        "success": False,
                        "message": "Some users are already assigned to this license.",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if len(users) > license_obj.remaining_slots:
                return Response(
                    {
                        "success": False,
                        "message": f"Cannot assign {len(users)} users. Only {license_obj.remaining_slots} slots remaining.",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            license_obj.users.add(*valid_users)

            return Response(
                {"success": True, "message": "Users assigned to license successfully."},
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error(f"Failed to assign license users: {e}")
            return Response(
                {
                    "success": False,
                    "message": "An error occurred while assigning users to the license.",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    @action(detail=False, methods=["post"], url_path="remove-license-users")
    def remove_license_users(self, request, *args, **kwargs):
        try:
            data = request.data
            license_uid = data.get("license_uid")
            users = data.get("users", [])

            if not license_uid:
                return Response(
                    {"success": False, "message": "License UID is required."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if not users:
                return Response(
                    {"success": False, "message": "Users are required."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if not isinstance(users, list):
                return Response(
                    {"success": False, "message": "Users must be a list."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            license_obj = License.objects.filter(uid=license_uid).first()
            if not license_obj:
                return Response(
                    {"success": False, "message": "License not found."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            valid_users = User.objects.filter(id__in=users)
            if valid_users.count() != len(users):
                return Response(
                    {"success": False, "message": "One or more users do not exist."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            license_obj.users.remove(*valid_users)

            return Response(
                {"success": True, "message": "Users removed from license successfully."},
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error(f"Failed to remove license users: {e}")
            return Response(
                {
                    "success": False,
                    "message": "An error occurred whilst processing your request.",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    @action(detail=False, methods=["get"], url_path="expiring-licenses")
    def fetch_expiring_licenses(self, request, *args, **kwargs):
        try:
            if not is_privileged(request.user):
                return Response(
                    {"success": False, "message": "Unauthorized request."},
                    status=status.HTTP_403_FORBIDDEN,
                )

            expiry = arrow.now().shift(days=90).date()
            licenses = (
                License.objects.filter(expiry_date__lte=expiry)
                .select_related("license_type", "tenant")
                .order_by("expiry_date")
            )

            serializer = LicenseListSerializer(licenses, many=True)
            return Response(
                {"success": True, "data": serializer.data},
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error(f"Failed to fetch expiring licenses: {e}")
            return Response(
                {
                    "success": False,
                    "message": "An error occurred while fetching licenses.",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
    

class FetchOrgLicense(viewsets.ReadOnlyModelViewSet):
    content_model = License
    permission_classes = [TenantPermission]
    serializer_class = LicenseListSerializer

    def get_queryset(self):
        return (
            License.objects.filter(tenant=self.request.user.tenant)
            .select_related("license_type", "tenant")
            .order_by("-expiry_date")
        )

    def list(self, request, *args, **kwargs):
        try:
            queryset = self.get_queryset()
            serializer = self.get_serializer(queryset, many=True)
            return Response(
                {"success": True, "data": serializer.data},
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error(f"Failed to fetch org licenses: {e}")
            return Response(
                {
                    "success": False,
                    "message": "An error occurred while fetching licenses.",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class LicenseRenewalViewset(viewsets.ModelViewSet):
    content_model = LicenseRenewal
    queryset = LicenseRenewal.objects.select_related("license").all()
    permission_classes = [TenantPermission]
    lookup_field = "uid"

    def get_serializer_class(self):
        if self.action in ["create", "update", "partial_update"]:
            return LicenseRenewalCreateUpdateSerializer
        return LicenseRenewalListSerializer

    def list(self, request, *args, **kwargs):
        if not is_privileged(request.user):
                return Response(
                    {"success": False, "message": "Unauthorized request."},
                    status=status.HTTP_403_FORBIDDEN,
                )
        queryset = self.filter_queryset(self.get_queryset())
        serializer = self.get_serializer(queryset, many=True)
        return Response(
            {"success": True, "data": serializer.data},
            status=status.HTTP_200_OK,
        )

    def retrieve(self, request, *args, **kwargs):
        if not is_privileged(request.user):
                return Response(
                    {"success": False, "message": "Unauthorized request."},
                    status=status.HTTP_403_FORBIDDEN,
                )
        try:
            instance = self.get_object()
        except Http404:
            return Response(
                {"success": False, "message": "License renewal not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        serializer = self.get_serializer(instance)
        return Response(
            {"success": True, "data": serializer.data},
            status=status.HTTP_200_OK,
        )

    def create(self, request, *args, **kwargs):
        try:
            if not is_privileged(request.user):
                return Response(
                    {"success": False, "message": "Unauthorized request."},
                    status=status.HTTP_403_FORBIDDEN,
                )

            data = request.data
            required_fields = ["license", "quantity"]

            for field in required_fields:
                if not data.get(field):
                    return Response(
                        {"success": False, "message": f"{field} is required."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            if not License.objects.filter(id=data.get("license")).exists():
                return Response(
                    {"success": False, "message": "License does not exist."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            serializer = self.get_serializer(data=data)
            serializer.is_valid(raise_exception=True)
            serializer.save()

            return Response(
                {"success": True, "message": "License renewed successfully."},
                status=status.HTTP_201_CREATED,
            )

        except Exception as e:
            logger.error(f"Failed to create license renewal: {e}")
            return Response(
                {
                    "success": False,
                    "message": "An error occurred while processing your request.",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def update(self, request, *args, **kwargs):
        if not is_privileged(request.user):
            return Response(
                {"success": False, "message": "Unauthorized request."},
                status=status.HTTP_403_FORBIDDEN,
            )

        try:
            instance = self.get_object()
        except Http404:
            return Response(
                {"success": False, "message": "License renewal not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(
            {"success": True, "message": "License renewal updated successfully."},
            status=status.HTTP_200_OK,
        )



class LicenseHistoryViewset(viewsets.ViewSet):
    content_model = LicenseHistory
    permission_classes = [TenantPermission]
    serializer_class = LicenseHistoryListSerializer

    def list(self, request, *args, **kwargs):
        try:
            if not is_privileged(request.user):
                return Response(
                    {"success": False, "message": "Unauthorized request."},
                    status=status.HTTP_403_FORBIDDEN,
                )

            history = LicenseHistory.objects.select_related("license", "tenant").all()
            serializer = self.serializer_class(history, many=True)
            return Response(
                {"success": True, "data": serializer.data},
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error(f"Failed to fetch license history: {e}")
            return Response(
                {
                    "success": False,
                    "message": "An error occurred while fetching license history.",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


@extend_schema(
    summary="Fetch organisation license plans",
    description="Get license plans and expiring licenses for the authenticated user's organisation.",
    responses={200: OpenApiResponse(response=OpenApiTypes.OBJECT)},
)
@api_view(["GET"])
@permission_classes([TenantPermission])
def fetch_org_license_plans(request, *args, **kwargs):
    try:
        plans = License.objects.select_related("tenant", "license_type").filter(
            tenant=request.user.tenant
        )

        plan_data = []
        for plan in plans:
            plan_data.append(
                {
                    "type": plan.license_type.name,
                    "expiry": (
                        arrow.get(plan.expiry_date).date() if plan.expiry_date else None
                    ),
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
                    "percentage": f"{progress:.2f}",
                    "progressText": f"{elapsed_days} of {total_days} days",
                    "remainingText": f"{remaining_days} days remaining until your plan requires update",
                }
            )

        return Response(
            {"success": True, "data": {"plans": plan_data, "expirys": expiry_data}},
            status=status.HTTP_200_OK,
        )

    except Exception as e:
        logger.error(f"Failed to fetch org license plans: {e}")
        return Response(
            {
                "success": False,
                "message": "An error occurred while fetching license plans.",
            },
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@extend_schema(
    summary="Fetch dashboard card statistics",
    description="Get dashboard statistics including organisations, licenses, and users.",
    responses={200: OpenApiResponse(response=OpenApiTypes.OBJECT)},
)
@api_view(["GET"])
@permission_classes([TenantPermission])
def fetch_dashboard_card(request, *args, **kwargs):
    try:
        if not is_privileged(request.user):
            return Response(
                {"success": False, "message": "Unauthorized request."},
                status=status.HTTP_403_FORBIDDEN,
            )

        tenants = Tenant.objects.all()
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

        license_stats = licenses.aggregate(
            total=Count("id"),
            active=Count("id", filter=Q(status="active")),
            expired=Count("id", filter=Q(status="expired")),
            types=Count("license_type", distinct=True),
        )

        user_stats = User.objects.aggregate(
            total=Count("id"),
            active=Count("id", filter=Q(is_active=True)),
            inactive=Count("id", filter=Q(is_active=False)),
            admins=Count("id", filter=Q(is_superuser=True)),
        )

        return Response(
            {
                "success": True,
                "data": {
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
                },
            },
            status=status.HTTP_200_OK,
        )

    except Exception as e:
        logger.error(f"Failed to fetch dashboard stats: {e}")
        return Response(
            {"success": False, "message": "An unexpected error occurred."},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@extend_schema(
    summary="Fetch dashboard pie chart data",
    description="Get license distribution data for pie chart visualization.",
    responses={200: OpenApiResponse(response=OpenApiTypes.OBJECT)},
)
@api_view(["GET"])
@permission_classes([TenantPermission])
def fetch_dashboard_pie_charts(request, *args, **kwargs):
    try:
        if not is_privileged(request.user):
            return Response(
                {"success": False, "message": "Unauthorized request."},
                status=status.HTTP_403_FORBIDDEN,
            )

        all_license_types = list(LicenseType.objects.values_list("name", flat=True))
        license_counts = {lt_name: 0 for lt_name in all_license_types}

        licenses_by_type = License.objects.values("license_type__name").annotate(
            count=Count("id")
        )

        for item in licenses_by_type:
            lt_name = item["license_type__name"]
            if lt_name in license_counts:
                license_counts[lt_name] = item["count"]

        labels = list(license_counts.keys())
        counts = list(license_counts.values())

        background_colors = [
            "#3B82F6",
            "#10B981",
            "#F59E0B",
            "#EF4444",
            "#8B5CF6",
            "#EC4899",
        ]

        if len(labels) > len(background_colors):
            background_colors *= len(labels) // len(background_colors) + 1

        return Response(
            {
                "success": True,
                "data": {
                    "labels": labels,
                    "datasets": [
                        {
                            "data": counts,
                            "backgroundColor": background_colors[: len(labels)],
                            "borderWidth": 1,
                        }
                    ],
                },
            },
            status=status.HTTP_200_OK,
        )

    except Exception as e:
        logger.error(f"Failed to fetch pie chart data: {e}")
        return Response(
            {"success": False, "message": "An unexpected error occurred."},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@extend_schema(
    summary="Fetch dashboard bar chart data",
    description="Get recent license renewals data for bar chart visualization.",
    responses={200: OpenApiResponse(response=OpenApiTypes.OBJECT)},
)
@api_view(["GET"])
@permission_classes([TenantPermission])
def fetch_dashboard_bar_chart(request, *args, **kwargs):
    try:
        if not is_privileged(request.user):
            return Response(
                {"success": False, "message": "Unauthorized request."},
                status=status.HTTP_403_FORBIDDEN,
            )

        recent_renewals = (
            LicenseRenewal.objects.select_related("license", "license__tenant")
            .order_by("license__tenant_id", "-renewal_date")
            .distinct("license__tenant_id")[:10]
        )

        labels = []
        data = []

        for renewal in recent_renewals:
            labels.append(renewal.license.tenant.org_slug)
            data.append(renewal.license.quantity)

        return Response(
            {
                "success": True,
                "data": {
                    "labels": labels,
                    "datasets": [
                        {
                            "label": "License Quantity",
                            "data": data,
                            "backgroundColor": "#3B82F6",
                            "borderColor": "#3B82F6",
                            "borderWidth": 1,
                        }
                    ],
                },
            },
            status=status.HTTP_200_OK,
        )

    except Exception as e:
        logger.error(f"Failed to fetch bar chart data: {e}")
        return Response(
            {"success": False, "message": "An error occurred while fetching chart data."},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )