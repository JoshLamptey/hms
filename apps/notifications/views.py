import logging
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import transaction
from django.http import Http404
from django.utils import timezone
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import SimpleRateThrottle
from rest_framework.views import APIView
from redis.exceptions import RedisError
from apps.users.perms import TenantPermission
from apps.notifications.models import Campaign, Notification
from apps.notifications.serializers import (
    CampaignCreateUpdateSerializer,
    CampaignListSerializer,
    NotificationListSerializer,
)
from apps.notifications.tasks import send_campaign_task
from apps.notifications.tickets import TICKET_TTL_SECONDS, issue_ticket
from apps.notifications.service import  NotificationService
User = get_user_model()
logger = logging.getLogger(__name__)


service = NotificationService()


class _WebSocketTicketThrottle(SimpleRateThrottle):
    def cache_key(self, identity):
        return self.cache_format % {"scope": self.scope, "ident": identity}


class WebSocketTicketUserThrottle(_WebSocketTicketThrottle):
    scope = "ws_ticket"

    def get_cache_key(self, request, view):
        user_id = getattr(request.user, "pk", None)
        return self.cache_key(f"user:{user_id}") if user_id else None


class WebSocketTicketIPThrottle(_WebSocketTicketThrottle):
    scope = "ws_ticket_ip"

    def get_cache_key(self, request, view):
        return self.cache_key(f"ip:{self.get_ident(request)}")


class WebSocketTicketView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [WebSocketTicketUserThrottle, WebSocketTicketIPThrottle]

    def post(self, request):
        user = request.user
        if (
            not user.is_active
            or user.is_blocked
            or not user.login_enabled
            or user.status != User.Status.ACTIVE
            or (user.tenant_id is not None and not user.tenant.is_active)
        ):
            return Response(
                {"detail": "Account is not eligible for WebSocket access."},
                status=status.HTTP_403_FORBIDDEN,
            )

        origin = request.headers.get("Origin", "")
        allowed_origins = getattr(settings, "WS_ALLOWED_ORIGINS", [])
        if origin and origin not in allowed_origins:
            return Response(
                {"detail": "Origin is not allowed."},
                status=status.HTTP_403_FORBIDDEN,
            )

        try:
            ticket = issue_ticket(user, origin)
        except RedisError:
            logger.exception("WebSocket ticket issuance failed: Redis unavailable.")
            return Response(
                {"detail": "Realtime service temporarily unavailable."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        except Exception:
            logger.exception("WebSocket ticket issuance failed.")
            return Response(
                {"detail": "Realtime service temporarily unavailable."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        return Response(
            {"ticket": ticket, "expires_in": TICKET_TTL_SECONDS},
            status=status.HTTP_200_OK,
            headers={"Cache-Control": "no-store"},
        )


class CampaignViewSet(viewsets.ModelViewSet):
    content_model = Campaign
    permission_classes = [TenantPermission]
    lookup_field = "uid"

    def get_serializer_class(self):
        if self.action in ["create", "update", "partial_update"]:
            return CampaignCreateUpdateSerializer
        return CampaignListSerializer

    def get_queryset(self):
        return Campaign.objects.filter(
            org_slug=self.request.user.org_slug,
            created_by = self.request.user
        ).prefetch_related("notifications").order_by("-created_at")

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
                {"success": False, "message": "Campaign not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        serializer = self.get_serializer(instance)
        return Response(
            {"success": True, "data": serializer.data},
            status=status.HTTP_200_OK,
        )

    def create(self, request, *args, **kwargs):
        try:
            data = request.data
            required_fields = ["name", "channel", "message", "target_type"]

            for field in required_fields:
                if not data.get(field):
                    return Response(
                        {"success": False, "message": f"{field} is required."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            target_type = data.get("target_type")

            if target_type in [
                Campaign.TargetType.CUSTOMERS,
                Campaign.TargetType.CONTACT_UPLOAD,
                Campaign.TargetType.INDIVIDUAL,
            ]:
                if not data.get("contact"):
                    return Response(
                        {
                            "success": False,
                            "message": f"contact list is required when target_type is {target_type}.",
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            if target_type == Campaign.TargetType.STAFF:
                if not data.get("contact"):
                    pass

            serializer = self.get_serializer(data=data)
            serializer.is_valid(raise_exception=True)

            with transaction.atomic():
                campaign = serializer.save(
                    created_by=request.user,
                    org_slug=request.user.org_slug,
                )

            if not campaign.is_scheduled:
                send_campaign_task.delay(campaign.id)

            return Response(
                {"success": True, "message": "Campaign created successfully."},
                status=status.HTTP_201_CREATED,
            )

        except Exception as e:
            logger.error(f"Campaign create error: {e}")
            return Response(
                {"success": False, "message": "Failed to create campaign."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def update(self, request, *args, **kwargs):
        try:
            try:
                instance = self.get_object()
            except Http404:
                return Response(
                    {"success": False, "message": "Campaign not found."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            if instance.is_sent:
                return Response(
                    {"success": False, "message": "Cannot update a campaign that has already been sent."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            serializer = self.get_serializer(instance, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()

            return Response(
                {"success": True, "message": "Campaign updated successfully."},
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error(f"Campaign update error: {e}")
            return Response(
                {"success": False, "message": "Failed to update campaign."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def destroy(self, request, *args, **kwargs):
        try:
            try:
                instance = self.get_object()
            except Http404:
                return Response(
                    {"success": False, "message": "Campaign not found."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            if instance.is_sent:
                return Response(
                    {"success": False, "message": "Cannot delete a campaign that has already been sent."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            instance.delete()

            return Response(
                {"success": True, "message": "Campaign deleted successfully."},
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error(f"Campaign delete error: {e}")
            return Response(
                {"success": False, "message": "Failed to delete campaign."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    @action(detail=True, methods=["post"], url_path="send-now")
    def send_now(self, request, uid=None):
        try:
            try:
                campaign = self.get_object()
            except Http404:
                return Response(
                    {"success": False, "message": "Campaign not found."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            if campaign.is_sent:
                return Response(
                    {"success": False, "message": "Campaign has already been sent."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            send_campaign_task.delay(campaign.id)

            return Response(
                {"success": True, "message": "Campaign queued for sending."},
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error(f"Campaign send_now error: {e}")
            return Response(
                {"success": False, "message": "Failed to queue campaign."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class NotificationViewset(viewsets.ReadOnlyModelViewSet):
    content_model = Notification
    permission_classes = [TenantPermission]
    serializer_class = NotificationListSerializer
    lookup_field = "uid"

    def get_queryset(self):
        return Notification.objects.filter(
            recipient=self.request.user,
            channel = 'in_app'
        ).select_related("campaign", "recipient", "sender").order_by("-created_at")

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        unread_count = queryset.filter(
            channel=Notification.Channel.IN_APP,
            is_read=False,
        ).count()

        serializer = self.get_serializer(queryset, many=True)
        return Response(
            {
                "success": True,
                "data": serializer.data,
                "unread_count": unread_count,
            },
            status=status.HTTP_200_OK,
        )

    def retrieve(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
        except Http404:
            return Response(
                {"success": False, "message": "Notification not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        serializer = self.get_serializer(instance)
        return Response(
            {"success": True, "data": serializer.data},
            status=status.HTTP_200_OK,
        )

    @action(detail=True, methods=["post"], url_path="mark-read")
    def mark_read(self, request, *args, **kwargs):
        try:
            try:
                notification = self.get_object()
            except Http404:
                return Response(
                    {"success": False, "message": "Notification not found."},
                    status=status.HTTP_404_NOT_FOUND,
                )
            notification.mark_as_read()
            return Response(
                {"success": True, "message": "Notification marked as read."},
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            logger.error(f"mark_read error: {e}")
            return Response(
                {"success": False, "message": "Failed to mark notification as read."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    @action(detail=False, methods=["post"], url_path="mark-all-read")
    def mark_all_read(self, request):
        try:
            Notification.objects.filter(
                recipient=request.user,
                channel=Notification.Channel.IN_APP,
                is_read=False,
            ).update(
                is_read=True,
                status=Notification.Status.READ,
            )
            return Response(
                {"success": True, "message": "All notifications marked as read."},
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            logger.error(f"mark_all_read error: {e}")
            return Response(
                {"success": False, "message": "Failed to mark all notifications as read."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
    
    @action(detail=False, methods=["post"], url_path="notify-user")
    def notify_user(self,request, *args, **kwargs):
        """
        Send a direct in-app notification to a specific user.
        Admin/staff only — enforced by CustomPermission.
 
        Body: { "recipient": <user_id>, "message": "...", "subject": "..." }
        """
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            return Response({
                "success" : False,
                "info": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
            
            
        data= serializer.validated_data
        
        try:
            service.send_in_app(
                sender=request.user,
                recipient=data.get("recipient"),
                message=data.get("message"),
                subject=data.get("subject"),
            )
            return Response({
                "success" : True,
                "message" : "Notification sent successfully"
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            logger.error(f"notify_user error : {e}", exc_info=True)
            return Response({
                "success" : False,
                "message" : "An error occured while sending the notification"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
