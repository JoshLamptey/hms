import logging
from rest_framework import viewsets,status
from rest_framework.decorators import action
from rest_framework.response import Response
from apps.users.perms import CustomPermission
from apps.notifications.models import Campaign,Notification
from apps.notifications.serializers import (
    CampaignListSerializer,
    CampaignCreateSerializer,
    CampaignUpdateSerializer,
    NotificationCreateSerializer,
    NotificationListSerializer
)
from apps.notifications.service import NotificationService
from apps.users.models import User

logger = logging.getLogger(__name__)
service = NotificationService()

 
# ──────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────
 
def _resolve_recipients(data:dict, org_slug:str)->tuple[list, str | None]:
    """
    Resolves the recipient User list from the incoming request data.
 
    Returns:
        (list of User objects, error message or None)
 
    Handles three target types:
        - customers:        list of User IDs sent directly
        - staff:       list of User IDs sent directly
        - contact_upload: handled via Campaign.contact JSON field, no User resolution needed
        - individual:     single recipient User ID
    """
    target_type = data.get("target_type")
    
    if target_type == "customers":
        customer_ids = data.get("customers")
        if not customer_ids:
            return [], "customers list is required when target_type is customers."
    
        users = list(User.objects.filter(id__in=customer_ids, org_slug=org_slug, ))
        
        
        not_found = set(customer_ids)- {u.id for u in  users}
        
        if not_found:
            return [], f"Users with IDs {not_found} not found"
        return users,None
    
    elif target_type=="staff":
        staff_ids = data.get("staff")
        
        if not staff_ids:
            return [], "customers list is required when target_type is customers."
    
        users = list(User.objects.filter(id__in=staff_ids, org_slug=org_slug, ))
        
        
        not_found = set(staff_ids)- {u.id for u in  users}
        
        if not_found:
            return [], f"Users with IDs {not_found} not found"
        return users,None
    
    elif target_type == "contact_upload":
        # Recipients are external contacts stored in Campaign.contact JSON field
        # No User resolution needed — service sends directly to phone/email
        return [], None
    
    elif target_type == "individual" :
        recipient_id = data.get("recipient")
        
        if not recipient_id:
            return [], "recipient is required when target_type is 'Individual'"
        
        user = User.objects.filter(id=recipient_id, org_slug=org_slug).first()
        
        if not user:
            return [], "Recipient not found"
        return [user], None
    
    
    return [], f"Unknown target_type : {target_type}"


 
# ──────────────────────────────────────────────
# CAMPAIGN VIEWSET
# ──────────────────────────────────────────────
 
class CampaignViewSet(viewsets.ModelViewSet):
    permission_classes = [CustomPermission]
    lookup_field = "uid"
    
    def get_queryset(self):
        return Campaign.objects.filter(
            org_slug=self.request.user.org_slug
        ).prefetch_related("notifications")
        
    
    def get_serializer_class(self):
        if self.action == "create" : 
            return CampaignCreateSerializer
        if self.action in ["update", "partial_update"]:
            return CampaignUpdateSerializer
        return CampaignListSerializer
    
    
    def list(self, request, *args, **kwargs):
        instance = self.get_queryset()
        serializer = self.get_serializer(instance)
        return Response({
            "success" : True,
            "info" : serializer.data
        },status=status.HTTP_200_OK)
    
    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response({
            "success": True,
            "info" : serializer.data
        },status=status.HTTP_200_OK)
        
    
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if not serializer():
            return Response({
                "success" : False,
                "info" : serializer.errors
            },status=status.HTTP_400_BAD_REQUEST)
            
        data = serializer.data
        target_type = data.get("target_type")
        
        if target_type == "contact_upload":
            recipients,error = _resolve_recipients(data, request.user.org_slug)
            
            if error:
                return Response({
                    "success" : False,
                    "info" : error
                },status=status.HTTP_400_BAD_REQUEST)
                
            if not recipients:
                return Response({
                    "success" : False,
                    "info" : "No recipients found"
                }, status=status.HTTP_400_BAD_REQUEST)
                
        
        else:
            recipients = []
            
        try:
            campaign = service.create_campaign(
                data=data,
                created_by=request.user,
                recipient_users=recipients,
                org_slug=request.user.org_slug
            )
            
            return Response({
                "success" : True,
                "info" : "Campaign created successfully",
                "data" : campaign
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            logger.error(f"CampaignViewset.create error : {e}", exc_info=True)
            return Response({
                "success" : False,
                "info" : "An error occurred while creating the campaign"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
    
    
    def update(self, request, *args, **kwargs):
        instance= self.get_object()
        
        if instance.is_sent:
            return Response({
                "success" : False,
                "info" : "Cannot edit a campaign that has already been sent"
            }, status=status.HTTP_400_BAD_REQUEST)
            
        partial = kwargs.pop("partial",False)
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        
        if not serializer.is_valid():
            return Response({
                "success" : False,
                "info" : serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
            
        serializer.save()
        return Response({
            "success": True,
            "info" : "Campaign updated successully"
        }, status=status.HTTP_200_OK)
        
        
    
    
    def destroy(self, request, *args, **kwargs):
        instance=self.get_object()
        
        if instance.is_sent:
            return Response({
                "success" : False,
                "info" : "Cannot delete a campaign that has already been deleted"
            }, status=status.HTTP_400_BAD_REQUEST)
            
        
        instance.delete()
        return Response({
            "success" : True,
            "info" : "Campaign deleted successfully"
        }, status=status.HTTP_204_NO_CONTENT)
        
    
    @action(detail=True, methods=["post"], url_path="resend-failed")
    def resend_failed(self, request, *args, **kwargs):
        """
        Retry all failed notifications for a specific campaign.
        Resets them to pending and re-triggers the dispatch task.
        """
        from apps.notifications.tasks import dispatch_campaign_task
        
        instance = self.get_object()
        failed_count = instance.notifications.filter(status="failed").count()
        
        if not failed_count:
            return Response({
                "success" : False,
                "info" : "No failed notifications to retry"
            }, status=status.HTTP_400_BAD_REQUEST)
            
        instance.notifications.filter(status="failed").update(
            status="pending",
            failure_reason=None
        )
        
        dispatch_campaign_task.delay(instance.id)
        
        return Response({
            "success" : True,
            "info" : f"Retrying {failed_count} failed notification(s)"
        }, status=status.HTTP_200_OK)


# ──────────────────────────────────────────────
# NOTIFICATION VIEWSET
# ──────────────────────────────────────────────
 
 

class NotificationViewset(viewsets.ModelViewSet):
    """
    Handles in-app notifications for the currently authenticated user.
 
    Endpoints:
        GET    /notifications/                   — list current user's notifications
        GET    /notifications/{uid}/             — retrieve a single notification
        DELETE /notifications/{uid}/             — delete a notification
        POST   /notifications/notify-user/       — admin sends direct notification to a user
        PATCH  /notifications/{uid}/mark-read/   — mark a single notification as read
        POST   /notifications/mark-all-read/     — mark all notifications as read
        GET    /notifications/unread-count/      — unread count for bell badge
    """
    
    permission_classes = [CustomPermission]
    lookup_field = "uid"
    
    def get_queryset(self):
        # Users only ever see their own in-app notifications
        return Notification.objects.filter(
            recipient=self.request.user,
            channel="in_app"
        ).select_related("sender", "campaign")
        
    def get_serializer_class(self):
        if self.action == "notify_user":
            return NotificationCreateSerializer
        return NotificationListSerializer
    
    
    def list(self, request, *args, **kwargs):
        queryset= self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response({"success":True, "info":serializer.data}, status=status.HTTP_200_OK)
    
    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response({"success" : True, "info" : serializer.data}, status=status.HTTP_200_OK)
    
    def create(self, request, *args, **kwargs):
        return Response({"succes": False, "info": "Use /notify-user/ to send a notification"}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
    
    def update(self, request, *args, **kwargs):
        return Response({"success": False, "info":"Use /mark-read/ to update a notification" }, status=status.HTTP_405_METHOD_NOT_ALLOWED)
    
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        return Response({"success":True, "info" : "Notification deleted"}, status=status.HTTP_200_OK)
    
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
            service.notify_user(
                sender=request.user,
                recipient=data.get("recipient"),
                message=data.get("message"),
                subject=data.get("subject"),
            )
            return Response({
                "success" : True,
                "info" : "Notification sent successfully"
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            logger.error(f"notify_user error : {e}", exc_info=True)
            return Response({
                "success" : False,
                "info" : "An error occured while sending the notification"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            
    
    @action(detail=True, methods=["patch"],url_path="mark-read")
    def mark_read(self, request, *args, **kwargs):
        """Mark a single notification as read."""
        instance = self.get_object()
        instance.mark_read()
        return Response({"success": True, "info": "Notification marked as read"}, status=status.HTTP_200_OK)
    
    @action(detail=False, methods=["post"], url_path="mark-all-read")
    def mark_all_read(self, request, *args, **kwargs):
        """Mark all unread notifications as read for the current user."""
        count = service.mark_all_read(request.user)
        return Response({
            "success": True,
            "info": f"{count} notification(s) marked as read"
        },status=status.HTTP_200_OK)
    
    
    @action(detail=False, methods=["get"], url_path="unread-count")
    def unread_count(self, request, *args, **kwargs):
        """
        Lightweight endpoint for the frontend notification bell badge.
        Returns just the unread count — no need to fetch full notification list.
        """
        count = self.get_queryset().filter(is_read=False).count()
        return Response({
            "success" : True,
            "info" : {
                "unread_count" : count
            }
        }, status=status.HTTP_200_OK)