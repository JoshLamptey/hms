from django.urls import path,include
from rest_framework.routers import DefaultRouter
from apps.notifications.views import (
    CampaignViewSet,
    NotificationViewset,
    WebSocketTicketView,
)

router = DefaultRouter()

router.register(r"campaigns", CampaignViewSet, basename="campaign")
router.register(r"notifications", NotificationViewset, basename="notification")

urlpatterns = [
    path("notifications/ws-ticket/", WebSocketTicketView.as_view(), name="websocket-ticket"),
    path("", include(router.urls)),
]
