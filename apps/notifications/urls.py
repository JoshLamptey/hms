from django.urls import path,include
from rest_framework.routers import DefaultRouter
from apps.notifications.views import CampaignViewSet, NotificationViewset

router = DefaultRouter()

router.register(r"campaigns", CampaignViewSet, basename="campaign")
router.register(r"notifications", NotificationViewset, basename="notification")

urlpatterns = [
    path("", include(router.urls)),
]
