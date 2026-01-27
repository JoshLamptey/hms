from django.urls import  path, include
from rest_framework.routers import DefaultRouter
from apps.client.views import (
    TenantViewset,
    LicenseViewset,
    LicenseRenewalViewset,
    LicenseTypeViewset,
    LicenseHistoryViewset,
    FetchOrgLicense,
    fetch_dashboard_bar_chart,
    fetch_org_license_plans,
    fetch_dashboard_card,
    fetch_dashboard_pie_charts
)


router = DefaultRouter()


router.register(r"organisation", TenantViewset, basename="organisation")
router.register(r"license-type", LicenseTypeViewset, basename="license-type")
router.register(r"license", LicenseViewset, basename="license")
router.register(r"license-renewal",LicenseRenewalViewset, basename="license-renewal")
router.register(r"license-history",LicenseHistoryViewset, basename="license-history")
router.register(r"fetch-license-by-orgs", FetchOrgLicense, basename="fetch-org-license")


urlpatterns = [
    path("", include(router.urls)),
    path("fetch-dashboard-card/", fetch_dashboard_card, name="fetch-dashboard-card"),
    path("fetch-dashboard-charts/", fetch_dashboard_pie_charts, name="fetch-dashboard-charts"),
    path("fetch-dashboard-bar-chart/", fetch_dashboard_bar_chart, name="fetch-dashboard-bar-chart"),
    path("fetch-org-license-plans/", fetch_org_license_plans, name="fetch-org")
    
]
