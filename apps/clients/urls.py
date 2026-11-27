from django.urls import path, include
from rest_framework.routers import DefaultRouter
from apps.clients.views import (
    TenantViewset,
    LicenseTypeViewset,
    LicenseViewset,
    LicenseRenewalViewset,
    LicenseHistoryViewset,
    FetchOrgLicense,
    fetch_org_license_plans,
    fetch_dashboard_card,
    fetch_dashboard_pie_charts,
    fetch_dashboard_bar_chart,
)

router = DefaultRouter()
router.register(r"tenants", TenantViewset, basename="tenants")
router.register(r"license-types", LicenseTypeViewset, basename="license-types")
router.register(r"licenses", LicenseViewset, basename="licenses")
router.register(r"license-renewals", LicenseRenewalViewset, basename="license-renewals")
router.register(r"license-history", LicenseHistoryViewset, basename="license-history")
router.register(r"org-licenses", FetchOrgLicense, basename="org-licenses")

urlpatterns = [
    path("", include(router.urls)),
    path("dashboard/cards/", fetch_dashboard_card, name="dashboard-cards"),
    path(
        "dashboard/pie-charts/", fetch_dashboard_pie_charts, name="dashboard-pie-charts"
    ),
    path("dashboard/bar-chart/", fetch_dashboard_bar_chart, name="dashboard-bar-chart"),
    path("org-license-plans/", fetch_org_license_plans, name="org-license-plans"),
]
