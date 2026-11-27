"""Optional integrations used by ERP's user flows."""


def mark_attendance_on_login(user, latitude=None, longitude=None):
    """Delegate to ERP HR when installed; HMS has no HR app or attendance data."""
    try:
        from apps.hr.services import mark_attendance_on_login as mark_attendance
    except ModuleNotFoundError as error:
        if error.name not in {"apps.hr", "apps.hr.services"}:
            raise
        return None

    return mark_attendance(user=user, latitude=latitude, longitude=longitude)
