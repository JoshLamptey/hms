import logging
from django.utils import timezone
from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework.exceptions import Throttled, NotAuthenticated, AuthenticationFailed
from apps.users.models import UserRateLimitFlag

logger = logging.getLogger(__name__)


def custom_exception_handler(exc, context):
    request = context.get("request", None)

    if isinstance(exc, (NotAuthenticated, AuthenticationFailed)):
        return Response({"success": False, "data": str(exc.detail)}, status=401)

    if isinstance(exc, Throttled):
        user = getattr(request, "user", None)
        if user and user.is_authenticated:
            handle_rate_limit_flag(user)

    response = exception_handler(exc, context)

    if response is not None:
        return Response(
            {
                "success": False,
                "info": response.data.get("detail", "Request failed."),
            },
            status=response.status_code,
        )

    return response


def handle_rate_limit_flag(user):
    try:
        flag, created = UserRateLimitFlag.objects.get_or_create(
            user=user,
            reason="Exceeded rate limit",
        )

        if not created:
            flag.count += 1
            flag.last_flagged_at = timezone.now()
            flag.save()

        # uncomment this after the notification has been wired up
        # if flag.count == 2:
        #     send_rate_limit_warning_sms.delay(user.uid)
        #     flag.last_flagged_at = timezone.now()
        #     flag.save()

        if flag.count >= 3 and not flag.is_blocked:
            user.is_blocked = True
            user.blocked_at = timezone.now()
            user.save(update_fields=["is_blocked", "blocked_at"])

            flag.is_blocked = True
            flag.last_flagged_at = timezone.now()
            flag.save()

    except Exception as e:
        logger.error(f"Error handling rate limit flag: {e}")
