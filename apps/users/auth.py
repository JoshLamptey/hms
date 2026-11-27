import logging
import jwt
import arrow
import uuid
import re
import random
from django.core.cache import cache
from django.contrib.auth import get_user_model
from rest_framework.exceptions import AuthenticationFailed, PermissionDenied
from rest_framework.authentication import BaseAuthentication
from rest_framework.response import Response
from drf_spectacular.extensions import OpenApiAuthenticationExtension
from apps.users.models import RefreshToken

from apps.notifications.service import NotificationService
from decouple import config

service = NotificationService()
logger = logging.getLogger(__name__)
User = get_user_model()

ACTIVE_JTI_CACHE_TIMEOUT = 60 * 60 * 24  # 24 hours

def _track_active_jti(user_id, jti, exp):
    """
    Tracks this access token's jti against the user, so all of a user's
    live sessions (across devices) can be killed together on force-logout.
    Prunes already-expired entries on every call.
    """
    cache_key = f"active_jtis:{user_id}"
    jtis = cache.get(cache_key) or {}
    now_ts = int(arrow.utcnow().timestamp())
    jtis = {k : v for k, v in jtis.items() if v > now_ts}
    jtis[jti] = exp
    cache.set(cache_key, jtis, timeout=ACTIVE_JTI_CACHE_TIMEOUT)


def force_logout_user_sessions(user):
    """
    Immediately kills every active session (all devices) for this user:
    blacklists every tracked access token jti, revokes all refresh tokens,
    and clears the active-jti cache entry.
    """
    cache_key = f"active_jtis:{user.id}"
    jtis = cache.get(cache_key) or {}
    now_ts =int(arrow.utcnow().timestamp())


    for jti, exp in jtis.items():
        ttl = exp - now_ts
        if ttl > 0:
            cache.set(f"blacklist:access:{jti}", "blacklisted", timeout=ttl)


    RefreshToken.objects.filter(user=user, is_revoked=False).update(is_revoked=True)

    cache.delete(cache_key)

class Authenticator:

    def generate_access_token(self, user):
        jti = uuid.uuid4()

        payload = {
            "jti": str(jti),
            "user_id": user.id,
            "user_uid": str(user.uid),
            "full_name": f"{user.first_name} {user.last_name}",
            "role": user.role.name if user.role else None,
            "org_slug": user.org_slug or None,
            "type": "access",
            "iat": arrow.utcnow().datetime,
            "exp": arrow.utcnow().shift(minutes=+15).datetime,
        }

        token = jwt.encode(payload, config("SECRET_KEY"), algorithm="HS256")

        return token

    def generate_refresh_token(self, user):
        jti = uuid.uuid4()

        payload = {
            "jti": str(jti),
            "user_id": user.id,
            "user_uid": str(user.uid),
            "type": "refresh",
            "iat": arrow.utcnow().datetime,
            "exp": arrow.utcnow().shift(hours=+12).datetime,
        }
        token = jwt.encode(payload, config("SECRET_KEY"), algorithm="HS256")

        RefreshToken.objects.create(
            jti=jti,
            user=user,
            token=token,
            expires_at=arrow.utcnow().shift(hours=+12).datetime,
        )

        return token

    def generate_reset_token(self, user, identifier):
        payload = {
            "user_id": user.id,
            "user_uid": str(user.uid),
            "identifier": identifier,
            "type": "password_reset",
            "iat": arrow.utcnow().datetime,
            "exp": arrow.utcnow().shift(minutes=+10).datetime,
        }
        token = jwt.encode(payload, config("SECRET_KEY"), algorithm="HS256")
        if isinstance(token, bytes):
            token = token.decode("utf-8")

        cache.set(f"reset_token:{identifier}", token, timeout=600)

        return token

    def generate_otp(self):
        return random.randint(100000, 999999)

    def send_otp(self, email=None, phone=None, full_name=None):
        try:
            otp = self.generate_otp()

            if email:
                cache.set(email, otp, timeout=600)
                service.send_otp(
                    email_address=email,
                    otp=otp,
                    expires_in_minutes=10,
                    full_name=full_name
                )
            elif phone:
                cache.set(phone, otp, timeout=300)
                service.send_otp(
                    phone_number=phone,
                    otp=otp,
                    expires_in_minutes=10,
                    full_name=full_name,
                )
                logger.info(f"OTP sms sent to {phone}")

            else:
                raise ValueError("Either email or phone must be provided to send OTP.")

            return otp
        except Exception as e:
            logger.error(f"Error sending OTP: {str(e)}")
            raise

    def verify_otp(self, user_entered_otp, email=None, phone=None):
        cache_key = email if email else phone
        stored_otp = cache.get(cache_key)

        if stored_otp is None:
            logger.warning("OTP has expired or does not exist.")
            return False

        try:
            user_entered_otp = int(user_entered_otp)
        except ValueError:
            logger.warning("Invalid OTP format provided by user.")
            return False

        if stored_otp != user_entered_otp:
            logger.warning("Wrong OTP provided by user.")
            return False

        cache.delete(cache_key)
        return True

    def forget_verify_otp(self, user_entered_otp, email=None, phone=None):
        cache_key = email if email else phone

        if not cache_key:
            return Response(
                {"success": False, "data": "Email or phone must be provided"}
            )

        stored_otp = cache.get(cache_key)

        if stored_otp is None:
            logger.warning("OTP has expired or does not exist.")
            return Response(
                {"success": False, "data": "OTP has expired or does not exist"}
            )

        try:
            user_otp = int(user_entered_otp)
        except ValueError:
            logger.warning("Invalid OTP format provided by user.")
            return Response(
                {"success": False, "data": "Invalid OTP format provided by user"}
            )

        if stored_otp != user_otp:
            retries = cache.get(f"retries:{cache_key}")
            if retries is None:
                retries = 0
            retries += 1
            cache.set(f"retries:{cache_key}", retries, timeout=600)

            if retries >= 4:
                cache.delete(cache_key)
                return Response(
                    {
                        "success": False,
                        "data": "Too many failed attempts. Please try resending the OTP.",
                    }
                )

            return Response(
                {
                    "success": False,
                    "data": f"Wrong OTP. You have {3 - retries} attempts left.",
                }
            )

        cache.delete(cache_key)
        cache.delete(f"retries:{cache_key}")
        return Response({"success": True, "data": "OTP verified successfully."})

    def send_reset_password(self, field, password=None, full_name=None):
        try:
            if "@" in field:
                if not re.match(r"[^@]+@[^@]+\.[^@]+", field):
                    return Response({"success": False, "data": "Invalid email format."})
                service.send_temporary_password(
                    email_address=field,
                    password=password,
                    full_name=full_name,
                )

            else:
                if not re.match(r"^\+?1?\d{9,15}$", field):
                    return Response(
                        {"success": False, "data": "Invalid phone number format."}
                    )
                service.send_temporary_password(
                    phone_number=field,
                    password=password,
                    full_name=full_name,
                )

        except Exception as e:
            logger.error(f"Error sending reset password: {str(e)}")
            raise


class JWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get("Authorization")

        if not auth_header:
            return None

        try:
            prefix, token = auth_header.split(" ")
            if prefix.lower() != "bearer":
                raise AuthenticationFailed("Invalid token prefix.")
        except ValueError:
            raise AuthenticationFailed("Invalid Authorization header format. ")

        try:
            payload = jwt.decode(
                token,
                config("SECRET_KEY"),
                algorithms=["HS256"],
            )

            jti = payload.get("jti")

            if cache.get(f"blacklist:access:{jti}"):
                raise PermissionDenied("Access token has been revoked.")

            if payload.get("type") != "access":
                raise AuthenticationFailed("Invalid token type.")

            try:
                logged_user = User.objects.select_related("role", "tenant").get(
                    id=payload["user_id"],
                    uid=payload["user_uid"],
                )
            except User.DoesNotExist:
                raise AuthenticationFailed("User not found.")

            if logged_user.is_blocked:
                raise AuthenticationFailed(
                    "Your account has been blocked. Please contact your administrator."
                )

            is_privileged = logged_user.is_superuser or (
                logged_user.role and logged_user.role.name == 'SUPER_ADMIN'
            )
            if not is_privileged and logged_user.tenant:
                cache.set(f"org_slug:{logged_user.id}", logged_user.tenant.org_slug)

            exp = payload.get("exp")
            if jti and exp:
                _track_active_jti(logged_user.id, jti, exp)

            return (logged_user, payload)



        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Access token expired")
        except jwt.InvalidTokenError:
            raise AuthenticationFailed("Invalid token")



class JWTAuthenticationScheme(OpenApiAuthenticationExtension):
    target_class = "apps.users.auth.JWTAuthentication"
    name = "JWTAuth"

    def get_security_definition(self, auto_schema):
        return {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
        }
