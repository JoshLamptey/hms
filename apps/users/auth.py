import logging
import jwt
import arrow
import uuid
import random
from rest_framework.response import Response
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from apps.users.models import RefreshToken
from decouple import config
from django.core.cache import cache
from apps.users.utils import send_notification
from django.contrib.auth import get_user_model

logger = logging.getLogger(__name__)
User = get_user_model()


class Authenticator:
    
    def generate_access_token(self, user):
        jti = uuid.uuid4()
        logger.info(f"jti generated: {jti}")
        
        payload = {
            "jti": str(jti),
            "user_id": user.id,
            "user_uid" : str(user.uid),
            "full_name": f"{user.first_name} {user.last_name}",
            "type": "access",
            "iat" : arrow.utcnow().datetime,
            "exp": arrow.utcnow().shift(minutes=+15).datetime,
        }
        
        token = jwt.encode(payload, config("JWT_SECRET_KEY"), algorithm="HS256")
        
        return token
    
    
    def generate_refresh_token(self, user):
        jti = uuid.uuid4()
        logger.info(f"jti generated: {jti}")
        
        payload = {
            "jti": str(jti),
            "user_id": user.id,
            "user_uid" : str(user.uid),
            "full_name": f"{user.first_name} {user.last_name}",
            "type": "refresh",
            "iat" : arrow.utcnow().datetime,
            "exp": arrow.utcnow().shift(days=+7).datetime,
        }
        token = jwt.encode(payload, config("SECRET_KEY"), algorithm="HS256")
        RefreshToken.objects.create(
            jti=jti,
            user=user,
            token=token,
            expires_at=arrow.utcnow().shift(days=+7).datetime,
        )
        return token
    
    
    def generate_otp(self):
        rand = random.randint(100000, 999999)
        return rand
    
    
    def send_otp(self,email=None, phone=None):
        try:
            otp = self.generate_otp()
            logger.info(f"otp generated: {otp}")
            
            if email:
                cache.set(email, otp, timeout=300)
                context = {
                    "template":"otp",
                    "context":{"otp": otp},
                    }
                
                mail = send_notification.delay(
                    recipient=email,
                    context=context,
                )
                logger.info(f"OTP email sent to {email}")
            
            if phone:
                cache.set(phone, otp, timeout=300)
                sms = send_notification.delay(
                    medium="sms",
                    recipient=phone,
                    message = f"Your HMS OTP code is {otp}. It is valid for 5 minutes.",
                )
                logger.info(f"OTP sms sent to {phone}")
                
            else:
                raise ValueError("Either email or phone must be provided to send OTP.")
            
            return otp
        
        except Exception as e:
            logger.error(f"Error sending OTP: {e}")
            raise {
                "success": False,
                "info": "Failed to send OTP.",
            }
            
    def verify_otp(self, user_entered_otp, email=None, phone=None):
        cache_key = email if email else phone
        stored_otp = cache.get(cache_key)
        logger.info(stored_otp)
        
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
        else:
            cache.delete(cache_key)
            logger.info("OTP verified successfully.")
            return True
        
        
    
    def forget_verify_otp(self, user_entered_otp, email=None, phone=None):
        cache_key = email if email else phone
        
        if not cache_key:
            return Response({
                "success": False,
                "info": "Email or phone must be provided.",
            })
            
        
        stored_otp = cache.get(cache_key)
        logger.info(stored_otp)
        
        if stored_otp is None:
            logger.warning("OTP has expired or does not exist.")
            return Response({
                "success": False,
                "info": "OTP has expired or does not exist. Kindly click on the resend button to continue.",
            })
            
        try:
            user_otp = int(user_entered_otp)
        except ValueError:
            return Response({
                "success": False,
                "info": "Invalid OTP format provided by user.",
            
            })
            
        if stored_otp != user_otp:
            retries = cache.get(f"retries:{email}")
            if retries is None:
                retries = 0
            retries += 1
            cache.set(f"retries:{email}", retries, timeout=300)
            if retries >= 4:
                cache.delete(email)
                return Response({
                    "success": False,
                    "info": "Too many failed attempts. Please try resending the OTP.",
                })
            return Response({
                "success": False,
                "info": f"Wrong OTP provided. You have {3 - retries} attempts left.",
            })
            
        
        cache.delete(f"{email}")
        cache.delete(f"retries:{email}")
        logger.info("OTP verified successfully.")
        return Response({
            "success": True,
            "info": "OTP verified successfully.",
        })
        
        
        
        
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
            raise AuthenticationFailed("Invalid authorization header format.")
        
        
        try:
            payload = jwt.decode(
                token,
                config("SECRET_KEY"),
                algorithms=["HS256"],
            )
            
            if payload.get("type") != "access":
                raise AuthenticationFailed("Invalid token type.")
            
            try:
                logged_user = User.objects.get(id=payload["user_id"])
            except User.DoesNotExist:
                raise AuthenticationFailed("User not found.")
            
            if logged_user.is_blocked:
                raise AuthenticationFailed("User account is blocked.")
            
            
            cache.set(f"org_slug:{logged_user.id}", logged_user.org_slug)
            
            
            return (logged_user, None)
        
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Token has expired.")
        except jwt.InvalidTokenError:
            raise AuthenticationFailed("Invalid token.")
        except Exception as e:
            raise AuthenticationFailed(str(e))
        
        
        