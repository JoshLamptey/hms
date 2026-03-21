import logging
import jwt
from urllib.parse import parse_qs
from channels.middleware import BaseMiddleware
from channels.db import database_sync_to_async
from django.contrib.auth.models import AnonymousUser
from decouple import config


logger = logging.getLogger(__name__)

@database_sync_to_async
def get_user_from_token(token:str):
    """
    Validates the JWT token and returns the corresponding User.
    Returns AnonymousUser if the token is invalid or the user doesn't exist.
 
    We reuse the same SECRET_KEY and algorithm as your existing JWTAuthentication
    so the frontend can use the same access token for both HTTP and WebSocket.
    """
    from apps.users.models import User
    
    try:
        payload = jwt.decode(token, config("SECRET_KEY"), algorithms=["HS256"])
        user_uid = payload.get("user_uid") or payload.get("user_id")
        
        if not user_uid:
            logger.warning("JWT payload missing user_uid/user_id")
            return AnonymousUser()
        
        user = User.objects.filter(uid=user_uid).first() or \
            User.objects.filter(id=user_uid).first()
            
            
        if not user:
            logger.warning("No user found for token uid : {uid}")
            return AnonymousUser()
        
        return user
    
    except jwt.ExpiredSignatureError:
        logger.warning("Websocket JWT token has expired")
        return AnonymousUser()
    except jwt.InvalidTokenError as e:
        logger.warning(f"Websocket JWT token invalid : {e}")
        return AnonymousUser()
    
    except Exception as e:
        logger.error(f"Unexpected error in websocket auth : {e}")
        return AnonymousUser()
    

class JWTWebSocketMiddleWare(BaseMiddleware):
    """
    Authenticates WebSocket connections using a JWT token.
 
    The frontend passes the token in the query string:
        ws://yourhost/ws/notifications/?token=<access_token>
 
    This runs before the consumer so that by the time the consumer's
    connect() method is called, self.scope["user"] is already populated.
 
    Why query string and not headers?
    Browser WebSocket API doesn't support custom headers — query string
    is the standard workaround for WebSocket JWT auth.
    """
    async def __call__(self, scope, recieve, send):
        # Parse token from query string
        query_string = scope.get("query_string", "b").decode("utf-8")
        params = parse_qs(query_string)
        token_list = params.get("token", [])
        
        if token_list:
            token = token_list[0]
            scope["user"] = await get_user_from_token(token)
            
        else :
            logger.warning("Websocket connection attempted with no token")
            scope["user"] = AnonymousUser()
            
        return await super().__call__(scope, recieve, send)
    
    