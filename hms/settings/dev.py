from decouple import config

from .base import *  # noqa: F403

ENVIRONMENT = "dev"
DEBUG = config("DEBUG", default=True, cast=bool)
EMAIL_BACKEND = config(
    "EMAIL_BACKEND", default="django.core.mail.backends.console.EmailBackend"
)
COOKIE_SECURE = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SAMESITE = "Lax"
