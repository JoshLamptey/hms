"""Shared HMS settings. Environment-specific overrides live beside this file."""

from pathlib import Path

from celery.schedules import crontab
from decouple import config

BASE_DIR = Path(__file__).resolve().parent.parent.parent

SECRET_KEY = config("SECRET_KEY")
DEBUG = config("DEBUG", default=False, cast=bool)
ALLOWED_HOSTS = [host.strip() for host in config("ALLOWED_HOSTS", default="localhost,127.0.0.1").split(",") if host.strip()]
CSRF_TRUSTED_ORIGINS = [origin.strip() for origin in config("CSRF_TRUSTED_ORIGINS", default="http://localhost,http://127.0.0.1").split(",") if origin.strip()]
CORS_ALLOWED_ORIGINS = [origin.strip() for origin in config("CORS_ALLOWED_ORIGINS", default="").split(",") if origin.strip()]
CORS_ALLOW_CREDENTIALS = config("CORS_ALLOW_CREDENTIALS", default=False, cast=bool)
WS_ALLOWED_ORIGINS = [
    origin.strip()
    for origin in config("WS_ALLOWED_ORIGINS", default=",".join(CORS_ALLOWED_ORIGINS)).split(",")
    if origin.strip()
]

INSTALLED_APPS = [
    "daphne",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "corsheaders",
    "rest_framework",
    "drf_spectacular",
    "post_office",
    "django_extensions",
    "django_celery_results",
    "django_celery_beat",
    "channels",
    "apps.users",
    "apps.client",
    "apps.notifications",
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "hms.middleware.PermissionsPolicyMiddleware",
]

ROOT_URLCONF = "hms.urls"
TEMPLATES = [{
    "BACKEND": "django.template.backends.django.DjangoTemplates",
    "DIRS": [BASE_DIR / "templates"],
    "APP_DIRS": True,
    "OPTIONS": {"context_processors": [
        "django.template.context_processors.debug",
        "django.template.context_processors.request",
        "django.contrib.auth.context_processors.auth",
        "django.contrib.messages.context_processors.messages",
    ]},
}]

WSGI_APPLICATION = "hms.wsgi.application"
ASGI_APPLICATION = "hms.asgi.application"

DATABASES = {"default": {
    "ENGINE": config("POSTGRES_ENGINE", default="django.db.backends.postgresql"),
    "NAME": config("POSTGRES_DB", default="hms_db"),
    "USER": config("POSTGRES_USER", default="postgres"),
    "PASSWORD": config("POSTGRES_PASSWORD", default="postgres"),
    "HOST": config("POSTGRES_HOST", default="localhost"),
    "PORT": config("POSTGRES_PORT", default="5432"),
}}
DATABASE_ROUTERS = ["apps.client.routers.TenantRouter"]

REDIS_HOST = config("REDIS_HOST", default="redis://127.0.0.1:6379/0")
CACHES = {"default": {
    "BACKEND": "django.core.cache.backends.redis.RedisCache",
    "LOCATION": REDIS_HOST,
}}
CHANNEL_LAYERS = {"default": {
    "BACKEND": "channels_redis.core.RedisChannelLayer",
    "CONFIG": {"hosts": [REDIS_HOST]},
}}

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ["apps.users.auth.JWTAuthentication"],
    "EXCEPTION_HANDLER": "apps.users.exceptions.custom_exception_handler",
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.UserRateThrottle",
        "rest_framework.throttling.ScopedRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "user": "100/min",
        "login": "3/min",
        "passwordless_login": "3/min",
        "forgot_password": "3/min",
        "refresh_token": "2/min",
        "reset_password": "3/min",
    },
}

SPECTACULAR_SETTINGS = {
    "TITLE": "HMS Backend",
    "DESCRIPTION": "This is a HMS backend",
    "VERSION": "1.0.0",
    "SERVE_INCLUDE_SCHEMA": False,
}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 8}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
    {"NAME": "apps.users.validators.AlphaNumericSymbolValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"] if (BASE_DIR / "static").exists() else []
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"},
}
MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
AUTH_USER_MODEL = "users.User"

CELERY_BROKER_URL = config("CELERY_BROKER_URL", default=REDIS_HOST)
CELERY_RESULT_BACKEND = config("CELERY_RESULT_BACKEND", default=REDIS_HOST)
CELERY_TIMEZONE = config("CELERY_TIME_ZONE", default="Africa/Accra")
CELERY_TASK_ALWAYS_EAGER = False
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True
CELERY_BROKER_TRANSPORT = "redis"
CELERY_BROKER_BACKEND = "redis"
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"
CELERY_ACCEPT_CONTENT = ["json"]

POST_OFFICE = {
    "CELERY_ENABLED": True,
    "CELERY_SEND_TASK_ERROR_EMAILS": True,
    "DEFAULT_FROM_EMAIL": config("DEFAULT_FROM_EMAIL", default="no-reply@example.com"),
}

EMAIL_BACKEND = config("EMAIL_BACKEND", default="django.core.mail.backends.console.EmailBackend")
EMAIL_HOST = config("EMAIL_HOST", default="localhost")
EMAIL_PORT = config("EMAIL_PORT", default=25, cast=int)
EMAIL_HOST_USER = config("EMAIL_HOST_USER", default="")
EMAIL_HOST_PASSWORD = config("EMAIL_HOST_PASSWORD", default="")
EMAIL_USE_TLS = config("EMAIL_USE_TLS", default=False, cast=bool)
DEFAULT_FROM_EMAIL = config("DEFAULT_FROM_EMAIL", default="no-reply@example.com")

SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
COOKIE_SECURE = not DEBUG
SESSION_COOKIE_SECURE = COOKIE_SECURE
CSRF_COOKIE_SECURE = COOKIE_SECURE
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "None" if COOKIE_SECURE else "Lax"
CSRF_COOKIE_SAMESITE = "None" if COOKIE_SECURE else "Lax"

PERMISSIONS_POLICY = {
    "accelerometer": [], "camera": [], "geolocation": [], "gyroscope": [],
    "magnetometer": [], "microphone": [], "payment": [], "usb": [],
    "fullscreen": ["self"],
}

CELERY_BEAT_SCHEDULE = {
    "retry-failed-notifications": {
        "task": "apps.notifications.tasks.retry_failed_notifications",
        "schedule": crontab(minute=0),
    },
}
