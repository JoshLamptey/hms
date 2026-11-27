#!/bin/sh
set -eu

export DJANGO_SETTINGS_MODULE="${DJANGO_SETTINGS_MODULE:-hms.settings.dev}"
exec python manage.py runserver "${APP_HOST:-0.0.0.0}:${APP_PORT:-8000}"
