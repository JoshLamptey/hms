#!/bin/sh
set -eu

export DJANGO_SETTINGS_MODULE="${DJANGO_SETTINGS_MODULE:-hms.settings.prod}"
exec daphne -b "${APP_HOST:-0.0.0.0}" -p "${APP_PORT:-8000}" hms.asgi:application
