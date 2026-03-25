from django.apps import AppConfig
from django.core.signals import setting_changed


def my_callback(sender, **kwargs):
    print("Setting changed!")


class BaseConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.client"

    def ready(self):
        from . import signals

        setting_changed.connect(my_callback)