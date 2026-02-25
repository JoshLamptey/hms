import os
from celery import Celery
from decouple import config


# Set the default Django settings module for the 'celery' program.

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "hms.settings")

app = Celery("hms")


app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()

@app.task(bind=True, ignore_result=True)
def debug_task(self):
    print(f"Request: {self.request!r}")

