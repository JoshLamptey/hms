import asyncio
import sys

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
import os
from celery import Celery
import kombu.transport.redis  # force Redis transport registration

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "hms.settings.dev")

app = Celery("hms")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()

@app.task(bind=True, ignore_result=True)
def debug_task(self):
    print(f"Request: {self.request!r}")
