# Notifications App Documentation

This document provides comprehensive documentation for the `apps/notifications` Django app, which handles all communication channels — email, SMS, in-app, and real-time WebSocket notifications — across the multi-tenant HMS platform.

---

## Overview

The Notifications app is the communication backbone of the platform. It handles transactional messages (OTP, credentials, password reset), bulk campaigns (email/SMS to staff or customers), in-app notification delivery via WebSocket, and Celery-based async processing.

Key features:

- Email delivery via Brevo (formerly Sendinblue) — free tier: 300 emails/day
- SMS delivery via Arkesel SMS API
- In-app notifications via Django Channels WebSocket
- Campaign management with scheduling and targeting
- Short-lived, one-time-ticket authenticated WebSocket connections
- Celery tasks for async sending, retries, and scheduled campaigns
- APP_NAME pulled from config — never hardcoded

---

## Models

### Campaign

Represents a bulk communication campaign targeting a group of recipients.

**Fields:**

- `uid`: UUIDField, unique, editable=False
- `name`: CharField(max_length=255)
- `channel`: CharField, choices:
  - `sms` — SMS via Arkesel
  - `email` — Email via Brevo
  - `in_app` — In-app notification
- `subject`: CharField(max_length=255, nullable) — email subject
- `message`: TextField — campaign body
- `target_type`: CharField, choices:
  - `staff` — all users in the org
  - `customers` — customer contact list
  - `contact_upload` — uploaded contact list
  - `individual` — specific contacts
- `created_by`: ForeignKey(User, SET_NULL, nullable, related_name='campaigns')
- `org_slug`: CharField(max_length=255, nullable) — set from request.user.org_slug on create
- `is_scheduled`: BooleanField(default=False)
- `scheduled_time`: DateTimeField(nullable)
- `is_sent`: BooleanField(default=False)
- `sent_at`: DateTimeField(nullable)
- `contact`: JSONField(nullable) — recipient data for non-staff targets
- `created_at`: DateTimeField(auto_now_add=True)
- `updated_at`: DateTimeField(auto_now=True)

**Properties:**

- `total_recipients`: Count of related Notification records
- `sent_count`: Count of notifications with status='sent'
- `failed_count`: Count of notifications with status='failed'

---

### Notification

Represents a single notification sent to a single recipient. Created per-recipient when a campaign is sent.

**Fields:**

- `uid`: UUIDField, unique, editable=False
- `campaign`: ForeignKey(Campaign, CASCADE, nullable, related_name='notifications')
- `recipient`: ForeignKey(User, CASCADE, nullable, related_name='notifications_received')
- `sender`: ForeignKey(User, SET_NULL, nullable, related_name='notifications_sent')
- `channel`: CharField, choices: sms / email / in_app
- `subject`: CharField(max_length=255, nullable)
- `message`: TextField
- `status`: CharField, choices:
  - `pending` — not yet sent
  - `sent` — delivered successfully
  - `failed` — delivery failed
  - `read` — in-app notification read by recipient
- `is_read`: BooleanField(default=False)
- `sent_at`: DateTimeField(nullable)
- `failure_reason`: TextField(nullable) — error message on failure
- `recipient_address`: CharField(max_length=255, nullable) — email/phone captured at send time
- `created_at`: DateTimeField(auto_now_add=True)

**Methods:**

- `mark_as_read()`: If channel == 'in_app' and not is_read, sets is_read=True and status=READ. Uses update_fields for efficiency.

---

## Providers (`providers.py`)

### ArkeselProvider

Handles SMS delivery via Arkesel SMS API.

**Configuration (from .env):** Set `APP_NAME=HMS` to brand messages. The code fallback is `ERP` if `APP_NAME` is missing.

```.env
ARKESEL_API_KEY=your-key
ARKESEL_BASE_URL=https://sms.arkesel.com/sms/api
ARKESEL_SENDER_ID=HMS
APP_NAME=HMS
```

**Methods:**

- `send(phone_number, message)` — single SMS
- `send_bulk(phone_numbers, message)` — comma-joined recipients
- `send_otp(phone_number, otp, expires_in_minutes=10)` — formatted OTP message
- `send_temporary_password(phone_number, password)` — formatted temp password message
- `send_scheduled(phone_number, message, scheduled_time)` — future-dated SMS

All methods return `{ success: bool, message: str, raw: dict }`.

### BrevoProvider

Handles email delivery via Brevo transactional email API.

**Configuration (from .env):** Set `APP_NAME=HMS` to brand messages. The code fallback is `ERP` if `APP_NAME` is missing.

```.env
BREVO_API_KEY=your-key
BREVO_FROM_EMAIL=noreply@yourdomain.com
BREVO_FROM_NAME=HMS
APP_NAME=HMS
```

**Methods:**

- `send_login_credentials(to, full_name, email, password)` — welcome email with credentials
- `send_otp(to, full_name, otp, expires_in_minutes=10)` — OTP email
- `send_temporary_password(to, full_name, password)` — password reset email
- `send_campaign_email(to, subject, body, sender_name)` — bulk campaign email

All methods return `{ success: bool, id: str|None, message: str }`.

**Email Templates (private functions):**

- `_base_template(title, body_html)` — base HTML wrapper with styling
- `_login_credentials_template(full_name, email, password, app_name)`
- `_otp_template(full_name, otp, expires_in_minutes, app_name)`
- `_temporary_password_template(full_name, password, app_name)`
- `_campaign_email_template(subject, body, sender_name, app_name)`

All templates use APP_NAME from config — not hardcoded.

---

## Service Layer (`service.py`)

### NotificationService

High-level abstraction over providers. Import this — never call providers directly from views.

```python
from apps.notifications.service import NotificationService
service = NotificationService()
```

**Auth notifications:**

- `send_login_credentials(to, full_name, password, email_address=None, phone_number=None)` — detects email vs phone from 'to' field
- `send_otp(full_name, otp, expires_in_minutes=10, email_address=None, phone_number=None)`
- `send_password_reset_otp(to, full_name, otp, expires_in_minutes=10)`
- `send_temporary_password(full_name, password, email_address=None, phone_number=None)`

**License notifications:**

- `send_license_expiry_notice(to, full_name, expiration_date, license_name)` — sends via Brevo directly

**Campaign notifications:**

- `send_campaign(campaign, recipients, sender_name)` — iterates recipients, creates Notification per recipient, sends via appropriate provider, updates status and failure_reason

**In-app notifications:**

- `send_in_app(recipient, message, subject=None, sender=None, campaign=None)` — creates Notification with status=SENT, returns the Notification instance

---

## Celery Tasks (`tasks.py`)

All tasks use `bind=True, max_retries=3` with 5-minute retry countdown.

### `send_campaign_task(campaign_id)`

Main campaign dispatch task. Called immediately on campaign create (if not scheduled).

1. Fetches Campaign by ID
2. Checks is_sent — skips if already sent
3. Calls `_resolve_recipients(campaign)` from views
4. Calls `service.send_campaign()`
5. Sets campaign.is_sent=True, sent_at=now

### `send_scheduled_campaigns()`

Beat task — runs every 5 minutes (configured in CELERY_BEAT_SCHEDULE).

Finds all campaigns where `is_scheduled=True, is_sent=False, scheduled_time <= now`. Queues `send_campaign_task.delay()` for each.

### `send_license_expiry_notices()`

Beat task — runs daily at 8am (configured in CELERY_BEAT_SCHEDULE).

Finds all active licenses expiring within 5 days. For each:

1. Sends notice to tenant.email
2. Sends notice to all users with role=ADMIN on that license

### `retry_failed_notifications()`

Beat task — runs every hour (configured in CELERY_BEAT_SCHEDULE).

Finds all Notification records with status=FAILED. Retries delivery via appropriate provider. Updates status to SENT or leaves as FAILED.

---

## WebSocket (`consumers.py` + `middleware.py` + `routing.py`)

### One-time WebSocket tickets

Request a one-time ticket using the normal authenticated API before opening a
WebSocket. Tickets expire after 60 seconds and are consumed on the first
connection attempt. The access token is not included in the WebSocket URL.

```python
POST /notifications/ws-ticket/
Authorization: Bearer {access_token}
Response: {"ticket": "<opaque-ticket>", "expires_in": 60}
```

Tickets are stored in Redis and bound to the authenticated user, tenant, and
request Origin. `WS_ALLOWED_ORIGINS` configures allowed browser origins and
defaults to `CORS_ALLOWED_ORIGINS`. Native clients without an Origin header are
supported. The WebSocket middleware consumes tickets atomically and checks the
user's account status again.

### NotificationConsumer

AsyncWebsocketConsumer. Each connected user joins a tenant-scoped group derived
from their authenticated identity. Clients cannot select another user's group.

**Client → Server messages:**

```json
{ "action": "mark_read", "notification_id": 123 }
{ "action": "ping" }
```

**Server → Client messages:**

Sent as the notification object via `channel_layer.group_send()` after the
notification row commits:

```json
{
  "id": 1,
  "uid": "e9d5...",
  "subject": "New task assigned",
  "message": "You have been assigned to Task X",
  "channel": "in_app",
  "status": "sent",
  "is_read": false,
  "sent_at": "2026-05-16T12:00:00Z",
  "created_at": "2026-05-16T12:00:00Z"
}
```

All existing producers publish through `NotificationService.send_in_app()`.
The service stores the notification and schedules WebSocket publication after
the database transaction commits. The notification REST API remains the
source of truth if Redis delivery is temporarily unavailable.

---

## Serializers

### CampaignCreateUpdateSerializer

Fields: name, channel, subject, message, target_type, is_scheduled, scheduled_time, contact

### CampaignListSerializer

Fields: id, uid, name, channel, subject, message, target_type, org_slug, created_by (nested), is_scheduled, scheduled_time, is_sent, sent_at, total_recipients, sent_count, failed_count, created_at, updated_at

`total_recipients`, `sent_count`, `failed_count` are SerializerMethodField — computed from Notification queryset. (Fixed from HMS where these were IntegerField conflicting with method fields.)

### NotificationListSerializer

Fields: id, uid, campaign (nested), recipient (nested), sender (nested), channel, subject, message, status, is_read, sent_at, failure_reason, recipient_address, created_at

---

## Views

### `_resolve_recipients(campaign)`

Module-level helper. Determines the recipient list based on campaign.target_type:

- `staff`: All users with matching org_slug, excluding campaign creator
- `customers`: Returns campaign.contact list (JSON)
- `contact_upload`: Returns campaign.contact list
- `individual`: Returns campaign.contact list (warns if empty)

### CampaignViewSet

**content_model:** Campaign
**lookup_field:** uid
**permission_classes:** [TenantPermission]

`get_queryset`: Filters by `org_slug=request.user.org_slug` — campaigns are always tenant-scoped.

| Action | Method | Notes |
| -------- | -------- | ------- |
| list | GET | Tenant/created_by-scoped |
| retrieve | GET | created_by scoped |
| create | POST | Queues send_campaign_task if not scheduled |
| update | PATCH | Blocked if campaign is_sent=True |
| destroy | DELETE | Blocked if campaign is_sent=True |
| send-now | POST | Manually triggers send_campaign_task |
| notify-user | GET | admin sends direct notification to a user |

### NotificationViewset

**content_model:** Notification
**lookup_field:** uid
**permission_classes:** [TenantPermission]
**Read-only**

`get_queryset`: Returns only notifications where `recipient=request.user`.

| Action | Method | Notes |
| -------- | -------- | ------- |
| list | GET | Returns unread_count in response |
| retrieve | GET | |
| mark-read | POST | Calls notification.mark_as_read() |
| mark-all-read | POST | Bulk update via .update() — single query |

---

## Endpoint Consumption Guide (Frontend)

### Campaigns

#### Create a campaign

```python
POST /notifications/campaigns/
Authorization: Bearer {access_token}
Body: {
  name: "Q1 Staff Update",
  channel: "email",
  subject: "Important Update",
  message: "Hello team...",
  target_type: "staff"
}
Response: { success, data: "Campaign created successfully." }
Note: Campaign is sent immediately if not scheduled.
```

#### Create a scheduled campaign

```python
POST /notifications/campaigns/
Body: {
  ...
  is_scheduled: true,
  scheduled_time: "2026-06-01T09:00:00Z"
}
```

#### Send to specific contacts

```python
POST /notifications/campaigns/
Body: {
  ...
  target_type: "individual",
  contact: [
    { name: "John", email: "john@example.com" },
    { name: "Jane", phone: "+233201234567" }
  ]
}
```

#### Manually trigger a campaign

```python
POST /notifications/campaigns/{uid}/send-now/
Authorization: Bearer {access_token}
Response: { success, data: "Campaign queued for sending." }
```

#### List campaigns

```python
GET /notifications/campaigns/
Authorization: Bearer {access_token}
Response: {
  success,
  data: [{
    uid, name, channel, is_sent, sent_at,
    total_recipients, sent_count, failed_count
  }]
}
```

### In-App Notifications

#### List notifications

```python
GET /notifications/notifications/
Authorization: Bearer {access_token}
Response: {
  success,
  data: [{ uid, subject, message, is_read, sent_at, channel }],
  unread_count: 5
}
```

#### Mark one as read

```python
POST /notifications/{uid}/mark-read/
Authorization: Bearer {access_token}
Response: { success, data: "Notification marked as read." }
```

```python
POST /notifications/notify-user/
Authorization: Bearer {access_token}
Body: { "recipient": <user_id>, "message": "...","subject": "..." }
Response: { success, data: "Notification sent successfully"}
```

#### Mark all as read

```python
POST /notifications/mark-all-read/
Authorization: Bearer {access_token}
Response: { success, data: "All notifications marked as read." }
```

### WebSocket Connection

#### Connect

```javascript
const token = getAccessToken(); // from memory
const response = await fetch('/notifications/ws-ticket/', {
  method: 'POST',
  headers: { Authorization: `Bearer ${token}` },
});
const { ticket } = await response.json();
const ws = new WebSocket(`wss://yourhost/ws/notifications/?ticket=${ticket}`);

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  if (data.type === 'pong') return;
  // handle new notification
  showNotificationToast(data.message);
  incrementUnreadCount();
};

ws.onclose = () => {
  // implement reconnect with backoff
};
```

#### Mark as read via WebSocket

```javascript
ws.send(JSON.stringify({
  action: 'mark_read',
  notification_id: 123
}));
```

## Keepalive

```javascript
setInterval(() => {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ action: 'ping' }));
  }
}, 30000);
```

## Token refresh and reconnect

Request a fresh ticket whenever reconnecting. Tickets are single-use and expire
quickly. Access tokens expire after 15 minutes and use the existing refresh
flow. Ticket authentication does not close an already-open socket if an
account is later disabled; immediate socket revocation is a separate feature.

---

## CELERY_BEAT_SCHEDULE Configuration

Add this to `settings.py` (already configured):

```python
from celery.schedules import crontab

CELERY_BEAT_SCHEDULE = {
    "send-license-expiry-notices": {
        "task": "apps.notifications.tasks.send_license_expiry_notices",
        "schedule": crontab(hour=8, minute=0),  # daily at 8am
    },
    "retry-failed-notifications": {
        "task": "apps.notifications.tasks.retry_failed_notifications",
        "schedule": crontab(minute=0),  # every hour
    },
    "send-scheduled-campaigns": {
        "task": "apps.notifications.tasks.send_scheduled_campaigns",
        "schedule": crontab(minute="*/5"),  # every 5 minutes
    },
}
```

---

## URL Structure

```python
campaigns/                       CampaignViewSet
campaigns/{uid}/send-now/        POST
notifications/                   NotificationViewset
/notifications/{uid}/mark-read/  POST
/notifications/mark-all-read/    POST
/notifications/notify-user/      GET

WebSocket:
POST /notifications/ws-ticket/ then connect to
wss://yourhost/ws/notifications/?ticket={one_time_ticket}
```

---

## Apps Configuration

### NotificationsConfig

```python
default_auto_field = "django.db.models.BigAutoField"
name = "apps.notifications"

def ready(self):
    pass  # no signals in this app
```

### ASGI Configuration

WebSocket routing is configured in `hms/asgi.py`. The import order is critical — `get_asgi_application()` must be called before any Django app imports:

```python
import os
from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "hms.settings.dev")
django_asgi_app = get_asgi_application()  # MUST be before other imports

from channels.routing import ProtocolTypeRouter, URLRouter
from apps.notifications.middleware import TicketAuthMiddleware
from apps.notifications.routing import websocket_urlpatterns

application = ProtocolTypeRouter({
    "http": django_asgi_app,
    "websocket": TicketAuthMiddleware(URLRouter(websocket_urlpatterns)),
})
```

### CHANNEL_LAYERS Configuration (settings.py)

```python
CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [config("REDIS_HOST")],
        },
    },
}
```
