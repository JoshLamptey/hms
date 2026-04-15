# Notifications App Documentation

> **Last Updated:** April 2026  
> **App Location:** `apps/notifications/`  
> **Django App Config:** `apps.notifications.NotificationsConfig`

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Models](#models)
4. [Views & Endpoints](#views--endpoints)
5. [Serializers](#serializers)
6. [Service Layer](#service-layer)
7. [Providers](#providers)
8. [Celery Tasks](#celery-tasks)
9. [WebSocket Integration](#websocket-integration)
10. [Middleware](#middleware)
11. [URL Configuration](#url-configuration)
12. [Usage Examples](#usage-examples)

---

## Overview

The `apps/notifications` app provides a comprehensive notification system supporting multiple communication channels:

| Channel | Description |
|---------|-------------|
| **SMS** | Send text messages via Arkesel SMS Gateway |
| **Email** | Send emails via Brevo (Sendinblue) API |
| **In-App** | Real-time WebSocket notifications for the notification bell |

### Key Features

- **Bulk Campaigns**: Send notifications to multiple recipients (staff, customers, or external contacts)
- **Scheduled Sending**: Schedule campaigns for future delivery via Celery Beat
- **Direct Notifications**: Send one-off in-app notifications between users
- **Real-time Push**: WebSocket-based instant notification delivery
- **Transactional Emails**: OTP, password reset, login credentials emails
- **Retry Mechanism**: Automatic retry of failed notifications
- **Multi-tenant**: Organization-scoped notifications via `org_slug`

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Client (Frontend)                         │
└───────────────────────────────┬─────────────────────────────────┘
                                │ HTTP/REST
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                         Views Layer                              │
│  ┌─────────────────────┐    ┌─────────────────────────────────┐ │
│  │  CampaignViewSet    │    │    NotificationViewset          │ │
│  │  - create           │    │    - list                       │ │
│  │  - update           │    │    - notify_user                │ │
│  │  - list/retrieve    │    │    - mark_read                  │ │
│  │  - resend_failed   │    │    - mark_all_read              │ │
│  │  - destroy          │    │    - unread_count               │ │
│  └──────────┬──────────┘    └────────────────┬────────────────┘ │
└─────────────┼───────────────────────────────┼───────────────────┘
              │                               │
              ▼                               ▼
┌───────────────────────────┐    ┌─────────────────────────────────┐
│    Service Layer          │    │       Serializers               │
│  NotificationService     │    │  - CampaignCreateSerializer     │
│  - create_campaign()      │    │  - CampaignListSerializer       │
│  - notify_user()          │    │  - CampaignUpdateSerializer     │
│  - dispatch_notification()│    │  - NotificationCreateSerializer│
│  - send_otp()             │    │  - NotificationListSerializer   │
│  - send_login_credentials()│    └─────────────────────────────────┘
│  - send_temporary_password()│
└───────────┬───────────────┘
            │
            ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Providers Layer                              │
│  ┌───────────────────────┐    ┌──────────────────────────────┐ │
│  │    ArkeselProvider     │    │      BrevoProvider            │ │
│  │    (SMS)               │    │      (Email)                  │ │
│  │  - send()             │    │    - send()                   │ │
│  │  - send_bulk()        │    │    - send_login_credentials()  │ │
│  │  - send_otp()         │    │    - send_otp()               │ │
│  │  - send_temporary_password()│  │    - send_temporary_password()│
│  │  - send_scheduled()    │    │    - send_campaign_email()    │ │
│  └───────────────────────┘    └──────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                     Celery Workers                               │
│  ┌────────────────────────────┐  ┌────────────────────────────┐ │
│  │ dispatch_campaign_task()    │  │ dispatch_scheduled_task()  │ │
│  │ dispatch_scheduled_task()   │  │ push_in_app_notification() │ │
│  │ retry_failed_notifications()│  └────────────────────────────┘ │
│  └────────────────────────────┘                                  │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                   WebSocket Layer                                 │
│  ┌────────────────────────────┐  ┌────────────────────────────┐ │
│  │ JWTWebSocketMiddleware     │  │  NotificationConsumer       │ │
│  │ - JWT token validation     │  │  - connect()               │ │
│  │ - User authentication      │  │  - disconnect()            │ │
│  └────────────────────────────┘  │  - receive()               │ │
│                                   │  - send_notification()    │ │
│                                   └────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

---

## Models

### Campaign

[`apps/notifications/models.py:4`](apps/notifications/models.py:4) - Represents a bulk notification campaign initiated by an admin.

| Field | Type | Description |
|-------|------|-------------|
| `uid` | UUID | Unique identifier (auto-generated) |
| `name` | CharField(255) | Campaign name |
| `channel` | CharField(10) | Delivery channel: `sms`, `email`, or `in_app` |
| `subject` | CharField(255) | Email subject line (email only, optional) |
| `message` | TextField | Notification message body |
| `target_type` | CharField(20) | Recipient type: `staff`, `customers`, `contact_upload`, `individual` |
| `created_by` | ForeignKey(User) | Admin who created the campaign |
| `org_slug` | CharField(255) | Organization schema slug for multi-tenancy |
| `is_scheduled` | BooleanField | Whether campaign is scheduled for later |
| `scheduled_time` | DateTimeField | When to send (if scheduled) |
| `is_sent` | BooleanField | Whether campaign has been dispatched |
| `sent_at` | DateTimeField | When campaign was sent |
| `contact` | JSONField | External contacts for `contact_upload` target type |
| `created_at` | DateTimeField | Creation timestamp |
| `updated_at` | DateTimeField | Last update timestamp |

#### Campaign Properties

```python
# Get total recipient count
campaign.total_recipients  # Returns Notification.objects.filter(campaign=campaign).count()

# Get sent count
campaign.sent_count  # Returns notifications with status="sent"

# Get failed count
campaign.failed_count  # Returns notifications with status="failed"
```

#### Channel Choices

```python
CHANNEL_CHOICES = [
    ("sms", "SMS"),
    ("email", "Email"),
    ("in_app", "In-App")
]
```

#### Target Type Choices

```python
TARGET_TYPE_CHOICES = [
    ("staff", "STAFF"),              # Send to selected staff members
    ("customers", "CUSTOMERS"),     # Send to selected customers
    ("contact_upload", "CONTACT_UPLOAD"),  # Send to external contacts (phone/email list)
    ("individual", "INDIVIDUAL")     # Send to a single recipient
]
```

#### Contact Upload Format

When `target_type` is `contact_upload`, the `contact` field stores raw contact data:

```python
contact = [
    {"name": "John Doe", "phone_number": "0201234567"},
    {"name": "Jane Doe", "email": "jane@example.com"},
    # ...
]
```

---

### Notification

[`apps/notifications/models.py:59`](apps/notifications/models.py:59) - Represents a single notification record sent to a recipient.

| Field | Type | Description |
|-------|------|-------------|
| `uid` | UUID | Unique identifier (auto-generated) |
| `campaign` | ForeignKey(Campaign) | Parent campaign (null for direct notifications) |
| `recipient` | ForeignKey(User) | User receiving the notification |
| `sender` | ForeignKey(User) | User who triggered the notification |
| `channel` | CharField(10) | Delivery channel |
| `subject` | CharField(255) | Email subject (email only) |
| `message` | TextField | Notification message |
| `status` | CharField(10) | Status: `pending`, `sent`, `failed`, `read` |
| `is_read` | BooleanField | Whether in-app notification has been read |
| `sent_at` | DateTimeField | When notification was sent |
| `created_at` | DateTimeField | Creation timestamp |
| `failure_reason` | TextField | Reason for failure (if applicable) |
| `recipient_address` | CharField(255) | Email/phone used at time of send (snapshot) |

#### Notification Status Choices

```python
STATUS_CHOICES = [
    ("pending", "Pending"),   # Queued for sending
    ("sent", "Sent"),         # Successfully delivered
    ("failed", "Failed"),    # Delivery failed
    ("read", "Read"),         # In-app notification read by user
]
```

#### Methods

```python
def mark_as_read(self):
    """Mark an in-app notification as read."""
    if self.channel == "in_app" and not self.is_read:
        self.is_read = True
        self.status = "read"
        self.save(update_fields=["is_read", "status"])
```

---

## Views & Endpoints

### CampaignViewSet

[`apps/notifications/views.py:95`](apps/notifications/views.py:95) - Handles CRUD operations for notification campaigns.

#### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/campaigns/` | Create a new campaign |
| `GET` | `/campaigns/` | List all campaigns (org-scoped) |
| `GET` | `/campaigns/{uid}/` | Retrieve a specific campaign |
| `PUT/PATCH` | `/campaigns/{uid}/` | Update a campaign |
| `DELETE` | `/campaigns/{uid}/` | Delete a campaign |
| `POST` | `/campaigns/{uid}/resend-failed/` | Retry failed notifications |

#### Creating a Campaign

```python
# Request body for staff target
{
    "name": "Staff Meeting Reminder",
    "channel": "email",
    "subject": "Meeting Tomorrow",
    "message": "Don't forget about the meeting tomorrow at 10 AM.",
    "target_type": "staff",
    "staff": [1, 2, 3]  # List of user IDs
}

# Request body for contact upload
{
    "name": "Promotional SMS",
    "channel": "sms",
    "message": "Check out our new products!",
    "target_type": "contact_upload",
    "contact": [
        {"name": "John", "phone_number": "0201234567"},
        {"name": "Jane", "phone_number": "0241234567"}
    ]
}

# Request body for scheduled campaign
{
    "name": "Weekly Newsletter",
    "channel": "email",
    "subject": "Weekly Update",
    "message": "Here's your weekly update...",
    "target_type": "customers",
    "customers": [1, 2, 3],
    "is_scheduled": True,
    "scheduled_time": "2026-04-10T09:00:00Z"
}
```

#### Response Format

```python
# Success response
{
    "success": True,
    "info": "Campaign created successfully",
    "campaign_uid": "uuid-string"
}

# Error response
{
    "success": False,
    "info": "Error message here"
}
```

---

### NotificationViewset

[`apps/notifications/views.py:264`](apps/notifications/views.py:264) - Handles in-app notifications for authenticated users.

#### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/notifications/` | List current user's notifications |
| `GET` | `/notifications/{uid}/` | Retrieve a specific notification |
| `DELETE` | `/notifications/{uid}/` | Delete a notification |
| `POST` | `/notifications/notify-user/` | Send notification to a user |
| `PATCH` | `/notifications/{uid}/mark-read/` | Mark single notification as read |
| `POST` | `/notifications/mark-all-read/` | Mark all notifications as read |
| `GET` | `/notifications/unread-count/` | Get unread count for bell badge |

#### Key Features

- **User-scoped**: Users only see their own in-app notifications
- **Real-time**: WebSocket push on creation
- **Batch operations**: Mark all as read in one request

#### Notify User Example

```python
# Request
{
    "recipient": 123,  # User ID
    "message": "Your report is ready for review",
    "subject": "Report Ready"
}

# Response
{
    "success": True,
    "info": "Notification sent successfully"
}
```

---

### Helper Functions

#### `_resolve_recipients(data, org_slug)`

[`apps/notifications/views.py:25`](apps/notifications/views.py:25) - Resolves recipient User objects from request data based on target type.

**Parameters:**
- `data` (dict): Request data containing `target_type` and recipient IDs
- `org_slug` (str): Organization slug for filtering

**Returns:** `(list[User], str|None)` - Tuple of users and error message

**Supported Target Types:**
- `customers`: Uses `customers` list from data
- `staff`: Uses `staff` list from data
- `contact_upload`: Returns empty list (no User resolution needed)
- `individual`: Uses `recipient` field

---

## Serializers

### NotificationListSerializer

[`apps/notifications/serializers.py:5`](apps/notifications/serializers.py:5) - Serializes notifications for list/retrieve operations.

**Fields:**
```python
[
    "uid", "campaign", "campaign_name", "recipient", "sender",
    "channel", "subject", "message", "status", "is_read",
    "recipient_address", "failure_reason", "sent_at", "created_at"
]
```

**Computed Fields:**
- `recipient`: Expanded user info (id, uid, full_name, email)
- `sender`: Expanded user info (id, uid, full_name, email)
- `campaign_name`: Campaign name if exists

---

### NotificationCreateSerializer

[`apps/notifications/serializers.py:62`](apps/notifications/serializers.py:62) - Validates direct notification creation.

**Validation:**
- Only `in_app` channel allowed for direct notifications
- SMS/email direct sends must use Campaign

---

### CampaignListSerializer

[`apps/notifications/serializers.py:88`](apps/notifications/serializers.py:88) - Serializes campaigns for list/retrieve.

**Fields:**
```python
[
    "uid", "name", "channel", "subject", "message", "target_type",
    "created_by", "org_slug", "is_scheduled", "scheduled_time",
    "is_sent", "sent_at", "contact", "total_recipients", "sent_count",
    "failed_count", "created_at", "updated_at"
]
```

---

### CampaignCreateSerializer

[`apps/notifications/serializers.py:144`](apps/notifications/serializers.py:144) - Validates campaign creation.

**Write-only Fields:**
- `staff`: List of staff user IDs
- `customers`: List of customer user IDs

**Validation Rules:**
1. Email campaigns require `subject`
2. Scheduled campaigns require `scheduled_time`
3. `scheduled_time` must be in the future
4. Staff target requires `staff` list
5. Customers target requires `customers` list
6. Contact upload target requires `contact` data

---

### CampaignUpdateSerializer

[`apps/notifications/serializers.py:229`](apps/notifications/serializers.py:229) - Validates campaign updates.

**Updatable Fields:**
- `name`
- `subject`
- `message`
- `is_scheduled`
- `scheduled_time`

**Note:** Sent campaigns cannot be edited (enforced in view).

---

## Service Layer

### NotificationService

[`apps/notifications/service.py:14`](apps/notifications/service.py:14) - Central service for all notification logic.

#### Public Methods

##### `create_campaign()`

```python
def create_campaign(
    self,
    data: dict,
    created_by: User,
    recipient_users: list,
    org_slug: str
) -> Campaign
```

Creates a Campaign and fans out Notification records per recipient.

**Process:**
1. Creates Campaign record
2. For each recipient, creates Notification with status="pending"
3. For `contact_upload`, creates notifications with `recipient_address` from contact data
4. Kicks off Celery task for sending

**Returns:** Created Campaign instance

---

##### `notify_user()`

```python
def notify_user(
    self,
    sender: User,
    recipient: User,
    message: str,
    subject: str = None
) -> Notification
```

Sends a direct in-app notification.

**Features:**
- Creates Notification with status="sent"
- Triggers WebSocket push immediately
- No campaign needed

**Returns:** Created Notification instance

---

##### `dispatch_notification()`

```python
def dispatch_notification(self, notification: Notification) -> bool
```

Sends a single Notification via its channel.

**Process:**
1. Routes to appropriate channel handler
2. Updates notification status to "sent" or "failed"
3. Records failure reason if applicable

**Returns:** `True` if successful, `False` if failed

---

##### `send_login_credentials()`

```python
def send_login_credentials(
    self,
    to: str,
    full_name: str,
    password: str
) -> bool
```

Sends login credentials email to new user.

**Note:** No Campaign or Notification record created.

---

##### `send_otp()`

```python
def send_otp(
    self,
    full_name: str,
    otp: str,
    expires_in_minutes: int = 10,
    email_address: str = None,
    phone_number: str = None
) -> bool
```

Sends OTP via email, SMS, or both.

**Note:** No Campaign or Notification record created.

---

##### `send_temporary_password()`

```python
def send_temporary_password(
    self,
    full_name: str,
    password: str,
    email_address: str = None,
    phone_number: str = None
) -> bool
```

Sends temporary password via email/SMS.

**Used by:** Forgot password flow

---

##### `mark_all_read()`

```python
def mark_all_read(self, user: User) -> int
```

Marks all unread in-app notifications as read.

**Returns:** Number of notifications updated

---

#### Private Methods

##### `_resolve_address()`

```python
def _resolve_address(self, user: User, channel: str) -> str | None
```

Snapshots recipient's contact address at send time.

| Channel | Returns |
|---------|---------|
| `email` | `user.email` |
| `sms` | `user.phone_number` |
| Other | `None` |

---

##### `_send_sms()`

Routes SMS sending to ArkeselProvider.

---

##### `_send_email()`

Routes email sending to BrevoProvider with sender name resolution.

---

##### `_push_in_app()`

```python
def _push_in_app(self, notification: Notification) -> dict
```

Sends WebSocket push to recipient's channel group.

**Payload Structure:**
```python
{
    "type": "send_notification",
    "data": {
        "id": notification.id,
        "uid": str(notification.uid),
        "message": notification.message,
        "subject": notification.subject,
        "is_read": notification.is_read,
        "timestamp": notification.created_at.isoformat(),
        "sender": {
            "id": notification.sender.id,
            "uid": str(notification.sender.uid),
            "full_name": notification.sender.get_full_name()
        }
    }
}
```

---

## Providers

### ArkeselProvider

[`apps/notifications/providers.py:14`](apps/notifications/providers.py:14) - SMS provider using Arkesel API.

#### Configuration

**Environment Variables:**
- `ARKESEL_API_KEY` - Arkesel API key
- `ARKESEL_SENDER_ID` - Sender ID (default: "HMS")
- `ARKESEL_BASE_URL` - API base URL

#### Methods

##### `send()`

```python
def send(self, phone_number: str, message: str) -> dict
```

Send a single SMS immediately.

**Returns:**
```python
{
    "success": bool,
    "message": str,
    "raw": dict  # Raw API response
}
```

---

##### `send_bulk()`

```python
def send_bulk(self, phone_numbers: list[str], message: str) -> dict
```

Send SMS to multiple recipients (comma-separated).

---

##### `send_otp()`

```python
def send_otp(
    self,
    phone_number: str,
    otp: str,
    expires_in_minutes: int = 10
) -> dict
```

Send OTP via SMS with formatted message.

**Message Format:**
```
Your HMS OTP is: 123456. Valid for 10 minutes. Do not share this code with anyone.
```

---

##### `send_temporary_password()`

```python
def send_temporary_password(
    self,
    phone_number: str,
    password: str
) -> dict
```

Send temporary password via SMS.

---

##### `send_scheduled()`

```python
def send_scheduled(
    self,
    phone_number: str,
    message: str,
    scheduled_time: str
) -> dict
```

Schedule SMS for future delivery.

**Note:** `scheduled_time` format: `"2025-12-01 08:00 AM"`

---

### BrevoProvider

[`apps/notifications/providers.py:233`](apps/notifications/providers.py:233) - Email provider using Brevo (Sendinblue) API.

#### Configuration

**Environment Variables:**
- `BREVO_API_KEY` - Brevo API key
- `BREVO_FROM_EMAIL` - Sender email address
- `BREVO_FROM_NAME` - Sender display name
- `APP_NAME` - App name for email templates

#### Methods

##### `send_login_credentials()`

```python
def send_login_credentials(
    self,
    to: str,
    full_name: str,
    email: str,
    password: str
) -> dict
```

Sends welcome email with login credentials.

**Template:** Clean HTML with highlighted password

---

##### `send_otp()`

```python
def send_otp(
    self,
    to: str,
    full_name: str,
    otp: str,
    expires_in_minutes: int = 10
) -> dict
```

Sends OTP email.

---

##### `send_temporary_password()`

```python
def send_temporary_password(
    self,
    to: str,
    full_name: str,
    password: str
) -> dict
```

Sends temporary password email.

---

##### `send_campaign_email()`

```python
def send_campaign_email(
    self,
    to: str | list[str],
    subject: str,
    body: str,
    sender_name: str
) -> dict
```

Sends campaign email with admin-written content.

**Template:** Includes sender attribution and formatted body

---

#### Email Templates

All emails use a base template with:
- Clean, responsive HTML design
- App branding
- Highlighted codes/passwords
- Auto-generated footer

---

## Celery Tasks

### dispatch_campaign_task

[`apps/notifications/tasks.py:11`](apps/notifications/tasks.py:11) - Fan-out task for campaign dispatch.

```python
@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def dispatch_campaign_task(self, campaign_id: int)
```

**Process:**
1. Fetches all pending notifications for campaign
2. Dispatches each via NotificationService
3. Tracks success/failure counts
4. Marks campaign as sent after processing

**Retry Policy:**
- Max 3 retries on unexpected errors
- 60-second delay between retries
- Individual send failures handled per-notification (not task retry)

---

### dispatch_scheduled_campaign_task

[`apps/notifications/tasks.py:86`](apps/notifications/tasks.py:86) - Wrapper for scheduled campaigns.

```python
@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def dispatch_scheduled_campaign_task(self, campaign_id: int)
```

**Usage:** Called by Celery Beat at scheduled time via `apply_async(eta=...)`

---

### push_in_app_notification_task

[`apps/notifications/tasks.py:99`](apps/notifications/tasks.py:99) - WebSocket push for in-app notifications.

```python
@shared_task(bind=True, max_retries=3, default_retry_delay=10)
def push_in_app_notification_task(self, notification_id: int)
```

**Features:**
- Shorter retry delay (10s) for near-instant delivery
- No retry for offline users (pushed when they next fetch)

---

### retry_failed_notifications

[`apps/notifications/tasks.py:140`](apps/notifications/tasks.py:140) - Periodic retry of failed notifications.

```python
@shared_task
def retry_failed_notifications()
```

**Process:**
1. Finds notifications failed in last 24 hours
2. Only retries SMS/email (not in-app)
3. Resets to pending and re-dispatches

**Usage:** Hook to Celery Beat (e.g., hourly)

---

## WebSocket Integration

### NotificationConsumer

[`apps/notifications/consumers.py:9`](apps/notifications/consumers.py:9) - WebSocket consumer for real-time notifications.

#### Connection Flow

```
1. Client connects: ws://host/ws/notifications/?token=<jwt>
2. JWTWebSocketMiddleware validates token
3. Consumer joins group: notify_<user_id>
4. Service calls channel_layer.group_send()
5. Consumer receives and forwards to client
```

#### Supported Client Messages

##### Ping

```json
{"type": "ping"}
```
**Response:** `{"type": "pong"}`

##### Mark Read

```json
{"type": "mark_read", "uid": "notification-uid"}
```

#### Server-to-Client Events

##### New Notification

```json
{
    "type": "notification.new",
    "data": {
        "id": 123,
        "uid": "uuid-string",
        "message": "Notification text",
        "subject": "Optional subject",
        "is_read": false,
        "timestamp": "2026-04-07T15:30:00Z",
        "sender": {
            "id": 1,
            "uid": "uuid-string",
            "full_name": "John Doe"
        }
    }
}
```

##### Connection Established

```json
{
    "type": "connection.established",
    "message": "Connected to notification stream"
}
```

#### Key Features

- **User Isolation**: Each user in their own group
- **Anonymous Rejection**: Unauthenticated connections rejected with code 4001
- **Graceful Disconnect**: Leaves group on disconnect
- **Database Sync**: Uses `database_sync_to_async` for ORM operations

---

## Middleware

### JWTWebSocketMiddleware

[`apps/notifications/middleware.py:56`](apps/notifications/middleware.py:56) - Authenticates WebSocket connections using JWT.

#### How It Works

1. Parses token from query string (`?token=<jwt>`)
2. Validates JWT using `SECRET_KEY` and `HS256` algorithm
3. Sets `scope["user"]` with authenticated User
4. Falls back to `AnonymousUser` on failure

#### Token Payload Expected

```python
{
    "user_id": 123,      # Optional
    "user_uid": "uuid",   # Preferred
    # ... other claims
}
```

#### Why Query String?

Browser WebSocket API doesn't support custom headers, so query string is the standard workaround.

---

## URL Configuration

### REST API URLs

[`apps/notifications/urls.py`](apps/notifications/urls.py)

```python
router = DefaultRouter()
router.register(r"campaigns", CampaignViewSet, basename="campaign")
router.register(r"notifications", NotificationViewset, basename="notification")
```

**Full URLs:**
- `/campaigns/` - Campaign CRUD
- `/notifications/` - Notification management

### WebSocket URLs

[`apps/notifications/routing.py`](apps/notifications/routing.py)

```python
websocket_urlpatterns = [
    re_path(r"^ws/notifications/$", consumers.NotificationConsumer.as_asgi()),
]
```

**WebSocket Endpoint:** `ws://host/ws/notifications/?token=<jwt>`

---

## Usage Examples

### Sending a Campaign

```python
# Via API
import requests

response = requests.post("/api/campaigns/", json={
    "name": "Staff Update",
    "channel": "email",
    "subject": "Important Update",
    "message": "Please read this important update.",
    "target_type": "staff",
    "staff": [1, 2, 3]
})
```

### Sending Direct Notification

```python
# Via API
response = requests.post("/api/notifications/notify-user/", json={
    "recipient": 123,
    "message": "Your task has been completed",
    "subject": "Task Complete"
})
```

### Marking Notifications as Read

```python
# Single notification
requests.patch("/api/notifications/{uid}/mark-read/")

# All notifications
requests.post("/api/notifications/mark-all-read/")
```

### WebSocket Integration (Frontend)

```javascript
const ws = new WebSocket(
    `ws://host/ws/notifications/?token=${accessToken}`
);

ws.onopen = () => {
    console.log("Connected to notification stream");
};

ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    if (data.type === "notification.new") {
        // Handle new notification
        console.log("New notification:", data.data);
    }
};

// Mark notification as read via WebSocket
ws.send(JSON.stringify({
    type: "mark_read",
    uid: "notification-uid"
}));

// Keepalive ping
setInterval(() => {
    ws.send(JSON.stringify({ type: "ping" }));
}, 30000);
```

### Using the Service Directly

```python
from apps.notifications.service import NotificationService

service = NotificationService()

# Send campaign
campaign = service.create_campaign(
    data={"name": "Test", "channel": "email", ...},
    created_by=request.user,
    recipient_users=[user1, user2],
    org_slug="my-org"
)

# Send direct notification
notification = service.notify_user(
    sender=request.user,
    recipient=user,
    message="Hello!"
)

# Send transactional email
service.send_login_credentials(
    to="user@example.com",
    full_name="John Doe",
    password="temp123"
)

# Send OTP
service.send_otp(
    full_name="John Doe",
    otp="123456",
    expires_in_minutes=10,
    email_address="user@example.com"
)
```

---

## Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `ARKESEL_API_KEY` | Arkesel SMS API key | Yes (if using SMS) |
| `ARKESEL_SENDER_ID` | SMS sender ID | No (default: "HMS") |
| `ARKESEL_BASE_URL` | Arkesel API base URL | Yes (if using SMS) |
| `BREVO_API_KEY` | Brevo API key | Yes (if using email) |
| `BREVO_FROM_EMAIL` | Sender email | Yes (if using email) |
| `BREVO_FROM_NAME` | Sender name | No |
| `APP_NAME` | Application name | No (default: "HMS") |

### Celery Configuration

```python
# settings.py
CELERY_BROKER_URL = "redis://localhost:6379/0"
CELERY_RESULT_BACKEND = "redis://localhost:6379/0"
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"
```

### Celery Beat Schedule (Optional)

```python
# Run retry_failed_notifications every hour
CELERY_BEAT_SCHEDULE = {
    "retry-failed-notifications": {
        "task": "apps.notifications.tasks.retry_failed_notifications",
        "schedule": 3600.0,  # Every hour
    },
}
```

---

## Error Handling

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `No phone number on record` | SMS to user without phone | Check user profile |
| `No email address on record` | Email to user without email | Check user profile |
| `Campaign not found` | Invalid campaign ID | Verify campaign exists |
| `Cannot edit sent campaign` | Attempted update after send | Create new campaign |
| `Websocket connection attempted with no token` | Missing auth token | Include JWT in query string |

### Logging

All components log using `logging.getLogger(__name__)`:

```python
logger.error(f"Arkesel error sending to {phone_number}: {e}")
logger.warning(f"Websocket push failed for notification {notification.uid}")
```

---

## Security Considerations

1. **JWT Validation**: All WebSocket connections validated via JWT
2. **User Isolation**: Users only see their own notifications
3. **Org Scoping**: Campaigns scoped by `org_slug`
4. **Permission System**: CustomPermission class for view access
5. **No Token in Headers**: WebSocket uses query string (standard practice)

---

## Performance Notes

1. **Bulk Create**: Notifications created using `bulk_create()` for efficiency
2. **Select Related**: Views use `select_related()` to reduce queries
3. **Prefetch Related**: Campaign list prefetches notifications
4. **Async WebSocket**: Consumer uses async for non-blocking operations
5. **Task Batching**: Consider batching for large campaigns
