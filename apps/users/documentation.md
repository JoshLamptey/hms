# Users App Documentation

This document provides comprehensive documentation for the `apps/users` Django app, which handles user authentication, authorization, and user management in a multi-tenant architecture.

## Table of Contents

1. [Overview](#overview)
2. [File Structure](#file-structure)
3. [Models](#models)
4. [Authentication System](#authentication-system)
5. [Permissions System](#permissions-system)
6. [Serializers](#serializers)
7. [Views and API Endpoints](#views-and-api-endpoints)
8. [URL Configuration](#url-configuration)
9. [Services](#services)
10. [Utilities and Tasks](#utilities-and-tasks)
11. [Validators](#validators)
12. [Exception Handling](#exception-handling)
13. [Django Admin Configuration](#django-admin-configuration)

---

## Overview

The Users app provides authentication and authorization functionality for the multi-tenant HMS (Hotel Management System) application. It includes JWT-based authentication, role-based access control, user groups, and comprehensive user management features.

### Key Features

- **JWT-based authentication** with access and refresh tokens
- **OTP (One-Time Password)** verification for login and password reset
- **Role-based access control (RBAC)** with custom permissions
- **User groups** with assigned permissions
- **Password management** (reset, change, expiry)
- **Rate limiting and throttling**
- **Multi-tenant user isolation**
- **Email notifications** via SendGrid

---

## File Structure

```txt
apps/users/
├── __init__.py          # Package initialization
├── admin.py             # Django admin configuration
├── apps.py              # App configuration
├── auth.py              # Authentication classes and JWT handling
├── exceptions.py        # Custom exception handlers
├── models.py            # Database models (User, UserRole, UserGroup)
├── pagination.py        # Pagination classes
├── perms.py             # Custom permission classes
├── serializers.py       # DRF serializers
├── services.py          # Email sending services (SendGrid)
├── tests.py             # Unit tests (placeholder)
├── urls.py              # URL routing configuration
├── utils.py             # Utility functions and Celery tasks
├── validators.py        # Custom validators
└── views.py             # API views and viewsets
```

---

## Models

### UserGroup Model

Represents a group of users with assigned permissions, enabling role-based access control at the group level.

**Location:** [`apps/users/models.py:16`](apps/users/models.py:16)

```python
class UserGroup(models.Model):
    uid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    users = models.ManyToManyField("users.User", verbose_name="user_perm_group", blank=True)
    permissions = models.ManyToManyField(Permission, blank=True, related_name="user_groups")
    tenant = models.ForeignKey("client.Tenant", on_delete=models.CASCADE, null=True, blank=True, related_name="user_groups")
    is_global = models.BooleanField(default=False)
    name = models.CharField(max_length=150, null=True, blank=True)
    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
```

| Field | Type | Description |
|-------|------|-------------|
| `uid` | UUIDField | Unique identifier, auto-generated |
| `users` | ManyToManyField | Related users through a junction table |
| `permissions` | ManyToManyField | Django permissions assigned to the group |
| `tenant` | ForeignKey | Associated tenant (optional, for multi-tenancy) |
| `is_global` | BooleanField | If True, visible to all tenants (SUPER_ADMIN only) |
| `name` | CharField | Group name |
| `description` | TextField | Group description |
| `created_at` | DateTimeField | Creation timestamp |
| `updated_at` | DateTimeField | Last update timestamp |

**Meta:**
- Verbose name: "User Group"
- Ordering: by `-created_at` (newest first)

---

### UserRole Model

Defines user roles in the system with predefined role types.

**Location:** [`apps/users/models.py:45`](apps/users/models.py:45)

```python
class UserRole(models.Model):
    class Role(models.TextChoices):
        SUPER_ADMIN = "SUPER_ADMIN", t("Super Admin")
        STAFF = "STAFF", t("Staff")
        CUSTOMER = "CUSTOMER", t("Customer")
    
    uid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    name = models.CharField(max_length=50, choices=Role.choices, default=Role.CUSTOMER)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
```

| Role | Display Name | Description |
|------|--------------|-------------|
| `SUPER_ADMIN` | Super Admin | Full system access across all tenants |
| `STAFF` | Staff | Staff-level access within an organization |
| `CUSTOMER` | Customer | Customer-level access |

| Field | Type | Description |
|-------|------|-------------|
| `uid` | UUIDField | Unique identifier |
| `name` | CharField | Role name from choices |
| `created_at` | DateTimeField | Creation timestamp |
| `updated_at` | DateTimeField | Last update timestamp |

**Meta:**
- Verbose name: "User Role"
- Ordering: by `-created_at` (newest first)

---

### User Model (Custom User)

Extends Django's AbstractUser with additional fields for multi-tenancy and extended user management.

**Location:** [`apps/users/models.py:65`](apps/users/models.py:65)

```python
class User(AbstractUser):
    class Gender(models.TextChoices):
        MALE = "MALE", t("Male")
        FEMALE = "FEMALE", t("Female")
        OTHER = "OTHER", t("Other")
    
    class Status(models.TextChoices):
        ACTIVE = "ACTIVE", t("Active")
        INACTIVE = "INACTIVE", t("Inactive")
        SUSPENDED = "SUSPENDED", t("Suspended")
    
    uid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    username = models.CharField(max_length=150, unique=True)
    middle_name = models.CharField(max_length=150, blank=True, null=True)
    role = models.ForeignKey(UserRole, on_delete=models.CASCADE, related_name="users", blank=True, null=True)
    phone_number = PhoneNumberField()
    gender = models.CharField(max_length=10, choices=Gender.choices, default=Gender.OTHER)
    status = models.CharField(max_length=15, choices=Status.choices, default=Status.ACTIVE)
    org_slug = models.CharField(max_length=150, blank=True, null=True)
    tenant = models.ForeignKey("client.Tenant", on_delete=models.CASCADE, related_name="users", blank=True, null=True)
    image = models.ImageField(upload_to="users/", null=True, blank=True)
    password = models.CharField(max_length=128, blank=True, null=True)
    is_blocked = models.BooleanField(default=False)
    blocked_at = models.DateTimeField(blank=True, null=True)
    password_changed = models.BooleanField(default=False)
    password_expiry = models.DateTimeField(blank=True, null=True)
    login_enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
```

| Field | Type | Description |
|-------|------|-------------|
| `uid` | UUIDField | Unique identifier |
| `username` | CharField | Unique username |
| `middle_name` | CharField | Optional middle name |
| `role` | ForeignKey | Reference to UserRole |
| `phone_number` | PhoneNumberField | E.164 formatted phone number |
| `gender` | CharField | Gender choice (MALE, FEMALE, OTHER) |
| `status` | CharField | Account status (ACTIVE, INACTIVE, SUSPENDED) |
| `org_slug` | CharField | Organization slug for multi-tenancy |
| `tenant` | ForeignKey | Reference to Tenant |
| `image` | ImageField | Profile picture upload |
| `password` | CharField | Hashed password |
| `is_blocked` | BooleanField | Whether account is blocked |
| `blocked_at` | DateTimeField | When account was blocked |
| `password_changed` | BooleanField | Whether password has been changed |
| `password_expiry` | DateTimeField | When password expires |
| `login_enabled` | BooleanField | Whether login is enabled |
| `created_at` | DateTimeField | Creation timestamp |
| `updated_at` | DateTimeField | Last update timestamp |

#### User Model Methods

**`generate_temporary_password()`**
- Generates a 12-character temporary password using UUID
- Returns: Random 12-character string

**`is_password_expired()`**
- Checks if the user's password has expired
- Returns: Boolean

**`save()`**
- Overrides default save to:
  - Generate temporary password if none provided
  - Send login credentials email via SendGrid
  - Set password expiry to 7 days from creation

---

## Authentication System

### Authenticator Class

The `Authenticator` class in [`apps/users/auth.py`](apps/users/auth.py:26) handles all authentication operations.

#### Token Generation Methods

**`generate_access_token(user)`** (line 28)
- Generates a JWT access token with 15-minute expiry
- Payload includes: `jti`, `user_id`, `user_uid`, `full_name`, `type`, `iat`, `exp`

**`generate_refresh_token(user)`** (line 45)
- Generates a JWT refresh token with 12-hour expiry
- Stores token in database with 7-day expiry
- Returns: JWT token string

**`generate_reset_token(user)`** (line 66)
- Generates a password reset token with 10-minute expiry
- Caches token in Redis with key pattern `reset_token:{phone_number}`
- Returns: JWT token string

#### OTP (One-Time Password) Methods

**`generate_otp()`** (line 86)
- Generates a random 6-digit OTP
- Returns: Integer between 100000-999999

**`send_otp(email=None, phone=None, full_name=None)`** (line 90)
- Generates and sends OTP to email or phone
- Email OTP: 10-minute expiry
- Phone OTP: 5-minute expiry
- Uses NotificationService to send via SendGrid/SMS

**`verify_otp(user_entered_otp, email=None, phone=None)`** (line 129)
- Verifies OTP from cache
- Deletes OTP from cache after successful verification
- Returns: Boolean

**`forget_verify_otp(user_entered_otp, email=None, phone=None)`** (line 152)
- Verifies OTP with retry tracking
- Returns: Response object with status

#### Password Reset Methods

**`send_reset_password(field, password=None, full_name=None)`** (line 216)
- Sends temporary password via email or SMS
- Validates email/phone format
- Uses NotificationService

---

### JWT Authentication Class

**`JWTAuthentication`** (line 255)
- Custom DRF authentication class
- Validates Bearer token from Authorization header
- Checks token blacklist in Redis
- Validates token type is "access"
- Returns: `(user, payload)` tuple or `None`

```python
class JWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        # Extracts Bearer token from Authorization header
        # Decodes JWT and validates
        # Checks blacklist for revoked tokens
        # Returns (user, payload) or None
```

**`JWTAuthenticationScheme`** (line 305)
- OpenAPI documentation extension for JWT authentication

---

## Permissions System

### CustomPermission Class

The `CustomPermission` class in [`apps/users/perms.py`](apps/users/perms.py:19) provides comprehensive permission checking.

```python
class CustomPermission(BasePermission):
    """
    Handles:
    - Token Validation
    - Role-based access
    - Group & model permissions
    - Organization context
    - License validation
    """
```

#### Permission Check Flow

1. **Authentication Check**: User must be authenticated
2. **Blocked Account Check**: Blocked users are denied access
3. **Super Admin Bypass**: SUPER_ADMIN role bypasses all permission checks
4. **Model Permission Mapping**:
   - `create` → `add_{model_name}`
   - `update` → `change_{model_name}`
   - `partial_update` → `change_{model_name}`
   - `destroy` → `delete_{model_name}`
   - `retrieve` → `view_{model_name}`
   - `list` → `view_{model_name}`
5. **Group Permission Check**: Checks UserGroup permissions
6. **Direct Permission Check**: Fallback to user's direct permissions
7. **Organization Context Check**: If enabled, verifies tenant access
8. **License Validation**: Checks for valid, active license

#### Organization Context Helper

**`_check_organization_context(request, view)`** (line 99)
- Verifies user belongs to an organization
- Filters querysets by organization if applicable

---

## Serializers

### UserRoleSerializer

**Location:** [`apps/users/serializers.py:5`](apps/users/serializers.py:5)

```python
class UserRoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserRole
        fields = "__all__"
```

---

### UserGroupSerializers

**Location:** [`apps/users/serializers.py:11`](apps/users/serializers.py:11)

**UserGroupCreateUpdateSerializer** - For creating/updating groups

**UserGroupListSerializer** - For listing groups with expanded relations

```python
class UserGroupListSerializer(serializers.ModelSerializer):
    permissions = serializers.SerializerMethodField()
    users = serializers.SerializerMethodField()
    tenants = serializers.SerializerMethodField()
```

- `get_permissions()`: Returns permission codenames, filters client permissions for non-super-admin
- `get_users()`: Returns user list with id, uid, full_name
- `get_tenants()`: Returns tenant info if available

---

### UserSerializers

**Location:** [`apps/users/serializers.py:77`](apps/users/serializers.py:77)

**UserCreateSerializer** - Fields for user creation
```python
fields = [
    "username", "first_name", "middle_name", "last_name", "email",
    "phone_number", "gender", "image", "role", "status", "is_blocked",
    "login_enabled", "org_slug", "tenant", "password", "password_changed",
    "password_expiry"
]
```

**UserSelfUpdateSerializer** - Fields users can update about themselves
```python
fields = ["first_name", "last_name", "middle_name", "phone_number", "gender", "image"]
```

**UserAdminUpdateSerializer** - Fields admins can update
```python
fields = ["role", "status", "login_enabled", "is_blocked"]
```

**UserListSerializer** - Comprehensive user listing
```python
class UserListSerializer(serializers.ModelSerializer):
    tenant = serializers.SerializerMethodField()
    role = serializers.SerializerMethodField()
    groups = serializers.SerializerMethodField()
```

---

## Views and API Endpoints

### ViewSets Overview

All viewsets are located in [`apps/users/views.py`](apps/users/views.py).

---

### UserRoleViewset

**Base URL:** `/api/users/user-role/`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `list` | `/` | List all user roles |
| `create` | `/` | Create a new user role |
| `retrieve` | `/{uid}/` | Get specific role details |
| `update` | `/{uid}/` | Update a role |
| `partial_update` | `/{uid}/` | Partial update a role |
| `destroy` | `/{uid}/` | Delete a role |

---

### PermissionViewset

**Base URL:** `/api/users/permissions/`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `list` | `/` | List all available permissions grouped by model |

Excluded apps from listing:
- `admin`, `auth`, `contenttypes`, `sessions`, `staticfiles`
- `rest_framework`, `drf_spectacular`, `post_office`
- `django_celery_results`, `django_celery_beat`, `client`

---

### UserGroupViewset

**Base URL:** `/api/users/user-group/`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `list` | `/` | List user groups (filtered by tenant) |
| `create` | `/` | Create a new user group |
| `retrieve` | `/{uid}/` | Get specific group details |
| `update` | `/{uid}/` | Update a group |
| `partial_update` | `/{uid}/` | Partial update a group |
| `destroy` | `/{uid}/` | Delete a group |
| `assign_user_group` | `/assign-user-group/` | Assign users to a group |
| `remove_user_group` | `/remove-user-group/` | Remove users from a group |

#### Custom Actions

**`assign_user_group`** (POST)
```python
{
    "group_id": int,
    "users": [user_id1, user_id2, ...]
}
```

**`remove_user_group`** (POST)
```python
{
    "group_id": int,
    "users": [user_id1, user_id2, ...]
}
```

---

### UserViewset

**Base URL:** `/api/users/users/`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `list` | `/` | List users (SUPER_ADMIN only) |
| `create` | `/` | Create a new user |
| `retrieve` | `/{uid}/` | Get user details |
| `update` | `/{uid}/` | Update a user |
| `partial_update` | `/{uid}/` | Partial update a user |
| `destroy` | `/{uid}/` | Delete a user |

#### Custom Actions

| Method | Endpoint | Description |
|--------|----------|-------------|
| `update_password` | `/update-password/` | Update current user's password |
| `reset_password` | `/reset-password/` | Reset password with token (public) |
| `forgot_password` | `/forgot-password/` | Initiate password reset flow (public) |
| `verify_otp` | `/verify-otp/` | Verify OTP for password reset (public) |
| `login` | `/login/` | User login with credentials (public) |
| `passwordless_login` | `/passwordless-login/` | Initiate passwordless login (public) |
| `verify_passwordless_otp` | `/passwordless-login-verify-otp/` | Complete passwordless login (public) |
| `users_by_organization` | `/users-by-organization/{uid}/` | Get users by org slug |
| `license_by_organization` | `/license-by-organization/{uid}/` | Get license by org slug |
| `send_reset_password` | `/send-reset-password/` | Send reset password email |
| `refresh_token` | `/refresh-token/` | Refresh access token (public) |
| `logout` | `/logout/` | Logout and revoke tokens |

##### Login Endpoint

**POST** `/api/users/users/login/`

```python
{
    "field": "email@example.com",  # or phone number
    "password": "userpassword"
}
```

**Response:**
```python
{
    "success": True,
    "info": "User logged in successfully",
    "password_changed": True,  # or False
    "access_token": "jwt_access_token",
    "refresh_token": "jwt_refresh_token",
    "role": "STAFF"
}
```

##### Passwordless Login Flow

1. **Initiate**: POST `/passwordless-login/` with `field`
   - OTP sent to email/phone
2. **Verify**: POST `/passwordless-login-verify-otp/` with `field` and `otp`
   - Returns access and refresh tokens

##### Password Reset Flow

1. **Request Reset**: POST `/forgot-password/` with `field`
   - OTP sent to email/phone
2. **Verify OTP**: POST `/verify-otp/` with `field` and `otp`
   - Returns temporary reset token
3. **Reset Password**: POST `/reset-password/` with `field`, `reset_token`, `password`, `confirm_password`

##### Update Password (Authenticated)

**POST** `/api/users/users/update-password/`

```python
{
    "field": "email@example.com",  # Must match logged-in user's email/phone
    "password": "newpassword",
    "confirm_password": "newpassword"
}
```

---

### FetchOrgUsers

**Base URL:** `/api/users/fetch-org-users/`

- **GET** `/` - List all users in the requesting user's organization

---

### FetchOrgUserGroups

**Base URL:** `/api/users/fetch-org-user-groups/`

- **GET** `/` - List all user groups in the requesting user's organization

---

### SystemLogsViewset

**Base URL:** `/api/users/system-logs/`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `download_debug_log` | `/download-debug-log/` | Download debug.log file (SUPER_ADMIN only) |

---

## URL Configuration

**Location:** [`apps/users/urls.py`](apps/users/urls.py)

```python
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from apps.users.views import (
    UserRoleViewset,
    UserGroupViewset,
    UserViewset,
    PermissionViewset,
    FetchOrgUserGroups,
    FetchOrgUsers,
    SystemLogsViewset,
)

router = DefaultRouter()

router.register(r"user-role", UserRoleViewset, basename="user-roles")
router.register(r"user-group", UserGroupViewset, basename="user-groups")
router.register(r"users", UserViewset, basename="users")
router.register(r"permissions", PermissionViewset, basename="permissions")
router.register(r"system-logs", SystemLogsViewset, basename="system-logs")
router.register(r"fetch-org-users", FetchOrgUsers, basename="fetch-org-users")
router.register(r"fetch-org-user-groups", FetchOrgUserGroups, basename="fetch-org-user-groups")

urlpatterns = [
    path("", include(router.urls)),
]
```

### Complete URL List

| Route | ViewSet/View |
|-------|--------------|
| `/api/users/user-role/` | UserRoleViewset |
| `/api/users/user-group/` | UserGroupViewset |
| `/api/users/users/` | UserViewset |
| `/api/users/permissions/` | PermissionViewset |
| `/api/users/system-logs/` | SystemLogsViewset |
| `/api/users/fetch-org-users/` | FetchOrgUsers |
| `/api/users/fetch-org-user-groups/` | FetchOrgUserGroups |

---

## Services

### SendGrid Email Service

**Location:** [`apps/users/services.py`](apps/users/services.py)

#### `send_sendgrid_email()`

```python
def send_sendgrid_email(
    recipient: str, subject: str, html_content: str, text_content: str | None = None
):
```

- Sends email via SendGrid Web API
- Requires `SENDGRID_API_KEY` and `DEFAULT_FROM_EMAIL` in environment
- Returns: Status code from SendGrid API

#### `render_email()`

```python
def render_email(template: str, context: dict) -> tuple[str, str]:
```

- Renders HTML and text email templates
- Templates stored in `templates/emails/{template}.html` and `.txt`
- Returns: Tuple of (html_content, text_content)

---

## Utilities and Tasks

### Celery Tasks

**Location:** [`apps/users/utils.py`](apps/users/utils.py)

#### `send_notification()`

```python
@shared_task(
    bind=True,
    autoretry_for=(Exception,),
    retry_kwargs={"max_retries": 3, "countdown": 60},
)
def send_notification(self, recipient: str, context: dict):
```

- Async task for sending email notifications
- Context format:
  ```python
  {
      "template": "otp",
      "subject": "Your OTP Code",
      "context": {...}
  }
  ```
- Retries up to 3 times with 60-second countdown

#### `send_login_credentials()`

```python
@shared_task
def send_login_credentials(email, password):
```

- Async task for sending login credentials
- Uses `login-credentials` email template

---

## Validators

### AlphaNumericSymbolValidator

**Location:** [`apps/users/validators.py`](apps/users/validators.py:6)

Ensures passwords contain:
- At least one letter
- At least one number
- At least one symbol

```python
class AlphaNumericSymbolValidator:
    def validate(self, password, user=None):
        # Raises ValidationError if requirements not met
    
    def get_help_text(self):
        return "Your password must contain at least one letter, one number, and one symbol."
```

---

## Exception Handling

### Custom Exception Handler

**Location:** [`apps/users/exceptions.py`](apps/users/exceptions.py:10)

```python
def custom_exception_handler(exc, context):
```

- Handles throttling exceptions
- Formats all DRF exceptions with consistent response structure:
  ```python
  {
      "success": False,
      "info": "Error message",
  }
  ```

### Rate Limit Flag Handling

**`handle_rate_limit_flag(user)`** (line 32)

- Creates/updates `UserRateLimitFlag` on rate limit exceeded
- Blocks user after 3 failed attempts:
  ```python
  if flag.count >= 3 and not flag.is_blocked:
      user.is_blocked = True
      user.blocked_at = timezone.now()
      user.save()
  ```

---

## Pagination

**Location:** [`apps/users/pagination.py`](apps/users/pagination.py:4)

```python
class FetchDataPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = "page_size"
```

---

## Django Admin Configuration

**Location:** [`apps/users/admin.py`](apps/users/admin.py)

```python
class BaseAdmin(admin.ModelAdmin):
    def get_list_display(self, request):
        return tuple(field.name for field in self.model._meta.fields)

@admin.register(User)
@admin.register(UserGroup)
@admin.register(UserRole)
class UserAdmin(BaseAdmin):
    pass
```

All models (User, UserGroup, UserRole) are registered with dynamic list display showing all model fields.

---

## App Configuration

**Location:** [`apps/users/apps.py`](apps/users/apps.py)

```python
class UsersConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.users"
```

---

## Rate Limiting

The system implements rate limiting using DRF's throttling classes:

| Throttle Scope | Description | Applied To |
|----------------|-------------|------------|
| `login` | Login attempts | Login endpoint |
| `reset_password` | Password reset requests | Reset password endpoint |
| `forgot_password` | Forgot password requests | Forgot password endpoint |
| `refresh_token` | Token refresh requests | Refresh token endpoint |
| `login_without_password` | Passwordless login attempts | Passwordless login endpoint |

Throttling is implemented via `ScopedRateThrottle` and `UserRateThrottle` classes.

---

## Security Features

1. **Token Blacklisting**: Revoked tokens are stored in Redis cache
2. **Password Hashing**: Uses Django's password hashers
3. **OTP Expiry**: OTPs expire after 5-10 minutes
4. **Password Expiry**: Passwords expire after configurable period (default 7 days)
5. **Account Lockout**: Accounts blocked after 3 rate limit violations
6. **License Validation**: Access requires valid active license

---

## Dependencies

Key dependencies used by the users app:

- **Django REST Framework**: API framework
- **drf-spectacular**: OpenAPI documentation
- **PyJWT**: JWT token handling
- **arrow**: Date/time handling
- **SendGrid**: Email delivery
- **Celery**: Async task processing
- **django-phonenumber-field**: Phone number handling

---

## Environment Variables Required

| Variable | Description |
|----------|-------------|
| `SECRET_KEY` | Django secret key for JWT signing |
| `DEFAULT_FROM_EMAIL` | Default sender email for notifications |
| `SENDGRID_API_KEY` | SendGrid API key for email delivery |
| `REDIS_URL` | Redis connection URL for caching |
