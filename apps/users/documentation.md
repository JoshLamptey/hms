# Users App Documentation

This document provides comprehensive documentation for the `apps/users` Django app, which handles user authentication, authorization, and user management in a multi-tenant architecture.

## Overview

The Users app provides authentication and authorization functionality for the multi-tenant HMS (Hotel Management System) application. It includes JWT-based authentication, role-based access control, user groups, and comprehensive user management features.

Key features:

- JWT-based authentication with access and refresh tokens
- OTP (One-Time Password) verification
- Role-based access control (RBAC) with custom permissions
- User groups with assigned permissions
- Password management (reset, change, expiry)
- Rate limiting and throttling
- Multi-tenant user isolation

## File Structure

```txt
apps/users/
├── __init__.py          # Package initialization
├── admin.py             # Django admin configuration
├── apps.py              # App configuration
├── auth.py              # Authentication classes and JWT handling
├── exceptions.py        # Custom exception handlers
├── models.py            # Database models
├── pagination.py        # Pagination classes
├── perms.py             # Permission classes
├── serializers.py       # DRF serializers
├── services.py          # Email sending services
├── tests.py             # Unit tests (placeholder)
├── urls.py              # URL routing
├── utils.py             # Utility functions and Celery tasks
├── validators.py        # Custom validators
└── views.py             # API views and viewsets
```

---

## Models

### UserGroup Model

Represents a group of users with assigned permissions, enabling role-based access control at the group level.

**Location:** [`apps/users/models.py`](apps/users/models.py:14)

**Fields:**

| Field | Type | Description |
| :------- | :------ | :------------- |
| `uid` | UUIDField | Unique identifier, auto-generated |
| `users` | ManyToManyField | Related users |
| `permissions` | ManyToManyField | Django permissions |
| `tenant` | ForeignKey | Associated tenant (optional) |
| `is_global` | BooleanField | If True, visible to all tenants |
| `name` | CharField | Group name |
| `description` | TextField | Group description |
| `created_at` | DateTimeField | Creation timestamp |
| `updated_at` | DateTimeField | Last update timestamp |

**Meta:**

- Verbose name: "User Group"
- Ordering: by -created_at

### UserRole Model

Defines user roles in the system with predefined role types.

**Location:** [`apps/users/models.py`](apps/users/models.py:43)

**Role Choices:**

| Value | Display Name | Description |
| :------- | -------------- | :------------- |
| `SUPER_ADMIN` | Super Admin | Full system access |
| `STAFF` | Staff | Staff-level access |
| `CUSTOMER` | Customer | Customer-level access |

**Fields:**

| Field | Type | Description |
| :------- | ------|-------------|
| `uid` | UUIDField | Unique identifier |
| `name` | CharField | Role name from choices |
| `created_at` | DateTimeField | Creation timestamp |
| `updated_at` | DateTimeField | Last update timestamp |

**Meta:**

- Verbose name: "User Role"
- Ordering: by -created_at

### User Model (Custom User)

Extends Django's AbstractUser with additional fields for multi-tenancy and extended user management.

**Location:** [`apps/users/models.py`](apps/users/models.py:63)

**Gender Choices:**

| Value | Display Name |
|-------|--------------|
| `MALE` | Male |
| `FEMALE` | Female |
| `OTHER` | Other |

**Status Choices:**

| Value | Display Name |
|-------|--------------|
| `ACTIVE` | Active |
| `INACTIVE` | Inactive |
| `SUSPENDED` | Suspended |

**Fields:**

| Field | Type | Description | Optional |
|-------|------|-------------|----------|
| `uid` | UUIDField | Unique identifier | No |
| `username` | CharField | Unique username | No |
| `middle_name` | CharField | User's middle name | Yes |
| `role` | ForeignKey | UserRole reference | Yes |
| `phone_number` | PhoneNumberField | Phone with country code | No |
| `gender` | CharField | Gender selection | No (default: OTHER) |
| `status` | CharField | Account status | No (default: ACTIVE) |
| `org_slug` | CharField | Organization identifier | Yes |
| `tenant` | ForeignKey | Tenant reference | Yes |
| `image` | ImageField | Profile picture | Yes |
| `password` | CharField | Hashed password | Yes |
| `is_blocked` | BooleanField | Account blocked status | No (default: False) |
| `blocked_at` | DateTimeField | Block timestamp | Yes |
| `password_changed` | BooleanField | Password changed flag | No (default: False) |
| `password_expiry` | DateTimeField | Password expiration | Yes |
| `login_enabled` | BooleanField | Login allowed | No (default: True) |
| `created_at` | DateTimeField | Creation timestamp | Auto |
| `updated_at` | DateTimeField | Last update timestamp | Auto |

**Methods:**

```python
def generate_temporary_password(self):
    """Generates an 8-character temporary password, hashes it, and sends credentials via email.
    Sets password_changed to False and password_expiry to 7 days from now.
    Returns: str - The temporary password (plain text)"""

def save(self, *args, **kwargs):
    """Override save to auto-generate temporary password if not set."""

def is_password_expired(self):
    """Checks if password_expiry is set and current time exceeds it.
    Returns: bool - True if expired, False otherwise"""
```

**Meta:**

- Verbose name: "User"
- Ordering: by -created_at

---

## Authentication (auth.py)

### Authenticator Class

Provides methods for generating JWT tokens and handling OTP verification.

**Location:** [`apps/users/auth.py`](apps/users/auth.py:24)

#### Methods

##### generate_access_token(user)

Creates a JWT access token with 15-minute expiry.

```python
def generate_access_token(self, user):
    """Generate JWT access token for user.
    
    Args:
        user: User instance
        
    Returns:
        str: JWT token string
        
    Token Payload:
        - jti: Unique token identifier (UUID)
        - user_id: User's database ID
        - user_uid: User's unique UUID
        - full_name: User's full name
        - type: "access"
        - iat: Issued at time
        - exp: Expiration time (15 minutes from now)
    """
```

##### generate_refresh_token(user)

Creates a JWT refresh token with 7-day expiry and stores it in the database.

```python
def generate_refresh_token(self, user):
    """Generate JWT refresh token for user.
    
    Args:
        user: User instance
        
    Returns:
        str: JWT token string
        
    Side Effects:
        - Creates RefreshToken record in database
        - Token stored with expires_at timestamp
    """
```

##### generate_otp()

Generates a 6-digit random OTP.

```python
def generate_otp(self):
    """Generate 6-digit OTP.
    
    Returns:
        int: Random number between 100000 and 999999
    """
```

##### send_otp(email=None, phone=None)

Sends OTP via email or phone (cached for 5 minutes).

```python
def send_otp(self, email=None, phone=None):
    """Send OTP to email or phone.
    
    Args:
        email: Email address (optional)
        phone: Phone number (optional)
        
    Returns:
        int: The generated OTP
        
    Raises:
        ValueError: If neither email nor phone provided
        
    Behavior:
        - OTP cached in Redis for 300 seconds (5 minutes)
        - Email sent via Celery task
        - SMS functionality commented out
    """
```

##### verify_otp(user_entered_otp, email=None, phone=None)

Verifies OTP from cache.

```python
def verify_otp(self, user_entered_otp, email=None, phone=None):
    """Verify user-entered OTP against cached value.
    
    Args:
        user_entered_otp: OTP entered by user
        email: Email used to send OTP (optional)
        phone: Phone used to send OTP (optional)
        
    Returns:
        bool: True if valid, False otherwise
        
    Behavior:
        - Retrieves OTP from cache
        - Deletes OTP from cache after successful verification
        - Returns False if OTP expired or invalid
    """
```

##### forget_verify_otp(user_entered_otp, email=None, phone=None)

OTP verification with retry limit (3 attempts).

```python
def forget_verify_otp(self, user_entered_otp, email=None, phone=None):
    """Verify OTP with retry limiting for password reset.
    
    Args:
        user_entered_otp: OTP entered by user
        email: Email used to send OTP
        phone: Phone used to send OTP
        
    Returns:
        Response: Success or failure response
        
    Behavior:
        - Maximum 3 retry attempts
        - Clears cache after 4 failed attempts
    """
```

##### send_reset_password(field, password)

Sends password reset via email or SMS.

```python
def send_reset_password(self, field, password):
    """Send password reset credentials.
    
    Args:
        field: Email or phone number
        password: New password to send
        
    Behavior:
        - Validates email format (regex)
        - Validates phone format (7-15 digits)
        - Sends via email or SMS (commented)
    """
```

### JWTAuthentication Class

Custom JWT authentication class for Django REST Framework.

**Location:** [`apps/users/auth.py`](apps/users/auth.py:242)

```python
class JWTAuthentication(BaseAuthentication):
    """JWT Bearer token authentication."""
    
    def authenticate(self, request):
        """Authenticate request using JWT token.
        
        Process:
            1. Extract Authorization header
            2. Validate Bearer prefix
            3. Decode JWT with SECRET_KEY
            4. Check token blacklist
            5. Validate token type (must be "access")
            6. Fetch user from database
            7. Check if user is blocked
            8. Cache org_slug for tenant context
            9. Return (user, payload) tuple
            
        Returns:
            tuple: (User, payload) or None
            
        Raises:
            AuthenticationFailed: For various auth errors
            PermissionDenied: If token blacklisted
        """
```

**Error Handling:**

| Error | Cause |
|-------|-------|
| `AuthenticationFailed("invalid token prefix")` | Missing "Bearer" prefix |
| `AuthenticationFailed("Invalid authorization header")` | Malformed header |
| `PermissionDenied("Access token has been revoked")` | Token blacklisted |
| `AuthenticationFailed("Invalid token type")` | Not an access token |
| `AuthenticationFailed("User not found")` | User deleted |
| `AuthenticationFailed("Sorry, Your account has been blocked...")` | User is blocked |
| `AuthenticationFailed("Access token expired")` | Token expired |
| `AuthenticationFailed("Invalid token")` | Malformed token |

### JWTAuthenticationScheme

OpenAPI/Swagger schema extension for JWT authentication.

**Location:** [`apps/users/auth.py`](apps/users/auth.py:292)

```python
class JWTAuthenticationScheme(OpenApiAuthenticationExtension):
    """OpenAPI authentication scheme for JWT."""
    
    target_class = "apps.users.auth.JWTAuthentication"
    name = "JWTAuth"
    
    def get_security_definition(self, auto_schema):
        return {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
        }
```

---

## Permissions (perms.py)

### CustomPermission Class

Comprehensive permission handler for the application that validates authentication, roles, groups, organization context, and licenses.

**Location:** [`apps/users/perms.py`](apps/users/perms.py:19)

```python
class CustomPermission(BasePermission):
    """Custom permission class handling multiple permission checks."""
    
    def has_permission(self, request, view):
        """Main permission check method.
        
        Checks:
            1. User is authenticated
            2. User account is not blocked
            3. Super admins have full access
            4. User has required model permissions
            5. Organization context is valid (if required)
            6. Organization has valid license
            
        Returns:
            bool: True if permitted, False otherwise
            
        Raises:
            PermissionDenied: For blocked users or invalid licenses
        """
```

**Permission Mapping:**

| View Action | Permission Codename |
|-------------|---------------------|
| `create` | `add_{model_name}` |
| `update` | `change_{model_name}` |
| `partial_update` | `change_{model_name}` |
| `destroy` | `delete_{model_name}` |
| `retrieve` | `view_{model_name}` |
| `list` | `view_{model_name}` |

**Key Features:**

1. **Token Validation**: Ensures valid JWT token
2. **Role-Based Access**: Super admins bypass most checks
3. **Group Permissions**: Checks UserGroup permissions first
4. **Direct Permissions**: Falls back to user permissions
5. **Organization Context**: Validates tenant association
6. **License Validation**: Ensures active license exists

### _check_organization_context()

Helper method to verify organization context.

```python
def _check_organization_context(self, request, view):
    """Verify organization context for the request.
    
    Returns:
        bool: True if org context is valid
    """
```

---

## Serializers

### UserRoleSerializer

**Location:** [`apps/users/serializers.py`](apps/users/serializers.py:5)

Standard ModelSerializer for UserRole.

**Fields:** All fields (`__all__`)

### UserGroupCreateUpdateSerializer

**Location:** [`apps/users/serializers.py`](apps/users/serializers.py:11)

For creating/updating user groups.

**Fields:** All fields (`__all__`)

### UserGroupListSerializer

**Location:** [`apps/users/serializers.py`](apps/users/serializers.py:17)

For listing user groups with nested data.

**Fields:**

- id, uid, name, description
- permissions (SerializerMethodField)
- users (SerializerMethodField)
- tenants (SerializerMethodField)
- created_at, updated_at

**Methods:**

```python
def get_permissions(self, obj):
    """Get filtered permissions based on user role.
    
    Behavior:
        - Super admins see all permissions
        - Non-super-admins: hide client app permissions
    """

def get_users(self, obj):
    """Get users in this group.
    
    Returns:
        list: [{id, uid, full_name}, ...]
    """

def get_tenants(self, obj):
    """Get associated tenant.
    
    Returns:
        list or None: Tenant details or None
    """
```

### UserCreateSerializer

**Location:** [`apps/users/serializers.py`](apps/users/serializers.py:77)

For creating users.

**Fields:**

- username, first_name, middle_name, last_name
- phone_number, gender, image
- role, status, is_blocked, login_enabled
- org_slug, tenant, password, password_changed, password_expiry

### UserSelfUpdateSerializer

**Location:** [`apps/users/serializers.py`](apps/users/serializers.py:100)

For users to update their own profile (non-admin fields).

**Fields:**

- first_name, last_name, middle_name
- phone_number, gender, image

### UserAdminUpdateSerializer

**Location:** [`apps/users/serializers.py`](apps/users/serializers.py:113)

For admin updates to user status and permissions.

**Fields:**
- role, status, login_enabled, is_blocked

### UserListSerializer

**Location:** [`apps/users/serializers.py`](apps/users/serializers.py:124)

For listing users with nested data.

**Fields:**
- id, uid, first_name, last_name, middle_name
- email, image, phone_number
- role (SerializerMethodField)
- tenant (SerializerMethodField)
- groups (SerializerMethodField)
- status, gender, last_login, is_blocked, created_at

**Methods:**

```python
def get_tenant(self, obj):
    """Returns tenant details as list."""

def get_role(self, obj):
    """Returns role details as list."""

def get_groups(self, obj):
    """Returns user groups with permissions."""
```

---

## Views

### UserRoleViewset (ModelViewSet)

CRUD operations for user roles.

**Location:** [`apps/users/views.py`](apps/users/views.py:48)

**Base Configuration:**

- `content_model`: UserRole
- `queryset`: UserRole.objects.all()
- `serializer_class`: UserRoleSerializer
- `permission_classes`: [CustomPermission]
- `lookup_field`: uid

**Endpoints:**

| Method | URL | Description |
|--------|-----|-------------|
| GET | `/user-role/` | List all roles |
| POST | `/user-role/` | Create new role |
| GET | `/user-role/{uid}/` | Retrieve role |
| PUT/PATCH | `/user-role/{uid}/` | Update role |
| DELETE | `/user-role/{uid}/` | Delete role |

### PermissionViewset (ViewSet)

Lists all available system permissions grouped by model.

**Location:** [`apps/users/views.py`](apps/users/views.py:144)

**Excluded Apps:**

```python
EXCLUDED_APPS = [
    "admin", "auth", "contenttypes", "sessions", "staticfiles",
    "rest_framework", "drf_spectacular", "post_office",
    "django_celery_results", "django_celery_beat"
]

CLIENT_EXCLUDED_APPS = ["client"]
```

**Endpoints:**

| Method | URL | Description |
|--------|-----|-------------|
| GET | `/permissions/` | List permissions grouped by model |

### UserGroupViewset (ModelViewSet)

CRUD operations for user groups with user assignment.

**Location:** [`apps/users/views.py`](apps/users/views.py:262)

**Base Configuration:**

- `content_model`: UserGroup
- `queryset`: UserGroup.objects.prefetch_related("permissions").all()
- `permission_classes`: [CustomPermission]
- `lookup_field`: uid

**Standard Endpoints:**

| Method | URL | Description |
|--------|-----|-------------|
| GET | `/user-group/` | List groups (filtered by tenant) |
| POST | `/user-group/` | Create new group |
| GET | `/user-group/{uid}/` | Retrieve group |
| PUT/PATCH | `/user-group/{uid}/` | Update group |
| DELETE | `/user-group/{uid}/` | Delete group |

**Custom Actions:**

| Method | URL | Description |
|--------|-----|-------------|
| POST | `/user-group/assign-user-group/` | Assign users to group |
| POST | `/user-group/remove-user-group/` | Remove users from group |

**Queryset Filtering:**

```python
def get_queryset(self):
    user = self.request.user
    if user.role == UserRole.Role.SUPER_ADMIN:
        return qs.filter(is_global=True)
    return qs.filter(is_global=False, tenant__org_slug=user.org_slug)
```

### UserViewset (ModelViewSet)

Comprehensive user management with authentication.

**Location:** [`apps/users/views.py`](apps/users/views.py:496)

**Base Configuration:**

- `content_model`: User
- `queryset`: User.objects.select_related("role").all()
- `permission_classes`: [CustomPermission]
- `lookup_field`: uid
- `throttle_classes`: [ScopedRateThrottle, UserRateThrottle]

**Throttle Scopes:**

- `login`: Rate limiting for login attempts
- `forgot_password`: Rate limiting for password reset
- `refresh_token`: Rate limiting for token refresh

**Serializer Selection:**

```python
def get_serializer_class(self):
    if self.action == "create":
        return UserCreateSerializer
    if self.action in ["update", "partial_update"]:
        obj = self.get_object()
        if obj.id == self.request.user.id:
            return UserSelfUpdateSerializer
        return UserAdminUpdateSerializer
    return UserListSerializer
```

**Standard Endpoints:**

| Method | URL | Description |
|--------|-----|-------------|
| GET | `/users/` | List users (super_admin only) |
| POST | `/users/` | Create new user |
| GET | `/users/{uid}/` | Retrieve user |
| PUT/PATCH | `/users/{uid}/` | Update user |
| DELETE | `/users/{uid}/` | Delete user |

**Custom Actions:**

| Method | URL | Description |
|--------|-----|-------------|
| POST | `/users/update-password/` | Update own password |
| POST | `/users/forgot-password/` | Request password reset OTP |
| POST | `/users/verify-otp/` | Verify OTP |
| POST | `/users/login/` | User login with credentials |
| POST | `/users/passwordless-login/` | Request OTP for login |
| POST | `/users/passwordless-login-verify-otp/` | Verify OTP and login |
| POST | `/users/refresh-token/` | Refresh access token |
| POST | `/users/logout/` | Revoke tokens |
| GET | `/users/license-by-organization/{uid}/` | Get org license |
| POST | `/users/send-reset-password/` | Send reset password |
| GET | `/users/users-by-organization/{uid}/` | Get users by org |

**Helper Methods:**

```python
def check_user_license_status(self, org_slug: str, email: str, phone: str = None) -> bool:
    """Check if user exists in valid active license for organization.
    
    Args:
        org_slug: Organization slug
        email: User's email
        phone: User's phone number
        
    Returns:
        bool: True if user has valid license
    """
```

### FetchOrgUsers (ModelViewSet)

Fetches users for the authenticated user's organization.

**Location:** [`apps/users/views.py`](apps/users/views.py:1664)

**Base Configuration:**

- `content_model`: User
- `permission_classes`: [CustomPermission]
- `serializer_class`: UserListSerializer

**Endpoints:**

| Method | URL | Description |
|--------|-----|-------------|
| GET | `/fetch-org-users/` | List org users |

### FetchOrgUserGroups (ReadOnlyModelViewSet)

Fetches user groups for the authenticated user's organization.

**Location:** [`apps/users/views.py`](apps/users/views.py:1700)

**Base Configuration:**

- `content_model`: UserGroup
- `permission_classes`: [CustomPermission]
- `serializer_class`: UserGroupListSerializer

**Endpoints:**

| Method | URL | Description |
|--------|-----|-------------|
| GET | `/fetch-org-user-groups/` | List org user groups |

### SystemLogsViewset (ViewSet)

System utility endpoints.

**Location:** [`apps/users/views.py`](apps/users/views.py:1738)

**Custom Actions:**

| Method | URL | Description |
|--------|-----|-------------|
| GET | `/system-logs/download-debug-log/` | Download debug.log |

**Access:** Super admin only (both role and is_superuser checked)

---

## URLs

**Location:** [`apps/users/urls.py`](apps/users/urls.py)

Uses Django REST Framework's DefaultRouter.

**Route Registration:**

```python
router.register(r"user-role", UserRoleViewset, basename="user-roles")
router.register(r"user-group", UserGroupViewset, basename="user-groups")
router.register(r"users", UserViewset, basename="users")
router.register(r"permissions", PermissionViewset, basename="permissions")
router.register(r"system-logs", SystemLogsViewset, basename="system-logs")
router.register(r"fetch-org-users", FetchOrgUsers, basename="fetch-org-users")
router.register(r"fetch-org-user-groups", FetchOrgUserGroups, basename="fetch-org-user-groups")
```

**Complete URL Patterns:**

| Endpoint | ViewSet/View | Description |
|----------|--------------|-------------|
| `/api/users/user-role/` | UserRoleViewset | User role management |
| `/api/users/user-group/` | UserGroupViewset | User group management |
| `/api/users/users/` | UserViewset | User management |
| `/api/users/permissions/` | PermissionViewset | System permissions |
| `/api/users/system-logs/` | SystemLogsViewset | System utilities |
| `/api/users/fetch-org-users/` | FetchOrgUsers | Organization users |
| `/api/users/fetch-org-user-groups/` | FetchOrgUserGroups | Organization groups |

---

## Exceptions (exceptions.py)

### custom_exception_handler

Global exception handler for Django REST Framework.

**Location:** [`apps/users/exceptions.py`](apps/users/exceptions.py:10)

```python
def custom_exception_handler(exc, context):
    """Handle exceptions and standardize response format.
    
    Behavior:
        - Wraps all DRF responses in {"success": bool, "info": any}
        - Handles Throttled exceptions specially
        - Calls handle_rate_limit_flag for throttled users
    """
```

### handle_rate_limit_flag

Tracks rate limit violations and blocks users after threshold.

**Location:** [`apps/users/exceptions.py`](apps/users/exceptions.py:32)

```python
def handle_rate_limit_flag(user):
    """Handle rate limit violations.
    
    Logic:
        1. Creates/updates UserRateLimitFlag
        2. After 2 violations: sends warning SMS (commented)
        3. After 3+ violations: blocks user account
    """
```

---

## Services (services.py)

### send_sendgrid_email

Sends email via SendGrid Web API.

**Location:** [`apps/users/services.py`](apps/users/services.py:10)

```python
def send_sendgrid_email(
    recipient: str, 
    subject: str, 
    html_content: str, 
    text_content: str | None = None
):
    """Send email via SendGrid API.
    
    Args:
        recipient: Email address
        subject: Email subject line
        html_content: HTML body content
        text_content: Plain text body (optional)
        
    Raises:
        Exception: On send failure
        
    Uses:
        - DEFAULT_FROM_EMAIL from config
        - SENDGRID_API_KEY from config
    """
```

### render_email

Renders email templates.

**Location:** [`apps/users/services.py`](apps/users/services.py:38)

```python
def render_email(template: str, context: dict) -> tuple[str, str]:
    """Render email templates.
    
    Args:
        template: Template name (without path extension)
        context: Dictionary of template variables
        
    Returns:
        tuple: (html_content, text_content)
        
    Behavior:
        - Looks for templates/emails/{template}.html
        - Looks for templates/emails/{template}.txt (optional)
        - Returns empty string for text if not found
    """
```

---

## Utils (utils.py)

### send_notification (Celery Task)

Async task for sending email notifications.

**Location:** [`apps/users/utils.py`](apps/users/utils.py:8)

```python
@shared_task(
    bind=True,
    autoretry_for=(Exception,),
    retry_kwargs={"max_retries": 3, "countdown": 60},
)
def send_notification(self, recipient: str, context: dict):
    """Send email notification asynchronously.
    
    Args:
        recipient: Email address
        context: Dict with keys:
            - template: Template name
            - subject: Email subject
            - context: Template variables
            
    Behavior:
        - Renders HTML and text from templates
        - Sends via SendGrid
        - Auto-retries on failure (3 attempts, 60s delay)
    """
```

### send_login_credentials (Celery Task)

Sends login credentials to new users.

**Location:** [`apps/users/utils.py`](apps/users/utils.py:44)

```python
@shared_task
def send_login_credentials(email, password):
    """Send login credentials to user.
    
    Args:
        email: Recipient email
        password: Plain text password
        
    Uses Template:
        - login-credentials.html
        
    Calls:
        - send_notification.delay()
    """
```

---

## Validators (validators.py)

### AlphaNumericSymbolValidator

Django password validator ensuring password complexity.

**Location:** [`apps/users/validators.py`](apps/users/validators.py:6)

```python
class AlphaNumericSymbolValidator:
    """Validates password contains letter, number, and symbol."""
    
    def validate(self, password, user=None):
        """Validate password complexity.
        
        Raises ValidationError if:
            - No letters present
            - No numbers present
            - No symbols present
        """
        
    def get_help_text(self):
        """Return help text for password requirements."""
```

**Requirements:**

| Requirement | Regex |
|-------------|-------|
| At least one letter | `[A-Za-z]` |
| At least one number | `\d` |
| At least one symbol | `[^\w\s]` |

---

## Pagination (pagination.py)

### FetchDataPagination

Standard pagination class for list endpoints.

**Location:** [`apps/users/pagination.py`](apps/users/pagination.py:4)

```python
class FetchDataPagination(PageNumberPagination):
    """Standard pagination for list endpoints."""
    
    page_size = 10              # Default items per page
    page_size_query_param = "page_size"  # Allow client override
```

---

## Admin

### BaseAdmin

**Location:** [`apps/users/admin.py`](apps/users/admin.py:11)

Base admin class with dynamic list_display.

```python
class BaseAdmin(admin.ModelAdmin):
    def get_list_display(self, request):
        """Dynamically show all model fields."""
        return tuple(field.name for field in self.model._meta.fields)
```

### UserAdmin

**Location:** [`apps/users/admin.py`](apps/users/admin.py:16)

Registers User, UserGroup, UserRole models.

```python
@admin.register(User)
@admin.register(UserGroup)
@admin.register(UserRole)
class UserAdmin(BaseAdmin):
    pass
```

---

## Apps Configuration

### UsersConfig

**Location:** [`apps/users/apps.py`](apps/users/apps.py:4)

```python
class UsersConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.users"
```

---

## Notes

- Uses JWT tokens with short-lived access tokens (15 minutes) and longer refresh tokens (7 days)
- OTP cached for 5 minutes with 3 retry limit for password reset
- Rate limiting with account blocking after 3 violations
- Password expiry: 7 days for temporary passwords, 3 days for reset passwords
- Super admins bypass license validation
- All endpoints (except login, forgot-password, verify-otp, passwordless-login) require authentication
- Uses SendGrid for transactional emails
- Celery tasks for async email sending
- Multi-tenant isolation via org_slug field on User model
- Refresh tokens are stored in database and can be revoked
- Token blacklist implemented in Redis cache
