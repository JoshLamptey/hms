# Users App Documentation

This document provides comprehensive documentation for the `apps/users` Django app, which handles authentication, authorization, user management, and group-based permissions across the multi-tenant HMS system.

---

## Overview

The Users app is the foundation of the entire platform. Every other app depends on it. It manages platform users (staff of tenant organisations), authentication via custom JWT, group-based permissions, OTP flows, and token lifecycle management.

Key features:

- Custom JWT authentication using PyJWT (NOT simplejwt)
- HttpOnly cookie-based refresh tokens
- Role labels for UI filtering (not access control)
- Group-based permission system scoped per tenant
- OTP for passwordless login and password reset
- Redis-based token blacklisting
- Rate limiting with automatic account blocking
- Temporary password generation on user creation

**Optional attendance integration:** Login flows call `apps.users.integrations.mark_attendance_on_login`. The adapter delegates to `apps.hr.services` only when that optional HR package is installed. HMS currently has no `apps.hr` app, so login succeeds without attendance processing or an `attendance` response field.

---

## Models

### UserRole

Labels for grouping and UI display. NOT used for backend access control.

**Fields:**

- `uid`: UUIDField, unique, editable=False
- `name`: CharField(max_length=20), choices, unique=True
  - `SUPER_ADMIN` — platform owner (developer)
  - `ADMIN` — tenant organisation admin
  - `MANAGER` — can approve leaves, expenses, deals
  - `STAFF` — baseline role
- `created_at`: DateTimeField(auto_now_add=True)
- `updated_at`: DateTimeField(auto_now=True)

**Important:** `unique=True` on name prevents duplicate roles. `CUSTOMER` role from HMS was removed — customers are `ClientDetails` records, not platform users.

---

### UserGroup

Permission groups scoped to a tenant or globally available.

**Fields:**

- `uid`: UUIDField, unique, editable=False
- `name`: CharField(max_length=150, nullable)
- `description`: TextField(nullable)
- `users`: ManyToManyField(User) — members of this group
- `permissions`: ManyToManyField(Permission) — Django model permissions
- `tenant`: ForeignKey(clients.Tenant, SET_NULL, nullable) — owning tenant
- `is_global`: BooleanField(default=False) — visible to all tenants
- `created_at`: DateTimeField(auto_now_add=True)
- `updated_at`: DateTimeField(auto_now=True)

**Logic:** SUPER_ADMIN creates global groups (`is_global=True`). Tenant admins create tenant-scoped groups. On permission checks, the system queries groups where `tenant=request.user.tenant OR is_global=True`.

---

### User

Extends Django's AbstractUser. Represents staff members of tenant organisations.

**Fields:**

- `uid`: UUIDField, unique, editable=False
- `username`: CharField(max_length=150, unique)
- `first_name`, `last_name`: inherited from AbstractUser
- `middle_name`: CharField(max_length=150, nullable)
- `email`: EmailField — used for login (not username)
- `role`: ForeignKey(UserRole, SET_NULL, nullable) — display/filter only
- `phone_number`: PhoneNumberField — also used for login
- `gender`: CharField, choices: MALE, FEMALE, OTHER
- `status`: CharField, choices: ACTIVE, INACTIVE, SUSPENDED
- `org_slug`: CharField(max_length=150, nullable) — cached tenant identifier
- `tenant`: ForeignKey(clients.Tenant, SET_NULL, nullable)
- `image`: ImageField(upload_to='users/', nullable)
- `password`: CharField(max_length=128, nullable)
- `is_blocked`: BooleanField(default=False)
- `blocked_at`: DateTimeField(nullable)
- `password_changed`: BooleanField(default=False)
- `password_expiry`: DateTimeField(nullable)
- `login_enabled`: BooleanField(default=True)
- `created_at`: DateTimeField(auto_now_add=True)
- `updated_at`: DateTimeField(auto_now=True)

**Methods:**

- `generate_temporary_password()`: Returns 12-char UUID hex string
- `save()`: If no password set, generates temp password, hashes it, sets expiry to 7 days, sends credentials via NotificationService
- `is_password_expired()`: Returns True if password_expiry has passed

**Important decisions:**

- `role` on_delete=SET_NULL — deleting a role never deletes users
- `tenant` on_delete=SET_NULL — offboarding a tenant never wipes users
- Login uses email OR phone_number, not username
- Username auto-generated as `firstname_lastname` (with counter suffix for duplicates)

---

### RefreshToken

Tracks issued refresh tokens for revocation.

**Fields:**

- `jti`: UUIDField(unique) — JWT ID
- `user`: ForeignKey(User, CASCADE, related_name='refresh_tokens')
- `token`: TextField — full encoded token
- `expires_at`: DateTimeField
- `last_used_at`: DateTimeField(nullable)
- `is_revoked`: BooleanField(default=False)
- `created_at`: DateTimeField(auto_now_add=True)

**Methods:**

- `is_expired()`: Returns True if expires_at has passed

**Note:** Moved from apps/clients (HMS) to apps/users. RefreshToken is an auth concern, not a tenant concern. Lives inside the permission system unlike clients app models.

---

### UserRateLimitFlag

Tracks throttle violations per user for auto-blocking.

**Fields:**

- `uid`: UUIDField, unique, editable=False
- `user`: ForeignKey(User, CASCADE, related_name='rate_limit_flags')
- `reason`: TextField(max_length=500, db_index=True)
- `count`: IntegerField(default=0)
- `last_flagged_at`: DateTimeField(auto_now=True)
- `is_blocked`: BooleanField(default=False)

**Meta:** `unique_together = ('user', 'reason')`

**Logic:** After 3 throttle violations, `user.is_blocked` is set to True automatically via `handle_rate_limit_flag` in exceptions.py.

---

## Auth Module (`auth.py`)

### Authenticator Class

Handles all token generation and OTP operations.

**`generate_access_token(user)`**

- Creates JWT with 15-minute expiry
- Payload includes: jti, user_id, user_uid, full_name, role (frontend display only), org_slug, type='access', iat, exp
- Signed with SECRET_KEY using HS256

**`generate_refresh_token(user)`**

- Creates JWT with 12-hour expiry
- Creates RefreshToken DB record
- Sets payload: jti, user_id, user_uid, type='refresh', iat, exp
- role and org_slug NOT in refresh token payload

**`generate_reset_token(user, identifier)`**

- Creates JWT with 10-minute expiry for password reset
- Stores token in Django cache at key `reset_token:{identifier}`
- One-time use — deleted from cache on successful reset

**`generate_otp()`**

- Returns random 6-digit integer

**`send_otp(email, phone, full_name)`**

- Generates OTP, stores in Django cache (email: 10min, phone: 5min)
- Sends via NotificationService (commented until notifications wired)
- Note: cache.set calls must be uncommented alongside service calls

**`verify_otp(user_entered_otp, email, phone)`**

- Retrieves from cache, compares, deletes on match
- Returns True/False

**`forget_verify_otp(user_entered_otp, email, phone)`**

- As verify_otp but with retry counting (max 3 attempts)
- Tracks retries in cache at `retries:{cache_key}`
- Deletes OTP after 4 failed attempts

**`send_reset_password(field, password, full_name)`**

- Validates email format or phone format
- Sends temporary password via NotificationService

### JWTAuthentication Class

Extends DRF's BaseAuthentication.

**`authenticate(request)`**

- Extracts Bearer token from Authorization header
- Decodes JWT, checks blacklist via `cache.get(f'blacklist:access:{jti}')`
- Validates type == 'access'
- Fetches user with `select_related('role', 'tenant')`
- Checks is_blocked
- Caches org_slug at `org_slug:{user_id}`
- Returns (user, payload) or raises AuthenticationFailed

### JWTAuthenticationScheme

drf-spectacular OpenAPI extension for Swagger UI authentication.

---

## Permission System (`perms.py`)

### TenantPermission

Base permission class. Goes on every viewset.

**Check order:**

1. User authenticated → else False
2. is_superuser → True immediately
3. role.name == 'SUPER_ADMIN' → True immediately
4. is_blocked → PermissionDenied
5. login_enabled → PermissionDenied
6. view has content_model → else False
7. Maps view.action to Django permission codename (add/change/delete/view)
8. Checks Permission exists in system → else False
9. Queries UserGroup for user + permission + (tenant OR is_global)
10. Falls back to user.has_perm() direct permission
11. check_organization_context if view sets it

**ViewSet requirement:** Every ViewSet must set `content_model = ModelClass` for this to work.

### LicenseGuard

Opt-in permission class. Add explicitly to viewsets that need license validation.

**Checks:** authenticated → is_superuser/SUPER_ADMIN bypass → tenant exists → license exists and is_active

### Important

Roles are NOT used for access control. `UserRole` values (ADMIN, MANAGER, STAFF) exist for UI filtering and grouping only. The only special roles for backend access are `is_superuser` (Django flag) and `SUPER_ADMIN` (role name).

---

## Exception Handler (`exceptions.py`)

**`custom_exception_handler(exc, context)`**

Registered in REST_FRAMEWORK settings as the global exception handler.

- Catches NotAuthenticated/AuthenticationFailed → returns 401 with `{success: false, data: message}`
- Catches Throttled → calls `handle_rate_limit_flag(user)` then returns throttle response

**`handle_rate_limit_flag(user)`**

- Gets or creates UserRateLimitFlag for user + "Exceeded rate limit" reason
- Increments count
- At count >= 3: sets user.is_blocked=True, user.blocked_at=now, flag.is_blocked=True

---

## Serializers

### UserRoleSerializer

Fields: id, uid, name, created_at, updated_at

### UserGroupCreateUpdateSerializer

Fields: id, uid, name, description, users, permissions, tenant, is_global, created_at, updated_at

### UserGroupListSerializer

Fields: id, uid, name, description, is_global, permissions (nested), users (nested), tenant (nested), created_at, updated_at

`get_permissions`: Filters out clients app permissions for non-SUPER_ADMIN users. Returns id, codename, name per permission.

`get_users`: Returns id, uid, full_name per user.

`get_tenant`: Returns id, uid, name.

### UserCreateSerializer

Fields: username, first_name, middle_name, last_name, email, phone_number, gender, image, role, status, is_blocked, login_enabled, org_slug, tenant, password, password_changed, password_expiry

### UserSelfUpdateSerializer

Fields: first_name, last_name, middle_name, phone_number, gender, image

### UserAdminUpdateSerializer

Fields: role, status, login_enabled, is_blocked

### UserListSerializer

Fields: id, uid, first_name, last_name, middle_name, email, image, phone_number, role (nested), tenant (nested), groups (nested with permissions), status, gender, last_login, is_blocked, login_enabled, password_changed, created_at, updated_at

`get_groups`: Queries UserGroup for user, returns id, uid, name, permissions (codenames list)

---

## Views

### UserRoleViewSet

**content_model:** UserRole
**lookup_field:** uid
**permission_classes:** [TenantPermission]

| Action | Method | Access |
| -------- | -------- | -------- |
| list | GET | All authenticated |
| retrieve | GET | All authenticated |
| create | POST | SUPER_ADMIN only |

### PermissionViewset

Lists all Django permissions grouped by model name. Filters out system apps (admin, auth, contenttypes, etc.) and clients app for non-SUPER_ADMIN users.

Returns: `{ model_name: [{ id, name, codename }] }`

### UserGroupViewSet

**content_model:** UserGroup
**lookup_field:** uid
**permission_classes:** [TenantPermission]

`get_queryset`: SUPER_ADMIN sees global groups only. Others see their tenant's non-global groups.

| Action | Method | Notes |
| -------- | -------- | ------- |
| list | GET | Scoped by tenant |
| retrieve | GET | Scoped by tenant |
| create | POST | SUPER_ADMIN groups auto-flagged is_global=True |
| assign-user-group | POST | Adds users to group by group_uid |
| remove-user-group | POST | Removes users from group by group_uid |

### UserViewSet

**content_model:** User
**lookup_field:** uid
**permission_classes:** [TenantPermission]
**pagination_class:** FetchDataPagination (page_size=10)
**throttle_classes:** [ScopedRateThrottle, UserRateThrottle]

`get_queryset`: SUPER_ADMIN sees all users. Others see only their tenant's users. Supports query params: tenant (SUPER_ADMIN only), role, status, name.

`get_object`: Non-privileged users can only access their own record.

`get_serializer_class`: create→UserCreateSerializer, update (self)→UserSelfUpdateSerializer, update (other)→UserAdminUpdateSerializer, else→UserListSerializer

| Action | Method | Auth | Notes |
| ------- | ------ | ------- | ------- |
| list | GET | Authenticated | Paginated |
| retrieve | GET | Authenticated | Own record only for non-privileged |
| create | POST | Authenticated | Auto-generates username, temp password |
| update/partial_update | PATCH | Authenticated | Cannot change tenant/org_slug |
| update-password | POST | Authenticated | Own password only, blacklists current tokens |
| forgot-password | POST | AllowAny | Sends OTP, silent on unknown user |
| verify-otp | POST | AllowAny | Returns temp_token on success |
| reset-password | POST | AllowAny | Validates reset token + OTP |
| login | POST | AllowAny | Returns access_token, sets refresh HttpOnly cookie |
| passwordless-login | POST | AllowAny | Sends OTP |
| passwordless-login-verify-otp | POST | AllowAny | Returns tokens on OTP success |
| refresh-token | POST | AllowAny | Reads cookie, returns new access_token |
| logout | POST | Authenticated | Blacklists both tokens, clears cookie |
| users-by-organization/{uid} | GET | SUPER_ADMIN | Users by org_slug |

### FetchOrgUsers

Filtered list of users for the requesting user's organisation. Supports role, status, name filters. Paginated.

### FetchOrgUserGroups

Read-only list of permission groups for the requesting user's tenant. Includes permissions and users nested.

---

## Endpoint Consumption Guide (Frontend)

### Authentication Flow

#### Login

```python
POST /auth/users/login/
Body: { field: "email_or_phone", password: "password" }
Response: { success, data, password_changed, access_token, role }
Cookie set: refresh_token (HttpOnly, Lax, 12h)
```

#### Sending authenticated requests

```python
Authorization: Bearer {access_token}
```

#### Refreshing the access token

```python
POST /auth/users/refresh-token/
Credentials: include  (sends HttpOnly cookie automatically)
Body: {}
Response: { success, data, access_token }
```

Call this when a request returns 401 "Access token expired". Implement interceptor to auto-refresh.

### Logout

```python
POST /auth/users/logout/
Authorization: Bearer {access_token}
Credentials: include
Body: {}
Response: { success, data }
Cookie cleared: refresh_token
```

### Passwordless Login

```python
Step 1: POST /auth/users/passwordless-login/
        Body: { field: "email_or_phone" }
        Response: { success, data: "OTP sent" }

Step 2: POST /auth/users/passwordless-login-verify-otp/
        Body: { field: "email_or_phone", otp: "123456" }
        Response: { success, data, access_token, role }
        Cookie set: refresh_token
```

### Password Reset

```python
Step 1: POST /auth/users/forgot-password/
        Body: { field: "email_or_phone" }
        Response: { success, data } (always 200, even for unknown users)

Step 2: POST /auth/users/verify-otp/
        Body: { field: "email_or_phone", otp: "123456" }
        Response: { success, data, temp_token }

Step 3: POST /auth/users/reset-password/
        Body: { field, reset_token, password, confirm_password }
        Response: { success, data }
```

### First Login Password Change**

Check `password_changed` in login response. If false, redirect to change password page immediately.

```txt
POST /auth/users/update-password/
Authorization: Bearer {access_token}
Body: { field: "email_or_phone", password, confirm_password }
Response: { success, data }
```

User is logged out after this — redirect to login.

### Token Management

The `role` field in the login/token response is for frontend UI only — use it to show/hide menu items, labels, dashboards. Never trust it for security decisions.

Access tokens expire in 15 minutes. Implement a request interceptor:

1. Request fails with 401
2. Call refresh-token endpoint (with credentials: include)
3. Retry original request with new access_token
4. If refresh also fails → logout user

### User Management

#### List users (with pagination)

```python
GET /auth/users/users/?page=1&page_size=10&role=STAFF&status=ACTIVE&name=john
Authorization: Bearer {access_token}
Response: { success, data: [...], meta: { count, next, previous } }
```

#### Create user

```python
POST /auth/users/users/
Authorization: Bearer {access_token}
Body: { first_name, last_name, email, phone_number, gender, role }
Note: SUPER_ADMIN must also include tenant ID
```

#### Update own profile

```python
PATCH /auth/users/users/{uid}/
Authorization: Bearer {access_token}
Body: { first_name, last_name, middle_name, phone_number, gender, image }
```

#### Admin update user

```python
PATCH /auth/users/users/{uid}/
Authorization: Bearer {access_token}
Body: { role, status, login_enabled, is_blocked }
```

### Permission Groups

#### List permissions available to assign

```txt
GET /auth/permissions/
Authorization: Bearer {access_token}
Response: { success, data: { model_name: [{ id, name, codename }] } }
```

#### Create a group

```txt
POST /auth/user-group/
Authorization: Bearer {access_token}
Body: { name, description, permissions: [1, 2, 3] }
```

#### Assign users to group

```txt
POST /auth/user-group/assign-user-group/
Authorization: Bearer {access_token}
Body: { group_uid: "uuid", users: [1, 2, 3] }
```

---

## Throttle Scopes

| Scope | Limit | Endpoint |
| --- | --- | --- |
| login | 3/min | /auth/users/login/ |
| passwordless_login | 3/min | /auth/users/passwordless-login/ |
| forgot_password | 3/min | /auth/users/forgot-password/ |
| refresh_token | 2/min | /auth/users/refresh-token/ |
| reset_password | 3/min | /auth/users/reset-password/ |
| user | 100/min | All authenticated endpoints |

After 3 throttle violations, the account is automatically blocked.

---

## URL Structure

All users app URLs are prefixed with `/auth/` in the root urlconf.

```python
/auth/user-role/                          UserRoleViewSet
/auth/user-group/                         UserGroupViewSet
/auth/user-group/assign-user-group/       POST
/auth/user-group/remove-user-group/       POST
/auth/users/                              UserViewSet
/auth/users/login/                        POST (AllowAny)
/auth/users/passwordless-login/           POST (AllowAny)
/auth/users/passwordless-login-verify-otp/ POST (AllowAny)
/auth/users/forgot-password/              POST (AllowAny)
/auth/users/verify-otp/                   POST (AllowAny)
/auth/users/reset-password/               POST (AllowAny)
/auth/users/refresh-token/                POST (AllowAny)
/auth/users/logout/                       POST (Authenticated)
/auth/users/update-password/              POST (Authenticated)
/auth/users/users-by-organization/{uid}/  GET (SUPER_ADMIN)
/auth/permissions/                        PermissionViewset
/auth/fetch-org-users/                    FetchOrgUsers
/auth/fetch-org-user-groups/              FetchOrgUserGroups
```

---

## Apps Configuration

### UsersConfig

```python
default_auto_field = "django.db.models.BigAutoField"
name = "apps.users"
```

No signals registered in users app. RefreshToken and UserRateLimitFlag have no signals — lifecycle managed in views.
