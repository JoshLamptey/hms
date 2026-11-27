# Clients App Documentation

This document provides comprehensive documentation for the `apps/clients` Django app, which handles multi-tenant license management in a schema-based architecture.

---

## Overview

The Clients app is the platform licensing layer. It manages organisations (tenants), their license types, active licenses, renewals, and history. This app lives entirely in the **public PostgreSQL schema** — its data is shared across the platform, not isolated per tenant.

Key features:

- Multi-tenant architecture with PostgreSQL schemas (one schema per tenant)
- License management with types, quantities, and expiration
- Automatic license key generation
- License renewal with history tracking
- Dashboard analytics for tenants, licenses, and users
- Schema creation via post_save signal
- All models excluded from group permissions — only SUPER_ADMIN and is_superuser can access

**Critical distinction:** The word "clients" here means licensed organisations using the HMS platform, not the patients or customers served by those organisations. Those domain records are outside this app's scope.

---

## Models

### Tenant

Represents an organisation/tenant using the platform.

**Fields:**

- `uid`: UUIDField, unique, editable=False
- `name`: CharField(max_length=150, unique, nullable)
- `address`: CharField(max_length=150, nullable)
- `schema_name`: CharField(max_length=63, unique) — PostgreSQL schema name, auto-generated
- `is_active`: BooleanField(default=True)
- `org_slug`: SlugField(max_length=255, unique) — used as schema identifier and JWT payload
- `logo`: ImageField(upload_to='tenant/logo', nullable)
- `email`: EmailField(unique)
- `phone_number`: PhoneNumberField
- `created_at`: DateTimeField(auto_now_add=True)
- `updated_at`: DateTimeField(auto_now=True)

**Important:** `org_slug` has `unique=True` — two tenants cannot share the same slug. The slug is used to route all tenant-scoped database queries via `SET search_path TO {org_slug}, public`.

**On creation:** `post_save` signal fires `create_schema_for_client()` which executes `CREATE SCHEMA IF NOT EXISTS {schema_name}` in PostgreSQL. This is how tenant isolation is established.

---

### LicenseType

Defines the types of licenses available on the platform.

**Fields:**

- `uid`: UUIDField, unique, editable=False
- `name`: CharField(max_length=150, unique)
- `coverage`: TextField(nullable)
- `sub_name`: CharField(max_length=150, nullable)
- `description`: TextField(nullable)
- `duration`: IntegerField(default=0) — license duration in days
- `max_users`: PositiveIntegerField(default=10) — maximum users per license
- `created_at`: DateTimeField(auto_now_add=True)
- `updated_at`: DateTimeField(auto_now=True)

**Properties:**

- `full_text`: Returns `"name | sub_name"` if sub_name exists, else just name

---

### License

A license issued to a specific tenant.

**Fields:**

- `uid`: UUIDField, unique, editable=False
- `license_type`: ForeignKey(LicenseType, CASCADE, related_name='licenses')
- `tenant`: ForeignKey(Tenant, CASCADE, related_name='licenses')
- `users`: ManyToManyField(User, blank=True, related_name='user_licenses') — users on this license
- `issue_date`: DateField(auto_now_add=True)
- `expiry_date`: DateField(nullable) — auto-set from license_type.duration in save()
- `quantity`: PositiveIntegerField(default=1) — number of licensed seats
- `status`: CharField, choices: pending / active / expired / revoked
- `license_key`: CharField(max_length=255, unique, editable=False) — auto-generated 32-char hex
- `created_at`: DateTimeField(auto_now_add=True)
- `updated_at`: DateTimeField(auto_now=True)

**Properties:**

- `name`: Returns license_type.full_text
- `remaining_slots`: quantity minus users.count()
- `is_active`: True if status == ACTIVE and today < expiry_date. Safe for None expiry_date.

**`save()` logic:**

1. If no expiry_date: sets it to today + license_type.duration days
2. If quantity > max_users: caps quantity at max_users
3. If no license_key: generates one via generate_license_key()
4. If status == ACTIVE and today >= expiry_date: auto-sets status to EXPIRED

**Meta:** UniqueConstraint on (license_key, tenant)

---

### LicenseRenewal

Records a renewal of an existing license.

**Fields:**

- `uid`: UUIDField, unique, editable=False
- `license`: ForeignKey(License, CASCADE, related_name='renewals')
- `quantity`: PositiveIntegerField(default=1)
- `renewal_date`: DateField(auto_now_add=True)
- `expiration_date`: DateField(nullable) — auto-calculated
- `created_at`: DateTimeField(auto_now_add=True)
- `updated_at`: DateTimeField(auto_now=True)

**`save()` logic:**

1. Calculates expiration_date from license_type.duration if not set
2. Caps quantity at license_type.max_users
3. Updates license.quantity, license.expiry_date, license.status=ACTIVE
4. Triggers LicenseHistory RENEW entry via signal

---

### LicenseHistory

Immutable audit trail for license changes.

**Fields:**

- `uid`: UUIDField, unique, editable=False
- `license`: ForeignKey(License, CASCADE, related_name='history')
- `tenant`: ForeignKey(Tenant, CASCADE, related_name='license_history')
- `action`: CharField, choices: CREATE / UPDATE / DELETE / RENEW
- `timestamp`: DateTimeField(auto_now_add=True)

**Note:** LicenseHistory records are never edited manually. All fields are readonly in admin. Populated entirely by signals.

---

## Signals (`signals.py`)

### `create_client_schema`

**Trigger:** post_save on Tenant, created=True only

**Action:** Calls `create_schema_for_client(instance)` which executes `CREATE SCHEMA IF NOT EXISTS {schema_name}` via raw SQL cursor. Logs success or raises on failure.

---

### `save_license_history`

**Trigger:** post_save on License

**Action:** Creates LicenseHistory with action=CREATE (if created) or action=UPDATE.

---

### `delete_license_history`

**Trigger:** post_delete on License

**Action:** Creates LicenseHistory with action=DELETE.

---

### `save_renewal_history`

**Trigger:** post_save on LicenseRenewal, created=True only

**Action:** Creates LicenseHistory with action=RENEW on the related license.

---

## Utils (`utils.py`)

### `sanitize_schema_name(name)`

Converts any string to a valid PostgreSQL schema name:

1. Lowercase and strip
2. Replace spaces with underscores
3. Remove non-alphanumeric characters except underscore
4. Prefix with `org_` if first character is not alpha
5. Truncate to 63 characters (PostgreSQL limit)

### `create_schema_for_client(client)`

1. Gets raw value from client.org_slug or client.name
2. Sanitizes via sanitize_schema_name()
3. Validates against SAFE_SCHEMA_NAME regex: `^[a-z][a-z0-9_]{0,62}$`
4. Executes `CREATE SCHEMA IF NOT EXISTS {schema_name}` via Django connection cursor
5. Returns schema_name string

---

## Management Commands

### `create_schema`

Creates a PostgreSQL schema manually.

```bash
python manage.py create_schema schema_name_1 schema_name_2
python manage.py create_schema schema_name --skip-public
```

Arguments:

- `schema_name`: One or more schema names to create
- `--skip-public`: Skip the public schema

Validation: Schema name must match safe regex pattern.

---

### `migrate_schemas`

Applies tenant-app migrations to client schemas. HMS currently has no tenant-only apps configured (`TENANT_APP_LABELS = []`), so the command exits successfully without running migrations.

```bash
python manage.py migrate_schemas
python manage.py migrate_schemas --schemas org_abc org_xyz
python manage.py migrate_schemas --schemas org_abc --dry-run
python manage.py migrate_schemas --schemas org_abc --verbose
```

When tenant app labels are added in `hms/settings/base.py`, the command can migrate those apps in the selected schemas. `--schemas` accepts zero or more schema names; without it, configured tenant schemas are discovered automatically.

---

## Serializers

### TenantCreateUpdateSerializer

Fields: name, address, email, phone_number, logo, is_active

Note: schema_name and org_slug are excluded — they are auto-generated and must never be set via API.

### TenantListSerializer

Fields: id, uid, name, address, org_slug, schema_name, email, phone_number, logo (absolute URL), is_active, created_at, updated_at

`get_logo`: Uses `request.build_absolute_uri()` — not hardcoded BASE_URL. Works correctly across all environments.

### LicenseTypeCreateUpdateSerializer

Fields: name, sub_name, coverage, description, duration, max_users

### LicenseTypeListSerializer

Fields: id, uid, name, sub_name, coverage, description, duration, max_users, created_at, updated_at

### LicenseCreateUpdateSerializer

Fields: tenant, license_type, expiry_date, quantity, status, users

### LicenseListSerializer

Fields: id, uid, tenant (nested), license_type (nested), license_key, issue_date, expiry_date, quantity, status, is_active, remaining_slots, users (nested), days_till_expiry, created_at, updated_at

`get_days_till_expiry`: Returns humanized string via arrow (e.g. "in 3 months") or "Expired".
`get_is_active`: Exposes the is_active property.

### LicenseRenewalCreateUpdateSerializer

Fields: license, quantity, expiration_date

### LicenseRenewalListSerializer

Fields: id, uid, license (nested: id, uid, name), quantity, renewal_date, expiration_date, created_at, updated_at

### LicenseHistoryListSerializer

Fields: id, uid, license (nested), tenant (nested), action, timestamp

---

## Views

All write operations (create, update, destroy) on tenants and licenses are restricted to is_privileged users (is_superuser or role.name == 'SUPER_ADMIN').

### TenantViewset

**content_model:** Tenant
**lookup_field:** uid
**permission_classes:** [TenantPermission]

| Action | Access |
| -------- | -------- |
| list | SUPER_ADMIN only |
| retrieve | SUPER_ADMIN only |
| create | SUPER_ADMIN only |
| update | SUPER_ADMIN only |
| destroy | SUPER_ADMIN only |
| my-organisation | Any authenticated (own tenant) |

### LicenseTypeViewset

**content_model:** LicenseType
**lookup_field:** uid
**permission_classes:** [TenantPermission]

list and retrieve, create, update, destroy: SUPER_ADMIN only.

### LicenseViewset

**content_model:** License
**lookup_field:** uid
**permission_classes:** [TenantPermission]

| Action | Access |
| -------- | -------- |
| list | SUPER_ADMIN only |
| retrieve | SUPER_ADMIN only |
| create | SUPER_ADMIN only |
| update | SUPER_ADMIN only |
| destroy | SUPER_ADMIN only |
| assign-license-users | Any authenticated |
| remove-license-users | Any authenticated |
| expiring-licenses | SUPER_ADMIN only |

### LicenseRenewalViewset

**content_model:** LicenseRenewal
**lookup_field:** uid

list, retrieve, create, update: SUPER_ADMIN only.

### LicenseHistoryViewset

list: SUPER_ADMIN only.

### FetchOrgLicense

Read-only. Returns licenses for the requesting user's tenant. Ordered by expiry_date descending.

### Dashboard Views (function-based)

| Endpoint | Access | Returns |
| ---------- | -------- | --------- |
| fetch_dashboard_card | SUPER_ADMIN | Tenant/license/user counts |
| fetch_dashboard_pie_charts | SUPER_ADMIN | License type distribution |
| fetch_dashboard_bar_chart | SUPER_ADMIN | Recent renewals per tenant |
| fetch_org_license_plans | Any authenticated | Own org license plans + expiry progress |

---

## Tasks (`tasks.py`)

### `send_license_expiry_notice`

Celery task that runs daily at 8am (configured in CELERY_BEAT_SCHEDULE).

Finds all active licenses expiring within 5 days. For each:

1. Sends expiry notice to tenant email
2. Sends expiry notice to all users with role=ADMIN on that license

---

## Endpoint Consumption Guide (Frontend)

### Organisation Management (SUPER_ADMIN only)

#### List all organisations

```python
GET /tenants/
Authorization: Bearer {access_token}
Response: { success, data: [{ uid, name, org_slug, email, is_active, ... }] }
```

#### Create organisation

```python
POST /tenants/
Authorization: Bearer {access_token}
Body: { name, email, phone_number, address }
Response: { success, data: "Organisation created successfully." }
Note: Schema is created automatically via signal after this call.
```

#### Get own organisation

```python
GET /tenants/my-organisation/
Authorization: Bearer {access_token}
Response: { success, data: { uid, name, org_slug, email, logo, ... } }
```

### License Management

#### List license types

```python
GET /license-types/
Authorization: Bearer {access_token}
Response: { success, data: [{ uid, name, duration, max_users, ... }] }
```

#### Create license for an organisation (SUPER_ADMIN)

```python
POST /licenses/
Authorization: Bearer {access_token}
Body: { tenant: id, license_type: id, quantity: 10 }
Response: { success, data: "License created successfully." }
```

#### Get own org's license

```python
GET /my-org-licenses/
Authorization: Bearer {access_token}
Response: { success, data: [{ uid, status, expiry_date, remaining_slots, days_till_expiry }] }
```

### Assign users to license

```python
POST /licenses/assign-license-users/
Authorization: Bearer {access_token}
Body: { license_uid: "uuid", users: [1, 2, 3] }
Response: { success, data: "Users assigned to license successfully." }
```

### Org license plans (widget data)

```python
GET /org-license-plans/
Authorization: Bearer {access_token}
Response: {
  success,
  data: {
    plans: [{ type, expiry, seats }],
    expirys: [{ license, percentage, progressText, remainingText }]
  }
}
```

### Dashboard cards (SUPER_ADMIN)

```python
GET /dashboard/cards/
Authorization: Bearer {access_token}
Response: {
  success,
  data: {
    tenants: { total, active, inactive, with_licenses },
    licenses: { total, active, expired, types },
    users: { total, active, inactive, admins }
  }
}
```

---

## URL Structure

All clients app URLs are prefixed at root `/` in the root urlconf.

```python
/tenants/                           TenantViewset
/tenants/my-organisation/           GET — own org
/license-types/                     LicenseTypeViewset
/licenses/                          LicenseViewset
/licenses/assign-license-users/     POST
/licenses/remove-license-users/     POST
/licenses/expiring-licenses/        GET (SUPER_ADMIN)
/licenses/my-org-license/           GET
/license-renewals/                  LicenseRenewalViewset
/license-history/                   LicenseHistoryViewset
/org-licenses/                      FetchOrgLicense
/dashboard/cards/                   fetch_dashboard_card
/dashboard/pie-charts/              fetch_dashboard_pie_charts
/dashboard/bar-chart/               fetch_dashboard_bar_chart
/org-license-plans/                 fetch_org_license_plans
```

---

## Apps Configuration

### ClientsConfig

```python
default_auto_field = "django.db.models.BigAutoField"
name = "apps.clients"

def ready(self):
    import apps.clients.signals
```

Signals must be imported in `ready()` or they will never fire.
