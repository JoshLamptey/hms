# Client App Documentation

This document provides comprehensive documentation for the `apps/client` Django app, which handles multi-tenant license management in a schema-based architecture.

## Overview

The Client app is designed for a multi-tenant SaaS application where each tenant (organization) has its own database schema. It manages tenants, license types, licenses, renewals, and history tracking.

Key features:

- Multi-tenant architecture with PostgreSQL schemas
- License management with types, quantities, and expiration
- Automatic license renewal and history tracking
- Dashboard analytics for tenants, licenses, and users
- Custom decorators and middleware for schema switching

## Models

### Tenant Model

Represents an organization/tenant in the system.

**Fields:**

- `uid`: UUID, unique identifier
- `name`: CharField, tenant name (optional)
- `address`: CharField, tenant address (optional)
- `schema_name`: CharField, PostgreSQL schema name (unique)
- `is_active`: BooleanField, activation status
- `org_slug`: SlugField, organization slug
- `logo`: ImageField, tenant logo
- `email`: EmailField, tenant email (unique)
- `phone_number`: PhoneNumberField
- `created_at`: DateTimeField, auto-now-add
- `updated_at`: DateTimeField, auto-now

**Methods:**

- `__str__()`: Returns tenant name
- `save()`: Auto-generates org_slug from email domain if not set

**Meta:**

- Verbose name: "tenant"
- Ordering: by -created_at

### LicenseType Model

Defines types of licenses available.

**Fields:**

- `uid`: UUID, unique identifier
- `name`: CharField, license type name (unique)
- `coverage`: TextField, coverage details (optional)
- `sub_name`: CharField, sub-name (optional)
- `description`: TextField, description (optional)
- `duration`: IntegerField, duration in days (default 0)
- `max_users`: PositiveIntegerField, maximum users (default 10)
- `created_at`: DateTimeField, auto-now-add
- `updated_at`: DateTimeField, auto-now

**Properties:**

- `full_text`: Combined name and sub_name

**Meta:**

- Verbose name: "License Type"
- Ordering: by -created_at

### License Model

Represents individual licenses issued to tenants.

**Fields:**

- `uid`: UUID, unique identifier
- `license_type`: ForeignKey to LicenseType
- `issue_date`: DateField, auto-now-add
- `expiry_date`: DateField
- `quantity`: PositiveIntegerField, number of licenses
- `status`: CharField, choices: pending/active/expired/revoked
- `tenant`: ForeignKey to Tenant
- `license_key`: CharField, unique key (auto-generated)
- `users`: ManyToManyField to User
- `created_at`: DateTimeField, auto-now-add
- `updated_at`: DateTimeField, auto-now

**Properties:**

- `name`: License type name
- `remaining_slots`: Quantity minus users count
- `license_info`: License type full text
- `is_active`: Boolean based on status and expiry

**Methods:**

- `generate_license_key()`: Creates unique 64-char hex key
- `save()`: Sets expiry, enforces max users, generates key, auto-expires

**Meta:**

- Unique constraint on license_key per tenant
- Ordering: by -created_at

### LicenseRenewal Model

Handles license renewals.

**Fields:**

- `license`: ForeignKey to License
- `quantity`: PositiveIntegerField
- `renewal_date`: DateField, auto-now-add
- `expiration_date`: DateField, default +1 month
- `created_at`: DateTimeField, auto-now-add
- `updated_at`: DateTimeField, auto-now

**Methods:**

- `save()`: Updates license expiry and quantity

**Meta:**

- Verbose name: "License Renewal"
- Ordering: by -created_at

### LicenseHistory Model

Tracks changes to licenses.

**Fields:**

- `license`: ForeignKey to License
- `tenant`: ForeignKey to Tenant
- `action`: CharField, choices: CREATE/UPDATE/DELETE/RENEW
- `timestamp`: DateTimeField, auto-now-add

## Serializers

### TenantCreateUpdateSerializer

For creating/updating tenants.

**Fields:** name, schema_name, is_active, org_slug, logo, email

### TenantListSerializer

For listing tenants, includes logo URL.

**Fields:** uid, name, schema_name, is_active, org_slug, logo, email, created_at, updated_at

### LicenseTypeSerializer

For license types.

**Fields:** uid, name, coverage, sub_name, description, duration, max_users, created_at, updated_at

### LicenseCreateUpdateSerializer

For creating/updating licenses.

**Fields:** tenant, license_type, issue_date, expiry_date, quantity, status, users

### LicenseListSerializer

For listing licenses with nested data.

**Fields:** uid, tenant, license_type, issue_date, expiry_date, quantity, status, users, created_at, updated_at

**Custom Methods:**

- `get_days_till_expiry()`: Humanized time to expiry
- `get_license_type()`: Nested license type data
- `get_tenant()`: Nested tenant data
- `get_users()`: List of users with details

### LicenseHistoryListSerializer

For license history (incomplete in code).

### LicenseRenewalCreateUpdateSerializer

For creating/updating renewals.

**Fields:** license, quantity, expiration_date

### LicenseRenewalListSerializer

For listing renewals.

**Fields:** license, quantity, expiration_date, created_at, updated_at

## Views

### TenantViewset (ModelViewSet)

Handles tenant CRUD operations.

**Permissions:** CustomPermission

**Lookup Field:** uid

**Actions:**

- `list`: Superuser only, returns all tenants
- `retrieve`: Superuser only, returns single tenant
- `create`: Superuser only, validates required fields, checks uniqueness
- `update`: Superuser only, partial update
- `destroy`: Superuser only
- `fetch_organisations`: Custom action for user's tenant

### LicenseTypeViewset (ModelViewSet)

Standard CRUD for license types.

### LicenseViewset (ModelViewSet)

Handles license operations.

**Actions:**

- `list`: All licenses
- `retrieve`: Single license
- `create`: Create license
- `update`: Update license
- `destroy`: Delete license
- `fetch_expiring_licenses`: Licenses expiring in 90 days
- `get_single_license_by_org`: License by org and uid

### LicenseRenewalViewset (ModelViewSet)

Handles renewals.

**Actions:**

- `create`: Superuser only
- `update`: Superuser only

### LicenseHistoryViewset (ViewSet)

Lists license history.

### FetchOrgLicense (ReadOnlyModelViewSet)

Fetches licenses for user's tenant (admin_user role required).

### API Views

#### fetch_org_license_plans

Returns license plans and expiry data for user's tenant.

#### fetch_dashboard_card

Returns dashboard statistics: tenant counts, license counts, user counts.

#### fetch_dashboard_pie_charts

Returns pie chart data for license types distribution.

#### fetch_dashboard_bar_chart

Returns bar chart data for recent license renewals by tenant.

## URLs

Uses DefaultRouter for ViewSets.

**Routes:**

- `organisation/` -> TenantViewset
- `license-type/` -> LicenseTypeViewset
- `license/` -> LicenseViewset
- `license-renewal/` -> LicenseRenewalViewset
- `license-history/` -> LicenseHistoryViewset
- `fetch-license-by-orgs/` -> FetchOrgLicense

**Additional Paths:**

- `fetch-dashboard-card/` -> fetch_dashboard_card
- `fetch-dashboard-charts/` -> fetch_dashboard_pie_charts
- `fetch-dashboard-bar-chart/` -> fetch_dashboard_bar_chart
- `fetch-org-license-plans/` -> fetch_org_license_plans

## Admin

### BaseAdmin

Base admin class with readonly created_at/updated_at and dynamic list_display.

### TenantAdmin

Registers Tenant, License, LicenseType, LicenseHistory, LicenseRenewal with BaseAdmin.

## Signals

### create_license_history

Helper function to create history records.

### post_save License

Creates CREATE/UPDATE history.

### post_delete License

Creates DELETE history.

### post_save LicenseRenewal

Creates RENEW history.

## Tasks

### send_license_expiry_notice (Commented out)

Celery task to notify about expiring licenses via email/SMS.

## Management Commands

### create_schema

Creates PostgreSQL schemas for tenants.

**Arguments:**

- `schema_name`: Schema names to create
- `--skip-public`: Skip public schema

**Validation:** Schema name must match regex.

### migrate_schemas

Applies migrations to specified schemas.

**Arguments:**

- `schema_names`: Schemas to migrate (default all)
- `--fake`: Mark as applied without running
- `--plan`: Show plan without applying

### sync_users_to_tenant (Commented out)

Syncs users to tenant schemas (for isolated tenants).

## Decorators

### with_schema

Decorator for views to set search_path to tenant's schema.

**Process:**

- Gets user from request
- Retrieves org_slug from cache
- Fetches tenant by org_slug
- Sets connection search_path to schema,public
- Executes view function

**Error Handling:** PermissionDenied for missing context, APIException for DB errors.

## Middleware

### TenantMiddleware (Commented out)

Alternative to decorator for automatic schema switching.

Sets search_path based on user's org_slug from cache.

## Tests

### tests.py

Empty test file, placeholder for unit tests.

## Apps Configuration

### ClientConfig

Standard AppConfig with BigAutoField.

## Notes

- Many files have commented-out code for features not yet implemented (middleware, tasks, commands).
- Uses arrow for date handling, phonenumbers for validation.
- Multi-tenant via PostgreSQL schemas.
- Permissions use CustomPermission from users app.
- Serializers use decouple for BASE_URL
