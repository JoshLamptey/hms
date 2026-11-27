import re
from django.conf import settings
from django.core.management.base import BaseCommand
from django.core.management import call_command
from django.db import connection, DatabaseError
from django.db.migrations.recorder import MigrationRecorder
from psycopg2 import sql

SCHEMA_NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class Command(BaseCommand):
    help = "Applies tenant app migrations to all client schemas."

    def add_arguments(self, parser):
        parser.add_argument("--schemas", nargs="*", type=str)
        parser.add_argument("--verbose", action="store_true")
        parser.add_argument("--dry-run", action="store_true")

    def handle(self, *args, **kwargs):
        specified_schemas = kwargs.get("schemas") or []
        verbose = kwargs.get("verbose", False)
        dry_run = kwargs.get("dry_run", False)
        verbosity = 2 if verbose else 1

        tenant_app_labels = set(getattr(settings, "TENANT_APP_LABELS", []))

        if not tenant_app_labels:
            self.stdout.write(self.style.SUCCESS(
                "No tenant app labels configured; no tenant migrations to run."
            ))
            return

        # Fetch schemas
        if not specified_schemas:
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT schema_name FROM information_schema.schemata
                    WHERE schema_name NOT IN (
                        'public', 'information_schema', 'pg_catalog', 'pg_toast'
                    )
                """)
                schemas = [row[0] for row in cursor.fetchall()]
        else:
            schemas = specified_schemas

        if not schemas:
            self.stdout.write(self.style.WARNING("No tenant schemas found."))
            return

        # Validate schemas
        invalid_schemas = []
        for schema in schemas:
            if not SCHEMA_NAME_PATTERN.match(schema):
                self.stdout.write(self.style.ERROR(
                    f"Invalid schema name format: '{schema}'"
                ))
                invalid_schemas.append(schema)
                continue
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT schema_name FROM information_schema.schemata "
                    "WHERE schema_name = %s",
                    [schema]
                )
                if not cursor.fetchone():
                    self.stdout.write(self.style.ERROR(
                        f"Schema does not exist: '{schema}'"
                    ))
                    invalid_schemas.append(schema)

        if invalid_schemas:
            self.stdout.write(self.style.ERROR(
                "Aborting. Fix the above issues before retrying."
            ))
            return

        # Save original search_path for cleanup
        with connection.cursor() as cursor:
            cursor.execute("SHOW search_path")
            original_search_path = cursor.fetchone()[0]

        # Read what's applied in public — these get fake-marked in tenant schemas
        # so dependency resolution works without recreating shared tables
        with connection.cursor() as cursor:
            cursor.execute("SET search_path TO public")
        public_applied = set(MigrationRecorder(connection).applied_migrations())

        succeeded = []
        failed = []

        for schema in schemas:
            self.stdout.write(f"\nMigrating tenant schema: '{schema}'")

            if dry_run:
                self.stdout.write(self.style.WARNING(
                    f"Dry run: would migrate '{schema}'"
                ))
                succeeded.append(schema)
                continue

            try:
                # Switch to tenant schema with public as fallback so FKs to
                # shared tables (users_user, auth_*, contenttypes, etc.)
                # resolve correctly via search_path without duplicating those tables
                with connection.cursor() as cursor:
                    cursor.execute(
                        sql.SQL("SET search_path TO {}, public").format(
                            sql.Identifier(schema)
                        )
                    )

                # Create django_migrations in tenant schema if it doesn't exist
                # then populate it with shared app migration records (fake entries)
                # so tenant app dependency checks resolve without recreating shared tables
                recorder = MigrationRecorder(connection)
                recorder.ensure_schema()
                tenant_applied = set(recorder.applied_migrations())

                for (app, name) in public_applied:
                    if (
                        app not in tenant_app_labels
                        and (app, name) not in tenant_applied
                    ):
                        recorder.record_applied(app, name)

                # Run real migrations for tenant apps only
                for app_label in sorted(tenant_app_labels):
                    call_command("migrate", app_label, verbosity=verbosity)

                succeeded.append(schema)
                self.stdout.write(self.style.SUCCESS(
                    f"Schema '{schema}' migrated successfully."
                ))

            except (DatabaseError, Exception) as e:
                self.stdout.write(self.style.ERROR(
                    f"Error migrating schema '{schema}': {e}"
                ))
                failed.append(schema)

            finally:
                try:
                    # If the migration failed mid-transaction the connection is
                    # in an aborted state — rollback before any cleanup queries
                    connection.rollback()
                    with connection.cursor() as cursor:
                        cursor.execute(
                            sql.SQL("SET search_path TO {}").format(
                                sql.Identifier(original_search_path)
                            )
                        )
                except Exception as cleanup_error:
                    self.stdout.write(self.style.WARNING(
                        f"Warning: could not reset search_path after error: {cleanup_error}"
                    ))

        # Summary
        self.stdout.write("\n--- Migration Summary ---")
        if succeeded:
            self.stdout.write(self.style.SUCCESS(
                f"Succeeded ({len(succeeded)}): {', '.join(succeeded)}"
            ))
        if failed:
            self.stdout.write(self.style.ERROR(
                f"Failed ({len(failed)}): {', '.join(failed)}"
            ))
        if not failed:
            self.stdout.write(self.style.SUCCESS(
                "All tenant schemas migrated successfully."
            ))
        else:
            self.stdout.write(self.style.WARNING(
                f"{len(failed)} schema(s) failed. Review errors above."
            ))
