from django.core.management.base import BaseCommand
from django.db import connection
from apps.client.models import Tenant
import re


class Command(BaseCommand):
    help = "Creates postgresql schema for a tenant and registers them too"

    def add_arguments(self, parser):
        parser.add_argument(
            "schema_name",
            nargs="+",
            type=str,
            help="The schema name to create for the tenant",
        )

        parser.add_argument(
            "--skip-public",
            action="store_true",
            help="Skip creating schema for public tenant",
        )

    def validate_schema_name(self, name):
        """Ensures the schema name is valid."""
        if not re.match(r"^[a-z][a-z0-9_]{0,62}$", name):
            raise ValueError(
                "Schema name must:"
                "1) start with a letter,\n"
                "2) contain only lowercase letters, numbers, and underscores,\n"
                "3) be between 1 and 63 characters long."
            )

    def handle(self, *args, **kwargs):

        if not kwargs["skip_public"]:
            with connection.cursor() as cursor:
                cursor.execute("CREATE SCHEMA IF NOT EXISTS public;")
                self.stdout.write(self.style.SUCCESS("Public schema ensured."))

        for schema_name in kwargs["schema_name"]:
            try:
                self.validate_schema_name(schema_name)

                with connection.cursor() as cursor:
                    # create schema
                    cursor.execute(
                        f"""
                        CREATE SCHEMA IF NOT EXISTS {schema_name}
                    """
                    )

                # register tenant
                Tenant.objects.get_or_create(
                    schema_name=schema_name,
                    org_slug=schema_name,
                    defaults={"name": schema_name.replace("_", " ").title()},
                )

                self.stdout.write(
                    self.style.SUCCESS(
                        f"Schema '{schema_name}' created and tenant registered successfully."
                    )
                )

            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f"Error creating schema '{schema_name}': {str(e)}")
                )
