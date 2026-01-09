from django.core.management.base import BaseCommand
from django.db import connection, DatabaseError
from django.core.management import call_command
from apps.client.models import Tenant


class Command(BaseCommand):
    
    help = "Applies migrations to specified schemas with safety checks"
    
    def add_arguments(self, parser):
        parser.add_argument(
            "schema_names",
            nargs="+",
            type=str,
            help="Migrate specific schemas (default: all non-system schemas)"
        )
        parser.add_argument(
            "--fake",
            action="store_true",
            help="Mark migrations as applied without actually running them"
        )
        parser.add_argument(
            "--plan",
            action="store_true",
            help="Show the migration plan without applying migrations"
        )
        
    def get_valid_schemas(self):
        # Fetch all tenant schema names from the database
        return list(Tenant.objects.values_list("schema_name", flat=True))
    
    def handle(self, *args, **kwargs):
        requested_schemas = kwargs["schema_names"]
        verbosity = kwargs["verbosity"]
        
        #determine valid schemas
        valid_schemas = self.get_valid_schemas()
        
        if requested_schemas:
            invalid = set(requested_schemas) - set(valid_schemas)
            if invalid:
                self.stderr.write(
                    f"Error: The following schemas are invalid: {', '.join(invalid)}"
                )
                return
            schemas_to_migrate = requested_schemas
        else:
            schemas_to_migrate = valid_schemas
            
        #migration execution
        for schema in schemas_to_migrate:
            self.stdout.write(f"\nMigrating schema: {schema}")
            
            try:
                with connection.cursor() as cursor:
                    cursor.execute(f"SET search_path TO {schema};")
                    
                    call_command(
                        "migrate",
                        verbosity=verbosity,
                        fake=kwargs["fake"],
                        plan=kwargs["plan"],
                        database="default"
                    )
                    
            except DatabaseError as e:
                self.stderr.write(
                    f"Database error while migrating schema '{schema}': {str(e)}"
                    )
            finally:
                # Reset search path to public schema
                with connection.cursor() as cursor:
                    cursor.execute("SET search_path TO public;")
                    
        self.stdout.write(
            self.style.SUCCESS("\nMigrations completed successfully.")
        )
        
        
                
    
        