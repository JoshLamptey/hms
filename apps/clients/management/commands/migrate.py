from django.core.management.commands.migrate import Command as BaseCommand
from django.conf import settings
from django.db import connection


class Command(BaseCommand):
    help = "Wraps Django's migrate to enforce schema boundaries."

    def handle(self, *app_label, **options):
        tenant_app_labels = set(getattr(settings, "TENANT_APP_LABELS", []))

        if not tenant_app_labels:
            return super().handle(*app_label, **options)

        with connection.cursor() as cursor:
            cursor.execute("SHOW search_path")
            current_search_path = cursor.fetchone()[0]

        in_public = "public" in current_search_path and not any(
            s for s in current_search_path.split(",")
            if s.strip() not in ("public", '"$user"', "")
        )

        # app_label comes through options, not *args
        target_app = options.get("app_label")

        if target_app and in_public and target_app in tenant_app_labels:
            self.stdout.write(self.style.ERROR(
                f"Blocked: '{target_app}' is a tenant app and cannot be "
                f"migrated into the public schema. "
                f"Use migrate_schemas instead."
            ))
            return

        if not target_app and in_public:
            shared_labels = getattr(settings, "SHARED_APP_LABELS", [])
            for label in shared_labels:
                # FIX: pass label via options, not as positional arg
                super().handle(**{**options, "app_label": label})
            self.stdout.write(self.style.WARNING(
                f"Skipped tenant apps: {', '.join(sorted(tenant_app_labels))}. "
                f"Run migrate_schemas to migrate those."
            ))
            return

        return super().handle(*app_label, **options)