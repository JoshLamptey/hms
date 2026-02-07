import threading

_thread_local = threading.local()


class TenantRouter:
    def get_current_schema(self):
        # This method can still be used by your middleware if needed.
        return getattr(_thread_local, "schema_name", "public")

    def db_for_read(self, model, **hints):
        # Always use the default connection.
        return "default"

    def db_for_write(self, model, **hints):
        # Always use the default connection.
        return "default"

    def allow_relation(self, obj1, obj2, **hints):
        return True

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        # You may want to restrict migrations to a specific schema.
        return db == "default"

    def allow_migrate_model(self, db, app_label, model_name=None, **hints):
        # You may want to restrict migrations to a specific schema.
        return db == "default"
