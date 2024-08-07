# myproject/db_router.py

class CVEDatabaseRouter:
    """
    A router to control all database operations on models in the
    api application.
    """
    def db_for_read(self, model, **hints):
        """Attempt to read cve models go to cve_db."""
        if model._meta.app_label == 'api':
            return 'cve_db'
        return None

    def db_for_write(self, model, **hints):
        """Attempt to write cve models go to cve_db."""
        if model._meta.app_label == 'api':
            return 'cve_db'
        return None

    def allow_relation(self, obj1, obj2, **hints):
        """Allow relations if a model in the api app is involved."""
        if obj1._meta.app_label == 'api' or obj2._meta.app_label == 'api':
            return True
        return None

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        """Make sure the api app only appears in the 'cve_db' database."""
        if app_label == 'api':
            return db == 'cve_db'
        return None
