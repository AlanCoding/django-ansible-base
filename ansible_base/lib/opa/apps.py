from django.apps import AppConfig


class DABOPAConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'ansible_base.lib.opa'
    label = 'dab_opa'
    verbose_name = 'DAB OPA Authorization'

    def ready(self):
        from ansible_base.lib.opa.registry import opa_registry

        opa_registry.validate(self.apps)
