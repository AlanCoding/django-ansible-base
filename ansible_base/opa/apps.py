from django.apps import AppConfig


class DABOPAConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'ansible_base.opa'
    label = 'dab_opa'
    verbose_name = 'DAB OPA Authorization'

    def ready(self):
        from ansible_base.opa.registry import opa_registry
        from ansible_base.opa.signals import connect_user_signal

        opa_registry.validate(self.apps)
        connect_user_signal()
