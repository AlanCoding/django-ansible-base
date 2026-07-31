# Python
import logging

from django.apps import apps
from django.conf import settings

from ansible_base.jwt_consumer.common.auth import JWTAuthentication

logger = logging.getLogger('ansible_base.jwt_consumer.awx.auth')


class AwxJWTAuthentication(JWTAuthentication):
    use_rbac_permissions = True

    def process_permissions(self):
        super().process_permissions()
        saved_claims = getattr(self.common_auth, '_saved_claims', None)
        if saved_claims is not None:
            objects, object_roles, global_roles = saved_claims
            self._sync_old_rbac(self.common_auth.user, objects, object_roles)

    def _sync_old_rbac(self, user, objects, object_roles):
        """Sync old AWX Role.members to match the claims that were just processed.

        bulk_create skips post_save signals, so AWX's signal-based sync
        doesn't fire. This method replaces that by syncing directly from
        the claims dict.
        """
        try:
            from awx.main.models.rbac import ROLE_DEFINITION_TO_ROLE_FIELD, Role
            from awx.main.signals import disable_activity_stream
        except ImportError:
            return

        managed_field_names = set(ROLE_DEFINITION_TO_ROLE_FIELD.values())
        Resource = apps.get_model('dab_resource_registry', 'Resource')

        all_ansible_ids = set()
        for role_data in object_roles.values():
            ct = role_data['content_type']
            for idx in role_data['objects']:
                all_ansible_ids.add(objects[ct][idx]['ansible_id'])

        resource_map = {str(r.ansible_id): r for r in Resource.objects.filter(ansible_id__in=all_ansible_ids)}

        desired_role_pks = set()
        with disable_activity_stream():
            for role_name, role_data in object_roles.items():
                field_name = ROLE_DEFINITION_TO_ROLE_FIELD.get(role_name)
                if not field_name:
                    continue
                ct = role_data['content_type']
                for idx in role_data['objects']:
                    ansible_id = objects[ct][idx]['ansible_id']
                    resource = resource_map.get(ansible_id)
                    if resource is None:
                        continue
                    content_object = resource.content_object
                    if content_object is None:
                        continue
                    old_role = getattr(content_object, field_name, None)
                    if old_role is not None:
                        old_role.members.add(user)
                        desired_role_pks.add(old_role.pk)

            stale_roles = Role.objects.filter(
                members=user, role_field__in=managed_field_names,
            ).exclude(pk__in=desired_role_pks)
            for role in stale_roles:
                role.members.remove(user)
