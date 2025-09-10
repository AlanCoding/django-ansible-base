import logging
from datetime import datetime
from django.db import models

logger = logging.getLogger(__name__)

# This method has moved, and this is put here temporarily to make branch management easier
from ansible_base.rbac.management import create_dab_permissions as create_custom_permissions  # noqa


def give_permissions(apps, rd, users=(), teams=(), object_id=None, content_type_id=None):
    """
    Give user permission to an object, but for use in migrations
    rd - role definition to grant the user
    users - list of users to give this permission to
    teams - list of teams to give this permission to, can be objects or id list

    target object is implicitly specified by
    object_id - primary key of the object permission will apply to
    content_type_id - primary key of the content type for the object
    """
    ObjectRole = apps.get_model('dab_rbac', 'ObjectRole')

    # Create the object role and add users to it
    object_role_fields = dict(role_definition=rd, object_id=object_id, content_type_id=content_type_id)
    object_role, _ = ObjectRole.objects.get_or_create(**object_role_fields)

    if users:
        # Django seems to not process through_fields correctly in migrations
        # so it will use created_by as the target field name, which is incorrect, should be user
        # basically can not use object_role.users.add(actor)
        RoleUserAssignment = apps.get_model('dab_rbac', 'RoleUserAssignment')
        user_assignments = [
            RoleUserAssignment(object_role=object_role, user=user, **object_role_fields)
            for user in users
        ]
        RoleUserAssignment.objects.bulk_create(user_assignments, ignore_conflicts=True)
    if teams:
        RoleTeamAssignment = apps.get_model('dab_rbac', 'RoleTeamAssignment')
        # AWX has trouble getting the team object, conditionally accept team id list
        if isinstance(teams[0], models.Model):
            team_assignments = [
                RoleTeamAssignment(object_role=object_role, team=team, **object_role_fields)
                for team in teams
            ]
        else:
            team_assignments = [
                RoleTeamAssignment(object_role=object_role, team_id=team_id, **object_role_fields)
                for team_id in teams
            ]
        RoleTeamAssignment.objects.bulk_create(team_assignments, ignore_conflicts=True)


def get_model_class_from_content_type(apps, content_type):
    """
    Get a model class from a content type in a migration-safe way.

    This is needed because content_type.model_class() is not available in migrations.
    """
    try:
        return apps.get_model(content_type.app_label, content_type.model)
    except (LookupError, AttributeError):
        return None


def populate_object_created_field(apps, schema_editor=None):
    """Populate the object_created field for existing role assignments."""
    assignment_models = [
        ('roleuserassignment', 'RoleUserAssignment'),
        ('roleteamassignment', 'RoleTeamAssignment'),
    ]

    updated_count = 0

    for model_name, model_class_name in assignment_models:
        assignment_cls = apps.get_model('dab_rbac', model_name)
        assignments_to_update = assignment_cls.objects.filter(object_created__isnull=True)

        for assignment in assignments_to_update:
            object_created_value = None

            # Try to get the actual object to extract its created timestamp
            if assignment.object_id and assignment.content_type:
                try:
                    # Get the model class from the old content_type field (before migration to DABContentType)
                    model_class = get_model_class_from_content_type(apps, assignment.content_type)
                    if model_class:
                        try:
                            # Try to get the actual object
                            actual_object = model_class.objects.get(pk=assignment.object_id)

                            # Try to get created timestamp from common field names
                            for field_name in ('created', 'created_at'):
                                if hasattr(actual_object, field_name):
                                    val = getattr(actual_object, field_name)
                                    if isinstance(val, datetime):
                                        object_created_value = val
                                        break
                        except (model_class.DoesNotExist, ValueError, TypeError):
                            # Object doesn't exist or can't be retrieved, skip
                            pass
                except (AttributeError, LookupError):
                    # Content type or model class issues, skip
                    pass

            # Update the assignment if we found a created timestamp
            if object_created_value:
                assignment.object_created = object_created_value
                assignment.save(update_fields=['object_created'])
                updated_count += 1

    if updated_count:
        logger.info(f'Populated object_created field for {updated_count} existing role assignments')

    return updated_count
