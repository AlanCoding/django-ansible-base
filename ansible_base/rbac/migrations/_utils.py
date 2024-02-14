def give_permissions(apps, rd, users=(), teams=(), obj=None):
    """
    Give user permission to an object, but for use in migrations
    rd - role definition to grant the user
    users - list of users to give this permission to
    teams - list of teams to give this permission to
    obj - object that this permission applies to
    """
    ObjectRole = apps.get_model('dab_rbac', 'ObjectRole')
    ContentType = apps.get_model('contenttypes', 'ContentType')
    ct = ContentType.objects.get_for_model(obj)

    # Create the object role and add users to it
    object_role_fields = dict(role_definition=rd, object_id=obj.pk, content_type=ct)
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
        RoleUserAssignment.objects.bulk_create(user_assignments)
    if teams:
        RoleTeamAssignment = apps.get_model('dab_rbac', 'RoleTeamAssignment')
        team_assignments = [
            RoleTeamAssignment(object_role=object_role, team=team, **object_role_fields)
            for team in teams
        ]
        RoleTeamAssignment.objects.bulk_create(team_assignments)
