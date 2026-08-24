from unittest.mock import MagicMock

import pytest

from ansible_base.rbac.models import RoleDefinition
from ansible_base.rbac.pipeline import bulk_give_permissions, bulk_remove_permissions
from ansible_base.rbac.signals import dab_rbac_assignments_created, dab_rbac_assignments_pre_delete
from test_app.models import Inventory, User


@pytest.mark.django_db
class TestBulkAssignmentCreatedSignal:
    """Tests for dab_rbac_assignments_created signal."""

    def test_bulk_give_fires_created_signal(self, organization, rando, org_inv_rd):
        """bulk_give_permissions with 2+ user triples should fire signal once with all assignments."""
        second_user = User.objects.create(username='signal-user-2')
        mck = MagicMock()
        dab_rbac_assignments_created.connect(mck.signal_handler, dispatch_uid='test-created')

        try:
            assignments = bulk_give_permissions(
                user_permissions=[
                    (org_inv_rd, rando, organization),
                    (org_inv_rd, second_user, organization),
                ]
            )

            mck.signal_handler.assert_called_once()
            call_kwargs = mck.signal_handler.call_args.kwargs
            assert 'assignment_data' in call_kwargs
            assignment_data = call_kwargs['assignment_data']
            assert len(assignment_data) == 2
            # Verify it's a list of tuples
            for item in assignment_data:
                assert isinstance(item, tuple) and len(item) == 2
                assignment, content_object = item
                assert assignment in assignments
                assert content_object == organization
        finally:
            dab_rbac_assignments_created.disconnect(mck.signal_handler, dispatch_uid='test-created')

    def test_single_give_permission_fires_created_signal(self, organization, rando, org_inv_rd):
        """RoleDefinition.give_permission() should fire signal with a 1-element list."""
        mck = MagicMock()
        dab_rbac_assignments_created.connect(mck.signal_handler, dispatch_uid='test-single')

        try:
            assignment = org_inv_rd.give_permission(rando, organization)

            mck.signal_handler.assert_called_once()
            call_kwargs = mck.signal_handler.call_args.kwargs
            assert 'assignment_data' in call_kwargs
            assignment_data = call_kwargs['assignment_data']
            assert len(assignment_data) == 1
            assert assignment_data[0][0] == assignment
            # Content object may be None for single give_permission calls
        finally:
            dab_rbac_assignments_created.disconnect(mck.signal_handler, dispatch_uid='test-single')

    def test_bulk_give_idempotent_no_signal(self, organization, rando, org_inv_rd):
        """Giving the same permissions twice should not fire signal on the second call."""
        # First call creates the assignment
        bulk_give_permissions(user_permissions=[(org_inv_rd, rando, organization)])

        # Second call should be idempotent (no new assignments created)
        mck = MagicMock()
        dab_rbac_assignments_created.connect(mck.signal_handler, dispatch_uid='test-idempotent')

        try:
            assignments = bulk_give_permissions(user_permissions=[(org_inv_rd, rando, organization)])

            # Signal should not fire if no new assignments were created
            if not assignments or all(a.pk is None for a in assignments):
                mck.signal_handler.assert_not_called()
        finally:
            dab_rbac_assignments_created.disconnect(mck.signal_handler, dispatch_uid='test-idempotent')

    def test_bulk_give_team_fires_created_signal(self, organization, team, inv_rd):
        """bulk_give_permissions with team triples should include team assignments in signal."""
        inv = Inventory.objects.create(name='signal-inv', organization=organization)
        mck = MagicMock()
        dab_rbac_assignments_created.connect(mck.signal_handler, dispatch_uid='test-team')

        try:
            assignments = bulk_give_permissions(team_permissions=[(inv_rd, team, inv)])

            mck.signal_handler.assert_called_once()
            call_kwargs = mck.signal_handler.call_args.kwargs
            assignment_data = call_kwargs['assignment_data']
            assert len(assignment_data) == 1
            assignment, content_object = assignment_data[0]
            assert assignment == assignments[0]
            assert assignment.team == team
            assert content_object == inv
        finally:
            dab_rbac_assignments_created.disconnect(mck.signal_handler, dispatch_uid='test-team')

    def test_bulk_give_mixed_fires_created_signal(self, organization, team, rando, inv_rd):
        """Mix of user and team triples should all appear in one signal."""
        inv = Inventory.objects.create(name='mixed-inv', organization=organization)
        mck = MagicMock()
        dab_rbac_assignments_created.connect(mck.signal_handler, dispatch_uid='test-mixed')

        try:
            assignments = bulk_give_permissions(
                user_permissions=[(inv_rd, rando, inv)],
                team_permissions=[(inv_rd, team, inv)],
            )

            mck.signal_handler.assert_called_once()
            call_kwargs = mck.signal_handler.call_args.kwargs
            assignment_data = call_kwargs['assignment_data']
            assert len(assignment_data) == 2
            for assignment, content_object in assignment_data:
                assert assignment in assignments
                assert content_object == inv
        finally:
            dab_rbac_assignments_created.disconnect(mck.signal_handler, dispatch_uid='test-mixed')

    def test_created_signal_fires_regardless_of_fire_signals_flag(self, organization, rando, org_inv_rd):
        """Signal should fire regardless of fire_signals_on_create flag."""
        mck = MagicMock()
        dab_rbac_assignments_created.connect(mck.signal_handler, dispatch_uid='test-flag')

        try:
            assignments = bulk_give_permissions(
                user_permissions=[(org_inv_rd, rando, organization)],
                fire_signals_on_create=False,
            )

            mck.signal_handler.assert_called_once()
            call_kwargs = mck.signal_handler.call_args.kwargs
            assignment_data = call_kwargs['assignment_data']
            assert len(assignment_data) == 1
            assert assignment_data[0][0] == assignments[0]
        finally:
            dab_rbac_assignments_created.disconnect(mck.signal_handler, dispatch_uid='test-flag')


@pytest.mark.django_db
class TestBulkAssignmentPreDeleteSignal:
    """Tests for dab_rbac_assignments_pre_delete signal."""

    def test_bulk_remove_fires_pre_delete_signal(self, organization, rando, org_inv_rd):
        """bulk_remove_permissions with 2+ triples should fire signal once before deletion."""
        second_user = User.objects.create(username='rm-signal-user-2')
        bulk_give_permissions(
            user_permissions=[
                (org_inv_rd, rando, organization),
                (org_inv_rd, second_user, organization),
            ]
        )

        mck = MagicMock()
        dab_rbac_assignments_pre_delete.connect(mck.signal_handler, dispatch_uid='test-pre-delete')

        try:
            bulk_remove_permissions(
                user_permissions=[
                    (org_inv_rd, rando, organization),
                    (org_inv_rd, second_user, organization),
                ]
            )

            mck.signal_handler.assert_called_once()
            call_kwargs = mck.signal_handler.call_args.kwargs
            assignment_data = call_kwargs['assignment_data']
            assert len(assignment_data) == 2
            for assignment, content_object in assignment_data:
                assert content_object == organization
        finally:
            dab_rbac_assignments_pre_delete.disconnect(mck.signal_handler, dispatch_uid='test-pre-delete')

    def test_single_remove_permission_fires_pre_delete_signal(self, organization, rando, org_inv_rd):
        """RoleDefinition.remove_permission() should fire signal."""
        org_inv_rd.give_permission(rando, organization)

        mck = MagicMock()
        dab_rbac_assignments_pre_delete.connect(mck.signal_handler, dispatch_uid='test-single-rm')

        try:
            org_inv_rd.remove_permission(rando, organization)

            mck.signal_handler.assert_called_once()
            call_kwargs = mck.signal_handler.call_args.kwargs
            assignment_data = call_kwargs['assignment_data']
            assert len(assignment_data) == 1
        finally:
            dab_rbac_assignments_pre_delete.disconnect(mck.signal_handler, dispatch_uid='test-single-rm')

    def test_pre_delete_signal_has_valid_assignments(self, organization, rando, org_inv_rd):
        """Signal handler should be able to read assignment data before deletion."""
        org_inv_rd.give_permission(rando, organization)

        captured_data = {}

        def capture_assignment_data(sender, assignment_data, **kwargs):
            # Read assignment data — this should not raise because the signal
            # fires BEFORE deletion
            assignment, content_object = assignment_data[0]
            captured_data['role_name'] = assignment.role_definition.name
            captured_data['object_id'] = assignment.object_id
            captured_data['user_id'] = assignment.user_id
            captured_data['content_object'] = content_object

        dab_rbac_assignments_pre_delete.connect(capture_assignment_data, dispatch_uid='test-valid')

        try:
            bulk_remove_permissions(user_permissions=[(org_inv_rd, rando, organization)])

            assert 'role_name' in captured_data
            assert captured_data['role_name'] == org_inv_rd.name
            assert captured_data['object_id'] == str(organization.pk)
            assert captured_data['user_id'] == rando.pk
            assert captured_data['content_object'] == organization
        finally:
            dab_rbac_assignments_pre_delete.disconnect(capture_assignment_data, dispatch_uid='test-valid')

    def test_remove_nonexistent_no_signal(self, organization, rando, org_inv_rd):
        """Removing permissions that don't exist should not fire signal."""
        # Don't create the permission first
        mck = MagicMock()
        dab_rbac_assignments_pre_delete.connect(mck.signal_handler, dispatch_uid='test-nonexistent')

        try:
            bulk_remove_permissions(user_permissions=[(org_inv_rd, rando, organization)])

            mck.signal_handler.assert_not_called()
        finally:
            dab_rbac_assignments_pre_delete.disconnect(mck.signal_handler, dispatch_uid='test-nonexistent')

    def test_pre_delete_signal_with_teams(self, organization, team, inv_rd):
        """Signal should fire for team assignment removal."""
        inv = Inventory.objects.create(name='rm-team-inv', organization=organization)
        bulk_give_permissions(team_permissions=[(inv_rd, team, inv)])

        mck = MagicMock()
        dab_rbac_assignments_pre_delete.connect(mck.signal_handler, dispatch_uid='test-team-rm')

        try:
            bulk_remove_permissions(team_permissions=[(inv_rd, team, inv)])

            mck.signal_handler.assert_called_once()
            call_kwargs = mck.signal_handler.call_args.kwargs
            assignment_data = call_kwargs['assignment_data']
            assert len(assignment_data) == 1
            assignment, content_object = assignment_data[0]
            assert assignment.team == team
            assert content_object == inv
        finally:
            dab_rbac_assignments_pre_delete.disconnect(mck.signal_handler, dispatch_uid='test-team-rm')

    def test_pre_delete_mixed_assignments(self, organization, team, rando, inv_rd):
        """Mix of user and team removals should all appear in one signal."""
        inv = Inventory.objects.create(name='mixed-rm-inv', organization=organization)
        bulk_give_permissions(
            user_permissions=[(inv_rd, rando, inv)],
            team_permissions=[(inv_rd, team, inv)],
        )

        mck = MagicMock()
        dab_rbac_assignments_pre_delete.connect(mck.signal_handler, dispatch_uid='test-mixed-rm')

        try:
            bulk_remove_permissions(
                user_permissions=[(inv_rd, rando, inv)],
                team_permissions=[(inv_rd, team, inv)],
            )

            mck.signal_handler.assert_called_once()
            call_kwargs = mck.signal_handler.call_args.kwargs
            assignment_data = call_kwargs['assignment_data']
            assert len(assignment_data) == 2
            for assignment, content_object in assignment_data:
                assert content_object == inv
        finally:
            dab_rbac_assignments_pre_delete.disconnect(mck.signal_handler, dispatch_uid='test-mixed-rm')
