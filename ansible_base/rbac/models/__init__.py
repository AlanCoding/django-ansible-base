from django.db import connection

from .content_type import DABContentType
from .permission import DABPermission
from .role import RoleDefinition, RoleUserAssignment, RoleTeamAssignment, ObjectRole, RoleEvaluation, RoleEvaluationUUID

__all__ = [
    'DABContentType',
    'RoleDefinition',
    'DABPermission',
    'RoleUserAssignment',
    'RoleTeamAssignment',
    'ObjectRole',
    'RoleEvaluation',
    'RoleEvaluationUUID',
    'get_evaluation_model',
]


def get_evaluation_model(cls):
    pk_field = cls._meta.pk
    # For proxy models, including django-polymorphic, use the id field from parent table
    # we accomplish this by inspecting the raw database type of the field
    pk_db_type = pk_field.db_type(connection)
    for eval_cls in (RoleEvaluation, RoleEvaluationUUID):
        if pk_db_type == eval_cls._meta.get_field('object_id').db_type(connection):
            return eval_cls
    # HACK: integer pk caching is handled by same model for now, better to use default pk type later
    # the integer unsigned case happens in AWX in sqlite3 specifically
    if pk_db_type in ('bigint', 'integer', 'integer unsigned'):
        return RoleEvaluation

    raise RuntimeError(f'Model {cls._meta.model_name} primary key type of {type(pk_field)} (db type {pk_db_type}) is not supported')
