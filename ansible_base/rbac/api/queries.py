from typing import Union

from django.db.models import Model

from ..models import DABContentType, get_evaluation_model
from ..remote import RemoteObject


def assignment_qs_user_to_obj(actor: Model, obj: Union[Model, RemoteObject]):
    """Queryset of assignments (team or user) that grants the actor any form of permission to obj"""
    evaluation_cls = get_evaluation_model(obj)
    ct = DABContentType.objects.get_for_model(obj)
    reverse_name = evaluation_cls._meta.get_field('role').remote_field.name

    # All relevant assignments for the object
    obj_eval_qs = evaluation_cls.objects.filter(object_id=obj.pk, content_type_id=ct.id)
    obj_assignment_qs = actor.role_assignments.filter(**{f'object_role__{reverse_name}__in': obj_eval_qs})

    global_assignment_qs = actor.role_assignments.filter(content_type=None, role_definition__permissions__content_type=ct)

    return (global_assignment_qs | obj_assignment_qs).distinct()


def assignment_qs_user_to_obj_perm(actor: Model, obj: Union[Model, RemoteObject], permission: Model):
    """Queryset of assignments that grants this specific permission to this specific object"""
    evaluation_cls = get_evaluation_model(obj)
    ct = DABContentType.objects.get_for_model(obj)
    reverse_name = evaluation_cls._meta.get_field('role').remote_field.name

    obj_eval_qs = evaluation_cls.objects.filter(codename=permission.codename, object_id=obj.pk, content_type_id=ct.id)
    obj_assignment_qs = actor.role_assignments.filter(**{f'object_role__{reverse_name}__in': obj_eval_qs})

    global_assignment_qs = actor.role_assignments.filter(content_type=None, role_definition__permissions=permission)

    return (global_assignment_qs | obj_assignment_qs).distinct()
