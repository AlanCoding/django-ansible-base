from django.contrib.contenttypes.fields import GenericForeignKey as DjangoGenericForeignKey
from django.core import checks
from django.core.exceptions import FieldDoesNotExist, ObjectDoesNotExist
from django.db import DEFAULT_DB_ALIAS, models
from django.db.models import DO_NOTHING, ForeignObject, ForeignObjectRel
from django.db.models.base import ModelBase, make_foreign_order_accessors
from django.db.models.fields.related import lazy_related_operation
from django.db.models.query_utils import PathInfo
from django.db.models.sql import AND
from django.db.models.sql.where import WhereNode

from ..remote import get_local_resource_prefix
from .content_type import DABContentType


class FederatedForeignKey(DjangoGenericForeignKey):
    """A GenericForeignKey variant aware of service boundaries."""

    def __init__(
        self,
        ct_field="content_type",
        fk_field="object_id",
        for_concrete_model=True,
    ):
        super().__init__(ct_field=ct_field, fk_field=fk_field, for_concrete_model=for_concrete_model)

    def _check_content_type_field(self):
        try:
            field = self.model._meta.get_field(self.ct_field)
        except FieldDoesNotExist:
            return [
                checks.Error(
                    "The GenericForeignKey content type references the nonexistent field '%s.%s'." % (self.model._meta.object_name, self.ct_field),
                    obj=self,
                    id="contenttypes.E002",
                )
            ]
        else:
            if not isinstance(field, models.ForeignKey):
                return [
                    checks.Error(
                        "'%s.%s' is not a ForeignKey." % (self.model._meta.object_name, self.ct_field),
                        hint=("GenericForeignKeys must use a ForeignKey to 'federated_foreign_key.DABContentType' as the 'content_type' field."),
                        obj=self,
                        id="contenttypes.E003",
                    )
                ]
            elif field.remote_field.model != DABContentType:
                return [
                    checks.Error(
                        "'%s.%s' is not a ForeignKey to 'federated_foreign_key.DABContentType'." % (self.model._meta.object_name, self.ct_field),
                        hint=("GenericForeignKeys must use a ForeignKey to 'federated_foreign_key.DABContentType' as the 'content_type' field."),
                        obj=self,
                        id="contenttypes.E004",
                    )
                ]
            else:
                return []

    def get_content_type(self, obj=None, id=None, using=None, model=None):
        if obj is not None:
            return DABContentType.objects.db_manager(obj._state.db).get_for_model(
                obj.__class__,
            )
        elif id is not None:
            return DABContentType.objects.db_manager(using).get_for_id(id)
        elif model is not None:
            return DABContentType.objects.db_manager(using).get_for_model(model)
        else:
            raise Exception("Impossible arguments to get_content_type")

    def __get__(self, instance, cls=None):
        if instance is None:
            return self
        f = instance._meta.get_field(self.ct_field)
        ct_id = getattr(instance, f.attname, None)
        pk_val = getattr(instance, self.fk_field)
        rel_obj = self.get_cached_value(instance, default=None)
        if rel_obj is None and self.is_cached(instance):
            return rel_obj
        if rel_obj is not None:
            ct_match = ct_id == self.get_content_type(obj=rel_obj).id
            pk_match = ct_match and rel_obj.pk == pk_val
            if pk_match:
                return rel_obj
            else:
                rel_obj = None
        if ct_id is not None:
            ct = self.get_content_type(id=ct_id)
            if ct.service in (get_local_resource_prefix(), "shared"):
                try:
                    rel_obj = ct.get_object_for_this_type(pk=pk_val)
                except (ObjectDoesNotExist, LookupError):
                    rel_obj = None
            else:
                rel_obj = ct.get_object_for_this_type(pk=pk_val)
        self.set_cached_value(instance, rel_obj)
        return rel_obj


class FederatedRel(ForeignObjectRel):
    def __init__(
        self,
        field,
        to,
        related_name=None,
        related_query_name=None,
        limit_choices_to=None,
    ):
        super().__init__(
            field,
            to,
            related_name=related_query_name or "+",
            related_query_name=related_query_name,
            limit_choices_to=limit_choices_to,
            on_delete=DO_NOTHING,
        )


class FederatedRelation(ForeignObject):
    auto_created = False
    empty_strings_allowed = False

    many_to_many = False
    many_to_one = False
    one_to_many = True
    one_to_one = False

    rel_class = FederatedRel

    mti_inherited = False

    def __init__(
        self,
        to,
        object_id_field="object_id",
        content_type_field="content_type",
        for_concrete_model=True,
        related_query_name=None,
        limit_choices_to=None,
        **kwargs,
    ):
        kwargs["rel"] = self.rel_class(
            self,
            to,
            related_query_name=related_query_name,
            limit_choices_to=limit_choices_to,
        )
        kwargs["null"] = True
        kwargs["blank"] = True
        kwargs["on_delete"] = models.CASCADE
        kwargs["editable"] = False
        kwargs["serialize"] = False
        super().__init__(to, from_fields=[object_id_field], to_fields=[], **kwargs)
        self.object_id_field_name = object_id_field
        self.content_type_field_name = content_type_field
        self.for_concrete_model = for_concrete_model

    def check(self, **kwargs):
        return [
            *super().check(**kwargs),
            *self._check_generic_foreign_key_existence(),
        ]

    def _is_matching_generic_foreign_key(self, field):
        return isinstance(field, FederatedForeignKey) and field.ct_field == self.content_type_field_name and field.fk_field == self.object_id_field_name

    def _check_generic_foreign_key_existence(self):
        target = self.remote_field.model
        if isinstance(target, ModelBase):
            fields = target._meta.private_fields
            if any(self._is_matching_generic_foreign_key(field) for field in fields):
                return []
            else:
                return [
                    checks.Error(
                        ("The GenericRelation defines a relation with the model '%s', but that model does not have a GenericForeignKey.") % target._meta.label,
                        obj=self,
                        id="contenttypes.E004",
                    )
                ]
        else:
            return []

    def resolve_related_fields(self):
        self.to_fields = [self.model._meta.pk.name]
        return [
            (
                self.remote_field.model._meta.get_field(self.object_id_field_name),
                self.model._meta.pk,
            )
        ]

    def get_local_related_value(self, instance):
        return self.get_instance_value_for_fields(instance, self.foreign_related_fields)

    def get_foreign_related_value(self, instance):
        return tuple(
            foreign_field.to_python(val)
            for foreign_field, val in zip(
                self.foreign_related_fields,
                self.get_instance_value_for_fields(instance, self.local_related_fields),
            )
        )

    def _get_path_info_with_parent(self, filtered_relation):
        path = []
        opts = self.remote_field.model._meta.concrete_model._meta
        parent_opts = opts.get_field(self.object_id_field_name).model._meta
        target = parent_opts.pk
        path.append(
            PathInfo(
                from_opts=self.model._meta,
                to_opts=parent_opts,
                target_fields=(target,),
                join_field=self.remote_field,
                m2m=True,
                direct=False,
                filtered_relation=filtered_relation,
            )
        )
        parent_field_chain = []
        while parent_opts != opts:
            field = opts.get_ancestor_link(parent_opts.model)
            parent_field_chain.append(field)
            opts = field.remote_field.model._meta
        parent_field_chain.reverse()
        for field in parent_field_chain:
            path.extend(field.remote_field.path_infos)
        return path

    def get_path_info(self, filtered_relation=None):
        opts = self.remote_field.model._meta
        object_id_field = opts.get_field(self.object_id_field_name)
        if object_id_field.model != opts.model:
            return self._get_path_info_with_parent(filtered_relation)
        else:
            target = opts.pk
            return [
                PathInfo(
                    from_opts=self.model._meta,
                    to_opts=opts,
                    target_fields=(target,),
                    join_field=self.remote_field,
                    m2m=True,
                    direct=False,
                    filtered_relation=filtered_relation,
                )
            ]

    def get_reverse_path_info(self, filtered_relation=None):
        opts = self.model._meta
        from_opts = self.remote_field.model._meta
        return [
            PathInfo(
                from_opts=from_opts,
                to_opts=opts,
                target_fields=(opts.pk,),
                join_field=self,
                m2m=False,
                direct=False,
                filtered_relation=filtered_relation,
            )
        ]

    def value_to_string(self, obj):
        qs = getattr(obj, self.name).all()
        return str([instance.pk for instance in qs])

    def contribute_to_class(self, cls, name, **kwargs):
        kwargs["private_only"] = True
        super().contribute_to_class(cls, name, **kwargs)
        self.model = cls
        if self.mti_inherited:
            self.remote_field.related_name = "+"
            self.remote_field.related_query_name = None
        # NOTE: standard for GenericForeignKey but we will not just not use reverse relations
        # setattr(cls, self.name, ReverseFederatedManyToOneDescriptor(self.remote_field))

        if not cls._meta.abstract:

            def make_generic_foreign_order_accessors(related_model, model):
                if self._is_matching_generic_foreign_key(model._meta.order_with_respect_to):
                    make_foreign_order_accessors(model, related_model)

            lazy_related_operation(
                make_generic_foreign_order_accessors,
                self.model,
                self.remote_field.model,
            )

    def set_attributes_from_rel(self):
        pass

    def get_internal_type(self):
        return "ManyToManyField"

    def get_content_type(self):
        return DABContentType.objects.get_for_model(self.model, for_concrete_model=self.for_concrete_model)

    def get_extra_restriction(self, alias, remote_alias):
        field = self.remote_field.model._meta.get_field(self.content_type_field_name)
        contenttype_pk = self.get_content_type().pk
        lookup = field.get_lookup("exact")(field.get_col(remote_alias), contenttype_pk)
        return WhereNode([lookup], connector=AND)

    def bulk_related_objects(self, objs, using=DEFAULT_DB_ALIAS):
        return self.remote_field.model._base_manager.db_manager(using).filter(
            **{
                f"{self.content_type_field_name}__pk": DABContentType.objects.db_manager(using)
                .get_for_model(self.model, for_concrete_model=self.for_concrete_model)
                .pk,
                f"{self.object_id_field_name}__in": [obj.pk for obj in objs],
            }
        )
