from collections import defaultdict
from typing import Any, Dict, Optional, Sequence, Tuple, Type

from django.apps import apps
from django.db import models as django_models
from django.db.models.options import Options
from django.utils.translation import gettext_lazy as _

from ..remote import get_remote_object_class, get_local_resource_prefix, RemoteObject


class DABContentTypeManager(django_models.Manager["DABContentType"]):
    """Manager storing DABContentType objects in a local cache like original ContentType.

    The major structural difference is that the cache keys have to add the service reference.
    """

    use_in_migrations = True

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._cache: Dict[str, Dict[Tuple[str, str, str] | int, "DABContentType"]] = {}

    def clear_cache(self) -> None:
        self._cache.clear()

    def create(self, *args: Any, **kwargs: Any) -> "DABContentType":
        obj = super().create(*args, **kwargs)
        self._add_to_cache(self.db, obj)
        return obj

    def _add_to_cache(self, using: str, ct: "DABContentType") -> None:
        """Store ``ct`` in the manager cache for the given database alias."""
        key = (ct.service, ct.app_label, ct.model)
        self._cache.setdefault(using, {})[key] = ct
        self._cache.setdefault(using, {})[ct.id] = ct

    def _get_from_cache(self, opts: Options, service: str) -> "DABContentType":
        """Return a cached ``DABContentType`` for ``opts`` and ``service``."""
        key = (service, opts.app_label, opts.model_name)
        return self._cache[self.db][key]

    def _get_opts(self, model: Type[django_models.Model], for_concrete_model: bool) -> Options:
        """Return the ``Options`` object for ``model``."""
        return model._meta.concrete_model._meta if for_concrete_model else model._meta

    def get_for_model(
        self,
        model: Type[django_models.Model],
        for_concrete_model: bool = True,
        service: Optional[str] = None,
    ) -> "DABContentType":
        if service is None:
            service = get_local_resource_prefix()
        opts = self._get_opts(model, for_concrete_model)
        try:
            return self._get_from_cache(opts, service)
        except KeyError:
            pass

        try:
            ct = self.get(service=service, app_label=opts.app_label, model=opts.model_name)
        except self.model.DoesNotExist:
            ct, _ = self.get_or_create(
                service=service,
                app_label=opts.app_label,
                model=opts.model_name,
            )
        self._add_to_cache(self.db, ct)
        return ct

    def get_for_models(
        self,
        *model_list: Type[django_models.Model],
        for_concrete_models: bool = True,
        service: Optional[str] = None,
    ) -> Dict[Type[django_models.Model], "DABContentType"]:
        """Return ``DABContentType`` objects for each model in ``model_list``."""
        if service is None:
            service = get_local_resource_prefix()
        results: Dict[Type[django_models.Model], "DABContentType"] = {}
        needed_models: Dict[str, set[str]] = defaultdict(set)
        needed_opts: Dict[Tuple[str, str], list[Type[django_models.Model]]] = defaultdict(list)
        for model in model_list:
            opts = self._get_opts(model, for_concrete_models)
            try:
                ct = self._get_from_cache(opts, service)
            except KeyError:
                needed_models[opts.app_label].add(opts.model_name)
                needed_opts[(opts.app_label, opts.model_name)].append(model)
            else:
                results[model] = ct

        if needed_opts:
            condition = django_models.Q(
                *(
                    django_models.Q(
                        ("service", service),
                        ("app_label", app_label),
                        ("model__in", models),
                    )
                    for app_label, models in needed_models.items()
                ),
                _connector=django_models.Q.OR,
            )
            cts = self.filter(condition)
            for ct in cts:
                opts_models = needed_opts.pop((ct.app_label, ct.model), [])
                for model in opts_models:
                    results[model] = ct
                self._add_to_cache(self.db, ct)
            for (app_label, model_name), opts_models in needed_opts.items():
                ct = self.create(service=service, app_label=app_label, model=model_name)
                self._add_to_cache(self.db, ct)
                for model in opts_models:
                    results[model] = ct
        return results

    def get_by_natural_key(self, *args: str) -> "DABContentType":
        """Return the content type identified by its natural key."""
        if len(args) == 2:
            service = get_local_resource_prefix()
            app_label, model = args
        else:
            service, app_label, model = args
        key = (service, app_label, model)
        try:
            return self._cache[self.db][key]
        except KeyError:
            ct = self.get(service=service, app_label=app_label, model=model)
            self._add_to_cache(self.db, ct)
            return ct

    def get_for_id(self, id: int) -> "DABContentType":
        """Return the content type with primary key ``id`` from the cache."""
        try:
            return self._cache[self.db][id]
        except KeyError:
            ct = self.get(pk=id)
            self._add_to_cache(self.db, ct)
            return ct


class DABContentType(django_models.Model):
    """Like Django ContentType model but scoped by service."""

    service = django_models.CharField(
        max_length=100,
        default=get_local_resource_prefix,
        help_text=_("service namespace to track what service this type is for. Can have a value of shared, which indicates it is synchronized."),
    )
    app_label = django_models.CharField(
        max_length=100,
        help_text=_("Django app that the model is in. This is an internal technical detail that does not affect API use."),
    )
    model = django_models.CharField(
        max_length=100,
        help_text=_("Name of the type according to the Django ORM Meta model_name convention. Comes from the python class, but lowercase with no spaces."),
    )

    objects = DABContentTypeManager()

    class Meta:
        unique_together = [
            ("service", "app_label", "model"),
        ]

    def __str__(self) -> str:
        return self.app_labeled_name

    @property
    def name(self) -> str:
        model = self.model_class()
        if not model:
            return self.model
        return str(model._meta.verbose_name)

    @property
    def app_labeled_name(self) -> str:
        model = self.model_class()
        if not model:
            return self.model
        return f"{model._meta.app_config.verbose_name} | {model._meta.verbose_name}"

    def model_class(self) -> Optional[Type[django_models.Model]]:
        """Return the model class if available for the current service."""
        if self.service not in ("shared", get_local_resource_prefix()):
            return None
        try:
            return apps.get_model(self.app_label, self.model)
        except LookupError:
            return None

    def get_object_for_this_type(self, **kwargs: Any) -> django_models.Model | RemoteObject:
        """Return the object referenced by this content type."""
        model = self.model_class()
        if model is None:
            object_id = kwargs.get("pk") or kwargs.get("id") or kwargs.get("pk__exact") or kwargs.get("id__exact")
            if object_id is None:
                raise LookupError("Model not available in this service")
            return get_remote_object_class()(self, object_id)
        return model._base_manager.get(**kwargs)

    def get_all_objects_for_this_type(self, **kwargs: Any) -> django_models.QuerySet | Sequence[django_models.Model | RemoteObject]:
        """Return all objects referenced by this content type."""
        model = self.model_class()
        if model is None:
            ids = kwargs.get("pk__in") or kwargs.get("id__in") or (kwargs.get("pk") and [kwargs["pk"]]) or (kwargs.get("id") and [kwargs["id"]])
            if not ids:
                return []
            return [get_remote_object_class()(self, obj_id) for obj_id in ids]
        return list(model._base_manager.filter(**kwargs))

    def natural_key(self) -> Tuple[str, str, str]:
        return (self.service, self.app_label, self.model)
