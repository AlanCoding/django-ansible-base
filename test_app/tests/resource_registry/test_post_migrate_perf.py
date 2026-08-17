"""Profile NOT IN vs NOT EXISTS under low work_mem with actual execution."""

import time

import pytest
from django.contrib.contenttypes.models import ContentType
from django.db import connection
from django.db.models import Exists, OuterRef, TextField
from django.db.models.functions import Cast

from ansible_base.resource_registry.models import Resource, init_resource_from_object
from ansible_base.resource_registry.registry import get_registry
from test_app.models import Organization


def _create_orgs_with_resources(n):
    ct = ContentType.objects.get_for_model(Organization)
    registry = get_registry()
    resource_config = registry.get_config_for_model(Organization)

    batch = 500
    for start in range(0, n, batch):
        end = min(start + batch, n)
        orgs = Organization.objects.bulk_create([Organization(name=f"perf-org-{i}") for i in range(start, end)])
        resources = [init_resource_from_object(org, resource_config=resource_config) for org in orgs]
        Resource.objects.bulk_create(resources, ignore_conflicts=True)

    return ct


def _explain_analyze(qs):
    sql, params = qs.query.sql_with_params()
    with connection.cursor() as c:
        c.execute(f"EXPLAIN ANALYZE {sql}", params)
        return [row[0] for row in c.fetchall()]


@pytest.mark.django_db
@pytest.mark.parametrize("n", [5_000, 10_000])
def test_pr1094_wall_clock(n):
    """Get actual execution times under low work_mem."""
    if connection.vendor != 'postgresql':
        pytest.skip("PostgreSQL-specific")

    ct = _create_orgs_with_resources(n)

    with connection.cursor() as c:
        c.execute("ANALYZE test_app_organization")
        c.execute("ANALYZE dab_resource_registry_resource")

    original_qs = Organization.objects.annotate(pk_text=Cast('pk', TextField())).exclude(
        pk_text__in=Resource.objects.filter(content_type=ct).values("object_id")
    )
    pr_qs = Organization.objects.annotate(pk_text=Cast('pk', TextField())).exclude(
        Exists(Resource.objects.filter(content_type=ct, object_id=OuterRef('pk_text')))
    )

    with connection.cursor() as c:
        c.execute("SET LOCAL work_mem = '64kB'")

        print(f"\n--- {n} orgs, work_mem=64kB, ANALYZE'd ---")

        print(f"\nOriginal (NOT IN):")
        for line in _explain_analyze(original_qs):
            print(f"  {line}")

        print(f"\nPR #1094 (NOT EXISTS):")
        for line in _explain_analyze(pr_qs):
            print(f"  {line}")
