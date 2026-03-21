# Removing DAB RBAC

This document describes what must happen before `ansible_base.rbac` can be
removed from django-ansible-base. This work **cannot** happen as part of the
DAB OPA patch — it depends on every downstream application completing its own
migration first.

## Prerequisites for downstream applications

Each application that currently uses `ansible_base.rbac` (AWX, Gateway, EDA,
and any other consumers) must complete the following before RBAC removal can
proceed:

1. **Adopt DAB OPA as the authorization backend.**
   - Add `ansible_base.opa` to `INSTALLED_APPS`.
   - Register all permissioned models in the OPA registry.
   - Replace `AnsibleBaseObjectPermissions` (or equivalent RBAC permission
     classes) with `OPAPermission` on all viewsets.
   - Replace RBAC queryset filtering with OPA queryset filtering.

2. **Run the RBAC-to-OPA migration.**
   - Execute `manage.py migrate_rbac_to_opa` to convert existing role
     assignments into OPA roles, policies, groups, and assignments.
   - Use `--verify` mode during a transition period to confirm parity.

3. **Remove all references to `ansible_base.rbac`.**
   - Drop `ansible_base.rbac` from `INSTALLED_APPS`.
   - Remove imports of RBAC models, mixins, permission classes, and utilities.
   - Remove or replace any RBAC-specific test fixtures and assertions.

4. **Validate in CI and staging.**
   - Confirm that the application's full test suite passes without
     `ansible_base.rbac` installed.
   - Run the transition validation (`DAB_OPA_TRANSITION_VALIDATION`) in a
     staging environment with production-like data before cutting over.

## Removal steps in DAB (after all downstream apps have migrated)

Once no downstream consumer depends on `ansible_base.rbac`:

1. Remove `ansible_base.rbac` from the DAB codebase.
2. Remove RBAC references from shared DAB apps (`api_documentation`, view
   mixins, etc.).
3. Remove the transition validation setting and dual-evaluation logic.
4. Remove the `migrate_rbac_to_opa` management command (or keep it for one
   release cycle if any late adopters need it).
5. Remove RBAC test fixtures and tests from `test_app`.

## Timeline

No target date is set. Removal is blocked until all known downstream consumers
have completed their migration and confirmed they no longer depend on
`ansible_base.rbac`.
