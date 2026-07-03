"""FastAPI router for the Phase 1 governance authoring surface.

Warehouse-style governance endpoints under `/v1/{prefix}/governance/*`. Kept in
its own module + mounted via `include_router` so the core Iceberg REST
server (server.py) stays essentially untouched — the governance layer is an
additive, independently-removable experiment.

Authorization: these paths live under `/v1/` so the existing
`bearer_auth_middleware` already gates them. Because the paths contain no
`namespaces` segment, `request_namespace()` returns None and `scope_allows`
only passes a wildcard (`*:*:*`) token — i.e. governance authoring is
admin-only by construction in Phase 1, which is what we want. The principal
is decoded here purely for audit attribution.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from .auth import AuthConfig, claims_from_request
from .catalog import DuckLakeCatalog
from .config import Settings
from .governance import (
    ATTACH_TARGETS,
    OBJECT_KINDS,
    POLICY_KINDS,
    VALID_ATTACH_TARGETS,
    GovernanceConflict,
    GovernanceStore,
)
from .policies import PolicyEngine


# ---- request models ---------------------------------------------------

class CreateTagRequest(BaseModel):
    tag_ns: str = Field(alias="namespace")
    tag_name: str = Field(alias="name")
    allowed_values: list[str] | None = Field(default=None, alias="allowed-values")
    model_config = {"populate_by_name": True}


class AssignObjectTagRequest(BaseModel):
    object_kind: str = Field(alias="object-kind")
    schema_name: str = Field(alias="schema")
    object_name: str = Field(default="", alias="object")
    column_name: str = Field(default="", alias="column")
    tag_ns: str = Field(alias="tag-namespace")
    tag_name: str = Field(alias="tag-name")
    tag_value: str | None = Field(default=None, alias="value")
    model_config = {"populate_by_name": True}


class CreatePolicyRequest(BaseModel):
    name: str
    signature_sql: str = Field(alias="signature")
    body_sql: str = Field(alias="body")
    # Roles that bypass this policy (Phase 2 enforcement). A principal
    # holding any of these sees unmasked data / unfiltered rows.
    unmasked_roles: list[str] | None = Field(default=None, alias="unmasked-roles")
    # Phase 4: also materialize the mask physically as masked Parquet
    # copies (byte-level enforcement for direct Parquet readers; more
    # storage). Masking policies only — ignored on row-access policies.
    file_layer_masking: bool = Field(default=False, alias="file-layer-masking")
    model_config = {"populate_by_name": True}


class AttachPolicyRequest(BaseModel):
    policy_kind: str = Field(alias="policy-kind")
    policy_name: str = Field(alias="policy-name")
    target_kind: str = Field(alias="target-kind")
    tag_ns: str | None = Field(default=None, alias="tag-namespace")
    tag_name: str | None = Field(default=None, alias="tag-name")
    schema_name: str | None = Field(default=None, alias="schema")
    object_name: str | None = Field(default=None, alias="object")
    column_name: str | None = Field(default=None, alias="column")
    columns: list[str] | None = None
    model_config = {"populate_by_name": True}


class CreateRoleRequest(BaseModel):
    role_name: str = Field(alias="name")
    model_config = {"populate_by_name": True}


class RoleGrantRequest(BaseModel):
    role_name: str = Field(alias="role")
    principal_sub: str = Field(alias="principal")
    model_config = {"populate_by_name": True}


class ObjectGrantRequest(BaseModel):
    object_kind: str = Field(alias="object-kind")
    schema_name: str = Field(alias="schema")
    object_name: str = Field(default="", alias="object")
    privilege: str
    role_name: str = Field(alias="role")
    model_config = {"populate_by_name": True}


class StaticS3KeyRequest(BaseModel):
    principal: str
    access_key_id: str = Field(alias="access-key-id")
    # Optional: storing the secret server-side enables turnkey vending via
    # ducklake-credentials, at the cost of the governance DB holding a
    # project-scoped storage secret. Recommended: omit; clients keep it.
    secret_access_key: str | None = Field(default=None, alias="secret-access-key")
    note: str | None = None
    model_config = {"populate_by_name": True}


def build_governance_router(
    catalog: DuckLakeCatalog,
    settings: Settings,
    auth_cfg: AuthConfig,
    on_table_policy_change=None,
) -> APIRouter:
    """`on_table_policy_change(ns: list[str], table: str)` (optional) is
    invoked for each table whose effective policy set changed via a
    detach/untag, so the server can resync masking views / exports / props."""
    router = APIRouter(prefix="/v1/{prefix}/governance", tags=["governance"])
    store = GovernanceStore(catalog)
    engine = PolicyEngine(store)

    def _resync(affected: list[tuple[str, str]]) -> None:
        if not on_table_policy_change:
            return
        for sch, tbl in affected:
            try:
                on_table_policy_change([sch], tbl)
            except Exception:
                pass   # best-effort; next read recreates artifacts anyway

    def _check_prefix(prefix: str) -> None:
        if prefix != settings.catalog_name:
            raise HTTPException(status_code=404, detail=f"Unknown catalog prefix '{prefix}'")

    def _principal(request: Request) -> str:
        return claims_from_request(auth_cfg, request).get("sub") or "anonymous"

    @router.post("/tags", status_code=200)
    def create_tag(prefix: str, req: CreateTagRequest, request: Request):
        _check_prefix(prefix)
        store.create_tag(_principal(request), req.tag_ns, req.tag_name, req.allowed_values)
        return {"status": "created", "tag": f"{req.tag_ns}.{req.tag_name}"}

    @router.post("/object-tags", status_code=200)
    def assign_object_tag(prefix: str, req: AssignObjectTagRequest, request: Request):
        _check_prefix(prefix)
        if req.object_kind not in OBJECT_KINDS:
            raise HTTPException(400, f"object-kind must be one of {sorted(OBJECT_KINDS)}")
        try:
            store.assign_object_tag(
                _principal(request), object_kind=req.object_kind,
                schema_name=req.schema_name, object_name=req.object_name,
                column_name=req.column_name, tag_ns=req.tag_ns, tag_name=req.tag_name,
                tag_value=req.tag_value,
            )
        except GovernanceConflict as e:
            raise HTTPException(409, str(e))
        return {"status": "assigned"}

    @router.post("/masking-policies", status_code=200)
    def create_masking_policy(prefix: str, req: CreatePolicyRequest, request: Request):
        _check_prefix(prefix)
        store.create_masking_policy(_principal(request), req.name, req.signature_sql,
                                    req.body_sql, req.unmasked_roles,
                                    file_layer_masking=req.file_layer_masking)
        return {"status": "created", "policy": req.name}

    @router.post("/row-access-policies", status_code=200)
    def create_row_access_policy(prefix: str, req: CreatePolicyRequest, request: Request):
        _check_prefix(prefix)
        store.create_row_access_policy(_principal(request), req.name, req.signature_sql,
                                       req.body_sql, req.unmasked_roles)
        return {"status": "created", "policy": req.name}

    @router.post("/policy-attachments", status_code=200)
    def attach_policy(prefix: str, req: AttachPolicyRequest, request: Request):
        _check_prefix(prefix)
        if req.policy_kind not in POLICY_KINDS:
            raise HTTPException(400, f"policy-kind must be one of {sorted(POLICY_KINDS)}")
        if req.target_kind not in ATTACH_TARGETS:
            raise HTTPException(400, f"target-kind must be one of {sorted(ATTACH_TARGETS)}")
        # Reject pairings the resolver silently ignores (e.g. masking→table,
        # row_access→column): a no-op attachment must not masquerade as
        # protection. See VALID_ATTACH_TARGETS.
        if req.target_kind not in VALID_ATTACH_TARGETS[req.policy_kind]:
            raise HTTPException(
                400,
                f"{req.policy_kind} policies cannot target '{req.target_kind}'; "
                f"valid targets: {sorted(VALID_ATTACH_TARGETS[req.policy_kind])}")
        try:
            store.attach_policy(
                _principal(request), policy_kind=req.policy_kind, policy_name=req.policy_name,
                target_kind=req.target_kind, tag_ns=req.tag_ns, tag_name=req.tag_name,
                schema_name=req.schema_name, object_name=req.object_name,
                column_name=req.column_name, columns=req.columns,
            )
        except GovernanceConflict as e:
            raise HTTPException(409, str(e))
        return {"status": "attached"}

    @router.post("/roles", status_code=200)
    def create_role(prefix: str, req: CreateRoleRequest, request: Request):
        _check_prefix(prefix)
        store.create_role(_principal(request), req.role_name)
        return {"status": "created", "role": req.role_name}

    @router.post("/role-grants", status_code=200)
    def grant_role(prefix: str, req: RoleGrantRequest, request: Request):
        _check_prefix(prefix)
        store.grant_role(_principal(request), req.role_name, req.principal_sub)
        return {"status": "granted", "role": req.role_name, "principal": req.principal_sub}

    @router.post("/object-grants", status_code=200)
    def grant_object(prefix: str, req: ObjectGrantRequest, request: Request):
        _check_prefix(prefix)
        if req.object_kind not in OBJECT_KINDS:
            raise HTTPException(400, f"object-kind must be one of {sorted(OBJECT_KINDS)}")
        store.grant_object(
            _principal(request), object_kind=req.object_kind, schema_name=req.schema_name,
            object_name=req.object_name, privilege=req.privilege, role_name=req.role_name,
        )
        return {"status": "granted"}

    # ---- delete / detach / revoke (mirror the POST surface) -----------

    @router.delete("/masking-policies/{name}", status_code=200)
    def delete_masking_policy(prefix: str, name: str, request: Request):
        _check_prefix(prefix)
        try:
            if not store.delete_masking_policy(_principal(request), name):
                raise HTTPException(404, f"masking policy '{name}' not found")
        except GovernanceConflict as e:
            raise HTTPException(409, str(e))
        return {"status": "deleted", "policy": name}

    @router.delete("/row-access-policies/{name}", status_code=200)
    def delete_row_access_policy(prefix: str, name: str, request: Request):
        _check_prefix(prefix)
        try:
            if not store.delete_row_access_policy(_principal(request), name):
                raise HTTPException(404, f"row-access policy '{name}' not found")
        except GovernanceConflict as e:
            raise HTTPException(409, str(e))
        return {"status": "deleted", "policy": name}

    @router.delete("/policy-attachments", status_code=200)
    def detach_policy(prefix: str, req: AttachPolicyRequest, request: Request):
        _check_prefix(prefix)
        affected = store.detach_policy(
            _principal(request), policy_kind=req.policy_kind,
            policy_name=req.policy_name, target_kind=req.target_kind,
            tag_ns=req.tag_ns, tag_name=req.tag_name, schema_name=req.schema_name,
            object_name=req.object_name, column_name=req.column_name,
        )
        _resync(affected)
        return {"status": "detached", "resynced_tables": affected}

    @router.delete("/tags/{tag_ns}/{tag_name}", status_code=200)
    def delete_tag(prefix: str, tag_ns: str, tag_name: str, request: Request):
        _check_prefix(prefix)
        try:
            if not store.delete_tag(_principal(request), tag_ns, tag_name):
                raise HTTPException(404, f"tag {tag_ns}.{tag_name} not found")
        except GovernanceConflict as e:
            raise HTTPException(409, str(e))
        return {"status": "deleted", "tag": f"{tag_ns}.{tag_name}"}

    @router.delete("/object-tags", status_code=200)
    def remove_object_tag(prefix: str, req: AssignObjectTagRequest, request: Request):
        _check_prefix(prefix)
        affected = store.remove_object_tag(
            _principal(request), object_kind=req.object_kind,
            schema_name=req.schema_name, object_name=req.object_name,
            column_name=req.column_name, tag_ns=req.tag_ns, tag_name=req.tag_name,
        )
        _resync(affected)
        return {"status": "removed", "resynced_tables": affected}

    @router.delete("/roles/{name}", status_code=200)
    def delete_role(prefix: str, name: str, request: Request):
        _check_prefix(prefix)
        try:
            if not store.delete_role(_principal(request), name):
                raise HTTPException(404, f"role '{name}' not found")
        except GovernanceConflict as e:
            raise HTTPException(409, str(e))
        return {"status": "deleted", "role": name}

    @router.delete("/role-grants", status_code=200)
    def revoke_role(prefix: str, req: RoleGrantRequest, request: Request):
        _check_prefix(prefix)
        store.revoke_role(_principal(request), req.role_name, req.principal_sub)
        return {"status": "revoked", "role": req.role_name,
                "principal": req.principal_sub}

    @router.delete("/object-grants", status_code=200)
    def revoke_object_grant(prefix: str, req: ObjectGrantRequest, request: Request):
        _check_prefix(prefix)
        store.revoke_object_grant(
            _principal(request), object_kind=req.object_kind,
            schema_name=req.schema_name, object_name=req.object_name,
            privilege=req.privilege, role_name=req.role_name,
        )
        return {"status": "revoked"}

    # ---- static S3 keys (no-STS backends, e.g. Hetzner) -----------------

    @router.post("/static-s3-keys", status_code=200)
    def set_static_s3_key(prefix: str, req: StaticS3KeyRequest, request: Request):
        _check_prefix(prefix)
        store.set_static_key(req.principal, req.access_key_id,
                             secret=req.secret_access_key, note=req.note)
        return {"status": "set", "principal": req.principal,
                "access-key-id": req.access_key_id,
                "has-secret": req.secret_access_key is not None}

    @router.get("/static-s3-keys", status_code=200)
    def list_static_s3_keys(prefix: str):
        _check_prefix(prefix)
        # Never echo stored secrets — key ids + a has-secret flag only.
        return {"keys": [
            {"principal": k.principal, "access-key-id": k.access_key_id,
             "has-secret": k.secret_access_key is not None, "note": k.note}
            for k in store.list_static_keys()
        ]}

    @router.delete("/static-s3-keys/{principal}", status_code=200)
    def delete_static_s3_key(prefix: str, principal: str, request: Request):
        _check_prefix(prefix)
        if not store.delete_static_key(principal):
            raise HTTPException(404, f"no static key for principal '{principal}'")
        return {"status": "deleted", "principal": principal}

    @router.get("/effective-policies", status_code=200)
    def effective_policies(prefix: str, table: str, principal: str | None = None):
        _check_prefix(prefix)
        if "." not in table:
            raise HTTPException(400, "table must be 'schema.table'")
        schema, tbl = table.split(".", 1)
        principal = principal or "anonymous"
        derived = store.effective_policies(principal=principal, schema=schema, table=tbl)
        # Phase 2: also show what would *actually* be enforced for this
        # principal (after applying the unmasked-roles bypass), using the
        # principal's authored roles.
        plan = engine.plan_for(
            principal=principal, roles=store.roles_for_principal(principal),
            schema=schema, table=tbl,
        )
        derived["enforcement"] = {
            "masked_columns": plan.masked_columns,
            "row_filter": plan.row_filter,
            "applied_policies": plan.applied_policies,
            "view_sql": plan.view_sql,
        }
        return derived

    @router.get("/audit", status_code=200)
    def audit(prefix: str, limit: int = 200):
        _check_prefix(prefix)
        return {"entries": store.list_audit(limit=limit)}

    return router
