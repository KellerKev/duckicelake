"""Pure-unit tests for the remote signer (no proxy, no network)."""
from __future__ import annotations

import pytest

from duckicelake import signer
from duckicelake.config import S3Settings, Settings
from duckicelake.policies import MaskDecision, TablePolicyPlan, mask_signature


def _s3(**overrides) -> S3Settings:
    base = dict(
        endpoint="http://127.0.0.1:9000",
        region="us-east-1",
        bucket="lakehouse",
        root_access_key="minioadmin",
        root_secret_key="minioadmin",
        path_style=True,
        data_prefix="data/",
    )
    base.update(overrides)
    return S3Settings(**base)


def _settings(**s3_overrides) -> Settings:
    return Settings(
        pg_host="/tmp", pg_port=5432, pg_user="x", pg_database="x",
        catalog_name="lake", s3=_s3(**s3_overrides),
    )


# ---- parse_s3_uri ---------------------------------------------------------

def test_parse_path_style():
    assert signer.parse_s3_uri(
        "http://127.0.0.1:9000/lakehouse/data/ns/t/a.parquet", _s3()
    ) == ("lakehouse", "data/ns/t/a.parquet")


def test_parse_vhost_style():
    assert signer.parse_s3_uri(
        "https://lakehouse.fsn1.your-objectstorage.com/data/ns/t/a.parquet",
        _s3(endpoint="https://fsn1.your-objectstorage.com"),
    ) == ("lakehouse", "data/ns/t/a.parquet")


def test_parse_foreign_host_rejected():
    assert signer.parse_s3_uri(
        "http://evil.example.com/lakehouse/data/ns/t/a.parquet", _s3()
    ) is None


# ---- authorize_sign --------------------------------------------------------

class _StubStore:
    def __init__(self, roles=None):
        self._roles = roles or []

    def roles_for_principal(self, sub):
        return self._roles


class _StubEngine:
    def __init__(self, plan=None, error=False):
        self._plan = plan
        self._error = error

    def plan_for(self, *, principal, roles, schema, table):
        if self._error:
            raise RuntimeError("governance store down")
        if self._plan is not None:
            return self._plan
        return TablePolicyPlan(principal=principal, roles=roles,
                               schema=schema, table=table)


class _StubRef:
    data_prefix = "data/"


class _StubCtx:
    def __init__(self, plan=None, error=False, roles=None):
        self.ref = _StubRef()
        self.store = _StubStore(roles)
        self.policy_engine = _StubEngine(plan, error)


def _empty_plan(ns="ns", table="t") -> TablePolicyPlan:
    return TablePolicyPlan(principal="p", roles=[], schema=ns, table=table)


def _file_layer_plan(ns="ns", table="t") -> TablePolicyPlan:
    return TablePolicyPlan(
        principal="p", roles=[], schema=ns, table=table,
        masks=[MaskDecision(column="email", policy_name="pii",
                            mask_expr="'***'", doc="")],
        file_layer=True,
    )


@pytest.fixture(autouse=True)
def _fresh_cache():
    signer._plan_cache.clear()
    yield
    signer._plan_cache.clear()


def _auth(ctx, method, key, claims=None, settings=None):
    return signer.authorize_sign(
        ctx, settings or _settings(), claims or {"sub": "alice"},
        method, "lakehouse", key)


def test_allows_read_in_table_prefix():
    d = _auth(_StubCtx(), "GET", "data/ns/t/a.parquet")
    assert d.allowed and d.reason == "signed"


def test_denies_foreign_bucket():
    d = signer.authorize_sign(
        _StubCtx(), _settings(), {"sub": "alice"},
        "GET", "otherbucket", "data/ns/t/a.parquet")
    assert not d.allowed and d.reason == "sign_denied_bucket"


def test_denies_outside_data_prefix():
    d = _auth(_StubCtx(), "GET", "private/ns/t/a.parquet")
    assert not d.allowed and d.reason == "sign_denied_prefix"


def test_denies_shallow_key():
    d = _auth(_StubCtx(), "GET", "data/loosefile.txt")
    assert not d.allowed and d.reason == "sign_denied_path"


def test_denies_unknown_method():
    d = _auth(_StubCtx(), "OPTIONS", "data/ns/t/a.parquet")
    assert not d.allowed and d.reason == "sign_denied_method"


def test_denies_base_prefix_for_file_layer_masked_principal():
    ctx = _StubCtx(plan=_file_layer_plan())
    d = _auth(ctx, "GET", "data/ns/t/a.parquet")
    assert not d.allowed and d.reason == "sign_denied_file_layer_base"


def test_masked_sig_prefix_read_allowed_on_sig_match():
    plan = _file_layer_plan()
    sig = mask_signature(plan)
    ctx = _StubCtx(plan=plan)
    d = _auth(ctx, "GET", f"data/__masked__/ns/t/{sig}/snap-1/a.parquet")
    assert d.allowed and d.reason == "signed"


def test_masked_sig_prefix_denied_on_sig_mismatch():
    ctx = _StubCtx(plan=_file_layer_plan())
    d = _auth(ctx, "GET", "data/__masked__/ns/t/deadbeef9999/snap-1/a.parquet")
    assert not d.allowed and d.reason == "sign_denied_masked_scope"


def test_masked_sig_prefix_never_writable():
    plan = _file_layer_plan()
    sig = mask_signature(plan)
    ctx = _StubCtx(plan=plan)
    d = _auth(ctx, "PUT", f"data/__masked__/ns/t/{sig}/snap-1/a.parquet")
    assert not d.allowed and d.reason == "sign_denied_masked_write"


def test_governance_error_fails_closed():
    ctx = _StubCtx(error=True)
    d = _auth(ctx, "GET", "data/ns/t/a.parquet")
    assert not d.allowed and d.reason == "sign_denied_governance_error"


def test_read_only_scope_denies_write_sign():
    claims = {"sub": "alice", "scope": "ns:ns:r"}
    d = _auth(_StubCtx(), "PUT", "data/ns/t/a.parquet", claims=claims)
    assert not d.allowed and d.reason == "sign_denied_token_scope"
    d2 = _auth(_StubCtx(), "GET", "data/ns/t/a.parquet", claims=claims)
    assert d2.allowed


def test_write_scope_allows_write_sign():
    claims = {"sub": "alice", "scope": "ns:ns:rw"}
    d = _auth(_StubCtx(), "DELETE", "data/ns/t/a.parquet", claims=claims)
    assert d.allowed


def test_plan_cache_expires(monkeypatch):
    ctx = _StubCtx()
    calls = []
    orig = ctx.policy_engine.plan_for

    def counting(**kw):
        calls.append(1)
        return orig(**kw)

    ctx.policy_engine.plan_for = counting
    settings = _settings()
    _auth(ctx, "GET", "data/ns/t/a.parquet", settings=settings)
    _auth(ctx, "GET", "data/ns/t/b.parquet", settings=settings)
    assert len(calls) == 1  # second call hit the cache
    signer._plan_cache.clear()
    _auth(ctx, "GET", "data/ns/t/c.parquet", settings=settings)
    assert len(calls) == 2


# ---- sign_v4 ---------------------------------------------------------------

def test_sign_v4_produces_valid_sigv4_headers():
    resp = signer.sign_v4(
        _s3(), "GET", "http://127.0.0.1:9000/lakehouse/data/ns/t/a.parquet",
        {"Host": ["127.0.0.1:9000"],
         "x-amz-meta-foo": ["bar"],
         "Range": ["bytes=0-100"],
         "User-Agent": ["pyiceberg"],
         "Authorization": ["should-be-dropped"]})
    flat = {k.lower(): v[0] for k, v in resp.headers.items()}
    auth = flat["authorization"]
    assert auth.startswith("AWS4-HMAC-SHA256 Credential=minioadmin/")
    assert "/us-east-1/s3/aws4_request" in auth
    assert flat["x-amz-content-sha256"] == "UNSIGNED-PAYLOAD"
    assert "x-amz-date" in flat
    signed = auth.split("SignedHeaders=")[1].split(",")[0].split(";")
    assert "host" in signed
    assert "x-amz-meta-foo" in signed
    assert "range" in signed
    assert "user-agent" not in signed
    # the client's placeholder Authorization header never reaches signing
    assert flat["authorization"] == auth


def test_sign_v4_uses_server_region_not_client_region():
    resp = signer.sign_v4(
        _s3(region="fsn1"), "GET",
        "https://fsn1.your-objectstorage.com/lakehouse/data/ns/t/a.parquet",
        {})
    auth = resp.headers["Authorization"][0]
    assert "/fsn1/s3/aws4_request" in auth
    # Host reconstructed from the URI when the client omitted it
    assert resp.headers.get("Host") == ["fsn1.your-objectstorage.com"]
