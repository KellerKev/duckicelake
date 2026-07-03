"""Pure-unit tests for STS credential vending (no network calls).

Covers the AWS-correctness layer: endpoint sentinel resolution, session-
policy size degradation, and the AssumeRole retry paths. The live vend path
against MinIO is exercised by the governance suites.
"""
from __future__ import annotations

import json

import pytest
from botocore.exceptions import ClientError

from duckicelake import sts
from duckicelake.config import S3Settings


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


# ---- endpoint sentinel resolution --------------------------------------

def test_sts_endpoint_default_falls_back_to_s3_endpoint():
    s3 = _s3()
    assert not s3.sts_disabled
    assert s3.resolved_sts_endpoint() == "http://127.0.0.1:9000"
    client = sts._sts_client(s3)
    assert client.meta.endpoint_url == "http://127.0.0.1:9000"


def test_sts_endpoint_aws_sentinel_resolves_regional():
    s3 = _s3(sts_endpoint="aws", region="eu-central-1")
    assert s3.resolved_sts_endpoint() == "https://sts.eu-central-1.amazonaws.com"
    client = sts._sts_client(s3)
    assert client.meta.endpoint_url == "https://sts.eu-central-1.amazonaws.com"


def test_sts_endpoint_explicit_url_used_verbatim():
    s3 = _s3(sts_endpoint="https://sts.example.internal:8443")
    client = sts._sts_client(s3)
    assert client.meta.endpoint_url == "https://sts.example.internal:8443"


def test_sts_endpoint_none_disables_vending():
    s3 = _s3(sts_endpoint="none")
    assert s3.sts_disabled
    with pytest.raises(RuntimeError, match="STS is disabled"):
        sts._sts_client(s3)
    with pytest.raises(RuntimeError, match="STS is disabled"):
        sts.vend_credentials(s3, namespace="ns", table="t")


# ---- policy shapes (regression anchors) ---------------------------------

def test_scoped_policy_read_keys_shape():
    p = sts._scoped_policy("b", write_prefix="data/",
                           read_only=True, read_keys=["data/ns/t/a.parquet"])
    sids = [s["Sid"] for s in p["Statement"]]
    assert sids == ["ListDuckLakePrefix", "ReadOwnFiles"]
    assert p["Statement"][1]["Resource"] == ["arn:aws:s3:::b/data/ns/t/a.parquet"]


def test_scoped_policy_prefix_and_deny_shape():
    p = sts._scoped_policy(
        "b", write_prefix="data/", read_only=True,
        read_prefixes=["data/ns/t/"], deny_prefixes=["data/ns/secret/"])
    sids = [s["Sid"] for s in p["Statement"]]
    assert sids == ["ListDuckLakePrefix", "ReadOwnPrefixes",
                    "DenyGovernedBasePrefixes"]
    deny = p["Statement"][2]
    assert deny["Effect"] == "Deny"
    assert deny["Resource"] == ["arn:aws:s3:::b/data/ns/secret/*"]


def test_scoped_policy_write_shape_is_prefix_scoped():
    p = sts._scoped_policy("b", write_prefix="data/", read_only=False,
                           read_keys=["ignored/key"])
    sids = [s["Sid"] for s in p["Statement"]]
    assert sids == ["ListDuckLakePrefix", "ReadWriteInDataPrefix"]
    # write mode never embeds per-file keys
    assert p["Statement"][1]["Resource"] == ["arn:aws:s3:::b/data/*"]


# ---- size degradation ----------------------------------------------------

def _many_keys(n: int) -> list[str]:
    return [f"data/ns/t/part-{i:05d}-0123456789abcdef.parquet"
            for i in range(n)]


def test_build_policy_small_key_list_not_degraded():
    s3 = _s3()
    policy_json, degraded = sts._build_policy(
        s3, namespace="ns", table="t", write_prefix="data/",
        read_only=True, read_keys=_many_keys(3), read_prefixes=None,
        deny_prefixes=None, data_prefix=None)
    assert not degraded
    assert "ReadOwnFiles" in policy_json


def test_build_policy_degrades_large_key_list_to_table_prefix():
    s3 = _s3()
    policy_json, degraded = sts._build_policy(
        s3, namespace="ns", table="t", write_prefix="data/",
        read_only=True, read_keys=_many_keys(500), read_prefixes=None,
        deny_prefixes=None, data_prefix=None)
    assert degraded
    assert len(policy_json) <= sts._POLICY_MAX
    policy = json.loads(policy_json)
    sids = [s["Sid"] for s in policy["Statement"]]
    assert "ReadOwnFiles" not in sids
    prefixes = policy["Statement"][sids.index("ReadOwnPrefixes")]["Resource"]
    assert prefixes == ["arn:aws:s3:::lakehouse/data/ns/t/*"]


def test_build_policy_degradation_preserves_deny_statements():
    s3 = _s3()
    deny = ["data/__masked__/ns/t/", "data/ns/secret/"]
    policy_json, degraded = sts._build_policy(
        s3, namespace="ns", table="t", write_prefix="data/",
        read_only=True, read_keys=_many_keys(500), read_prefixes=None,
        deny_prefixes=deny, data_prefix=None)
    assert degraded
    policy = json.loads(policy_json)
    deny_stmt = [s for s in policy["Statement"] if s["Effect"] == "Deny"]
    assert len(deny_stmt) == 1
    assert deny_stmt[0]["Resource"] == [
        f"arn:aws:s3:::lakehouse/{p}*" for p in deny]


def test_build_policy_raises_when_deny_list_alone_over_budget():
    s3 = _s3()
    deny = [f"data/__masked__/ns{i:04d}/table{i:04d}/" for i in range(60)]
    with pytest.raises(ValueError, match="even after degradation"):
        sts._build_policy(
            s3, namespace="ns", table="t", write_prefix="data/",
            read_only=True, read_keys=_many_keys(500), read_prefixes=None,
            deny_prefixes=deny, data_prefix=None)


# ---- AssumeRole retry paths ----------------------------------------------

class _StubSTS:
    """assume_role stub that raises the given errors in order, then
    succeeds; records every call's kwargs."""

    def __init__(self, errors: list[str]):
        self._errors = list(errors)
        self.calls: list[dict] = []

    def assume_role(self, **kwargs):
        self.calls.append(kwargs)
        if self._errors:
            code = self._errors.pop(0)
            msg = ("1 validation error detected: Value at 'DurationSeconds' "
                   "failed to satisfy constraint"
                   if code == "ValidationError" else code)
            raise ClientError(
                {"Error": {"Code": code, "Message": msg}}, "AssumeRole")
        import datetime
        return {"Credentials": {
            "AccessKeyId": "AKIA_TEST",
            "SecretAccessKey": "secret",
            "SessionToken": "token",
            "Expiration": datetime.datetime(2026, 1, 1),
        }}


def _vend_with_stub(monkeypatch, stub, s3=None, **kwargs):
    monkeypatch.setattr(sts, "_sts_client", lambda _s3: stub)
    return sts.vend_credentials(s3 or _s3(), namespace="ns", table="t",
                                **kwargs)


def test_packed_policy_too_large_degrades_and_retries_once(monkeypatch):
    stub = _StubSTS(["PackedPolicyTooLarge"])
    creds = _vend_with_stub(
        monkeypatch, stub, read_only=True,
        data_file_uris=[f"s3://lakehouse/{k}" for k in _many_keys(3)])
    assert creds.degraded
    assert len(stub.calls) == 2
    retry_policy = json.loads(stub.calls[1]["Policy"])
    sids = [s["Sid"] for s in retry_policy["Statement"]]
    assert "ReadOwnFiles" not in sids and "ReadOwnPrefixes" in sids


def test_packed_policy_too_large_without_keys_reraises(monkeypatch):
    stub = _StubSTS(["PackedPolicyTooLarge", "PackedPolicyTooLarge"])
    with pytest.raises(ClientError):
        _vend_with_stub(monkeypatch, stub, read_only=True,
                        read_prefixes=["data/ns/t/"])
    assert len(stub.calls) == 1  # nothing to degrade → no retry


def test_duration_validation_error_retries_at_3600(monkeypatch):
    stub = _StubSTS(["ValidationError"])
    creds = _vend_with_stub(monkeypatch, stub, read_only=True,
                            read_prefixes=["data/ns/t/"],
                            duration_seconds=43200)
    assert creds.access_key_id == "AKIA_TEST"
    assert len(stub.calls) == 2
    assert stub.calls[0]["DurationSeconds"] == 43200
    assert stub.calls[1]["DurationSeconds"] == 3600


def test_access_denied_reraises_without_retry(monkeypatch):
    stub = _StubSTS(["AccessDenied", "AccessDenied"])
    with pytest.raises(ClientError):
        _vend_with_stub(monkeypatch, stub, read_only=True,
                        read_prefixes=["data/ns/t/"])
    assert len(stub.calls) == 1


def test_configured_role_arn_is_used(monkeypatch):
    stub = _StubSTS([])
    _vend_with_stub(monkeypatch, stub,
                    s3=_s3(sts_role_arn="arn:aws:iam::123456789012:role/Vend"),
                    read_only=True, read_prefixes=["data/ns/t/"])
    assert stub.calls[0]["RoleArn"] == "arn:aws:iam::123456789012:role/Vend"
