"""Integration tests for the no-STS remote-signing path, against MinIO.

A second proxy runs with DUCKICELAKE_STS_ENDPOINT=none (the Hetzner shape).
The signer signs requests for ANY S3 backend, so MinIO verifies the
signatures end-to-end: we sign through the proxy and then replay the raw
HTTP request against MinIO expecting real bytes back.

Token-scope enforcement inside the signer is unit-tested in
test_signer_unit.py (this module's proxy runs auth-off, matching the rest
of the integration suite).
"""
from __future__ import annotations

import json
import os
import signal as _signal
import subprocess
import time
import uuid

import httpx
import pytest

from conftest import PROXY_URL, REPO, requires_sts
from duckicelake import s3util
from test_governance_phase3 import (  # noqa: F401  (helpers)
    SCHEMA_JSON,
    _make_table,
    _seed_rows,
)

_SIGN_PORT = 18191
SIGN_URL = f"http://127.0.0.1:{_SIGN_PORT}"


def _ns(suffix: str) -> str:
    return f"rsig_{suffix}_{uuid.uuid4().hex[:6]}"


@pytest.fixture(scope="module")
def signing_proxy():
    env = dict(
        os.environ,
        DUCKICELAKE_STS_ENDPOINT="none",
        DUCKICELAKE_PUBLIC_URL=SIGN_URL,
        # Gateway OFF here: this proxy tests the static-key / fail-closed tier
        # (test_ducklake_credentials_no_sts_matrix). The gateway is exercised
        # via the main proxy (conftest).
        DUCKICELAKE_S3_GATEWAY_ENABLED="0",
    )
    proc = subprocess.Popen(
        ["uvicorn", "duckicelake.server:app",
         "--host", "127.0.0.1", "--port", str(_SIGN_PORT),
         "--log-level", "warning"],
        cwd=REPO, env=env,
    )
    try:
        deadline = time.time() + 30
        while True:
            try:
                if httpx.get(f"{SIGN_URL}/healthz", timeout=1).status_code == 200:
                    break
            except Exception:
                pass
            assert time.time() < deadline, "signing proxy failed to start"
            time.sleep(0.3)
        yield proc
    finally:
        proc.send_signal(_signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.fixture
def sclient(signing_proxy):
    with httpx.Client(base_url=SIGN_URL, timeout=30.0) as c:
        yield c


def _table_keys(s3, prefix: str) -> list[str]:
    c = s3util.s3_client(s3)
    keys = []
    for p in c.get_paginator("list_objects_v2").paginate(
            Bucket=s3.bucket, Prefix=prefix):
        keys.extend(o["Key"] for o in p.get("Contents", []))
    return keys


def _sign(client, method: str, uri: str, headers=None):
    return client.post("/v1/lake/aws/s3/sign", json={
        "method": method, "region": "us-east-1", "uri": uri,
        "headers": headers or {},
    })


def _author_file_layer_policy(client, ns: str, table: str) -> None:
    """pii.email tag + file-layer masking policy on ns.table.email."""
    client.post("/v1/lake/governance/tags",
                json={"namespace": "pii", "name": "email"}).raise_for_status()
    client.post("/v1/lake/governance/object-tags",
                json={"object-kind": "column", "schema": ns, "object": table,
                      "column": "email", "tag-namespace": "pii",
                      "tag-name": "email"}).raise_for_status()
    client.post("/v1/lake/governance/masking-policies",
                json={"name": "mask_email", "signature": "(val VARCHAR)",
                      "body": "left(val,2)||'***'",
                      "unmasked-roles": ["pii_reader"],
                      "file-layer-masking": True}).raise_for_status()
    client.post("/v1/lake/governance/policy-attachments",
                json={"policy-kind": "masking", "policy-name": "mask_email",
                      "target-kind": "tag", "tag-namespace": "pii",
                      "tag-name": "email"}).raise_for_status()


# ---- LoadTable config -------------------------------------------------------

def test_load_table_emits_remote_signing_config(sclient, settings):
    ns = _ns("cfg")
    _make_table(sclient, ns, "events")
    r = sclient.get(f"/v1/lake/namespaces/{ns}/tables/events",
                    headers={"X-Iceberg-Access-Delegation": "vended-credentials"})
    assert r.status_code == 200, r.text
    cfg = r.json()["config"]
    assert cfg["s3.remote-signing-enabled"] == "true"
    assert cfg["s3.signer"] == "S3V4RestSigner"
    assert cfg["s3.signer.uri"] == SIGN_URL
    assert cfg["s3.signer.endpoint"] == "v1/lake/aws/s3/sign"
    assert cfg["py-io-impl"] == "pyiceberg.io.fsspec.FsspecFileIO"
    # no static or vended keys leak in no-STS mode
    assert "s3.access-key-id" not in cfg
    assert "s3.session-token" not in cfg

    # the `remote-signing` delegation header token gets the same answer
    r2 = sclient.get(f"/v1/lake/namespaces/{ns}/tables/events",
                     headers={"X-Iceberg-Access-Delegation": "remote-signing"})
    assert r2.json()["config"]["s3.remote-signing-enabled"] == "true"

    # without the delegation header there is no signer config
    r3 = sclient.get(f"/v1/lake/namespaces/{ns}/tables/events")
    assert "s3.signer" not in r3.json()["config"]


@requires_sts
def test_sts_proxy_still_vends_credentials(client, settings):
    """Control: the session proxy (STS mode) still vends session tokens."""
    ns = _ns("stsctl")
    _make_table(client, ns, "events")
    r = client.get(f"/v1/lake/namespaces/{ns}/tables/events",
                   headers={"X-Iceberg-Access-Delegation": "vended-credentials"})
    cfg = r.json()["config"]
    assert "s3.session-token" in cfg
    assert cfg["s3.remote-signing-enabled"] == "false"


# ---- end-to-end signing against MinIO --------------------------------------

def test_signer_signs_allowed_get_end_to_end(sclient, settings):
    ns = _ns("e2e")
    _make_table(sclient, ns, "events")
    _seed_rows(settings, ns)
    s3 = settings.s3
    parquet = [k for k in _table_keys(s3, f"{s3.data_prefix}{ns}/events/")
               if k.endswith(".parquet")]
    assert parquet, "seeding produced no parquet files"
    uri = f"{s3.endpoint}/{s3.bucket}/{parquet[0]}"

    r = _sign(sclient, "GET", uri, {"Host": [s3.host]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["uri"] == uri
    headers = {k: v[0] for k, v in body["headers"].items()}
    lower = {k.lower(): v for k, v in headers.items()}
    assert lower["x-amz-content-sha256"] == "UNSIGNED-PAYLOAD"

    raw = httpx.get(uri, headers=headers)
    assert raw.status_code == 200, raw.text
    assert raw.content[:4] == b"PAR1"   # real parquet bytes through the signer


def test_signer_compatible_with_pyiceberg_client(sclient, settings):
    """Drive the sign round-trip with PYICEBERG'S OWN S3V4RestSigner class:
    it builds the request body, calls our endpoint, and mutates a botocore
    AWSRequest — then we replay that request raw against MinIO."""
    pytest.importorskip("pyiceberg")
    from botocore.awsrequest import AWSRequest
    from pyiceberg.io.fsspec import S3V4RestSigner

    ns = _ns("pyice")
    _make_table(sclient, ns, "events")
    _seed_rows(settings, ns)
    s3 = settings.s3
    parquet = [k for k in _table_keys(s3, f"{s3.data_prefix}{ns}/events/")
               if k.endswith(".parquet")]
    uri = f"{s3.endpoint}/{s3.bucket}/{parquet[0]}"

    signer = S3V4RestSigner({
        "uri": SIGN_URL,
        "s3.signer.uri": SIGN_URL,
        "s3.signer.endpoint": "v1/lake/aws/s3/sign",
    })
    req = AWSRequest(method="GET", url=uri, headers={"Host": s3.host})
    req.context["client_region"] = s3.region
    signer(req)

    raw = httpx.get(req.url, headers=dict(req.headers.items()))
    assert raw.status_code == 200
    assert raw.content[:4] == b"PAR1"


# ---- denies -----------------------------------------------------------------

def test_signer_denies(sclient, settings):
    s3 = settings.s3
    ns = _ns("deny")
    _make_table(sclient, ns, "events")

    # foreign endpoint host
    r = _sign(sclient, "GET", f"http://evil.example.com/{s3.bucket}/data/x/y/z")
    assert r.status_code == 403

    # foreign bucket on our endpoint
    r = _sign(sclient, "GET", f"{s3.endpoint}/otherbucket/data/{ns}/events/a")
    assert r.status_code == 403

    # outside the data prefix
    r = _sign(sclient, "GET", f"{s3.endpoint}/{s3.bucket}/private/{ns}/events/a")
    assert r.status_code == 403


def test_signer_file_layer_masking_enforced(sclient, settings):
    """A file-layer-masked principal: base-prefix signs are denied (and
    audited), the CURRENT masked sig prefix signs for GET but never PUT."""
    ns = _ns("mask")
    _make_table(sclient, ns, "events")
    _author_file_layer_policy(sclient, ns, "events")
    _seed_rows(settings, ns)
    s3 = settings.s3

    # LoadTable triggers export + shadow metadata materialization
    r = sclient.get(f"/v1/lake/namespaces/{ns}/tables/events",
                    headers={"X-Iceberg-Access-Delegation": "vended-credentials"})
    assert r.status_code == 200, r.text

    base_keys = [k for k in _table_keys(s3, f"{s3.data_prefix}{ns}/events/")
                 if k.endswith(".parquet")]
    masked_keys = [k for k in
                   _table_keys(s3, f"{s3.data_prefix}__masked__/{ns}/events/")
                   if k.endswith(".parquet")]
    assert base_keys and masked_keys, "export did not materialize"

    # base bytes: denied + audited
    r = _sign(sclient, "GET", f"{s3.endpoint}/{s3.bucket}/{base_keys[0]}")
    assert r.status_code == 403
    assert "sign_denied_file_layer_base" in r.text
    audit = sclient.get("/v1/lake/governance/audit").json()["entries"]
    assert any(e.get("operation") == "s3_sign"
               and e.get("decision") == "sign_denied_file_layer_base"
               for e in audit)

    # masked bytes: GET signs and MinIO serves them
    masked_uri = f"{s3.endpoint}/{s3.bucket}/{masked_keys[0]}"
    r = _sign(sclient, "GET", masked_uri)
    assert r.status_code == 200, r.text
    headers = {k: v[0] for k, v in r.json()["headers"].items()}
    raw = httpx.get(masked_uri, headers=headers)
    assert raw.status_code == 200
    assert raw.content[:4] == b"PAR1"

    # masked tree is never writable through the signer
    r = _sign(sclient, "PUT", masked_uri)
    assert r.status_code == 403
    assert "sign_denied_masked_write" in r.text


# ---- ducklake-credentials in no-STS mode ------------------------------------

def test_ducklake_credentials_no_sts_matrix(sclient, settings):
    ns = _ns("nosts")
    _make_table(sclient, ns, "events")

    # 1. no static key registered → fail closed, audited
    r = sclient.get(f"/v1/lake/namespaces/{ns}/ducklake-credentials",
                    params={"table": "events", "principal": "carol"})
    assert r.status_code == 200, r.text
    assert r.json()["s3"] is None
    audit = sclient.get("/v1/lake/governance/audit").json()["entries"]
    assert any(e.get("decision") == "error_no_sts"
               and e.get("principal") == "carol" for e in audit)

    # 2. registered static key (id only) → vended with bucket-policy marker
    r = sclient.post("/v1/lake/governance/static-s3-keys",
                     json={"principal": "carol",
                           "access-key-id": "AKCAROLTEST",
                           "note": "hetzner project key"})
    assert r.status_code == 200, r.text
    assert r.json()["has-secret"] is False
    r = sclient.get(f"/v1/lake/namespaces/{ns}/ducklake-credentials",
                    params={"table": "events", "principal": "carol"})
    s3c = r.json()["s3"]
    assert s3c is not None
    assert s3c["access-key-id"] == "AKCAROLTEST"
    assert s3c["secret-access-key"] is None      # client supplies its own
    assert s3c["static-key"] is True
    assert s3c["enforcement"] == "bucket-policy"

    # 3. listing never echoes secrets
    keys = sclient.get("/v1/lake/governance/static-s3-keys").json()["keys"]
    entry = next(k for k in keys if k["principal"] == "carol")
    assert "secret-access-key" not in entry and entry["has-secret"] is False

    # 4. file-layer-masked principal with a static key → fail closed
    ns2 = _ns("nostsmask")
    _make_table(sclient, ns2, "events")
    _author_file_layer_policy(sclient, ns2, "events")
    _seed_rows(settings, ns2)
    r = sclient.get(f"/v1/lake/namespaces/{ns2}/ducklake-credentials",
                    params={"table": "events", "principal": "carol"})
    assert r.status_code == 200, r.text
    assert r.json()["s3"] is None
    audit = sclient.get("/v1/lake/governance/audit").json()["entries"]
    assert any(e.get("decision") == "error_no_sts_masked"
               and e.get("principal") == "carol" for e in audit)

    # 5. cleanup: delete the key; vend fails closed again
    r = sclient.delete("/v1/lake/governance/static-s3-keys/carol")
    assert r.status_code == 200
    r = sclient.get(f"/v1/lake/namespaces/{ns}/ducklake-credentials",
                    params={"table": "events", "principal": "carol"})
    assert r.json()["s3"] is None


def test_hetzner_policy_cli_dry_run(sclient, settings):
    """The bucket-policy generator emits per-access-key statements for
    registered principals (dry-run prints JSON to stdout)."""
    principal = f"dave_{uuid.uuid4().hex[:6]}"
    sclient.post("/v1/lake/governance/static-s3-keys",
                 json={"principal": principal,
                       "access-key-id": "AKDAVETEST"}).raise_for_status()
    env = dict(os.environ, DUCKICELAKE_HETZNER_PROJECT_ID="4711")
    try:
        out = subprocess.run(
            ["python", "-m", "duckicelake.hetzner_policy"],
            check=True, capture_output=True, cwd=REPO, env=env, timeout=120,
        )
        policy = json.loads(out.stdout)
        assert policy["Version"] == "2012-10-17"
        arns = [s["Principal"]["AWS"] for s in policy["Statement"]]
        assert any(a == "arn:aws:iam:::user/p4711:AKDAVETEST" for a in arns)
    finally:
        sclient.delete(f"/v1/lake/governance/static-s3-keys/{principal}")
