"""Pure-unit tests for the S3 gateway credential mint/verify (no network).

The definitive interop check: sign a request with botocore's own
`S3SigV4Auth` — exactly what a DuckDB/boto client does — and assert the
gateway's `verify_sigv4` accepts it, and rejects every tamper.
"""
from __future__ import annotations

import base64
import json

import pytest
from botocore.auth import S3SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from fastapi import HTTPException

from duckicelake import s3_gateway as gw
from duckicelake.config import S3Settings, Settings


def _settings(**over) -> Settings:
    s3 = S3Settings(
        endpoint="https://fsn1.your-objectstorage.com", region="fsn1",
        bucket="fineupp", root_access_key="root", root_secret_key="rootsecret",
        path_style=True, data_prefix="levitate/", sts_endpoint="none",
    )
    base = dict(
        pg_host="/tmp", pg_port=5432, pg_user="x", pg_database="x",
        catalog_name="lake", s3=s3, s3_gateway_enabled=True,
        s3_gateway_secret=b"gateway-hmac-key-not-the-jwt-one",
        s3_gateway_url="http://10.0.0.3:8181", s3_gateway_ttl=900,
    )
    base.update(over)
    return Settings(**base)


_HOST = "10.0.0.3:8181"


def _client_sign(access_key_id: str, secret: str, method: str, path: str,
                 *, query: str = "", region: str = "fsn1",
                 extra: dict | None = None) -> dict:
    """Sign a request the way a DuckDB/boto client would, and return the
    on-the-wire (lowercased) header view the gateway would receive."""
    url = f"http://{_HOST}{path}" + (f"?{query}" if query else "")
    req = AWSRequest(method=method, url=url, headers=dict(extra or {}))
    S3SigV4Auth(Credentials(access_key_id, secret), "s3", region).add_auth(req)
    headers = {k.lower(): v for k, v in req.headers.items()}
    headers.setdefault("host", _HOST)  # the HTTP client sets Host on the wire
    return headers


def _verify(settings, headers, *, method="GET",
            path="/fineupp/levitate/ns/t/a.parquet", query="", now=None):
    return gw.verify_sigv4(
        settings, method=method, host=_HOST, decoded_path=path,
        raw_query=query, headers=headers, now=now)


# ---- mint ------------------------------------------------------------------

def test_mint_shape_and_expiry():
    s = _settings()
    cred = gw.mint_credentials(
        s, sub="alice", scope="ns:sales:r", roles=["analyst"],
        catalog_id="lake", now=1_000_000)
    assert cred["access_key_id"].startswith("DLGW_")
    assert cred["claims"]["exp"] == 1_000_000 + 900
    assert cred["claims"]["sub"] == "alice"
    assert cred["claims"]["scope"] == "ns:sales:r"
    # secret is HMAC-derived from the key id — reproducible, id-bound
    assert cred["secret_access_key"] == gw._derive_secret(
        s.s3_gateway_secret, cred["access_key_id"])


def test_parse_credential_roundtrip():
    s = _settings()
    cred = gw.mint_credentials(s, sub="bob", scope="*:*:*", roles=[],
                               catalog_id="lake")
    claims = gw.parse_credential(cred["access_key_id"])
    assert claims["sub"] == "bob"
    assert gw.parse_credential("AKIAFOREIGNKEY") is None
    assert gw.parse_credential("DLGW_not-base64!!") is None


# ---- verify (happy path) ---------------------------------------------------

def test_verify_accepts_botocore_signed_request():
    s = _settings()
    cred = gw.mint_credentials(s, sub="alice", scope="ns:ns:r", roles=["r"],
                               catalog_id="lake")
    headers = _client_sign(cred["access_key_id"], cred["secret_access_key"],
                           "GET", "/fineupp/levitate/ns/t/a.parquet")
    claims = _verify(s, headers)
    assert claims["sub"] == "alice" and claims["scope"] == "ns:ns:r"


def test_verify_accepts_with_range_and_query():
    s = _settings()
    cred = gw.mint_credentials(s, sub="alice", scope="*:*:*", roles=[],
                               catalog_id="lake")
    headers = _client_sign(
        cred["access_key_id"], cred["secret_access_key"], "GET",
        "/fineupp/levitate/ns/t/a.parquet", query="partNumber=2",
        extra={"Range": "bytes=0-1023"})
    claims = _verify(s, headers, query="partNumber=2")
    assert claims["sub"] == "alice"


# ---- verify (rejections) ---------------------------------------------------

def test_verify_rejects_foreign_key():
    s = _settings()
    headers = _client_sign("AKIAFOREIGN0000", "somesecret", "GET",
                           "/fineupp/levitate/ns/t/a.parquet")
    with pytest.raises(HTTPException) as e:
        _verify(s, headers)
    assert e.value.status_code == 403
    assert "gateway credential" in e.value.detail


def test_verify_rejects_expired():
    s = _settings()
    cred = gw.mint_credentials(s, sub="alice", scope="*:*:*", roles=[],
                               catalog_id="lake", now=1_000)
    headers = _client_sign(cred["access_key_id"], cred["secret_access_key"],
                           "GET", "/fineupp/levitate/ns/t/a.parquet")
    with pytest.raises(HTTPException) as e:
        _verify(s, headers, now=1_000 + 900 + 1)  # one second past exp
    assert e.value.status_code == 403 and "expired" in e.value.detail


def test_verify_rejects_bad_signature():
    s = _settings()
    cred = gw.mint_credentials(s, sub="alice", scope="*:*:*", roles=[],
                               catalog_id="lake")
    headers = _client_sign(cred["access_key_id"], cred["secret_access_key"],
                           "GET", "/fineupp/levitate/ns/t/a.parquet")
    # Flip the last hex digit of the signature.
    auth = headers["authorization"]
    head, sig = auth.rsplit("Signature=", 1)
    tampered = "0" if sig[-1] != "0" else "1"
    headers["authorization"] = head + "Signature=" + sig[:-1] + tampered
    with pytest.raises(HTTPException) as e:
        _verify(s, headers)
    assert e.value.status_code == 403 and "mismatch" in e.value.detail


def test_verify_rejects_claim_tampering():
    """An attacker who widens the packed scope changes the key id, so the
    required secret changes too — a secret they can't derive. Signing with
    the original secret but presenting the escalated id must fail."""
    s = _settings()
    cred = gw.mint_credentials(s, sub="alice", scope="ns:sales:r", roles=[],
                               catalog_id="lake")
    claims = gw.parse_credential(cred["access_key_id"])
    claims["scope"] = "*:*:*"  # escalate
    forged = "DLGW_" + base64.urlsafe_b64encode(
        json.dumps(claims, separators=(",", ":"), sort_keys=True).encode()
    ).rstrip(b"=").decode()
    # Client only holds the ORIGINAL secret.
    headers = _client_sign(forged, cred["secret_access_key"], "GET",
                           "/fineupp/levitate/ns/t/a.parquet")
    with pytest.raises(HTTPException) as e:
        _verify(s, headers)
    assert e.value.status_code == 403 and "mismatch" in e.value.detail


def test_verify_rejects_unsigned_request():
    s = _settings()
    with pytest.raises(HTTPException) as e:
        _verify(s, {"host": _HOST})
    assert e.value.status_code == 403


def test_verify_rejects_path_swap():
    """Signature is bound to the path: a signature minted for object A must
    not authorize object B (SigV4 covers the canonical URI)."""
    s = _settings()
    cred = gw.mint_credentials(s, sub="alice", scope="*:*:*", roles=[],
                               catalog_id="lake")
    headers = _client_sign(cred["access_key_id"], cred["secret_access_key"],
                           "GET", "/fineupp/levitate/ns/t/a.parquet")
    with pytest.raises(HTTPException) as e:
        _verify(s, headers, path="/fineupp/levitate/ns/t/SECRET.parquet")
    assert e.value.status_code == 403 and "mismatch" in e.value.detail
