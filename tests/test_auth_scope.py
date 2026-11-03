"""A client without an explicit scope is a config error, never a superuser,
and a token that carries no scope claim grants nothing."""
from __future__ import annotations

import json

import pytest

from duckicelake.auth import (AuthConfig, _parse_clients_env, _parse_clients_file,
                              issue_token, scope_allows)


def test_env_client_without_scope_is_rejected():
    with pytest.raises(ValueError, match="no scope"):
        _parse_clients_env("bot:secret")
    with pytest.raises(ValueError, match="no scope"):
        _parse_clients_env("bot:secret||role-a|acct")
    got = _parse_clients_env("svc:s|*, ro:s2|sales:r|analyst|acct-1")
    assert got["svc"]["scope"] == "*"
    assert got["ro"] == {"secret": "s2", "scope": "sales:r", "roles": "analyst",
                         "account": "acct-1"}


def test_file_client_without_scope_is_rejected(tmp_path):
    for entry in ("legacy-secret", {"secret": "s"}, {"secret": "s", "scope": " "}):
        p = tmp_path / "c.json"
        p.write_text(json.dumps({"bot": entry}))
        with pytest.raises(ValueError, match="no scope"):
            _parse_clients_file(str(p))
    p.write_text(json.dumps({"bot": {"secret": "s", "scope": "*:r", "roles": ["a", "b"]}}))
    assert _parse_clients_file(str(p))["bot"]["roles"] == "a b"


def test_scopeless_token_is_denied(monkeypatch):
    import duckicelake.server as srv
    from fastapi.testclient import TestClient
    assert not scope_allows("", None, "GET")
    assert not scope_allows("", "sales", "GET")
    cfg = AuthConfig(jwt_secret=b"test-secret-32-bytes-xxxxxxxxxxx",
                     clients={"c": {"secret": "s", "scope": "*", "roles": "", "account": ""}},
                     ttl_seconds=300, issuer="duckicelake")
    monkeypatch.setattr(srv, "auth_cfg", cfg)
    bare = issue_token(cfg, "bot", scope=None)["access_token"]
    admin = issue_token(cfg, "bot", scope="*")["access_token"]
    with TestClient(srv.app) as client:
        def get(tok):
            return client.get("/v1/lake/namespaces",
                              headers={"Authorization": f"Bearer {tok}"}).status_code
        assert get(bare) == 403
        assert get(admin) == 200
