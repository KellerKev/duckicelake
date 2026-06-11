"""Config loading: TOML/.env file sources + the suppress-root-creds default.

The file loaders are pure (path → env-name dict) and tested directly;
`apply_file_config` mutates os.environ via setdefault, so those tests
clean up the keys they inject.
"""
from __future__ import annotations

import os

from duckicelake.config import (
    apply_file_config,
    dotenv_file_env,
    load_settings,
    toml_file_env,
)


def test_toml_mapping(tmp_path):
    cfg = tmp_path / "duckicelake.toml"
    cfg.write_text(
        """
        catalog = "mylake"
        suppress_root_creds = false

        [pg]
        port = 5555

        [s3]
        endpoint = "http://example:9100"
        path_style = true
        """
    )
    env = toml_file_env(cfg)
    assert env == {
        "DUCKICELAKE_CATALOG": "mylake",
        "DUCKICELAKE_SUPPRESS_ROOT_CREDS": "0",
        "DUCKICELAKE_PG_PORT": "5555",
        "DUCKICELAKE_S3_ENDPOINT": "http://example:9100",
        "DUCKICELAKE_S3_PATH_STYLE": "1",
    }


def test_dotenv_parsing(tmp_path):
    f = tmp_path / ".env"
    f.write_text(
        """
        # comment
        DUCKICELAKE_CATALOG=envlake
        export DUCKICELAKE_S3_ENDPOINT="http://q:9000"
        DUCKICELAKE_PG_USER='alice'
        UNRELATED_SECRET=nope
        malformed-line
        """
    )
    env = dotenv_file_env(f)
    assert env == {
        "DUCKICELAKE_CATALOG": "envlake",
        "DUCKICELAKE_S3_ENDPOINT": "http://q:9000",
        "DUCKICELAKE_PG_USER": "alice",
    }


def test_apply_precedence_env_over_dotenv_over_toml(tmp_path, monkeypatch):
    (tmp_path / "duckicelake.toml").write_text(
        'catalog = "from_toml"\n[pg]\nuser = "toml_user"\nport = 1111\n'
    )
    (tmp_path / ".env").write_text(
        "DUCKICELAKE_CATALOG=from_dotenv\nDUCKICELAKE_PG_USER=dotenv_user\n"
    )
    # real env wins over both
    monkeypatch.setenv("DUCKICELAKE_CATALOG", "from_env")
    monkeypatch.delenv("DUCKICELAKE_PG_USER", raising=False)
    monkeypatch.delenv("DUCKICELAKE_PG_PORT", raising=False)
    monkeypatch.delenv("DUCKICELAKE_CONFIG_FILE", raising=False)

    injected = apply_file_config(cwd=tmp_path)
    try:
        assert os.environ["DUCKICELAKE_CATALOG"] == "from_env"
        assert os.environ["DUCKICELAKE_PG_USER"] == "dotenv_user"  # .env > toml
        assert os.environ["DUCKICELAKE_PG_PORT"] == "1111"         # toml fills gap
        assert "DUCKICELAKE_CATALOG" not in injected
    finally:
        for key in injected:
            os.environ.pop(key, None)


def test_config_file_env_var_points_at_toml(tmp_path, monkeypatch):
    cfg = tmp_path / "elsewhere.toml"
    cfg.write_text("transparent_masking = false\n")
    monkeypatch.setenv("DUCKICELAKE_CONFIG_FILE", str(cfg))
    monkeypatch.delenv("DUCKICELAKE_TRANSPARENT_MASKING", raising=False)
    injected = apply_file_config(cwd=tmp_path)
    try:
        assert os.environ["DUCKICELAKE_TRANSPARENT_MASKING"] == "0"
        s = load_settings()
        assert s.transparent_masking is False
    finally:
        for key in injected:
            os.environ.pop(key, None)


def test_suppress_root_creds_defaults_on(monkeypatch):
    monkeypatch.delenv("DUCKICELAKE_SUPPRESS_ROOT_CREDS", raising=False)
    assert load_settings().suppress_root_creds is True
    monkeypatch.setenv("DUCKICELAKE_SUPPRESS_ROOT_CREDS", "0")
    assert load_settings().suppress_root_creds is False


def test_responses_omit_root_keys_by_default(client):
    """The session proxy runs with no DUCKICELAKE_SUPPRESS_ROOT_CREDS set —
    the new default must keep the root key pair out of every response
    config (endpoint/region/url-style stay, for client convenience)."""
    import uuid
    ns = f"cfg_{uuid.uuid4().hex[:6]}"
    client.post("/v1/lake/namespaces", json={"namespace": [ns]}).raise_for_status()
    client.post(f"/v1/lake/namespaces/{ns}/tables",
                json={"name": "t", "schema": {
                    "type": "struct", "schema-id": 0,
                    "fields": [{"id": 1, "name": "x", "required": True,
                                "type": "long"}]}}).raise_for_status()
    cfg = client.get(f"/v1/lake/namespaces/{ns}/tables/t").json()["config"]
    assert "s3.access-key-id" not in cfg
    assert "s3.secret-access-key" not in cfg
    assert cfg["s3.endpoint"]
