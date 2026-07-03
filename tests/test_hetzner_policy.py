"""Pure-unit tests for the Hetzner bucket-policy generator (no network)."""
from __future__ import annotations

import json

import pytest

from duckicelake.hetzner_policy import (
    PrincipalGrant,
    build_bucket_policy,
    principal_arn,
)


def test_principal_arn_shape():
    assert principal_arn("12345", "AKXYZ") == "arn:aws:iam:::user/p12345:AKXYZ"


def test_policy_golden_shape():
    grants = [PrincipalGrant(
        principal="alice",
        access_key_id="AKALICE",
        list_prefixes=["data/"],
        allow_prefixes=["data/", "data/__masked__/ns/t/cafe0123beef/"],
        deny_prefixes=["data/ns/t/"],
    )]
    policy = build_bucket_policy("lakehouse", "4711", grants)
    assert policy["Version"] == "2012-10-17"
    stmts = policy["Statement"]
    assert [s["Sid"] for s in stmts] == ["List0", "Read0", "DenyMaskedBase0"]
    arn = "arn:aws:iam:::user/p4711:AKALICE"
    assert all(s["Principal"] == {"AWS": arn} for s in stmts)

    lst = stmts[0]
    assert lst["Action"] == ["s3:ListBucket"]
    assert lst["Resource"] == ["arn:aws:s3:::lakehouse"]
    assert lst["Condition"]["StringLike"]["s3:prefix"] == ["data/*", "data/"]

    read = stmts[1]
    assert read["Effect"] == "Allow" and read["Action"] == ["s3:GetObject"]
    assert read["Resource"] == [
        "arn:aws:s3:::lakehouse/data/*",
        "arn:aws:s3:::lakehouse/data/__masked__/ns/t/cafe0123beef/*",
    ]

    deny = stmts[2]
    assert deny["Effect"] == "Deny"
    assert deny["Resource"] == ["arn:aws:s3:::lakehouse/data/ns/t/*"]
    # sanity: the whole document round-trips as JSON
    json.dumps(policy)


def test_policy_multiple_principals_get_disjoint_sids():
    grants = [
        PrincipalGrant(principal="a", access_key_id="AKA",
                       list_prefixes=["data/"], allow_prefixes=["data/"]),
        PrincipalGrant(principal="b", access_key_id="AKB",
                       list_prefixes=["data/"], allow_prefixes=["data/"]),
    ]
    policy = build_bucket_policy("b", "1", grants)
    sids = [s["Sid"] for s in policy["Statement"]]
    assert sids == ["List0", "Read0", "List1", "Read1"]


def test_policy_requires_project_id():
    with pytest.raises(ValueError, match="hetzner_project_id"):
        build_bucket_policy("b", "", [PrincipalGrant(
            principal="a", access_key_id="AK",
            list_prefixes=["data/"], allow_prefixes=["data/"])])


def test_policy_size_guard_raises_past_20kb():
    grants = [
        PrincipalGrant(
            principal=f"p{i}",
            access_key_id=f"AK{i:04d}" + "X" * 16,
            list_prefixes=["data/"],
            allow_prefixes=[f"data/ns{j}/table{j}/" for j in range(30)],
            deny_prefixes=[f"data/ns{j}/secret{j}/" for j in range(30)],
        )
        for i in range(40)
    ]
    with pytest.raises(ValueError, match="bucket policy is"):
        build_bucket_policy("lakehouse", "4711", grants)
