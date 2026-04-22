"""End-to-end smoke test hitting the running server via HTTP.

Assumes `pixi run serve` (or equivalent) is up on localhost:8181 and that
`pixi run ducklake-init` has created the default namespace.
"""
from __future__ import annotations

import sys

import httpx


BASE = "http://localhost:8181"


def pretty(title: str, resp: httpx.Response) -> None:
    print(f"--- {title} [{resp.status_code}] ---")
    try:
        body = resp.json()
    except Exception:
        body = resp.text
    print(body)
    print()


def main() -> int:
    with httpx.Client(base_url=BASE, timeout=15.0) as c:
        cfg = c.get("/v1/config")
        pretty("GET /v1/config", cfg)
        cfg.raise_for_status()
        prefix = cfg.json()["overrides"]["prefix"]

        ns_name = "smoke"
        # Ensure clean state for idempotent reruns.
        c.delete(f"/v1/{prefix}/namespaces/{ns_name}/tables/widgets")
        c.delete(f"/v1/{prefix}/namespaces/{ns_name}")

        pretty(
            "POST /v1/{prefix}/namespaces",
            c.post(
                f"/v1/{prefix}/namespaces",
                json={"namespace": [ns_name], "properties": {"owner": "kevin"}},
            ),
        )

        pretty(
            "GET /v1/{prefix}/namespaces",
            c.get(f"/v1/{prefix}/namespaces"),
        )

        pretty(
            "POST /v1/{prefix}/namespaces/{ns}/tables",
            c.post(
                f"/v1/{prefix}/namespaces/{ns_name}/tables",
                json={
                    "name": "widgets",
                    "schema": {
                        "type": "struct",
                        "schema-id": 0,
                        "fields": [
                            {"id": 1, "name": "id", "required": True, "type": "long"},
                            {"id": 2, "name": "name", "required": False, "type": "string"},
                            {"id": 3, "name": "price", "required": False, "type": "decimal(10, 2)"},
                            {"id": 4, "name": "created_at", "required": False, "type": "timestamptz"},
                        ],
                    },
                },
            ),
        )

        pretty(
            "GET /v1/{prefix}/namespaces/{ns}/tables",
            c.get(f"/v1/{prefix}/namespaces/{ns_name}/tables"),
        )

        pretty(
            "GET /v1/{prefix}/namespaces/{ns}/tables/widgets",
            c.get(f"/v1/{prefix}/namespaces/{ns_name}/tables/widgets"),
        )

        pretty(
            "DELETE /v1/{prefix}/namespaces/{ns}/tables/widgets",
            c.delete(f"/v1/{prefix}/namespaces/{ns_name}/tables/widgets"),
        )

        pretty(
            "DELETE /v1/{prefix}/namespaces/{ns}",
            c.delete(f"/v1/{prefix}/namespaces/{ns_name}"),
        )

    print("Smoke test OK.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
