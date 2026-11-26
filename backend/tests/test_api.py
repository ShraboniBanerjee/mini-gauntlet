"""REST API: starting, reading and filtering scans, pagination, 404 and 422."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.store import Store
from tests.conftest import INVENTORY_PATH

PROD, DEV, AZURE, GCP = (
    "123456789012",
    "210987654321",
    "8f14e45f-ceea-4e7a-9d3b-2f6c1a0b7d21",
    "example-corp-gcp",
)
STATUS_RANK = {"FAIL": 0, "CANNOT_SCAN": 1, "PASS": 2}
SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def make_client(db_path: Path, inventory_path: Path = INVENTORY_PATH) -> TestClient:
    settings = Settings(inventory_path=inventory_path, database_path=db_path)
    # No simulated latency in API tests; the engine tests cover timing.
    return TestClient(create_app(settings, sleep=lambda _: None))


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    with make_client(tmp_path / "test.db") as test_client:
        yield test_client


def start_scan(client: TestClient, body: Any = None) -> dict[str, Any]:
    response = client.post("/api/scans") if body is None else client.post("/api/scans", json=body)
    assert response.status_code == 202, response.text
    return response.json()


@pytest.fixture
def completed_scan(client: TestClient) -> dict[str, Any]:
    # TestClient runs background tasks before returning, so the scan has finished.
    scan = start_scan(client)
    return client.get(f"/api/scans/{scan['id']}").json()


# --- Health and catalog -------------------------------------------------------------


def test_health(client: TestClient) -> None:
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_checks_catalog(client: TestClient) -> None:
    checks = client.get("/api/checks").json()
    assert len(checks) == 10
    s3 = next(c for c in checks if c["check_id"] == "AWS-S3-01")
    assert s3 == {
        "check_id": "AWS-S3-01",
        "title": "S3 bucket blocks public access",
        "severity": "HIGH",
        "provider": "aws",
        "collection": "s3_buckets",
        "resource_id_field": "name",
    }


# --- Starting scans -----------------------------------------------------------------


def test_start_scan_returns_202_running(client: TestClient) -> None:
    scan = start_scan(client)
    assert scan["status"] == "RUNNING"
    assert scan["finished_at"] is None
    assert scan["score"] is None
    assert scan["account_ids"] is None  # every account


def test_completed_scan_summary(completed_scan: dict[str, Any]) -> None:
    assert completed_scan["status"] == "COMPLETED"
    assert completed_scan["finished_at"] is not None
    assert completed_scan["counts"] == {"PASS": 27, "FAIL": 18, "CANNOT_SCAN": 4}
    assert completed_scan["score"] == 60.0
    assert completed_scan["fail_counts_by_severity"] == {
        "CRITICAL": 7,
        "HIGH": 8,
        "MEDIUM": 2,
        "LOW": 1,
    }
    assert completed_scan["account_ids"] == [PROD, DEV, AZURE, GCP]


def test_completed_scan_per_account_scores(completed_scan: dict[str, Any]) -> None:
    accounts = {a["account_id"]: a for a in completed_scan["accounts"]}
    assert {k: v["score"] for k, v in accounts.items()} == {
        PROD: 58.3,  # 14 / 24
        DEV: 66.7,  # 2 / 3
        AZURE: 57.1,  # 4 / 7
        GCP: 63.6,  # 7 / 11
    }
    assert accounts[DEV]["counts"] == {"PASS": 2, "FAIL": 1, "CANNOT_SCAN": 4}
    assert accounts[AZURE]["name"] == "example-corp-azure"
    assert accounts[AZURE]["provider"] == "azure"


def test_scan_selected_accounts(client: TestClient) -> None:
    scan = start_scan(client, {"account_ids": [AZURE, AZURE]})  # duplicates collapse
    assert scan["account_ids"] == [AZURE]
    detail = client.get(f"/api/scans/{scan['id']}").json()
    assert [a["account_id"] for a in detail["accounts"]] == [AZURE]
    assert detail["counts"] == {"PASS": 4, "FAIL": 3, "CANNOT_SCAN": 0}


def test_empty_body_object_scans_everything(client: TestClient) -> None:
    scan = start_scan(client, {})
    assert scan["account_ids"] is None


def test_scan_with_only_cannot_scan_findings_has_null_score(tmp_path: Path) -> None:
    inventory = tmp_path / "inventory.json"
    inventory.write_text(
        '{"snapshot_taken_at": "2026-10-01T00:00:00Z", "accounts": [{"provider": "aws", '
        '"account_id": "1", "errors": {"iam_users": "AccessDenied"}, "resources": {}}]}'
    )
    with make_client(tmp_path / "db.sqlite", inventory) as client:
        scan = start_scan(client)
        detail = client.get(f"/api/scans/{scan['id']}").json()
    assert detail["counts"] == {"PASS": 0, "FAIL": 0, "CANNOT_SCAN": 2}
    assert detail["score"] is None
    assert detail["accounts"][0]["score"] is None


@pytest.mark.parametrize(
    "body",
    [
        {"account_ids": []},
        {"account_ids": ["nope"]},
        {"account_ids": [PROD, "nope"]},
        {"account_ids": [""]},
        {"account_ids": [123]},
        {"account_ids": "123456789012"},
        {"accounts": [PROD]},  # unknown field
    ],
)
def test_start_scan_rejects_bad_bodies(client: TestClient, body: Any) -> None:
    response = client.post("/api/scans", json=body)
    assert response.status_code == 422
    assert client.get("/api/scans").json() == []  # nothing was created


def test_unknown_account_error_names_the_account(client: TestClient) -> None:
    response = client.post("/api/scans", json={"account_ids": [PROD, "nope"]})
    detail = response.json()["detail"][0]
    assert detail["loc"] == ["body", "account_ids"]
    assert detail["input"] == ["nope"]


def test_unreadable_inventory_fails_the_scan(tmp_path: Path) -> None:
    with make_client(tmp_path / "db.sqlite", tmp_path / "missing.json") as client:
        scan = start_scan(client)
        detail = client.get(f"/api/scans/{scan['id']}").json()
    assert detail["status"] == "FAILED"
    assert "not found" in detail["error"]
    assert detail["finished_at"] is not None
    assert detail["score"] is None


# --- Reading scans --------------------------------------------------------------------


def test_list_scans_newest_first(client: TestClient) -> None:
    first = start_scan(client)
    second = start_scan(client, {"account_ids": [GCP]})
    scans = client.get("/api/scans").json()
    assert [s["id"] for s in scans] == [second["id"], first["id"]]
    assert scans[0]["counts"] == {"PASS": 7, "FAIL": 4, "CANNOT_SCAN": 0}
    assert scans[0]["score"] == 63.6
    assert set(scans[0]) >= {"id", "status", "started_at", "finished_at", "account_ids"}


def test_unknown_scan_is_404(client: TestClient) -> None:
    assert client.get("/api/scans/not-a-scan").status_code == 404
    assert client.get("/api/scans/not-a-scan/findings").status_code == 404


def test_scans_survive_a_restart(tmp_path: Path) -> None:
    db_path = tmp_path / "persist.db"
    with make_client(db_path) as client:
        scan_id = start_scan(client)["id"]
    with make_client(db_path) as client:
        detail = client.get(f"/api/scans/{scan_id}").json()
        findings = client.get(f"/api/scans/{scan_id}/findings").json()
    assert detail["status"] == "COMPLETED"
    assert findings["total"] == 49


def test_scan_running_at_shutdown_is_failed_on_startup(tmp_path: Path) -> None:
    db_path = tmp_path / "interrupted.db"
    store = Store(db_path)
    store.initialize()
    scan = store.create_scan(None)
    with make_client(db_path) as client:
        detail = client.get(f"/api/scans/{scan.id}").json()
    assert detail["status"] == "FAILED"
    assert "restarted" in detail["error"]


# --- Findings -------------------------------------------------------------------------


def findings(client: TestClient, scan_id: str, **params: Any) -> dict[str, Any]:
    response = client.get(f"/api/scans/{scan_id}/findings", params=params)
    assert response.status_code == 200, response.text
    return response.json()


def test_findings_default_page(client: TestClient, completed_scan: dict[str, Any]) -> None:
    page = findings(client, completed_scan["id"])
    assert (page["total"], page["page"], page["page_size"]) == (49, 1, 25)
    assert len(page["items"]) == 25
    assert set(page["items"][0]) == {
        "id",
        "scan_id",
        "check_id",
        "title",
        "provider",
        "account_id",
        "region",
        "resource_id",
        "status",
        "severity",
        "details",
    }


def test_findings_order(client: TestClient, completed_scan: dict[str, Any]) -> None:
    items = findings(client, completed_scan["id"], page_size=100)["items"]
    keys = [
        (
            STATUS_RANK[f["status"]],
            SEVERITY_RANK[f["severity"]],
            f["check_id"],
            f["resource_id"] or "",
        )
        for f in items
    ]
    assert keys == sorted(keys)
    assert items[0]["status"] == "FAIL"
    assert items[0]["severity"] == "CRITICAL"
    assert items[-1]["status"] == "PASS"
    statuses = [f["status"] for f in items]
    assert statuses == ["FAIL"] * 18 + ["CANNOT_SCAN"] * 4 + ["PASS"] * 27


def test_findings_pagination(client: TestClient, completed_scan: dict[str, Any]) -> None:
    scan_id = completed_scan["id"]
    every = findings(client, scan_id, page_size=100)["items"]
    paged = [
        f
        for page in range(1, 6)
        for f in findings(client, scan_id, page=page, page_size=10)["items"]
    ]
    assert [f["id"] for f in paged] == [f["id"] for f in every]
    last = findings(client, scan_id, page=5, page_size=10)
    assert len(last["items"]) == 9
    beyond = findings(client, scan_id, page=6, page_size=10)
    assert beyond["items"] == []
    assert beyond["total"] == 49


@pytest.mark.parametrize(
    ("params", "total"),
    [
        ({"status": "fail"}, 18),
        ({"status": "Cannot_Scan"}, 4),
        ({"status": "PASS"}, 27),
        ({"severity": "critical"}, 18),
        ({"status": "FAIL", "severity": "CRITICAL"}, 7),
        ({"provider": "AWS"}, 31),
        ({"provider": "azure"}, 7),
        ({"account_id": DEV}, 7),
        ({"account_id": "EXAMPLE-CORP-GCP"}, 11),
        ({"check_id": "aws-ec2-01"}, 9),
        ({"status": "fail", "provider": "gcp", "check_id": "GCP-GCS-01"}, 2),
        ({"status": ""}, 49),  # empty filter means no filter
        ({"account_id": "no-such-account"}, 0),
    ],
)
def test_findings_filters(
    client: TestClient, completed_scan: dict[str, Any], params: dict[str, Any], total: int
) -> None:
    page = findings(client, completed_scan["id"], page_size=100, **params)
    assert page["total"] == total
    assert len(page["items"]) == total


@pytest.mark.parametrize(
    "params",
    [
        {"page": 0},
        {"page_size": 0},
        {"page_size": 101},
        {"page": "two"},
        {"status": "BROKEN"},
        {"severity": "urgent"},
    ],
)
def test_findings_bad_params_are_422(
    client: TestClient, completed_scan: dict[str, Any], params: dict[str, Any]
) -> None:
    response = client.get(f"/api/scans/{completed_scan['id']}/findings", params=params)
    assert response.status_code == 422


def test_untrusted_strings_come_back_as_plain_data(
    client: TestClient, completed_scan: dict[str, Any]
) -> None:
    items = findings(client, completed_scan["id"], check_id="GCP-VPC-01", page_size=100)["items"]
    assert all("<img" not in f["details"] for f in items)
    response = client.get(f"/api/scans/{completed_scan['id']}/findings")
    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["x-content-type-options"] == "nosniff"
