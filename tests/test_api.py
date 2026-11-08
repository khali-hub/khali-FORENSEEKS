"""Automated test cases for the evaluation chapter. Each test notes the requirement it checks.

Run with:  pytest -v
"""
import hashlib
import os
import tempfile

_tmp = tempfile.mkdtemp()
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp}/test.db"
os.environ["EVIDENCE_DIR"] = f"{_tmp}/evidence"
os.environ["SECRET_KEY"] = "test-secret"
os.environ["ADMIN_USERNAME"] = "admin"
os.environ["ADMIN_PASSWORD"] = "AdminPass123!"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.database import SessionLocal  # noqa: E402
from app.main import app  # noqa: E402
from app.models import AuditEvent, Evidence  # noqa: E402
from app.storage import get_storage  # noqa: E402

PW = "Passw0rd!123"
CONTENT = b"2026-11-05 10:00:01 sshd[311]: Failed password for root from 10.0.0.5\n" * 20


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def login(client, username, password):
    r = client.post("/api/auth/login", data={"username": username, "password": password})
    return r


def headers(client, username, password=PW):
    return {"Authorization": f"Bearer {login(client, username, password).json()['access_token']}"}


@pytest.fixture(scope="module")
def users(client):
    admin = headers(client, "admin", "AdminPass123!")
    for name, role in (("inv1", "investigator"), ("inv2", "investigator"), ("rev1", "reviewer")):
        assert client.post("/api/users", json={"username": name, "password": PW, "role": role},
                           headers=admin).status_code == 201
    return {"admin": admin, "inv1": headers(client, "inv1"), "inv2": headers(client, "inv2"),
            "rev1": headers(client, "rev1")}


@pytest.fixture(scope="module")
def case_and_evidence(client, users):
    case = client.post("/api/cases", json={"title": "Suspicious SSH logins", "description": "Test"},
                       headers=users["inv1"]).json()
    r = client.post(f"/api/cases/{case['case_id']}/evidence", headers=users["inv1"],
                    files={"file": ("auth.log", CONTENT, "text/plain")})
    return case, r.json()


# ---- FR1 / NFR1: authentication --------------------------------------------------
def test_fr1_protected_route_requires_login(client):
    assert client.get("/api/cases").status_code == 401


def test_fr1_wrong_password_rejected(client, users):
    assert login(client, "inv1", "wrong-password").status_code == 401


# ---- FR2: cases ------------------------------------------------------------------
def test_fr2_create_and_list_case(client, users, case_and_evidence):
    case, _ = case_and_evidence
    ids = [c["case_id"] for c in client.get("/api/cases", headers=users["inv1"]).json()]
    assert case["case_id"] in ids


# ---- FR3 / FR4: registration and hashing -----------------------------------------
def test_fr4_hash_matches_independent_reference(case_and_evidence):
    _, ev = case_and_evidence
    assert ev["sha256_hash"] == hashlib.sha256(CONTENT).hexdigest()
    assert ev["file_size"] == len(CONTENT)
    assert "storage_key" not in ev  # NFR8: internals are not exposed


# ---- FR5 / NFR2: integrity verification ------------------------------------------
def test_fr5_unchanged_file_verifies(client, users, case_and_evidence):
    _, ev = case_and_evidence
    r = client.post(f"/api/evidence/{ev['evidence_id']}/verify", headers=users["inv1"])
    assert r.status_code == 200 and r.json()["result"] == "match"


def test_nfr2_modified_file_is_detected(client, users):
    case = client.post("/api/cases", json={"title": "Tamper test case"}, headers=users["inv1"]).json()
    ev = client.post(f"/api/cases/{case['case_id']}/evidence", headers=users["inv1"],
                     files={"file": ("note.txt", b"original evidence", "text/plain")}).json()
    with SessionLocal() as db:  # simulate someone altering the stored file
        key = db.get(Evidence, ev["evidence_id"]).storage_key
    with open(get_storage()._path(key), "ab") as f:
        f.write(b" tampered")
    r = client.post(f"/api/evidence/{ev['evidence_id']}/verify", headers=users["inv1"])
    assert r.json()["result"] == "mismatch"
    assert client.get(f"/api/evidence/{ev['evidence_id']}", headers=users["inv1"]).json()["status"] == "integrity_failed"


# ---- FR6 / NFR3: custody and audit -----------------------------------------------
def test_fr6_custody_events_recorded(client, users, case_and_evidence):
    _, ev = case_and_evidence
    client.get(f"/api/evidence/{ev['evidence_id']}/download", headers=users["inv1"])
    events = [e["event_type"] for e in
              client.get(f"/api/evidence/{ev['evidence_id']}/custody", headers=users["inv1"]).json()]
    assert events[0] == "registered" and "retrieved" in events and "verified" in events


def test_nfr3_audit_chain_valid_then_detects_tampering(client, users):
    assert client.get("/api/audit/verify-chain", headers=users["rev1"]).json()["valid"] is True
    with SessionLocal() as db:
        row = db.query(AuditEvent).order_by(AuditEvent.audit_id).offset(2).first()
        row.outcome = "success-edited"
        db.commit()
    assert client.get("/api/audit/verify-chain", headers=users["rev1"]).json()["valid"] is False


# ---- FR7 / NFR1: permissions -----------------------------------------------------
def test_fr7_reviewer_cannot_register_evidence(client, users, case_and_evidence):
    case, _ = case_and_evidence
    r = client.post(f"/api/cases/{case['case_id']}/evidence", headers=users["rev1"],
                    files={"file": ("x.txt", b"data", "text/plain")})
    assert r.status_code == 403


def test_fr7_admin_cannot_access_evidence(client, users, case_and_evidence):
    _, ev = case_and_evidence
    assert client.get(f"/api/evidence/{ev['evidence_id']}", headers=users["admin"]).status_code == 403


def test_fr7_investigator_cannot_open_another_investigators_case(client, users, case_and_evidence):
    case, ev = case_and_evidence
    assert client.get(f"/api/cases/{case['case_id']}", headers=users["inv2"]).status_code == 403
    assert client.get(f"/api/evidence/{ev['evidence_id']}/download", headers=users["inv2"]).status_code == 403


def test_fr7_reviewer_can_read_but_not_verify(client, users, case_and_evidence):
    _, ev = case_and_evidence
    assert client.get(f"/api/evidence/{ev['evidence_id']}", headers=users["rev1"]).status_code == 200
    assert client.post(f"/api/evidence/{ev['evidence_id']}/verify", headers=users["rev1"]).status_code == 403


# ---- FR8: retrieval --------------------------------------------------------------
def test_fr8_download_returns_original_bytes(client, users, case_and_evidence):
    _, ev = case_and_evidence
    r = client.get(f"/api/evidence/{ev['evidence_id']}/download", headers=users["inv1"])
    assert r.status_code == 200 and r.content == CONTENT


# ---- FR9 / FR10: report and search -----------------------------------------------
def test_fr9_report_contains_evidence_and_custody(client, users, case_and_evidence):
    case, _ = case_and_evidence
    rep = client.get(f"/api/cases/{case['case_id']}/report", headers=users["inv1"]).json()
    assert rep["evidence"][0]["custody"] and "audit_chain" in rep


def test_fr10_search_finds_case_and_evidence(client, users, case_and_evidence):
    res = client.get("/api/search", params={"q": "auth.log"}, headers=users["inv1"]).json()
    assert len(res["evidence"]) >= 1
    res2 = client.get("/api/search", params={"q": "auth.log"}, headers=users["inv2"]).json()
    assert res2["evidence"] == []  # investigators only see their own cases


# ---- NFR4: invalid input ---------------------------------------------------------
def test_nfr4_disallowed_file_type_rejected(client, users, case_and_evidence):
    case, _ = case_and_evidence
    r = client.post(f"/api/cases/{case['case_id']}/evidence", headers=users["inv1"],
                    files={"file": ("malware.exe", b"MZ...", "application/octet-stream")})
    assert r.status_code == 400


def test_nfr4_empty_file_rejected(client, users, case_and_evidence):
    case, _ = case_and_evidence
    r = client.post(f"/api/cases/{case['case_id']}/evidence", headers=users["inv1"],
                    files={"file": ("empty.txt", b"", "text/plain")})
    assert r.status_code == 400
