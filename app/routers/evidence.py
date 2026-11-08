import hmac
import os
import re
import uuid

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from ..audit import log_audit, log_custody
from ..config import settings
from ..database import get_db
from ..deps import get_case_checked, get_evidence_checked, require
from ..models import CustodyEvent, Evidence, User, Verification
from ..schemas import CustodyOut, EvidenceOut, VerificationOut
from ..storage import HashingReader, TooLarge, get_storage

router = APIRouter(prefix="/api", tags=["evidence"])


def _safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._ -]", "_", os.path.basename(name or ""))[:200]


@router.post("/cases/{case_id}/evidence", response_model=EvidenceOut, status_code=201)
def register_evidence(case_id: int, file: UploadFile = File(...),
                      user: User = Depends(require("evidence:register")), db: Session = Depends(get_db)):
    """FR3 + FR4: store the file, calculate its SHA-256 while storing, record custody + audit."""
    case = get_case_checked(db, user, case_id)
    if case.status != "open":
        raise HTTPException(409, "This case is closed")
    filename = _safe_name(file.filename)
    ext = os.path.splitext(filename)[1].lower()
    if not filename or ext not in settings.allowed_extensions:
        log_audit(db, user.user_id, "evidence_rejected", "case", case_id, "failure")
        db.commit()
        raise HTTPException(400, f"File type not permitted: {ext or 'no extension'}")

    storage = get_storage()
    key = f"cases/{case_id}/{uuid.uuid4().hex}"
    reader = HashingReader(file.file, settings.max_upload_mb * 1024 * 1024)
    try:
        storage.save(key, reader)
    except TooLarge:
        log_audit(db, user.user_id, "evidence_rejected", "case", case_id, "failure")
        db.commit()
        raise HTTPException(413, f"File exceeds the {settings.max_upload_mb} MB limit")
    if reader.size == 0:
        storage.delete(key)
        raise HTTPException(400, "Empty files cannot be registered")

    try:
        ev = Evidence(case_id=case_id, submitted_by=user.user_id, filename=filename,
                      file_type=file.content_type or "application/octet-stream", file_size=reader.size,
                      storage_key=key, sha256_hash=reader.sha256)
        db.add(ev)
        db.flush()
        log_custody(db, ev.evidence_id, user.user_id, "registered", f"sha256={ev.sha256_hash}")
        log_audit(db, user.user_id, "evidence_registered", "evidence", ev.evidence_id)
        db.commit()
    except Exception:
        db.rollback()
        storage.delete(key)
        raise
    db.refresh(ev)
    return ev


@router.get("/cases/{case_id}/evidence", response_model=list[EvidenceOut])
def list_evidence(case_id: int, user: User = Depends(require("evidence:read")), db: Session = Depends(get_db)):
    get_case_checked(db, user, case_id)
    return db.query(Evidence).filter(Evidence.case_id == case_id).order_by(Evidence.evidence_id).all()


@router.get("/evidence/{evidence_id}", response_model=EvidenceOut)
def get_evidence(evidence_id: int, user: User = Depends(require("evidence:read")), db: Session = Depends(get_db)):
    return get_evidence_checked(db, user, evidence_id)


@router.get("/evidence/{evidence_id}/custody", response_model=list[CustodyOut])
def custody_trail(evidence_id: int, user: User = Depends(require("evidence:read")), db: Session = Depends(get_db)):
    ev = get_evidence_checked(db, user, evidence_id)
    return db.query(CustodyEvent).filter(CustodyEvent.evidence_id == ev.evidence_id)\
        .order_by(CustodyEvent.event_id).all()


@router.get("/evidence/{evidence_id}/download")
def download_evidence(evidence_id: int, user: User = Depends(require("evidence:read")),
                      db: Session = Depends(get_db)):
    """FR8: retrieval is recorded in the custody trail and audit log."""
    ev = get_evidence_checked(db, user, evidence_id)
    log_custody(db, ev.evidence_id, user.user_id, "retrieved", "downloaded")
    log_audit(db, user.user_id, "evidence_retrieved", "evidence", ev.evidence_id)
    db.commit()
    return StreamingResponse(get_storage().stream(ev.storage_key), media_type="application/octet-stream",
                             headers={"Content-Disposition": f'attachment; filename="{ev.filename}"'})


@router.post("/evidence/{evidence_id}/verify", response_model=VerificationOut)
def verify_evidence(evidence_id: int, user: User = Depends(require("evidence:verify")),
                    db: Session = Depends(get_db)):
    """FR5: recompute the SHA-256 from storage and compare it with the registered hash."""
    ev = get_evidence_checked(db, user, evidence_id)
    try:
        calculated = get_storage().sha256(ev.storage_key)
        result = "match" if hmac.compare_digest(calculated, ev.sha256_hash) else "mismatch"
    except Exception:
        calculated, result = None, "error"

    verification = Verification(evidence_id=ev.evidence_id, requested_by=user.user_id,
                                calculated_hash=calculated, reference_hash=ev.sha256_hash, result=result)
    db.add(verification)
    ev.status = {"match": "verified", "mismatch": "integrity_failed", "error": "verification_error"}[result]
    log_custody(db, ev.evidence_id, user.user_id, "verified" if result == "match" else "integrity_failure",
                f"result={result}")
    log_audit(db, user.user_id, "evidence_verified", "evidence", ev.evidence_id,
              "success" if result == "match" else "failure")
    db.commit()
    db.refresh(verification)
    return verification


@router.get("/evidence/{evidence_id}/verifications", response_model=list[VerificationOut])
def verification_history(evidence_id: int, user: User = Depends(require("evidence:read")),
                         db: Session = Depends(get_db)):
    ev = get_evidence_checked(db, user, evidence_id)
    return db.query(Verification).filter(Verification.evidence_id == ev.evidence_id)\
        .order_by(Verification.verification_id).all()
