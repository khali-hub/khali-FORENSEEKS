import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session

from ..audit import log_audit, verify_chain
from ..database import get_db
from ..deps import get_case_checked, require
from ..models import Case, CustodyEvent, Evidence, User, Verification
from ..schemas import CaseCreate, CaseOut, CaseUpdate, EvidenceOut

router = APIRouter(prefix="/api", tags=["cases"])


def _visible_cases(db: Session, user: User):
    q = db.query(Case)
    if user.role == "investigator":
        q = q.filter(Case.created_by == user.user_id)
    return q


@router.post("/cases", response_model=CaseOut, status_code=201)
def create_case(body: CaseCreate, user: User = Depends(require("case:create")), db: Session = Depends(get_db)):
    ref = f"CASE-{datetime.now(timezone.utc).year}-{secrets.token_hex(3).upper()}"
    case = Case(case_reference=ref, title=body.title, description=body.description, created_by=user.user_id)
    db.add(case)
    db.flush()
    log_audit(db, user.user_id, "case_created", "case", case.case_id)
    db.commit()
    db.refresh(case)
    return case


@router.get("/cases", response_model=list[CaseOut])
def list_cases(user: User = Depends(require("case:read")), db: Session = Depends(get_db)):
    return _visible_cases(db, user).order_by(Case.case_id.desc()).all()


@router.get("/cases/{case_id}", response_model=CaseOut)
def get_case(case_id: int, user: User = Depends(require("case:read")), db: Session = Depends(get_db)):
    return get_case_checked(db, user, case_id)


@router.patch("/cases/{case_id}", response_model=CaseOut)
def update_case(case_id: int, body: CaseUpdate, user: User = Depends(require("case:update")),
                db: Session = Depends(get_db)):
    case = get_case_checked(db, user, case_id)
    for field in ("title", "description", "status"):
        value = getattr(body, field)
        if value is not None:
            setattr(case, field, value)
    log_audit(db, user.user_id, "case_updated", "case", case.case_id)
    db.commit()
    db.refresh(case)
    return case


@router.get("/cases/{case_id}/report")
def case_report(case_id: int, user: User = Depends(require("case:read")), db: Session = Depends(get_db)):
    """FR9: report with case, evidence, verification history and custody trail."""
    case = get_case_checked(db, user, case_id)
    items = db.query(Evidence).filter(Evidence.case_id == case_id).order_by(Evidence.evidence_id).all()
    evidence = []
    for ev in items:
        verifications = db.query(Verification).filter(Verification.evidence_id == ev.evidence_id)\
            .order_by(Verification.verification_id).all()
        custody = db.query(CustodyEvent).filter(CustodyEvent.evidence_id == ev.evidence_id)\
            .order_by(CustodyEvent.event_id).all()
        evidence.append({
            "evidence_id": ev.evidence_id, "filename": ev.filename, "file_size": ev.file_size,
            "sha256_hash": ev.sha256_hash, "status": ev.status, "registered_at": ev.created_at.isoformat(),
            "verifications": [{"time": v.verification_time.isoformat(), "result": v.result,
                               "calculated_hash": v.calculated_hash} for v in verifications],
            "custody": [{"time": c.event_time.isoformat(), "actor_id": c.actor_id,
                         "event": c.event_type, "details": c.details} for c in custody],
        })
    log_audit(db, user.user_id, "report_generated", "case", case_id)
    db.commit()
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generated_by": user.username,
        "case": CaseOut.model_validate(case).model_dump(mode="json"),
        "evidence": evidence,
        "audit_chain": verify_chain(db),
    }


@router.get("/search")
def search(q: str = Query(min_length=2, max_length=100), user: User = Depends(require("case:read")),
           db: Session = Depends(get_db)):
    """FR10: search across the cases and evidence the user is allowed to see."""
    like = f"%{q}%"
    cases = _visible_cases(db, user).filter(or_(
        Case.title.ilike(like), Case.case_reference.ilike(like), Case.description.ilike(like))).limit(50).all()
    ev_q = db.query(Evidence).join(Case, Case.case_id == Evidence.case_id)
    if user.role == "investigator":
        ev_q = ev_q.filter(Case.created_by == user.user_id)
    evidence = ev_q.filter(or_(Evidence.filename.ilike(like), Evidence.sha256_hash.ilike(like))).limit(50).all()
    return {"cases": [CaseOut.model_validate(c) for c in cases],
            "evidence": [EvidenceOut.model_validate(e) for e in evidence]}
