from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..audit import verify_chain
from ..database import get_db
from ..deps import require
from ..models import AuditEvent, User
from ..schemas import AuditOut

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("", response_model=list[AuditOut])
def list_audit(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
               user: User = Depends(require("audit:read")), db: Session = Depends(get_db)):
    return db.query(AuditEvent).order_by(AuditEvent.audit_id.desc()).offset(offset).limit(limit).all()


@router.get("/verify-chain")
def check_chain(user: User = Depends(require("audit:read")), db: Session = Depends(get_db)):
    return verify_chain(db)
