"""Authentication, role-based permissions and per-case access checks."""
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from .audit import log_audit
from .database import get_db
from .models import Case, Evidence, User
from .security import decode_token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# Role -> permissions. Admins manage users but have NO access to evidence (Section 3.6.2).
PERMISSIONS = {
    "admin": {"user:manage", "audit:read"},
    "investigator": {"case:create", "case:read", "case:update", "evidence:register",
                     "evidence:verify", "evidence:read"},
    "reviewer": {"case:read", "evidence:read", "audit:read"},  # read-only
}


def current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    unauthorised = HTTPException(401, "Invalid or expired token", headers={"WWW-Authenticate": "Bearer"})
    try:
        user_id = int(decode_token(token)["sub"])
    except Exception:
        raise unauthorised
    user = db.get(User, user_id)
    if not user or user.status != "active":
        raise unauthorised
    return user


def require(permission: str):
    def checker(user: User = Depends(current_user), db: Session = Depends(get_db)) -> User:
        if permission not in PERMISSIONS.get(user.role, set()):
            log_audit(db, user.user_id, f"denied:{permission}", "permission", None, "denied")
            db.commit()
            raise HTTPException(403, "You do not have permission to perform this action")
        return user
    return checker


def get_case_checked(db: Session, user: User, case_id: int) -> Case:
    """Investigators only reach their own cases; reviewers can read all cases."""
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(404, "Case not found")
    if user.role == "investigator" and case.created_by != user.user_id:
        log_audit(db, user.user_id, "denied:case_access", "case", case_id, "denied")
        db.commit()
        raise HTTPException(403, "You do not have access to this case")
    return case


def get_evidence_checked(db: Session, user: User, evidence_id: int) -> Evidence:
    ev = db.get(Evidence, evidence_id)
    if not ev:
        raise HTTPException(404, "Evidence not found")
    get_case_checked(db, user, ev.case_id)
    return ev
