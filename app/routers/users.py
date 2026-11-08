from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..audit import log_audit
from ..database import get_db
from ..deps import require
from ..models import User
from ..schemas import UserCreate, UserOut, UserUpdate
from ..security import hash_password

router = APIRouter(prefix="/api/users", tags=["users"])


@router.post("", response_model=UserOut, status_code=201)
def create_user(body: UserCreate, admin: User = Depends(require("user:manage")), db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == body.username).first():
        raise HTTPException(409, "Username already exists")
    user = User(username=body.username, password_hash=hash_password(body.password), role=body.role)
    db.add(user)
    db.flush()
    log_audit(db, admin.user_id, "user_created", "user", user.user_id)
    db.commit()
    db.refresh(user)
    return user


@router.get("", response_model=list[UserOut])
def list_users(admin: User = Depends(require("user:manage")), db: Session = Depends(get_db)):
    return db.query(User).order_by(User.user_id).all()


@router.patch("/{user_id}", response_model=UserOut)
def update_user(user_id: int, body: UserUpdate, admin: User = Depends(require("user:manage")),
                db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    if user.user_id == admin.user_id and (body.status == "disabled" or (body.role and body.role != "admin")):
        raise HTTPException(400, "You cannot disable or demote your own account")
    if body.role:
        user.role = body.role
    if body.status:
        user.status = body.status
    if body.password:
        user.password_hash = hash_password(body.password)
    log_audit(db, admin.user_id, "user_updated", "user", user.user_id)
    db.commit()
    db.refresh(user)
    return user
