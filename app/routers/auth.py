from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from ..audit import log_audit
from ..database import get_db
from ..deps import current_user
from ..models import User
from ..schemas import TokenOut, UserOut
from ..security import create_token, verify_password

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=TokenOut)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form.username).first()
    if not user or user.status != "active" or not verify_password(form.password, user.password_hash):
        log_audit(db, user.user_id if user else None, "login", "auth", form.username, "failure")
        db.commit()
        raise HTTPException(401, "Incorrect username or password", headers={"WWW-Authenticate": "Bearer"})
    log_audit(db, user.user_id, "login", "auth", user.user_id, "success")
    db.commit()
    return TokenOut(access_token=create_token(user.user_id, user.role), role=user.role, username=user.username)


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)):
    return user
