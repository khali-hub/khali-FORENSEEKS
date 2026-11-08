"""First-run setup: creates the first admin account if the database has no users."""
import secrets

from .config import settings
from .models import User
from .security import hash_password


def ensure_admin(db):
    if db.query(User).count() > 0:
        return
    password = settings.admin_password
    if not password:
        password = secrets.token_urlsafe(12)
        print(f"[setup] Created admin '{settings.admin_username}' with temporary password: {password}")
    db.add(User(username=settings.admin_username, password_hash=hash_password(password), role="admin"))
    db.commit()


if __name__ == "__main__":
    # Optional demo accounts for local testing ONLY. Change these passwords for anything real.
    from .database import Base, SessionLocal, engine
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        for name, role in (("investigator1", "investigator"), ("reviewer1", "reviewer")):
            if not db.query(User).filter(User.username == name).first():
                db.add(User(username=name, password_hash=hash_password("ChangeMe123!"), role=role))
        db.commit()
    print("Demo users created: investigator1 and reviewer1 (password ChangeMe123!)")
