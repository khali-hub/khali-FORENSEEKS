"""Database models. These mirror the class diagram in Figure 3.7 of Chapter 3.

Extension to the diagram: AuditEvent has prev_hash and entry_hash columns so the
audit log forms a hash chain (tamper-evident).
"""
from datetime import datetime, timezone

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


def utcnow() -> datetime:
    """Naive UTC timestamp (stored the same way in SQLite and PostgreSQL)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(Base):
    __tablename__ = "users"
    user_id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20))  # admin | investigator | reviewer
    status: Mapped[str] = mapped_column(String(20), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Case(Base):
    __tablename__ = "cases"
    case_id: Mapped[int] = mapped_column(primary_key=True)
    case_reference: Mapped[str] = mapped_column(String(30), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[int] = mapped_column(ForeignKey("users.user_id"))
    status: Mapped[str] = mapped_column(String(20), default="open")  # open | closed
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Evidence(Base):
    __tablename__ = "evidence_items"
    evidence_id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.case_id"), index=True)
    submitted_by: Mapped[int] = mapped_column(ForeignKey("users.user_id"))
    filename: Mapped[str] = mapped_column(String(255))
    file_type: Mapped[str] = mapped_column(String(100))
    file_size: Mapped[int] = mapped_column(BigInteger)
    storage_key: Mapped[str] = mapped_column(String(255), unique=True)
    sha256_hash: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(30), default="registered")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    audit_id: Mapped[int] = mapped_column(primary_key=True)
    actor_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    action: Mapped[str] = mapped_column(String(60))
    resource_type: Mapped[str] = mapped_column(String(40))
    resource_id: Mapped[str | None] = mapped_column(String(60), nullable=True)
    outcome: Mapped[str] = mapped_column(String(20))  # success | failure | denied
    event_time: Mapped[datetime] = mapped_column(DateTime)
    prev_hash: Mapped[str] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64))


class CustodyEvent(Base):
    __tablename__ = "custody_events"
    event_id: Mapped[int] = mapped_column(primary_key=True)
    evidence_id: Mapped[int] = mapped_column(ForeignKey("evidence_items.evidence_id"), index=True)
    actor_id: Mapped[int] = mapped_column(ForeignKey("users.user_id"))
    event_type: Mapped[str] = mapped_column(String(40))  # registered | retrieved | verified | integrity_failure
    event_time: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    details: Mapped[str] = mapped_column(Text, default="")


class Verification(Base):
    __tablename__ = "verifications"
    verification_id: Mapped[int] = mapped_column(primary_key=True)
    evidence_id: Mapped[int] = mapped_column(ForeignKey("evidence_items.evidence_id"), index=True)
    requested_by: Mapped[int] = mapped_column(ForeignKey("users.user_id"))
    verification_time: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    calculated_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reference_hash: Mapped[str] = mapped_column(String(64))
    result: Mapped[str] = mapped_column(String(20))  # match | mismatch | error
