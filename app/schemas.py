"""Request and response shapes. Note: storage_key and password_hash are never returned (NFR8)."""
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

Role = Literal["admin", "investigator", "reviewer"]


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    username: str


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=8, max_length=128)
    role: Role


class UserUpdate(BaseModel):
    role: Optional[Role] = None
    status: Optional[Literal["active", "disabled"]] = None
    password: Optional[str] = Field(default=None, min_length=8, max_length=128)


class UserOut(ORM):
    user_id: int
    username: str
    role: str
    status: str
    created_at: datetime


class CaseCreate(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(default="", max_length=5000)


class CaseUpdate(BaseModel):
    title: Optional[str] = Field(default=None, min_length=3, max_length=200)
    description: Optional[str] = Field(default=None, max_length=5000)
    status: Optional[Literal["open", "closed"]] = None


class CaseOut(ORM):
    case_id: int
    case_reference: str
    title: str
    description: str
    created_by: int
    status: str
    created_at: datetime


class EvidenceOut(ORM):
    evidence_id: int
    case_id: int
    submitted_by: int
    filename: str
    file_type: str
    file_size: int
    sha256_hash: str
    status: str
    created_at: datetime


class CustodyOut(ORM):
    event_id: int
    evidence_id: int
    actor_id: int
    event_type: str
    event_time: datetime
    details: str


class VerificationOut(ORM):
    verification_id: int
    evidence_id: int
    requested_by: int
    verification_time: datetime
    calculated_hash: Optional[str]
    reference_hash: str
    result: str


class AuditOut(ORM):
    audit_id: int
    actor_id: Optional[int]
    action: str
    resource_type: str
    resource_id: Optional[str]
    outcome: str
    event_time: datetime
    entry_hash: str
