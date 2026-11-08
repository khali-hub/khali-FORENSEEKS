"""Audit trail (hash-chained) and chain-of-custody helpers.

Every audit entry stores the hash of the previous entry. Changing or deleting any
earlier row breaks the chain, which verify_chain() detects.
"""
import hashlib

from sqlalchemy.orm import Session

from .models import AuditEvent, CustodyEvent, utcnow

GENESIS = "0" * 64


def _ts(dt) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")


def compute_entry_hash(prev_hash, actor_id, action, resource_type, resource_id, outcome, event_time) -> str:
    text = "|".join([prev_hash, str(actor_id), action, resource_type, str(resource_id), outcome, _ts(event_time)])
    return hashlib.sha256(text.encode()).hexdigest()


def log_audit(db: Session, actor_id, action, resource_type, resource_id=None, outcome="success") -> AuditEvent:
    """Add an audit entry to the current transaction (caller commits)."""
    last = db.query(AuditEvent).order_by(AuditEvent.audit_id.desc()).first()
    prev = last.entry_hash if last else GENESIS
    rid = None if resource_id is None else str(resource_id)[:60]
    now = utcnow()
    event = AuditEvent(
        actor_id=actor_id, action=action, resource_type=resource_type, resource_id=rid,
        outcome=outcome, event_time=now, prev_hash=prev,
        entry_hash=compute_entry_hash(prev, actor_id, action, resource_type, rid, outcome, now),
    )
    db.add(event)
    db.flush()
    return event


def log_custody(db: Session, evidence_id: int, actor_id: int, event_type: str, details: str = "") -> CustodyEvent:
    event = CustodyEvent(evidence_id=evidence_id, actor_id=actor_id, event_type=event_type, details=details)
    db.add(event)
    db.flush()
    return event


def verify_chain(db: Session) -> dict:
    prev, checked = GENESIS, 0
    for ev in db.query(AuditEvent).order_by(AuditEvent.audit_id):
        expected = compute_entry_hash(prev, ev.actor_id, ev.action, ev.resource_type,
                                      ev.resource_id, ev.outcome, ev.event_time)
        if ev.prev_hash != prev or ev.entry_hash != expected:
            return {"valid": False, "entries_checked": checked, "first_invalid_audit_id": ev.audit_id}
        prev = ev.entry_hash
        checked += 1
    return {"valid": True, "entries_checked": checked, "first_invalid_audit_id": None}
