"""CLSVH-ZT single-file research prototype."""
from __future__ import annotations
import base64, hashlib, json, sys, time, uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Optional
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

def _e(v: bytes) -> str: return base64.urlsafe_b64encode(v).decode("ascii")
def _d(v: str) -> bytes: return base64.urlsafe_b64decode(v.encode("ascii"))
def _canonical(v: dict[str, Any]) -> bytes: return json.dumps(v, sort_keys=True, separators=(",", ":")).encode()

@dataclass
class SigningKeyPair:
    key_id: str
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey
    @classmethod
    def generate(cls, key_id: str) -> "SigningKeyPair":
        private = Ed25519PrivateKey.generate()
        return cls(key_id, private, private.public_key())
    def sign(self, payload: bytes) -> str: return _e(self.private_key.sign(payload))
    def public_key_text(self) -> str:
        return _e(self.public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))

def load_public_key(value: str) -> Ed25519PublicKey: return Ed25519PublicKey.from_public_bytes(_d(value))
def verify_signature(key: Ed25519PublicKey, payload: bytes, signature: str) -> bool:
    try: key.verify(_d(signature), payload); return True
    except (InvalidSignature, ValueError): return False

@dataclass(frozen=True)
class ValidationEvent:
    component: str
    result: str
    checks_passed: int
    timestamp: int
    previous_hash: str
    event_hash: str
    @classmethod
    def create(cls, component: str, result: str, checks_passed: int, previous_hash: str) -> "ValidationEvent":
        timestamp = int(time.time())
        data = {"component": component, "result": result, "checks_passed": checks_passed, "timestamp": timestamp, "previous_hash": previous_hash}
        return cls(component, result, checks_passed, timestamp, previous_hash, hashlib.sha256(_canonical(data)).hexdigest())
    def to_dict(self) -> dict[str, Any]: return asdict(self)

@dataclass
class CLSVHHeader:
    session_id: str
    request_id: str
    subject_id: str
    audience: str
    resource: str
    action: str
    issuer: str
    key_id: str
    policy_version: str
    issued_at: int
    expires_at: int
    nonce: str
    trust_level: int = 0
    path_hint: str = "slow"
    lineage: list[ValidationEvent] = field(default_factory=list)
    signature: str = ""
    @classmethod
    def create(cls, subject_id: str, audience: str, resource: str, action: str, issuer: str, key_id: str, path_hint: str = "slow", ttl_seconds: int = 60, policy_version: str = "v1") -> "CLSVHHeader":
        if path_hint not in {"fast", "slow"}: raise ValueError("path_hint must be fast or slow")
        if ttl_seconds <= 0: raise ValueError("ttl_seconds must be positive")
        now = int(time.time())
        return cls(str(uuid.uuid4()), str(uuid.uuid4()), subject_id, audience, resource, action, issuer, key_id, policy_version, now, now + ttl_seconds, uuid.uuid4().hex, path_hint=path_hint)
    def unsigned_dict(self) -> dict[str, Any]:
        return {"session_id": self.session_id, "request_id": self.request_id, "subject_id": self.subject_id, "audience": self.audience, "resource": self.resource, "action": self.action, "issuer": self.issuer, "key_id": self.key_id, "policy_version": self.policy_version, "issued_at": self.issued_at, "expires_at": self.expires_at, "nonce": self.nonce, "trust_level": self.trust_level, "path_hint": self.path_hint, "lineage": [e.to_dict() for e in self.lineage]}
    def payload(self) -> bytes: return _canonical(self.unsigned_dict())
    def add_event(self, component: str, result: str, checks_passed: int) -> None:
        previous = self.lineage[-1].event_hash if self.lineage else "GENESIS"
        self.lineage.append(ValidationEvent.create(component, result, checks_passed, previous))
    def promote_trust(self) -> None: self.trust_level = min(3, self.trust_level + 1)
    def downgrade_trust(self) -> None: self.trust_level = max(0, self.trust_level - 1)
    def is_expired(self, now: Optional[int] = None) -> bool: return (int(time.time()) if now is None else now) >= self.expires_at
    def is_fresh(self, max_age_seconds: int = 60) -> bool:
        now = int(time.time()); return self.issued_at <= now and now - self.issued_at <= max_age_seconds

class ReplayCache:
    def __init__(self, retention_seconds: int = 120): self.retention_seconds, self._entries = retention_seconds, {}
    def consume(self, request_id: str, nonce: str) -> bool:
        now = int(time.time()); self.remove_expired(now); key = f"{request_id}:{nonce}"
        if key in self._entries: return False
        self._entries[key] = now + self.retention_seconds; return True
    def remove_expired(self, now: Optional[int] = None) -> None:
        current = int(time.time()) if now is None else now
        self._entries = {k: v for k, v in self._entries.items() if v > current}

@dataclass(frozen=True)
class PolicyDecision:
    decision: str
    reason: str

SENSITIVE_RESOURCES = {"payments", "identity", "admin"}
def evaluate_policy(header: CLSVHHeader, signature_valid: bool, replay_free: bool, risk_score: int = 0) -> PolicyDecision:
    if not signature_valid: return PolicyDecision("block", "invalid_signature")
    if not replay_free: return PolicyDecision("block", "replay_detected")
    if header.is_expired(): return PolicyDecision("block", "expired_header")
    if not header.is_fresh(): return PolicyDecision("block", "stale_header")
    if not 0 <= risk_score <= 100: return PolicyDecision("block", "invalid_risk_score")
    if risk_score >= 70: return PolicyDecision("block", "high_risk")
    if header.resource in SENSITIVE_RESOURCES: return PolicyDecision("allow_slow", "sensitive_resource")
    if header.trust_level >= 2 and header.path_hint == "fast": return PolicyDecision("allow_fast", "validated_fast_path")
    return PolicyDecision("allow_slow", "additional_validation_required")

class CLSVHValidator:
    def __init__(self, component_name: str, key_pair: SigningKeyPair, trusted_public_keys: dict[str, str]): self.component_name, self.key_pair, self.trusted_public_keys = component_name, key_pair, trusted_public_keys
    def validate_signature(self, header: CLSVHHeader) -> bool:
        key = self.trusted_public_keys.get(header.key_id)
        return bool(key) and verify_signature(load_public_key(key), header.payload(), header.signature)
    def validate(self, header: CLSVHHeader, checks_passed: int, decision: PolicyDecision) -> PolicyDecision:
        if decision.decision == "block": header.add_event(self.component_name, decision.reason, checks_passed); return decision
        if checks_passed <= 0:
            header.downgrade_trust(); header.add_event(self.component_name, "checks_failed", checks_passed); return PolicyDecision("block", "component_validation_failed")
        header.add_event(self.component_name, "ok", checks_passed); header.promote_trust(); header.issuer = self.component_name; header.key_id = self.key_pair.key_id; header.signature = self.key_pair.sign(header.payload()); return decision

def simulate_secure_flow() -> tuple[CLSVHHeader, str]:
    names = ("WAF", "Firewall", "Service"); keys = [SigningKeyPair.generate(n.lower()+"-2026") for n in names]; public = {k.key_id: k.public_key_text() for k in keys}
    header = CLSVHHeader.create("demo-user", "service", "orders", "read", "client", keys[0].key_id, "fast"); header.add_event("client", "created", 0); header.signature = keys[0].sign(header.payload())
    for index, (name, key) in enumerate(zip(names, keys)):
        valid = CLSVHValidator(name, key, public).validate_signature(header); decision = evaluate_policy(header, valid, index == 0); result = CLSVHValidator(name, key, public).validate(header, 1, decision)
        if result.decision == "block": return header, result.decision
    return header, evaluate_policy(header, True, True).decision

def self_test() -> None:
    keys = SigningKeyPair.generate("test"); sig = keys.sign(b"a"); assert verify_signature(keys.public_key, b"a", sig); assert not verify_signature(keys.public_key, b"b", sig)
    cache = ReplayCache(); assert cache.consume("r", "n"); assert not cache.consume("r", "n")
    header = CLSVHHeader.create("u", "s", "orders", "read", "client", "key"); old = header.payload(); header.trust_level = 3; assert old != header.payload(); header.add_event("WAF", "ok", 1); header.add_event("FW", "ok", 1); assert header.lineage[1].previous_hash == header.lineage[0].event_hash

def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "test": self_test(); print("self-tests: passed"); return
    header, decision = simulate_secure_flow(); print("=== Secure CLSVH-ZT Demo ==="); print("Decision:", decision); print("Trust level:", header.trust_level); print("Lineage events:", len(header.lineage))
    for event in header.lineage: print(f"- {event.component}: {event.result}")

if __name__ == "__main__": main()
