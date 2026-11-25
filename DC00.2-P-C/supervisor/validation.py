"""Pure data validators; no target access, process launch or file writes."""
import hashlib
from collections import Counter

class Rejected(ValueError):
    def __init__(self, code, reason):
        super().__init__(reason)
        self.code = code

def require(ok, code, reason):
    if not ok:
        raise Rejected(code, reason)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def identity(data, expected):
    require(sha(data) == expected, 10, "identity")

def coverage(rows, expected):
    require(Counter(rows) == Counter(expected) and len(set(expected)) == len(expected), 11, "coverage")

def dependency_check(observed, trusted):
    require(observed == trusted and bool(trusted), 13, "dependency inventory")

def artifact_check(data, reported, trusted):
    require(reported == trusted == {"size": len(data), "sha256": sha(data)}, 12, "artifact anchor")

def signed_manifest(payload, signature, public_key, expected_digest):
    # External trust inputs, not an authorization or proof of provenance by themselves.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, b"DC00.2-manifest-v1\x00" + payload)
    except Exception as exc:
        raise Rejected(12, "manifest signature") from exc
    require(sha(payload) == expected_digest, 12, "manifest digest")

def tiny_il(body):
    """Restricted structural parser for synthetic tiny methods only."""
    require(bool(body) and body[0] & 3 == 2, 12, "unsupported header")
    n = body[0] >> 2
    require(n > 0 and len(body) == n + 1, 12, "tiny length")
    code = body[1:]
    widths = {0x00:0, 0x02:0, 0x03:0, 0x15:0, 0x16:0, 0x17:0, 0x18:0, 0x19:0, 0x1f:1, 0x20:4, 0x58:0, 0x59:0, 0x2a:0}
    pos = 0
    ops = []
    while pos < n:
        opcode = code[pos]
        require(opcode in widths, 12, "unsupported opcode")
        end = pos + 1 + widths[opcode]
        require(end <= n, 12, "truncated operand")
        ops.append((pos, opcode, code[pos+1:end].hex()))
        pos = end
    require(ops[-1][1] == 0x2a, 12, "fixture terminal ret")
    return ops

def gate_snapshot(g, expected, now, revoked, sequence, floor):
    """Declarative gate checks only; cryptographic verification is separate."""
    require(g is not None, 17, "missing gate")
    require(all(g.get(k) == v for k,v in expected.items()), 17, "gate binding")
    require(g["issued"] <= now < g["expires"], 17, "time")
    require(g["id"] not in revoked and sequence >= floor, 17, "revocation")
