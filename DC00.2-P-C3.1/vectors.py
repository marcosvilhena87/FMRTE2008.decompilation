"""Deterministic synthetic trust material and data for the offline controls."""
from datetime import datetime, timezone
from hashlib import sha256
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from historical import ROOT, c2

P = ROOT / "DC00.2-P"
C1 = ROOT / "DC00.2-P-C"
C2 = ROOT / "DC00.2-P-C2"
ISSUED = "2026-01-01T00:00:00Z"
EXPIRES = "2026-01-03T00:00:00Z"
GATE_DOMAIN = b"DC00.2-v1"
MANIFEST_DOMAIN = b"DC00.2-manifest-v1"


def read_json(path):
    return c2.load(path.read_bytes())


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def key(label):
    # Publicly reproducible test seed. This key has no operational authority.
    return Ed25519PrivateKey.from_private_bytes(sha256(label.encode()).digest())


def sign(private_key, domain, raw):
    return private_key.sign(domain + b"\x00" + raw)


def artifact(path, data):
    return {"path": path, "size": len(data), "sha256": c2.digest(data)}


class Vectors:
    def __init__(self):
        self.schemas = {
            path.name.split(".")[0]: read_json(path)
            for path in sorted((P / "schemas").glob("*.schema.json"))
        }
        self.opaque = (P / "fixtures" / "opaque.txt").read_bytes()
        self.identity = read_json(P / "fixtures" / "identity.json")["files"]
        self.opaque_hash = self.identity["opaque.txt"]
        self.rows = read_json(P / "fixtures" / "rows.json")
        self.source = (C1 / "fixtures" / "Synthetic.cs").read_bytes()
        self.private = key("DC00.2-P-C3.1 synthetic fixture")
        public = self.private.public_key().public_bytes_raw()
        dependencies = {
            "Synthetic.Dependency": {
                "version": "1.0.0.0",
                "sha256": c2.digest(b"synthetic dependency v1"),
            }
        }
        dependency_raw = encode(dependencies)
        dependency_domain = b"DC00.2-P-C3.1-dependencies"
        self.dependencies = c2.authenticate(
            dependency_raw, sign(self.private, dependency_domain, dependency_raw),
            public, dependency_domain, 13,
        )
        record = artifact("opaque.txt", self.opaque)
        expected_manifest = {
            "baseline_sha256": c2.digest((P / "baseline.json").read_bytes()),
            "toolchain_sha256": c2.digest(dependency_raw),
            "module": "synthetic",
            "gate_refs": ["c31-fixture"],
        }
        self.manifest_doc = {
            **expected_manifest, "schema_version": 3, "run_id": "c31",
            "commit": None, "scope": "synthetic_homologation", "parameters": [],
            "environment": "offline fixture", "snapshot": "fixed",
            "limits": {"seconds": 300, "memory_bytes": 2147483648,
                       "output_bytes": 1073741824, "files": 10000,
                       "resource_bytes": 67108864},
            "started_utc": ISSUED, "ended_utc": ISSUED, "elapsed_ms": 0,
            "exit_code": 0, "logs": [], "inputs": [record], "outputs": [],
            "status": "complete",
        }
        raw = encode(self.manifest_doc)
        self.manifest_args = {
            "raw": raw, "sig": sign(self.private, MANIFEST_DOMAIN, raw), "key": public,
            "expected_digest": c2.digest(raw), "schemas": self.schemas,
            "blobs": {"opaque.txt": self.opaque}, "trusted_records": {"opaque.txt": record},
            "expected": expected_manifest,
        }
        expected_gate = {
            "authority": "c31-synthetic", "scope": "synthetic_homologation",
            "fixture_sha256": self.opaque_hash,
            "protocol_sha256": c2.digest((C2 / "tests" / "plan.json").read_bytes()),
            "toolchain_sha256": expected_manifest["toolchain_sha256"],
            "evidence_sha256": self.manifest_args["expected_digest"],
        }
        gate = {**expected_gate, "decision_id": "c31-fixture", "decision": "allow",
                "issued_utc": ISSUED, "expires_utc": EXPIRES}
        rev = {"sequence": 2, "revoked": [], "issued_utc": ISSUED, "expires_utc": EXPIRES}
        self.gate_args = self.gate_envelope(gate, rev)
        self.gate_args.update({
            "trust": {"key": public, "floor": 2,
                      "now": datetime(2026, 1, 2, tzinfo=timezone.utc)},
            "expected": expected_gate, "schemas": self.schemas,
        })

    def gate_envelope(self, gate, revocation):
        graw, rraw = encode(gate), encode(revocation)
        return {"graw": graw, "gsig": sign(self.private, GATE_DOMAIN, graw),
                "rraw": rraw, "rsig": sign(self.private, GATE_DOMAIN, rraw)}
