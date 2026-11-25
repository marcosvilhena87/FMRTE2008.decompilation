"""Data-only authentication and schema integration. No operational authority."""
import json, hashlib
from datetime import datetime, timezone

class Rejected(ValueError):
    def __init__(self,code,reason):
        super().__init__(reason)
        self.code=code

def require(ok,code,reason):
    if not ok: raise Rejected(code,reason)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def load(raw,code=12):
    def pairs(items):
        out={}
        for k,v in items:
            require(k not in out,code,"duplicate JSON key")
            out[k]=v
        return out
    def invalid(_): raise Rejected(code,"nonfinite JSON")
    try:
        return json.loads(raw.decode("utf-8","strict"),object_pairs_hook=pairs,parse_constant=invalid)
    except Rejected: raise
    except (ValueError,UnicodeError) as exc: raise Rejected(code,"invalid JSON") from exc

def schema(obj,definition,code=12):
    import jsonschema
    try:
        jsonschema.Draft202012Validator.check_schema(definition)
        jsonschema.Draft202012Validator(definition,format_checker=jsonschema.FormatChecker()).validate(obj)
    except (jsonschema.ValidationError,jsonschema.SchemaError) as exc:
        raise Rejected(code,"schema rejected") from exc

def authenticate(raw,sig,key,domain,code):
    require(isinstance(raw,bytes) and isinstance(sig,bytes) and isinstance(key,bytes),code,"missing trust input")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(sig,domain+b"\x00"+raw)
    except Exception as exc: raise Rejected(code,"signature rejected") from exc
    return load(raw,code)

def utc(value,code=17):
    require(isinstance(value,str) and value.endswith("Z"),code,"UTC required")
    try: return datetime.fromisoformat(value[:-1]+"+00:00")
    except ValueError as exc: raise Rejected(code,"timestamp rejected") from exc

GATE_FIELDS=("authority","scope","fixture_sha256","protocol_sha256","toolchain_sha256","evidence_sha256")
def gate(graw,gsig,rraw,rsig,trust,expected,schemas):
    require(set(expected)==set(GATE_FIELDS),17,"incomplete binding")
    require(trust["now"].tzinfo is not None and type(trust["floor"]) is int and trust["floor"]>=0,17,"clock or sequence")
    # Same signature domain as original verifier; schemas distinguish decision and revocation.
    g=authenticate(graw,gsig,trust["key"],b"DC00.2-v1",17)
    r=authenticate(rraw,rsig,trust["key"],b"DC00.2-v1",17)
    schema(g,schemas["gate"],17); schema(r,schemas["revocation"],17)
    require(g["decision"]=="allow" and g["scope"]=="synthetic_homologation" and all(g[k]==v for k,v in expected.items()),17,"scope or binding")
    now=trust["now"]
    require(all(utc(x["issued_utc"])<=now<utc(x["expires_utc"]) for x in (g,r)),17,"time")
    require(r["sequence"]>=trust["floor"] and g["decision_id"] not in r["revoked"],17,"revoked or rollback")
    return g["decision_id"]

def manifest(raw,sig,key,expected_digest,schemas,blobs,trusted_records,expected):
    m=authenticate(raw,sig,key,b"DC00.2-manifest-v1",12)
    require(digest(raw)==expected_digest,12,"manifest anchor")
    schema(m,schemas["manifest"])
    require(set(expected)=={"baseline_sha256","toolchain_sha256","module","gate_refs"},12,"manifest binding incomplete")
    require(all(m[k]==v for k,v in expected.items()),12,"manifest binding")
    require(utc(m["started_utc"],12)<=utc(m["ended_utc"],12),12,"time order")
    records=m["inputs"]+m["outputs"]+m["logs"]
    names=[x["path"] for x in records]
    require(len(set(names))==len(names) and set(names)==set(blobs)==set(trusted_records),12,"artifact set")
    for rec in records:
        p=rec["path"]
        require(rec==trusted_records[p] and len(blobs[p])==rec["size"] and digest(blobs[p])==rec["sha256"],12,"artifact identity")
    require(m["status"]=="complete" and m["exit_code"]==0,12,"incomplete manifest")
    return m

def integrate(gate_args,manifest_args):
    decision=gate(**gate_args)
    expected=manifest_args["expected"]
    require(expected["gate_refs"]==[decision],17,"gate reference")
    binding=gate_args["expected"]
    require(expected["toolchain_sha256"]==binding["toolchain_sha256"] and manifest_args["expected_digest"]==binding["evidence_sha256"],17,"evidence binding")
    return manifest(**manifest_args)
