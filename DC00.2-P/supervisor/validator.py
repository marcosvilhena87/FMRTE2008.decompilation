"""Offline data validation only. No process launcher, target parser or operational authorization."""
import json, hashlib, re, unicodedata, copy
from collections import Counter
from datetime import datetime, timezone
from pathlib import PureWindowsPath

class Rejected(ValueError):
    def __init__(self, code, reason):
        super().__init__(reason); self.code=code

def require(ok, code, reason):
    if not ok: raise Rejected(code, reason)

def digest(data): return hashlib.sha256(data).hexdigest()
def strict_load(data):
    def pairs(items):
        d={}
        for k,v in items:
            require(k not in d,12,'duplicate JSON key'); d[k]=v
        return d
    def invalid(x): raise Rejected(12,'nonfinite JSON')
    return json.loads(data.decode('utf-8','strict'),object_pairs_hook=pairs,parse_constant=invalid)

def schema_check(obj, schema):
    import jsonschema
    errors=list(jsonschema.Draft202012Validator(schema,format_checker=jsonschema.FormatChecker()).iter_errors(obj))
    require(not errors,12,'; '.join(e.message for e in errors))

def path_key(path):
    require(isinstance(path,str) and 0<len(path)<=240,14,'path length')
    parts=path.split('/')
    for p in parts:
        require(p not in ('','.','..') and not p.endswith(('.', ' ')) and not re.search(r'[\\:*?"<>|\x00-\x1f]',p),14,'unsafe path')
        require(not PureWindowsPath(p).is_reserved() and not re.fullmatch(r'(?i)(CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])',p.split('.')[0].rstrip(' ')),14,'reserved path')
    return unicodedata.normalize('NFC',path).casefold()

def artifacts(records, blobs, expected):
    keys=[path_key(r['path']) for r in records]
    require(len(keys)==len(set(keys)),14,'path collision')
    require(len(records)<=10000 and sum(r['size'] for r in records)<=1073741824,16,'quota')
    require(set(blobs)==set(expected)=={r['path'] for r in records},12,'artifact set')
    for r in records:
        b=blobs[r['path']]; e=expected[r['path']]
        require(len(b)==r['size']==e['size'] and digest(b)==r['sha256']==e['sha256'],12,'artifact identity')

def coverage(rows, expected):
    got=Counter((r['module'],r['table_id'],r['rid']) for r in rows)
    want=Counter(expected)
    require(all(n==1 for n in want.values()) and got==want,11,'coverage or multiplicity')
    return len(got)

PAIRS={'present':{'complete','partial','failed','pending'},'absent':{'na'},'unknown':{'pending','failed'}}
def methoddef(m, inventory, blobs, engine_map):
    require(m['il'] in PAIRS.get(m['body'],set()),12,'body/IL invariant')
    key=(m['module'],6,m['rid']); ref=inventory.get(key)
    require(ref is not None and m['signature']==ref['signature'] and m['owner']==ref['owner'] and m['body']==ref['body'],12,'independent identity')
    if m['body']=='absent':
        require(m['absence']==ref['absence'] and bool(m['absence']),12,'absence evidence')
    if m['il']=='complete':
        b=blobs.get(m['il_path']); require(b is not None and digest(b)==ref['il_sha256']==m['il_sha256'] and len(b)==ref['il_size'],12,'IL bytes')
    if m['csharp'] in ('direct','transformed'):
        require(bool(m['links']),15,'missing links')
        for link in m['links']:
            b=blobs.get(link['path']); require(b is not None and digest(b)==link['sha256'] and 0<=link['start']<link['end']<=len(b),15,'link extent')
            require(link['owner']==ref['owner'] and link['signature']==ref['signature'] and link in engine_map.get(key,[]),15,'link identity')
            b[link['start']:link['end']].decode('utf-8','strict')
    if m['csharp']=='na': require(not ref['csharp_eligible'] and bool(m['csharp_reason']),12,'C# eligibility')
    return {'final_eligible':m['body']!='unknown','il_success':m['il']=='complete','csharp_success':m['csharp'] in ('direct','transformed')}

def utc(s):
    require(isinstance(s,str) and s.endswith('Z'),12,'UTC required')
    return datetime.fromisoformat(s[:-1]+'+00:00')

def projection(doc):
    d=copy.deepcopy(doc)
    require(utc(d['ended_utc'])>=utc(d['started_utc']) and type(d['elapsed_ms']) is int and d['elapsed_ms']>=0 and isinstance(d['run_id'],str) and bool(d['run_id']),12,'envelope')
    for k in ('run_id','started_utc','ended_utc','elapsed_ms'): del d[k]
    return d

def compare(a,b): require(projection(a)==projection(b),15,'nonvolatile divergence')

def independence(a,b,property_name):
    x=set(a[property_name]); y=set(b[property_name]); require(bool(x) and bool(y) and not x&y,18,'shared or missing components')

# Detached Ed25519 verification over domain-separated exact UTF-8 payload bytes.
# Trust inputs must be supplied by an independently authenticated external supervisor.
def verify_signed(payload, signature, key):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try: Ed25519PublicKey.from_public_bytes(key).verify(signature,b'DC00.2-v1\x00'+payload)
    except Exception as exc: raise Rejected(17,'signature rejected') from exc
    return strict_load(payload)

def verify_gate(payload, signature, key, rev_payload, rev_signature, trusted_now, min_sequence, expected, schema, rev_schema):
    require(key is not None and trusted_now is not None and min_sequence is not None,17,'trust not provisioned')
    g=verify_signed(payload,signature,key); rev=verify_signed(rev_payload,rev_signature,key)
    try: schema_check(g,schema); schema_check(rev,rev_schema)
    except Rejected as e: raise Rejected(17,str(e)) from e
    require(g['decision']=='allow' and all(g.get(k)==v for k,v in expected.items()),17,'scope or binding')
    require(g['scope']=='synthetic_homologation',17,'target scope prohibited')
    require(utc(g['issued_utc'])<=trusted_now<utc(g['expires_utc']) and utc(rev['issued_utc'])<=trusted_now<utc(rev['expires_utc']),17,'expired or premature')
    require(rev['sequence']>=min_sequence and g['decision_id'] not in rev['revoked'],17,'revoked or rollback')
    return g['decision_id'] # evidence only, never permission to launch

def operational_start(*args, **kwargs):
    raise Rejected(17,'DC00.2-P: operational execution permanently disabled in this package')

# Fixed precedence for concurrent faults; concurrent faults never pass a single-mutation test.
PRECEDENCE=(14,16,17,10,12,13,11,15,18,99)
def classify(codes):
    codes=set(codes); return next((c for c in PRECEDENCE if c in codes),99 if codes else 0)
def oracle(expected, observed, forbidden_effect, concurrent):
    return expected==observed and observed!=99 and not forbidden_effect and not concurrent
