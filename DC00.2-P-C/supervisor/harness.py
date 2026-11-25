"""In-memory fixture materialization. No automatic test execution or process launch."""
import copy, json
from .validation import *

def fixture():
    data = b"synthetic opaque bytes"
    a = {"size": len(data), "sha256": sha(data)}
    return {
        "data": data, "anchor": a, "report": dict(a),
        "rows": [1,2,3], "expected_rows": [1,2,3],
        "deps": {"Synthetic.Dependency":"1.0.0.0:fixture-digest"},
        "trusted_deps": {"Synthetic.Dependency":"1.0.0.0:fixture-digest"},
        "approval": True, "reference": "artifact", "references": ["artifact"],
        "raw_json": b'{"key":1}', "doc": {"run_id":"A","value":1,"nested":{"run_id":"semantic"}},
        "other": {"run_id":"B","value":1,"nested":{"run_id":"semantic"}},
        "semantic": {"literal":1,"opcode":"add","token":1,"signature":"int A(int)","link":"A"},
        "trusted_semantic": {"literal":1,"opcode":"add","token":1,"signature":"int A(int)","link":"A"},
        "gate": {"id":"fixture-only","authority":"synthetic","scope":"synthetic_homologation","evidence":"fixture","issued":0,"expires":20},
        "gate_expected": {"authority":"synthetic","scope":"synthetic_homologation","evidence":"fixture"},
        "now":10,"revoked":[],"sequence":2,"floor":2,
        "components_a":["parser-a"],"components_b":["parser-b"],
    }

def materialize(case):
    state = fixture()
    control = copy.deepcopy(state)
    m = case["mutation"]
    if case["mode"] == "external_blocked":
        return {"case":case,"status":"blocked_external","control":None,"mutated":None}
    if m in ("byte_changed","changed_hash"): state["data"] += b"!"
    elif m == "missing_rid": state["rows"].pop()
    elif m == "unexpected_rid": state["rows"].append(4)
    elif m == "duplicate_replaces_rid": state["rows"][-1] = 2
    elif m in ("truncated_output_rehashed","joint_replacement"):
        state["data"] = state["data"][:-1]
        state["report"] = {"size":len(state["data"]),"sha256":sha(state["data"])}
    elif m == "missing_dependency": state["deps"].clear()
    elif m == "wrong_identity_same_name": state["deps"]["Synthetic.Dependency"] = "wrong"
    elif m == "forged_approval": state["report"]["sha256"] = "0"*64
    elif m == "duplicate_json_key": state["raw_json"] = b'{"key":1,"key":2}'
    elif m == "broken_reference": state["reference"] = "absent"
    elif m == "nonvolatile_change": state["other"]["value"] = 2
    elif m == "nested_homonym_change": state["other"]["nested"]["run_id"] = "changed"
    elif m == "opaque_read": pass
    elif m in ("literal","opcode","token","signature"): state["semantic"][m] = "changed"
    elif m == "swapped_link": state["semantic"]["link"] = "B"
    elif m == "missing_gate": state["gate"] = None
    elif m == "expired": state["now"] = 20
    elif m == "wrong_authority": state["gate"]["authority"] = "other"
    elif m == "wrong_scope": state["gate"]["scope"] = "other"
    elif m == "revoked_before": state["revoked"].append("fixture-only")
    elif m == "rollback": state["sequence"] = 1
    elif m == "changed_evidence": state["gate"]["evidence"] = "changed"
    elif m == "shared_component": state["components_b"] = ["parser-a"]
    else: raise ValueError("unknown mutation")
    return {"case":case,"status":"prepared_not_run","control":control,"mutated":state}

def strict_pairs(pairs):
    out = {}
    for key,value in pairs:
        require(key not in out,12,"duplicate key")
        out[key] = value
    return out

def evaluate_data(case, s):
    """Future unit-level evaluation only. Does not confer operational approval."""
    m = case["mutation"]
    require(case["mode"] == "in_memory",17,"external case blocked")
    if m in ("byte_changed","changed_hash","opaque_read"):
        identity(s["data"],s["anchor"]["sha256"])
    elif m in ("missing_rid","unexpected_rid","duplicate_replaces_rid"):
        coverage(s["rows"],s["expected_rows"])
    elif m in ("truncated_output_rehashed","joint_replacement","forged_approval"):
        artifact_check(s["data"],s["report"],s["anchor"])
    elif m in ("missing_dependency","wrong_identity_same_name"):
        dependency_check(s["deps"],s["trusted_deps"])
    elif m == "duplicate_json_key":
        json.loads(s["raw_json"],object_pairs_hook=strict_pairs)
    elif m == "broken_reference": require(s["reference"] in s["references"],12,"reference")
    elif m in ("nonvolatile_change","nested_homonym_change"):
        require({k:v for k,v in s["doc"].items() if k!="run_id"} == {k:v for k,v in s["other"].items() if k!="run_id"},15,"projection")
    elif m in ("literal","opcode","token","signature","swapped_link"):
        require(s["semantic"] == s["trusted_semantic"],15,"semantic record")
    elif m in ("missing_gate","expired","wrong_authority","wrong_scope","revoked_before","rollback","changed_evidence"):
        gate_snapshot(s["gate"],s["gate_expected"],s["now"],s["revoked"],s["sequence"],s["floor"])
    elif m == "shared_component": require(not set(s["components_a"]) & set(s["components_b"]),18,"shared component")
    else: raise ValueError("unknown mutation")

def observed(case,state):
    try:
        evaluate_data(case,state)
        return 0
    except Rejected as exc:
        return exc.code
    except Exception:
        return 99

def assess(case, *, authorized=False):
    # No use in DC00.2-P-C. Flag is not a cryptographic gate, nor permission to launch.
    if not authorized or case["mode"] != "in_memory":
        return {"status":"blocked","passed":False}
    prepared=materialize(case)
    control=observed(case,prepared["control"])
    mutated=observed(case,prepared["mutated"])
    return {"status":"data_unit_only","control_code":control,"observed_code":mutated,
            "matches_unit_expectation":control==0 and mutated==case["expected_code"] and mutated!=99,
            "homologated":False}

def operational_start(*args, **kwargs):
    raise Rejected(17,"operational execution disabled")
