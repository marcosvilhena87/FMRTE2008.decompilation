"""Preparation only: no CLI, launch, implicit evaluation or homologation."""
from . import il,evidence

EXTERNAL_REQUIRED=frozenset(("T13.06",))
STRUCTURAL=frozenset(("T04.01","T12.01","T12.02","T12.03"))

def verify_plan(plan,catalog):
    old={x["id"]:x for x in catalog["cases"]}
    new={x["id"]:x for x in plan["cases"]}
    evidence.require(len(old)==len(new)==len(plan["cases"])==len(catalog["cases"])==57 and old.keys()==new.keys(),12,"catalog coverage")
    for key,x in old.items():
        y=new[key]
        evidence.require((x["mutation"],x["expected_code"])==(y["mutation"],y["expected_code"]) and not y["executed"],12,"catalog binding")
        mode="external_blocked" if x["operational"] or key in EXTERNAL_REQUIRED else ("signed_gate_required" if x["parent"]=="T13" else "structural" if key in STRUCTURAL else "legacy_data")
        evidence.require(y["mode"]==mode,12,"mode mismatch")
    return new

def structural_case(case_id,positive,mutated,reference):
    def observed(body):
        try:
            parsed=il.parse(body)
            if case_id=="T04.01": return 0
            return 0 if parsed==reference else 15
        except il.InvalidIL:
            return 12
        except Exception:
            return 99
    a,b=observed(positive),observed(mutated)
    expected=12 if case_id=="T04.01" else 15
    return {"control_code":a,"observed_code":b,"unit_match":a==0 and b==expected,"homologated":False}

def evaluate(case_id,plan,catalog,gate_args,manifest_args,*,structural=None,gate_control=None,gate_mutation=None,legacy=None):
    """Future data-only evaluation after externally authenticated evidence.
    Inputs are supplied by trusted caller. Never establishes containment.
    """
    entries=verify_plan(plan,catalog)
    evidence.require(case_id in entries,12,"unknown case")
    case=entries[case_id]
    if case["mode"]=="external_blocked":
        return {"status":"blocked_external","homologated":False}
    evidence.integrate(gate_args,manifest_args)
    if case["mode"]=="structural":
        evidence.require(structural is not None,12,"missing structural fixture")
        return structural_case(case_id,**structural)
    if case["mode"]=="signed_gate_required":
        evidence.require(gate_control is not None and gate_mutation is not None,17,"signed test vectors required")
        def observe(args):
            try:
                evidence.gate(**args)
                return 0
            except evidence.Rejected as exc: return exc.code
            except Exception: return 99
        a,b=observe(gate_control),observe(gate_mutation)
        return {"control_code":a,"observed_code":b,"unit_match":a==0 and b==17,"homologated":False}
    # Legacy adapter is a supplied pure-data function. No operational claim.
    evidence.require(legacy is not None,12,"missing legacy data adapter")
    result=legacy(case_id)
    return {"status":"legacy_data_only","control_code":result["control_code"],
            "observed_code":result["observed_code"],"unit_match":result["control_code"]==0 and result["observed_code"]==case["expected_code"] and result["observed_code"]!=99,
            "homologated":False}

def operational_start(*args,**kwargs):
    raise evidence.Rejected(17,"operational launch disabled")
