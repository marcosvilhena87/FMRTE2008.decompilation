"""Run only the synthetic legacy controls, concurrent faults and audit probes."""
from importlib.metadata import version
import json
from pathlib import Path
from copy import copy
import platform
import sys

from audit import AuditGuard, LIMITS, PREFIXES

sys.path.insert(1, str(Path(__file__).resolve().parents[1] / "DC00.2-P-C3.1"))

BASE = "92756b5d12652a9b784ff50ea7bb70e1c1ded577"
CONCURRENT = (
    (("T01.01", "T05.01"), (10, 13), 10),
    (("T05.01", "T01.01"), (13, 10), 10),
    (("T06.01", "T06.04"), (12, 12), 12),
)


def observe(case_id, mutated, vectors, events):
    from cases import CASES
    from historical import c1, c2, p

    trace, start = {}, len(events)
    try:
        CASES[case_id](case_id, mutated, vectors, trace)
        code, reason = 0, None
    except (p.Rejected, c1.Rejected, c2.Rejected) as exc:
        code, reason = exc.code, str(exc)
    except Exception as exc:
        code, reason = 99, f"{type(exc).__name__}: {exc}"
    return {"id": case_id, "observed_code": code, "reason": reason,
            "trace": trace, "blocked_events": events[start:]}


def concurrent_controls(vectors, events, checks=CONCURRENT):
    from cases import manifest_args, validate_manifest
    from historical import c2, p
    from oracles import check

    results = []
    for cases, expected_codes, expected_priority in checks:
        faults = [observe(case, True, vectors, events) for case in cases]
        codes = [fault["observed_code"] for fault in faults]
        classification = p.classify(codes)
        forbidden = any(fault["blocked_events"] for fault in faults)
        concurrent = sum(code != 0 for code in codes) > 1
        single_accepted = p.oracle(expected_priority, classification, forbidden, concurrent)
        if cases == ("T06.01", "T06.04"):
            args = manifest_args(vectors, cases)
            trace = {}
            joint = {"code": 0, "reason": None, "trace": trace}
            try:
                validate_manifest(vectors, args, trace)
            except c2.Rejected as exc:
                joint.update(code=exc.code, reason=str(exc))
            joint_passed = (joint["code"] == 12 and joint["reason"] == "signature rejected"
                            and trace["available_artifacts"] == []
                            and trace["signature_valid"] is False)
        else:
            snapshot = copy(vectors)
            snapshot.rows_raw += b"!"
            snapshot.observed_dependencies = {}
            joint = [observe(case, False, snapshot, events) for case in cases]
            joint_passed = all(
                entry["observed_code"] == expected and not entry["blocked_events"]
                and check(entry["id"], True, entry["trace"], entry["reason"], vectors.anchors)
                for entry, expected in zip(joint, expected_codes, strict=True)
            )
        results.append({
            "joint_observation": joint, "faults": faults, "expected_codes": list(expected_codes),
            "expected_priority": expected_priority, "classified_code": classification,
            "concurrent": concurrent, "single_mutation_accepted": single_accepted,
            "passed": codes == list(expected_codes) and classification == expected_priority
            and concurrent and not single_accepted and not forbidden and joint_passed
            and all(check(fault["id"], True, fault["trace"], fault["reason"], vectors.anchors)
                    for fault in faults),
        })
    return results


def main():
    guard = AuditGuard()
    guard.install()
    probes = guard.verify()
    probe_events = list(guard.events)
    start = len(guard.events)

    from cases import CASES
    from historical import c2, p, plan_contract
    from oracles import check
    from vectors_r1 import P, C2, Vectors, read_json

    vectors = Vectors()
    anchors = vectors.anchors
    catalog = read_json(P / "tests" / "catalog.json")
    plan_path = C2 / "tests" / "plan.json"
    if (p.digest(plan_path.read_bytes()) != anchors["protocol_sha256"]
            or p.digest((P / "fixtures" / "identity.json").read_bytes())
            != anchors["catalog_fixture_sha256"]):
        raise ValueError("Historical plan or identity anchor mismatch")
    plan = plan_contract.verify_plan(read_json(plan_path), catalog)
    ids = {case_id for case_id, case in plan.items() if case["mode"] == "legacy_data"}
    if ids != CASES.keys() or len(ids) != 17:
        raise ValueError("Legacy implementation does not match historical plan")
    if {case["fixture_anchor_sha256"] for case in catalog["cases"]} != {
            anchors["catalog_fixture_sha256"]}:
        raise ValueError("Catalog fixture anchor mismatch")
    c2.integrate(vectors.gate_args, vectors.manifest_args)

    controls = []
    for case_id in sorted(ids):
        for mutated in (False, True):
            control = observe(case_id, mutated, vectors, guard.events)
            expected = plan[case_id]["expected_code"] if mutated else 0
            control.update(
                variant="mutation" if mutated else "positive", expected_code=expected,
                passed=p.oracle(expected, control["observed_code"], bool(control["blocked_events"]), False)
                and check(case_id, mutated, control["trace"], control["reason"], anchors),
            )
            controls.append(control)
    concurrent = concurrent_controls(vectors, guard.events)
    unexpected = guard.events[start:]
    report = {
        "stage": "DC00.2-P-C3.1-R1", "base_head": BASE, "homologated": False,
        "environment": {"python": platform.python_version(), "jsonschema": version("jsonschema"),
                        "cryptography": version("cryptography")},
        "catalog_modes": {mode: sum(case["mode"] == mode for case in plan.values())
                          for mode in sorted({case["mode"] for case in plan.values()})},
        "cases_executed": len(ids), "controls_executed": len(controls),
        "controls_passed": sum(control["passed"] for control in controls),
        "controls": controls, "concurrent_controls": concurrent,
        "audit": {"registration_verified": guard.probe_seen, "prefixes": PREFIXES, "limits": LIMITS, "probes": probes,
                  "probe_events": probe_events, "unexpected_denials": unexpected},
    }
    print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False))
    return int(bool(unexpected) or not all(item["passed"] for item in controls + concurrent + probes))


if __name__ == "__main__":
    sys.exit(main())
