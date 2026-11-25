"""Run the 17 legacy-data pairs offline and write JSON evidence to stdout."""
from importlib.metadata import version
import json
import platform
import sys


def main():
    blocked_events = []

    def offline(event, args):
        if event.startswith(("socket.", "os.exec", "os.fork", "os.posix_spawn",
                             "os.spawn", "os.system", "subprocess.")):
            blocked_events.append(event)
            raise PermissionError(f"Offline runner denied {event}")

    sys.addaudithook(offline)

    from historical import c1, c2, p, plan_contract
    from legacy import CASES
    from vectors import C2, P, Vectors, read_json

    catalog = read_json(P / "tests" / "catalog.json")
    plan = plan_contract.verify_plan(read_json(C2 / "tests" / "plan.json"), catalog)
    ids = {case_id for case_id, case in plan.items() if case["mode"] == "legacy_data"}
    if len(ids) != 17 or ids != CASES.keys():
        raise ValueError("Legacy implementation does not match the historical plan")
    identity_hash = p.digest((P / "fixtures" / "identity.json").read_bytes())
    if {case["fixture_anchor_sha256"] for case in catalog["cases"]} != {identity_hash}:
        raise ValueError("Historical fixture identity does not match catalog")

    vectors = Vectors()
    # Check the synthetic gate and manifest before evaluating any pair.
    c2.integrate(vectors.gate_args, vectors.manifest_args)
    results = []
    for case_id in sorted(ids):
        case = plan[case_id]
        runs = []
        for mutated in (False, True):
            trace = {}
            start_events = len(blocked_events)
            code, reason = 0, None
            try:
                CASES[case_id](case_id, mutated, vectors, trace)
            except (p.Rejected, c1.Rejected, c2.Rejected) as exc:
                code, reason = exc.code, str(exc)
            except Exception as exc:
                code, reason = 99, f"{type(exc).__name__}: {exc}"

            expected = case["expected_code"] if mutated else 0
            events = blocked_events[start_events:]
            runs.append({
                "variant": "mutation" if mutated else "positive",
                "expected_code": expected, "observed_code": code, "reason": reason,
                "passed": p.oracle(expected, code, bool(events), False)
                and check_trace(case_id, mutated, trace, reason),
                "trace": trace, "blocked_events": events,
            })
        results.append({"id": case_id, "mutation": case["mutation"], "controls": runs})

    controls = [run for result in results for run in result["controls"]]
    passed = sum(run["passed"] for run in controls)
    report = {
        "stage": "DC00.2-P-C3.1", "homologated": False,
        "environment": {"python": platform.python_version(), "jsonschema": version("jsonschema"),
                        "cryptography": version("cryptography")},
        "fixture_anchor_sha256": identity_hash,
        "offline": {"audit_hook": True, "blocked_events": blocked_events},
        "catalog_modes": {mode: sum(case["mode"] == mode for case in plan.values())
                          for mode in sorted({case["mode"] for case in plan.values()})},
        "cases_executed": len(results), "controls_executed": len(controls),
        "controls_passed": passed, "results": results,
    }
    print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False))
    return int(passed != len(controls) or bool(blocked_events))


def check_trace(case_id, mutated, trace, reason):
    """Check case-specific evidence in addition to the historical outcome codes."""
    if case_id == "T01.01":
        return trace["parser_calls"] == (0 if mutated else 1)
    if case_id == "T10-A.01":
        return trace["identical_bytes"] and trace["parser_calls"] == 0

    if case_id in ("T02.01", "T02.02", "T03.01"):
        rid2, rid3, rid4 = (("synthetic", 6, rid) for rid in (2, 3, 4))
        expected = {
            "T02.01": ([rid3], [], []),
            "T02.02": ([], [rid4], []),
            "T03.01": ([rid3], [], [(rid2, 2)]),
        }
        return tuple(trace[field] for field in ("missing", "unexpected", "duplicates")) == (
            expected[case_id] if mutated else ([], [], [])
        )

    manifest_reasons = {
        "T06.01": "signature rejected",
        "T06.02": "manifest anchor",
        "T06.03": "duplicate JSON key",
        "T06.04": "artifact set",
    }
    return not mutated or case_id not in manifest_reasons or reason == manifest_reasons[case_id]


if __name__ == "__main__":
    sys.exit(main())
