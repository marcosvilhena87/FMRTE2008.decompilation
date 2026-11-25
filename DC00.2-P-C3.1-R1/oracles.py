"""Independent expectations for the complete trace of each catalog control."""
import json
from hashlib import sha256


def digest(data):
    return sha256(data).hexdigest()


REASONS = {
    "T01.01": "identity", "T02.01": "coverage or multiplicity",
    "T02.02": "coverage or multiplicity", "T03.01": "coverage or multiplicity",
    "T05.01": "dependency inventory", "T05.02": "dependency inventory",
    "T06.01": "signature rejected", "T06.02": "manifest anchor",
    "T06.03": "duplicate JSON key", "T06.04": "artifact set",
    "T08.01": "nonvolatile divergence", "T08.02": "nonvolatile divergence",
    "T09-B.01": "identity", "T10-A.01": None, "T12.04": "method signature divergence",
    "T12.05": "link identity", "T14.01": "shared or missing components",
}
CHANGED_ROWS = "f699ed44ab53c194314338c66e0ae2eb555302e00b27fcc0513d7f1f05083ccf"
CHANGED_OPAQUE = "08f6bef6b018a8a6718abb31930fa4c1e82a2ea495031996b6103434adc4911d"
REPLACED_MANIFEST = "26436be7c0c096d2b360de4f3f93f5cdb25bca5cc86dec7e37872299f1253115"
DUPLICATE_MANIFEST = "2f1223321003335918db1b87bfecbfb8a478d50c100d3ff70956805a1509e56c"
VOLATILE = {"run_id", "started_utc", "ended_utc", "elapsed_ms"}


def check(case_id, mutated, trace, reason, anchors):
    if reason != (REASONS[case_id] if mutated else None):
        return False
    try:
        return expectation(case_id, mutated, trace, anchors)
    except (KeyError, TypeError, ValueError):
        return False


def expectation(case_id, mutated, trace, anchors):
    opaque = anchors["opaque"]["sha256"]
    if case_id in {"T01.01", "T09-B.01", "T10-A.01"}:
        rows = case_id == "T01.01"
        anchor = anchors["rows_sha256"] if rows else opaque
        changed = mutated and case_id != "T10-A.01"
        expected = {"anchor_sha256": anchor, "parser_calls": int(rows and not mutated),
                    "sha256": (CHANGED_ROWS if rows else CHANGED_OPAQUE) if changed else anchor}
        if case_id == "T10-A.01":
            expected["identical_bytes"] = True
        return trace == expected

    if case_id in {"T02.01", "T02.02", "T03.01"}:
        expected = {"missing": [], "unexpected": [], "duplicates": []}
        if mutated:
            field, value = {
                "T02.01": ("missing", [("synthetic", 6, 3)]),
                "T02.02": ("unexpected", [("synthetic", 6, 4)]),
                "T03.01": ("duplicates", [(("synthetic", 6, 2), 2)]),
            }[case_id]
            expected[field] = value
            if case_id == "T03.01":
                expected["missing"] = [("synthetic", 6, 3)]
        return trace == expected

    if case_id in {"T05.01", "T05.02"}:
        trusted = anchors["dependencies"]
        observed = trusted
        if mutated and case_id == "T05.01":
            observed = {}
        elif mutated:
            observed = {"Synthetic.Dependency": {"version": "1.0.0.0",
                                                 "sha256": digest(b"different dependency")}}
        return trace == {"trusted": trusted, "observed": observed}

    if case_id.startswith("T06."):
        anchor = anchors["manifest_sha256"]
        attack = case_id if mutated else None
        artifacts = {} if attack == "T06.04" else {
            "opaque.txt": CHANGED_OPAQUE if attack == "T06.02" else opaque}
        return trace == {
            "manifest_sha256": {"T06.02": REPLACED_MANIFEST,
                                "T06.03": DUPLICATE_MANIFEST}.get(attack, anchor),
            "anchor_sha256": anchor, "artifact_digests": artifacts,
            "available_artifacts": list(artifacts), "signature_valid": attack != "T06.01",
        }

    if case_id in {"T08.01", "T08.02"}:
        first, second = trace["raw"]
        base = dict(first)
        if base.pop("nested") != {"run_id": "semantic"}:
            return False
        if digest(json.dumps(base, sort_keys=True, separators=(",", ":")).encode()) != anchors["manifest_sha256"]:
            return False
        expected = {**first, "run_id": "second", "elapsed_ms": 1}
        if mutated and case_id == "T08.01":
            expected["module"] = "different"
        if mutated and case_id == "T08.02":
            expected["nested"] = {"run_id": "different"}
        projections = [{k: v for k, v in doc.items() if k not in VOLATILE}
                       for doc in (first, expected)]
        return trace == {"raw": [first, expected], "projections": projections}

    if case_id in {"T12.04", "T12.05"}:
        trusted = anchors["source_link"]
        observed = dict(trusted)
        signature, excerpt = trusted["signature"], "public int Same(int value) { return value + 1; }"
        result = {"code": 0, "reason": None}
        if mutated and case_id == "T12.04":
            signature, result = "int Same(short)", {"code": 12, "reason": "independent identity"}
        if mutated and case_id == "T12.05":
            observed["start"], observed["end"] = anchors["other_extent"]
            excerpt = "public int Same(short value) { return value + 2; }"
            result = {"code": 15, "reason": "link identity"}
        expected = {"observed_link": observed, "trusted_link": trusted,
                    "observed_signature": signature, "trusted_signature": trusted["signature"],
                    "source_excerpt": excerpt, "validator_result": result,
                    "validator": "DC00.2-P/supervisor/validator.py:methoddef"}
        if mutated and case_id == "T12.04":
            expected["signature_repair_code"] = 0
        return trace == expected

    if case_id == "T14.01":
        left, right = trace["graphs"]
        return (set(trace) == {"property", "graphs", "shared"}
                and trace["property"] == "coverage"
                and left == coverage_graph("reference", "reference_rows")
                and right == (coverage_graph("shared_reader", "reference_rows") if mutated
                              else coverage_graph("counted", "counted_rows"))
                and trace["shared"] == (["components:reference_rows"] if mutated else []))
    return False


def coverage_graph(entry, helper):
    root, child = f"components:{entry}", f"components:{helper}"
    return {"root": root, "nodes": sorted([root, child]),
            "edges": [(root, child)], "covered": True}
