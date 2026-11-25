"""Direct integration of the historical data validators for the 17 legacy cases."""
from collections import Counter
from copy import deepcopy

from historical import c1, c2, p
from vectors import MANIFEST_DOMAIN, P, artifact, encode, key, sign


def identity(case_id, mutated, vectors, trace):
    if case_id == "T01.01":
        original = (P / "fixtures" / "rows.json").read_bytes()
        anchor = vectors.identity["rows.json"]
    else:
        original, anchor = vectors.opaque, vectors.opaque_hash
    if case_id == "T10-A.01":
        data = (P / "fixtures" / "opaque.txt").read_bytes()
    else:
        data = original + b"!" if mutated else original
    trace.update(sha256=p.digest(data), anchor_sha256=anchor, parser_calls=0)
    c1.identity(data, anchor)
    if case_id == "T01.01":
        trace["parser_calls"] += 1
        p.strict_load(data)
    elif case_id == "T10-A.01":
        trace["identical_bytes"] = data == original
        if not trace["identical_bytes"]:
            raise AssertionError("opaque bytes changed")


def coverage(case_id, mutated, vectors, trace):
    rows = deepcopy(vectors.rows)
    expected = [("synthetic", 6, rid) for rid in (1, 2, 3)]
    if mutated:
        if case_id == "T02.01":
            rows.pop()
        elif case_id == "T02.02":
            rows.append({**rows[-1], "rid": 4})
        else:
            rows[-1]["rid"] = 2
    for row in rows:
        p.schema_check(row, vectors.schemas["row"])
    got = Counter((row["module"], row["table_id"], row["rid"]) for row in rows)
    trace.update(
        missing=sorted(set(expected) - got.keys()),
        unexpected=sorted(got.keys() - set(expected)),
        duplicates=sorted((row, count) for row, count in got.items() if count > 1),
    )
    p.coverage(rows, expected)


def dependency(case_id, mutated, vectors, trace):
    observed = deepcopy(vectors.dependencies)
    if mutated:
        if case_id == "T05.01":
            observed.clear()
        else:
            observed["Synthetic.Dependency"]["sha256"] = p.digest(b"different dependency")
    trace.update(observed=observed, trusted=vectors.dependencies)
    c1.dependency_check(observed, vectors.dependencies)


def manifest(case_id, mutated, vectors, trace):
    args = deepcopy(vectors.manifest_args)
    if mutated:
        if case_id == "T06.01":
            args["sig"] = sign(key("synthetic untrusted signer"), MANIFEST_DOMAIN, args["raw"])
        elif case_id == "T06.02":
            replacement = vectors.opaque + b"!"
            args["blobs"]["opaque.txt"] = replacement
            args["raw"] = encode({**vectors.manifest_doc,
                                  "inputs": [artifact("opaque.txt", replacement)]})
            args["sig"] = sign(vectors.private, MANIFEST_DOMAIN, args["raw"])
        elif case_id == "T06.03":
            args["raw"] = b'{"run_id":"duplicate",' + args["raw"][1:]
            args["sig"] = sign(vectors.private, MANIFEST_DOMAIN, args["raw"])
        else:
            args["blobs"].clear()
    trace.update(manifest_sha256=p.digest(args["raw"]), anchor_sha256=args["expected_digest"],
                 available_artifacts=sorted(args["blobs"]))
    document = c2.integrate(vectors.gate_args, args)
    p.artifacts(document["inputs"], args["blobs"], args["trusted_records"])


def projection(case_id, mutated, vectors, trace):
    first = {**vectors.manifest_doc, "nested": {"run_id": "semantic"}}
    second = {**deepcopy(first), "run_id": "second", "elapsed_ms": 1}
    if mutated:
        if case_id == "T08.01":
            second["module"] = "different"
        else:
            second["nested"]["run_id"] = "different"
    trace.update(raw=[first, second], projections=[p.projection(first), p.projection(second)])
    p.compare(first, second)


def method_link(case_id, mutated, vectors, trace):
    source_path = "Synthetic.cs"
    source = vectors.source

    def link(declaration, signature):
        start = source.index(declaration)
        return {
            **artifact(source_path, source), "start": start, "end": start + len(declaration),
            "owner": "PreparationFixtures.Sample", "signature": signature,
            "encoding": "utf-8", "kind": "direct",
            "engine_evidence": p.digest(b"synthetic link map v1"),
        }

    expected = link(b"public int Same(int value) { return value + 1; }", "int Same(int)")
    other = link(b"public int Same(short value) { return value + 2; }", "int Same(short)")
    observed = dict(expected)
    if mutated and case_id == "T12.05":
        observed.update(start=other["start"], end=other["end"])
    # Link records do not carry the artifact size.
    del observed["size"], expected["size"]
    method = {
        "module": "synthetic", "rid": 1, "owner": expected["owner"],
        "signature": expected["signature"], "body": "present",
        "il": "pending", "csharp": "direct", "absence": None, "il_path": None,
        "il_sha256": None, "links": [observed], "csharp_reason": None,
    }
    if mutated and case_id == "T12.04":
        method["signature"] = other["signature"]
    method_key = ("synthetic", 6, 1)
    inventory = {method_key: {"owner": expected["owner"], "signature": expected["signature"],
                              "body": "present"}}
    trace.update(observed_link=observed, trusted_link=expected,
                 observed_signature=method["signature"], trusted_signature=expected["signature"])
    p.schema_check(method, vectors.schemas["methoddef"])
    p.require(method["signature"] == inventory[method_key]["signature"], 15,
              "method signature divergence")
    p.methoddef(method, inventory, {source_path: source}, {method_key: [expected]})


def independence(case_id, mutated, vectors, trace):
    first = {"coverage": ["fixture-reader-a"], "reporting": ["shared-reporter"]}
    second = {"coverage": ["fixture-reader-b"], "reporting": ["shared-reporter"]}
    if mutated:
        second["coverage"].append("fixture-reader-a")
    trace.update(property="coverage", components=[first, second])
    p.independence(first, second, "coverage")


CASES = {
    "T01.01": identity,
    "T02.01": coverage, "T02.02": coverage, "T03.01": coverage,
    "T05.01": dependency, "T05.02": dependency,
    "T06.01": manifest, "T06.02": manifest, "T06.03": manifest, "T06.04": manifest,
    "T08.01": projection, "T08.02": projection,
    "T09-B.01": identity, "T10-A.01": identity,
    "T12.04": method_link, "T12.05": method_link,
    "T14.01": independence,
}
