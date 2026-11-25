"""Direct integration of the historical data validators for the 17 legacy cases."""
from collections import Counter
from copy import deepcopy

from components import independence
from historical import c1, c2, p
from vectors_r1 import MANIFEST_DOMAIN, P, artifact, encode, key, sign


def identity(case_id, mutated, vectors, trace):
    if case_id == "T01.01":
        original = vectors.rows_raw
        anchor = vectors.anchors["rows_sha256"]
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
    observed = deepcopy(vectors.observed_dependencies)
    if mutated:
        if case_id == "T05.01":
            observed.clear()
        else:
            observed["Synthetic.Dependency"]["sha256"] = p.digest(b"different dependency")
    trace.update(observed=observed, trusted=vectors.dependencies)
    c1.dependency_check(observed, vectors.dependencies)


def manifest_args(vectors, faults):
    args = deepcopy(vectors.manifest_args)
    for case_id in faults:
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
    return args


def manifest(case_id, mutated, vectors, trace):
    validate_manifest(vectors, manifest_args(vectors, [case_id] if mutated else []), trace)


def validate_manifest(vectors, args, trace):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        Ed25519PublicKey.from_public_bytes(args["key"]).verify(
            args["sig"], MANIFEST_DOMAIN + b"\x00" + args["raw"]
        )
        signature_valid = True
    except InvalidSignature:
        signature_valid = False
    trace.update(signature_valid=signature_valid,
                 artifact_digests={name: p.digest(data) for name, data in args["blobs"].items()},
                 manifest_sha256=p.digest(args["raw"]), anchor_sha256=args["expected_digest"],
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

    expected = dict(vectors.anchors["source_link"])
    declaration = b"public int Same(int value) { return value + 1; }"
    other = b"public int Same(short value) { return value + 2; }"
    extent = other if mutated and case_id == "T12.05" else declaration
    start = source.index(extent)
    observed = {
        "path": source_path, "sha256": p.digest(source), "start": start,
        "end": start + len(extent), "owner": "PreparationFixtures.Sample",
        "signature": "int Same(int)", "encoding": "utf-8", "kind": "direct",
        "engine_evidence": p.digest(b"synthetic link map v1"),
    }
    method = {
        "module": "synthetic", "rid": 1, "owner": "PreparationFixtures.Sample",
        "signature": "int Same(int)", "body": "present",
        "il": "pending", "csharp": "direct", "absence": None, "il_path": None,
        "il_sha256": None, "links": [observed], "csharp_reason": None,
    }
    if mutated and case_id == "T12.04":
        method["signature"] = "int Same(short)"
    method_key = ("synthetic", 6, 1)
    inventory = {method_key: {"owner": expected["owner"], "signature": expected["signature"],
                              "body": "present"}}
    trace.update(observed_link=observed, trusted_link=expected,
                 source_excerpt=source[start:start + len(extent)].decode("utf-8"),
                 observed_signature=method["signature"], trusted_signature=expected["signature"],
                 validator="DC00.2-P/supervisor/validator.py:methoddef")
    p.schema_check(method, vectors.schemas["methoddef"])
    validate_method(method, inventory, {source_path: source}, {method_key: [expected]}, trace)


def validate_method(method, inventory, blobs, engine_map, trace):
    """Translate the catalog's signature case only after historical rejection."""
    try:
        p.methoddef(method, inventory, blobs, engine_map)
    except p.Rejected as exc:
        trace["validator_result"] = {"code": exc.code, "reason": str(exc)}
        ref = inventory.get((method["module"], 6, method["rid"]))
        if (exc.code == 12 and str(exc) == "independent identity" and ref is not None
                and method["owner"] == ref["owner"] and method["body"] == ref["body"]
                and method["signature"] != ref["signature"]):
            # Repair only the signature to verify that there is no additional rejection.
            p.methoddef({**method, "signature": ref["signature"]}, inventory, blobs, engine_map)
            trace["signature_repair_code"] = 0
            raise p.Rejected(15, "method signature divergence") from exc
        raise
    trace["validator_result"] = {"code": 0, "reason": None}


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
