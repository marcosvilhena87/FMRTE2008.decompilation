"""Instrument the Python call graph of the synthetic coverage implementations."""
from collections import defaultdict
import sys

from historical import p

ROWS = (("synthetic", 6, 1), ("synthetic", 6, 2), ("synthetic", 6, 3))


def reference_rows(records):
    return [(row["module"], row["table_id"], row["rid"]) for row in records]


def reference(records):
    return sorted(reference_rows(records)) == list(ROWS)


def counted_rows(records):
    counts = {}
    for row in records:
        key = row["module"], row["table_id"], row["rid"]
        counts[key] = counts.get(key, 0) + 1
    return counts


def counted(records):
    return counted_rows(records) == dict.fromkeys(ROWS, 1)


def shared_reader(records):
    return sorted(reference_rows(records)) == list(ROWS)


def observe(root, rows):
    """Record transitive Python implementation calls, including recursion."""
    edges = set()
    nodes = set()
    active = []
    previous = sys.getprofile()

    def profile(frame, event, arg):
        if event == "call":
            code = frame.f_code
            name = f"{frame.f_globals['__name__']}:{code.co_qualname}"
            nodes.add(name)
            if active:
                edges.add((active[-1], name))
            active.append(name)
        elif event == "return" and active:
            active.pop()

    sys.setprofile(profile)
    try:
        covered = root(rows)
    finally:
        sys.setprofile(previous)
    return {"root": f"{root.__module__}:{root.__qualname__}", "nodes": sorted(nodes),
            "edges": sorted(edges), "covered": covered}


def reachable(graph):
    successors = defaultdict(set)
    for caller, callee in graph["edges"]:
        successors[caller].add(callee)
    seen, pending = set(), [graph["root"]]
    while pending:
        node = pending.pop()
        if node not in seen:
            seen.add(node)
            pending.extend(successors[node])
    if seen != set(graph["nodes"]):
        raise ValueError("Disconnected coverage graph")
    return seen


def independence(case_id, mutated, vectors, trace):
    first = observe(reference, vectors.rows)
    second = observe(shared_reader if mutated else counted, vectors.rows)
    left, right = reachable(first), reachable(second)
    trace.update(property="coverage", graphs=[first, second], shared=sorted(left & right))
    p.require(first["covered"] and second["covered"], 11, "coverage computation")
    p.independence({"coverage": left}, {"coverage": right}, "coverage")
