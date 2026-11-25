"""Adversarial regressions for the C3.1-R1 synthetic runner."""
from copy import deepcopy
from pathlib import Path
import json
import subprocess
import sys
import unittest
from unittest.mock import patch

from run import CONCURRENT, concurrent_controls, observe
from audit import AuditGuard
from cases import CASES, manifest_args, validate_manifest
from components import counted, observe as graph, reachable
from historical import c2, p
from oracles import REASONS, check
from vectors_r1 import MANIFEST_DOMAIN, Vectors, artifact


class RevisionTests(unittest.TestCase):
    def setUp(self):
        self.vectors = Vectors()

    def test_transitive_shared_reader_and_coverage(self):
        mutation = observe("T14.01", True, self.vectors, [])
        self.assertEqual(mutation["observed_code"], 18)
        self.assertEqual(mutation["trace"]["shared"], ["components:reference_rows"])
        # Removing one recorded edge must not turn shared dependencies into independence.
        broken = deepcopy(mutation["trace"]["graphs"][1])
        broken["edges"].clear()
        with self.assertRaisesRegex(ValueError, "Disconnected"):
            reachable(broken)
        for rows in (self.vectors.rows[:-1], self.vectors.rows + self.vectors.rows[:1]):
            self.assertFalse(graph(counted, rows)["covered"])
            with patch.object(self.vectors, "rows", rows):
                self.assertEqual(observe("T14.01", False, self.vectors, [])["observed_code"], 11)

    def test_joint_resigning_cannot_move_manifest_anchor(self):
        args = manifest_args(self.vectors, ["T06.02"])
        raw = args["raw"]
        args["trusted_records"]["opaque.txt"] = artifact("opaque.txt", args["blobs"]["opaque.txt"])
        self.assertEqual(c2.authenticate(raw, args["sig"], args["key"], MANIFEST_DOMAIN, 12)
                         ["inputs"], list(args["trusted_records"].values()))
        with self.assertRaisesRegex(c2.Rejected, "manifest anchor"):
            validate_manifest(self.vectors, args, {})
        args["expected_digest"] = p.digest(raw)
        with self.assertRaisesRegex(c2.Rejected, "evidence binding"):
            validate_manifest(self.vectors, args, {})

    def test_source_drift_cannot_move_trusted_extent_or_digest(self):
        original = self.vectors.source
        for source in (original + b" ", b" " + original):
            with patch.object(self.vectors, "source", source):
                result = observe("T12.04", False, self.vectors, [])
                self.assertEqual(result["reason"], "link identity")
                self.assertEqual(result["trace"]["trusted_link"], self.vectors.anchors["source_link"])
                self.assertFalse(check("T12.04", False, result["trace"], result["reason"],
                                       self.vectors.anchors))

    def test_observed_dependency_drift_keeps_trusted_inventory(self):
        self.vectors.observed_dependencies["Synthetic.Dependency"]["version"] = "2.0.0.0"
        result = observe("T05.01", False, self.vectors, [])
        self.assertEqual(result["observed_code"], 13)
        self.assertEqual(result["trace"]["trusted"], self.vectors.anchors["dependencies"])

    def test_priority_and_same_code_do_not_hide_concurrency(self):
        observations = concurrent_controls(self.vectors, [])
        self.assertTrue(all(entry["passed"] for entry in observations))
        self.assertEqual(observations[0]["classified_code"], observations[1]["classified_code"])
        same_code = observations[2]
        self.assertEqual([fault["observed_code"] for fault in same_code["faults"]], [12, 12])
        self.assertEqual(same_code["joint_observation"]["reason"], "signature rejected")
        self.assertFalse(same_code["single_mutation_accepted"])
        with patch.object(p, "classify", lambda codes: codes[0]):
            self.assertFalse(concurrent_controls(self.vectors, [], CONCURRENT[1:2])[0]["passed"])
        oracle = p.oracle
        with patch.object(p, "oracle", lambda expected, observed, forbidden, concurrent:
                          oracle(expected, observed, forbidden, False)):
            self.assertFalse(concurrent_controls(self.vectors, [], CONCURRENT[2:3])[0]["passed"])

    def test_code_15_requires_validator_rejection_for_signature(self):
        result = observe("T12.04", True, self.vectors, [])
        self.assertEqual(result["trace"]["validator_result"],
                         {"code": 12, "reason": "independent identity"})
        self.assertEqual(result["trace"]["signature_repair_code"], 0)
        with patch.object(p, "methoddef", return_value={}):
            self.assertEqual(observe("T12.04", True, self.vectors, [])["observed_code"], 0)
        with patch.object(p, "methoddef", side_effect=p.Rejected(12, "body/IL invariant")):
            self.assertEqual(observe("T12.04", True, self.vectors, [])["observed_code"], 12)
        with patch.object(p, "methoddef", side_effect=[
            p.Rejected(12, "independent identity"), p.Rejected(15, "link extent")
        ]):
            other = observe("T12.04", True, self.vectors, [])
            self.assertEqual(other["reason"], "link extent")
            self.assertNotIn("signature_repair_code", other["trace"])

    def test_every_trace_field_and_reason_is_checked(self):
        self.assertEqual(set(CASES), set(REASONS))
        for case in CASES:
            for mutated in (False, True):
                result = observe(case, mutated, self.vectors, [])
                trace, reason = result["trace"], result["reason"]
                with self.subTest(case=case, mutated=mutated):
                    self.assertTrue(check(case, mutated, trace, reason, self.vectors.anchors))
                    self.assertFalse(check(case, mutated, trace, "incorrect", self.vectors.anchors))
                    for field in trace:
                        bad = deepcopy(trace)
                        bad.pop(field)
                        self.assertFalse(check(case, mutated, bad, reason, self.vectors.anchors), field)
                        bad[field] = None
                        self.assertFalse(check(case, mutated, bad, reason, self.vectors.anchors), field)

    def test_registration_probe_fails_closed(self):
        with patch("sys.addaudithook"):
            with self.assertRaisesRegex(RuntimeError, "registration"):
                AuditGuard().install()

    def test_runner_audit_and_exit_status(self):
        runner = Path(__file__).with_name("run.py")
        result = subprocess.run([sys.executable, "-EB", str(runner)],
                                capture_output=True, check=True, text=True)
        report = json.loads(result.stdout)
        self.assertEqual(len(report["controls"]), 34)
        self.assertTrue(all(item["passed"] for item in report["audit"]["probes"]))
        self.assertEqual(report["audit"]["unexpected_denials"], [])
        self.assertIn("socket.__new__", report["audit"]["probe_events"])
        self.assertNotIn("open", report["audit"]["probe_events"])

        injected = """
import sys
import run
from cases import CASES
original = CASES["T01.01"]
def attempt(case_id, mutated, vectors, trace):
    try:
        sys.audit("subprocess.Popen")
    except PermissionError:
        pass
    return original(case_id, mutated, vectors, trace)
CASES["T01.01"] = attempt
sys.exit(run.main())
"""
        failed = subprocess.run([sys.executable, "-EB", "-c", injected], cwd=runner.parent,
                                capture_output=True, check=False, text=True)
        self.assertEqual(failed.returncode, 1, failed.stderr)
        report = json.loads(failed.stdout)
        self.assertEqual(set(report["audit"]["unexpected_denials"]), {"subprocess.Popen"})
        self.assertTrue(any(not item["passed"] for item in report["controls"]))


if __name__ == "__main__":
    unittest.main()
