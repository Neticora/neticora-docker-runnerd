import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("native_gate", Path(__file__).with_name("require_kata_native.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class NativeCoverageGateTests(unittest.TestCase):
    def events(self):
        return [{"Package": gate.PACKAGE, "Test": name, "Action": "pass"} for name in gate.REQUIRED] + [
            {"Package": gate.PACKAGE, "Action": "pass"}]

    def test_all_required_native_cases_executed(self):
        self.assertEqual(set(gate.require_native(self.events())), gate.REQUIRED)

    def test_green_package_with_missing_case_refused(self):
        with self.assertRaises(ValueError):
            gate.require_native(self.events()[1:])

    def test_skipped_native_case_refused(self):
        events = self.events()
        events[0]["Action"] = "skip"
        with self.assertRaises(ValueError):
            gate.require_native(events)

    def test_later_failure_cannot_be_hidden_by_pass(self):
        with self.assertRaises(ValueError):
            gate.require_native(self.events() + [{"Package": gate.PACKAGE, "Action": "fail"}])

    def test_truncated_package_run_refused(self):
        with self.assertRaises(ValueError):
            gate.require_native(self.events()[:-1])

    def test_other_package_cannot_supply_missing_coverage(self):
        events = self.events()
        events[0]["Package"] = "untrusted/other-package"
        with self.assertRaises(ValueError):
            gate.require_native(events)
