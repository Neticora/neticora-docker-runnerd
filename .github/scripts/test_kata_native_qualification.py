import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
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

    def test_previous_coverage_without_late_acquisition_refused(self):
        events = [event for event in self.events()
                  if event.get("Test") != "TestNativeSandboxLateReferenceAtUnlink"]
        with self.assertRaises(ValueError):
            gate.require_native(events)

    def test_late_acquisition_skip_refused(self):
        events = self.events()
        for event in events:
            if event.get("Test") == "TestNativeSandboxLateReferenceAtUnlink":
                event["Action"] = "skip"
        with self.assertRaises(ValueError):
            gate.require_native(events)

    def test_script_retains_gate_evidence_and_test_exit(self):
        # Exercise the real shell orchestration with synthetic tool output;
        # this checks gate failure handling, never native qualification itself.
        script = Path(__file__).with_name("qualify-kata-native.sh").resolve()
        missing = [event for event in self.events()
                   if event.get("Test") != "TestNativeSandboxLateReferenceAtUnlink"]
        failed = self.events() + [{"Package": gate.PACKAGE, "Action": "fail"}]
        for name, events, test_exit, expected_exit, refused in [
            ("complete", self.events(), 0, 0, False),
            ("test_failure", failed, 1, 1, True),
            ("missing_late_case", missing, 0, 1, True),
            ("failed_pipeline", self.events(), 17, 17, False),
        ]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                binary = root / "bin"
                binary.mkdir()
                fake_go = binary / "go"
                fake_go.write_text(
                    "#!/usr/bin/env python3\n"
                    "import os,sys\nfrom pathlib import Path\n"
                    "if sys.argv[1:] == ['version']:\n"
                    " print('synthetic go version')\n"
                    "elif sys.argv[1] == 'test':\n"
                    " sys.stdout.write(Path(os.environ['RUNNERD_TEST_EVENTS']).read_text())\n"
                    " sys.exit(int(os.environ['RUNNERD_TEST_EXIT']))\n"
                    "else:\n sys.exit(2)\n")
                fake_cc = binary / "cc"
                fake_cc.write_text("#!/bin/sh\necho 'synthetic compiler version'\n")
                for tool in (fake_go, fake_cc):
                    tool.chmod(0o755)
                event_file = root / "events.jsonl"
                event_file.write_text("".join(json.dumps(event) + "\n" for event in events))
                output = root / "output"
                env = dict(os.environ, PATH=str(binary) + os.pathsep + os.environ["PATH"],
                           RUNNERD_TEST_EVENTS=str(event_file), RUNNERD_TEST_EXIT=str(test_exit))
                result = subprocess.run(["bash", str(script), str(output)],
                                        cwd=script.parents[2], env=env,
                                        capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, expected_exit, result.stderr)
                self.assertEqual((output / "native-tests.jsonl").read_text(), event_file.read_text())
                gate_error = (output / "native-coverage.stderr").read_text()
                if refused:
                    self.assertIn("Native qualification refused:", gate_error)
                else:
                    self.assertEqual(gate_error, "")
                    self.assertEqual(json.loads((output / "native-coverage.json").read_text())["status"], "passed")
