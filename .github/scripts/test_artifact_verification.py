import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


VERIFY = Path(__file__).resolve().parents[2] / "packaging/verify-subject.sh"


class ArtifactVerificationTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.subject = self.root / "candidate.tar.gz"
        self.subject.write_bytes(b"test artifact")
        self.arguments = self.root / "arguments.json"
        self.sha = "1" * 40
        gh = self.root / "gh"
        gh.write_text("#!/usr/bin/env python3\nimport json, os, sys\n"
                      "with open(os.environ['CAPTURE_ARGUMENTS'], 'w') as output:\n"
                      "    json.dump(sys.argv[1:], output)\n"
                      "sys.exit(int(os.environ.get('VERIFY_EXIT', '0')))\n")
        gh.chmod(0o700)
        self.environment = {**os.environ, "PATH": str(self.root) + os.pathsep + os.environ["PATH"],
                            "CAPTURE_ARGUMENTS": str(self.arguments)}

    def run_verify(self, *arguments):
        return subprocess.run(["bash", str(VERIFY), *map(str, arguments)], env=self.environment,
                              capture_output=True, text=True, timeout=5)

    def test_verified_policy_binds_source_and_signer(self):
        # This checks policy arguments, not cryptographic verification itself.
        for subject in [str(self.subject), "oci://registry.example/image@sha256:" + "a" * 64]:
            with self.subTest(subject=subject):
                result = self.run_verify(subject, self.sha)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(self.arguments.read_text()), [
                    "attestation", "verify", "--hostname", "github.com",
                    "--repo", "Neticora/neticora-docker-runnerd",
                    "--cert-oidc-issuer", "https://token.actions.githubusercontent.com",
                    "--signer-workflow", "Neticora/neticora-docker-runnerd/.github/workflows/release-candidate.yml",
                    "--signer-digest", self.sha, "--source-ref", "refs/heads/main",
                    "--source-digest", self.sha, "--deny-self-hosted-runners", "--", subject])

    def test_option_shaped_filename_is_only_a_subject(self):
        # A file called --help must never turn verification into successful help output.
        (self.root / "--help").write_bytes(b"untrusted")
        result = subprocess.run(["bash", str(VERIFY), "--help", self.sha], cwd=self.root,
                                env=self.environment, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.arguments.read_text())[-2:], ["--", "--help"])

    def test_mutable_and_missing_inputs_reject_before_verification(self):
        for args in [(self.subject,), (self.subject, "main"), (self.subject, "a" * 39),
                     (self.root / "missing", self.sha), ("oci://registry.example/image:latest", self.sha)]:
            with self.subTest(args=args):
                self.assertNotEqual(self.run_verify(*args).returncode, 0)
                self.assertFalse(self.arguments.exists())

    def test_attestation_failure_is_not_accepted(self):
        self.environment["VERIFY_EXIT"] = "1"
        self.assertNotEqual(self.run_verify(self.subject, self.sha).returncode, 0)
