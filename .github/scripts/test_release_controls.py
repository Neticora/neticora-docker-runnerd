import copy
import importlib.util
import unittest
from pathlib import Path


spec = importlib.util.spec_from_file_location("controls", Path(__file__).with_name("check-release-controls.py"))
controls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controls)


class ReleaseControlsTest(unittest.TestCase):
    def setUp(self):
        self.environment = {
            "name": "runnerd-release",
            "protection_rules": [{"type": "required_reviewers", "prevent_self_review": True,
                                  "reviewers": [{"type": "Team", "reviewer": {"id": 123}}]}],
            "deployment_branch_policy": {"custom_branch_policies": True, "protected_branches": False},
        }
        self.branches = {"total_count": 1, "branch_policies": [{"name": "main", "type": "branch"}]}
        self.rules = [
            {"type": "deletion"}, {"type": "non_fast_forward"},
            {"type": "pull_request", "parameters": {"required_approving_review_count": 1,
                "dismiss_stale_reviews_on_push": True, "required_review_thread_resolution": True}},
            {"type": "required_status_checks", "parameters": {"strict_required_status_checks_policy": True,
                "required_status_checks": [{"context": name} for name in sorted(controls.CHECKS)]}},
        ]

    def test_complete_controls(self):
        controls.validate(self.environment, self.branches, self.rules)

    def test_unprotected_environment(self):
        cases = []
        for field, value in [("prevent_self_review", False), ("reviewers", [])]:
            candidate = copy.deepcopy(self.environment)
            candidate["protection_rules"][0][field] = value
            cases.append(candidate)
        cases.extend([{}, {**self.environment, "name": "other"},
                      {**self.environment, "protection_rules": []},
                      {**self.environment, "deployment_branch_policy": None}])
        for candidate in cases:
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                controls.validate(candidate, self.branches, self.rules)

    def test_branch_and_tag_restrictions(self):
        for name, kind, count in [("*", "branch", 1), ("main", "tag", 1), ("main", "branch", 2)]:
            candidate = {"total_count": count, "branch_policies": [{"name": name, "type": kind}]}
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                controls.validate(self.environment, candidate, self.rules)

    def test_rules_must_be_enforced(self):
        for index in range(len(self.rules)):
            candidate = self.rules[:index] + self.rules[index + 1:]
            with self.subTest(index=index), self.assertRaises(ValueError):
                controls.validate(self.environment, self.branches, candidate)

    def test_current_review_and_strict_checks(self):
        for index, field, value in [(2, "required_approving_review_count", 0),
                                    (2, "dismiss_stale_reviews_on_push", False),
                                    (2, "required_review_thread_resolution", False),
                                    (3, "strict_required_status_checks_policy", False),
                                    (3, "required_status_checks", [{"context": "build"}])]:
            candidate = copy.deepcopy(self.rules)
            candidate[index]["parameters"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                controls.validate(self.environment, self.branches, candidate)

    def test_last_push_approval_alternative(self):
        self.rules[2]["parameters"]["dismiss_stale_reviews_on_push"] = False
        self.rules[2]["parameters"]["require_last_push_approval"] = True
        controls.validate(self.environment, self.branches, self.rules)
