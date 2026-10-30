#!/usr/bin/env python3
"""Fail closed on the GitHub controls required before candidate signing."""

import json
import sys


CHECKS = {"lint", "typecheck", "unit-tests", "build", "contract-validation", "protocol-conformance"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate(environment, branches, rules):
    require(environment.get("name") == "runnerd-release", "wrong release environment")
    reviews = [r for r in environment.get("protection_rules", []) if r.get("type") == "required_reviewers"]
    require(any(r.get("reviewers") and r.get("prevent_self_review") is True for r in reviews),
            "release requires reviewers and prevention of self-review")
    policy = environment.get("deployment_branch_policy") or {}
    require(policy.get("custom_branch_policies") is True and policy.get("protected_branches") is False,
            "release requires an explicit main-only branch policy")
    entries = branches.get("branch_policies", [])
    require(branches.get("total_count") == 1 and len(entries) == 1
            and entries[0].get("name") == "main" and entries[0].get("type") == "branch",
            "release must allow only main, without tags or wildcard branches")
    require(isinstance(rules, list), "effective main rules must be an array")
    by_type = {}
    for rule in rules:
        by_type.setdefault(rule["type"], []).append(rule.get("parameters") or {})
    require("deletion" in by_type and "non_fast_forward" in by_type,
            "main must reject deletion and force pushes")
    require(any(p.get("required_approving_review_count", 0) >= 1
                and (p.get("dismiss_stale_reviews_on_push") is True or p.get("require_last_push_approval") is True)
                and p.get("required_review_thread_resolution") is True
                for p in by_type.get("pull_request", [])),
            "main requires review of current changes and resolved review threads")
    checks = set()
    for p in by_type.get("required_status_checks", []):
        if p.get("strict_required_status_checks_policy") is True:
            checks.update(c["context"] for c in p.get("required_status_checks", []))
    require(CHECKS <= checks, "main must require all six checks against the current base")


def main():
    try:
        require(len(sys.argv) == 4, "usage: check-release-controls.py ENVIRONMENT_JSON BRANCHES_JSON RULES_JSON")
        values = []
        for name in sys.argv[1:]:
            with open(name, encoding="utf-8") as source:
                values.append(json.load(source))
        validate(*values)
    except (ValueError, KeyError, TypeError, AttributeError, OSError):
        # API payloads and file paths can contain sensitive metadata.
        print("Release controls are missing, invalid or insufficient; signing refused.", file=sys.stderr)
        return 1
    print("Release environment and effective main rules passed preflight.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
