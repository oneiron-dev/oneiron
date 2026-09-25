#!/usr/bin/env python3
"""Generate a minimal ruleset PUT payload that pins Checks/Test to a GitHub App."""

import copy
import json
import sys


FIELDS = ("name", "target", "enforcement", "conditions", "bypass_actors", "rules")


def pinned_ruleset(current, app_id):
    if not isinstance(app_id, int) or app_id <= 0:
        raise ValueError("expected a positive GitHub App ID")
    if set(FIELDS) - current.keys():
        raise ValueError("live ruleset lacks required update fields")
    result = {field: copy.deepcopy(current[field]) for field in FIELDS}
    status_rules = [rule for rule in result["rules"] if rule["type"] == "required_status_checks"]
    if len(status_rules) != 1:
        raise ValueError("expected exactly one required-status-checks rule")
    checks = status_rules[0]["parameters"]["required_status_checks"]
    if sorted(check["context"] for check in checks) != ["Checks", "Test"]:
        raise ValueError("unexpected required check contexts; inspect the live ruleset")
    for check in checks:
        check["integration_id"] = app_id
    return result


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: pin_status_app.py <app-id> < current-ruleset.json")
    json.dump(pinned_ruleset(json.load(sys.stdin), int(sys.argv[1])), sys.stdout, indent=2)
    print()
