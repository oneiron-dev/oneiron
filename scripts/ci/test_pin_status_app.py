"""Required contexts must be tied to the trusted status App, not PR jobs."""

import unittest

from pin_status_app import pinned_ruleset


class PinnedStatusAppTests(unittest.TestCase):
    def test_preserves_other_rules_and_pins_only_required_status_source(self):
        ruleset = {
            "name": "main rules", "target": "branch", "enforcement": "active",
            "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
            "bypass_actors": [],
            "rules": [
                {"type": "deletion"},
                {"type": "pull_request", "parameters": {"required_approving_review_count": 0}},
                {"type": "required_status_checks", "parameters": {
                    "required_status_checks": [{"context": "Checks"}, {"context": "Test"}],
                    "strict_required_status_checks_policy": False,
                }},
            ],
        }
        result = pinned_ruleset(ruleset, 12345)
        self.assertEqual("active", result["enforcement"])
        self.assertEqual(ruleset["rules"][:2], result["rules"][:2])
        self.assertEqual(
            [{"context": "Checks", "integration_id": 12345},
             {"context": "Test", "integration_id": 12345}],
            result["rules"][2]["parameters"]["required_status_checks"],
        )
        self.assertNotIn("integration_id", ruleset["rules"][2]["parameters"]["required_status_checks"][0])

    def test_refuses_a_drifted_ruleset(self):
        with self.assertRaises(ValueError):
            pinned_ruleset({"rules": []}, 12345)


if __name__ == "__main__":
    unittest.main()
