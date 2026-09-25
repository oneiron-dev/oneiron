"""PR-head status decisions are made in the trusted base workflow."""

import json
import os
import unittest
from unittest.mock import patch, MagicMock

import pr_status

from pr_status import desired_states


class PrStatusTests(unittest.TestCase):
    def test_fork_gets_failure_not_skipped_success_even_if_it_edits_workflows(self):
        event = {"pull_request": {"head": {
            "sha": "f" * 40,
            "repo": {"full_name": "outsider/oneiron"},
            "changed_workflow": "jobs: {Checks: {runs-on: [self-hosted]}}",
        }}}
        for stage in ("admission", "completion"):
            with self.subTest(stage=stage):
                self.assertEqual(
                    {"Checks": "failure", "Test": "failure"},
                    desired_states(event, stage, "success", "success"),
                )

    def test_fork_admission_fails_required_contexts_on_head_and_merge(self):
        event = {"pull_request": {
            "merge_commit_sha": "c" * 40,
            "head": {"sha": "b" * 40, "repo": {"full_name": "outsider/oneiron"}},
        }}
        fake_response = MagicMock()
        fake_response.__enter__.return_value.status = 201
        with patch.dict(os.environ, {
            "GITHUB_EVENT_NAME": "pull_request_target",
            "GITHUB_REPOSITORY": "oneiron-dev/oneiron",
            "GITHUB_TOKEN": "fixture-token",
        }), patch.object(pr_status, "urlopen", return_value=fake_response) as call:
            pr_status.publish(event, "admission")
        self.assertEqual(4, call.call_count)
        for sha in ("b" * 40, "c" * 40):
            bodies = [json.loads(args.args[0].data) for args in call.call_args_list
                      if args.args[0].full_url.endswith("/" + sha)]
            self.assertEqual({"Checks": "failure", "Test": "failure"},
                             {body["context"]: body["state"] for body in bodies})

    def test_main_push_reports_real_results_from_trusted_app(self):
        event = {"ref": "refs/heads/main", "after": "e" * 40}
        self.assertEqual({"Checks": "success", "Test": "failure"},
                         desired_states(event, "completion", "success", "failure"))

    def test_main_push_publishes_from_trusted_reporter(self):
        event = {"ref": "refs/heads/main", "after": "e" * 40}
        fake_response = MagicMock()
        fake_response.__enter__.return_value.status = 201
        with patch.dict(os.environ, {
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_REPOSITORY": "oneiron-dev/oneiron",
            "GITHUB_TOKEN": "fixture-app-token",
        }), patch.object(pr_status, "urlopen", return_value=fake_response) as call:
            pr_status.publish(event, "completion", "success", "failure")
        bodies = [json.loads(args.args[0].data) for args in call.call_args_list]
        self.assertEqual({"Checks": "success", "Test": "failure"},
                         {body["context"]: body["state"] for body in bodies})
        self.assertTrue(all(args.args[0].full_url.endswith("/" + "e" * 40)
                            for args in call.call_args_list))

    def test_missing_head_repository_is_not_internal(self):
        event = {"pull_request": {"head": {"sha": "d" * 40, "repo": None}}}
        self.assertEqual({"Checks": "failure", "Test": "failure"},
                         desired_states(event, "admission"))

    def test_internal_pr_is_pending_until_real_jobs_finish(self):
        event = {"pull_request": {"head": {
            "sha": "a" * 40, "repo": {"full_name": "oneiron-dev/oneiron"},
        }}}
        self.assertEqual({"Checks": "pending", "Test": "pending"},
                         desired_states(event, "admission"))
        self.assertEqual({"Checks": "success", "Test": "failure"},
                         desired_states(event, "completion", "success", "skipped"))
        self.assertEqual({"Checks": "success", "Test": "success"},
                         desired_states(event, "completion", "success", "success"))


if __name__ == "__main__":
    unittest.main()
