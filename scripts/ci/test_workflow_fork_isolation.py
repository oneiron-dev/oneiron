"""Job admission check: untrusted fork PRs must not allocate persistent runners."""

import re
import unittest
from pathlib import Path


WORKFLOWS = Path(__file__).resolve().parents[2] / ".github" / "workflows"
FORK_GUARD = (
    "(github.event_name != 'pull_request_target' || "
    "github.event.pull_request.head.repo.full_name == 'oneiron-dev/oneiron')"
)


def blocks(text, indentation):
    """Yield (name, body) for keys at one YAML indentation level."""
    lines = text.splitlines()
    heading = re.compile(r"^" + " " * indentation + r"([\w-]+):(?:\s|$)")
    for index, line in enumerate(lines):
        match = heading.match(line)
        if match is None:
            continue
        end = index + 1
        while end < len(lines):
            current = lines[end]
            if current.strip() and not current.lstrip().startswith("#") and len(current) - len(current.lstrip()) <= indentation:
                break
            end += 1
        yield match.group(1), "\n".join(lines[index:end])


def workflow_sections(text):
    return dict(blocks(text, 0))


def unguarded_jobs(text):
    sections = workflow_sections(text)
    if "on" not in sections or "jobs" not in sections:
        raise AssertionError("workflow has no on/jobs section")
    triggers = " ".join(
        line.split(" #", 1)[0] for line in sections["on"].splitlines()
        if not line.lstrip().startswith("#")
    )
    if not re.search(r"\bpull_request(?:_target)?\b", triggers):
        return []
    missing = []
    for name, body in blocks(sections["jobs"], 2):
        fields = dict(blocks(body, 4))
        runner = fields.get("runs-on", "")
        if "self-hosted" not in runner and "${{" not in runner:
            continue
        condition = " ".join(
            line.split(" #", 1)[0].strip()
            for line in fields.get("if", "").splitlines()
            if not line.lstrip().startswith("#")
        )
        condition = " ".join(condition.split())
        if FORK_GUARD not in condition:
            missing.append(name)
    return missing


class WorkflowForkIsolationTests(unittest.TestCase):
    def test_pr_jobs_on_self_hosted_runners_have_job_guard(self):
        for workflow in sorted(
            path for path in WORKFLOWS.iterdir() if path.suffix in {".yml", ".yaml"}
        ):
            with self.subTest(workflow=workflow.name):
                self.assertEqual([], unguarded_jobs(workflow.read_text()), workflow.name)

    def test_pr_workflows_are_base_owned_and_runner_group_pinned(self):
        import json

        policy = WORKFLOWS.parents[1] / "scripts" / "ci" / "trusted-runner-group.json"
        config = json.loads(policy.read_text())
        self.assertEqual("oneiron-trusted", config["name"])
        self.assertTrue(config["restricted_to_workflows"])
        self.assertTrue(config["allows_public_repositories"])
        self.assertEqual("selected", config["visibility"])
        self.assertEqual([1113618625], config["selected_repository_ids"])
        expected = {
            "oneiron-dev/oneiron/.github/workflows/" + path.name + "@refs/heads/main"
            for path in WORKFLOWS.glob("*.yml")
        }
        self.assertEqual(expected, set(config["selected_workflows"]))
        self.assertEqual(len(expected), len(config["selected_workflows"]))
        installer = (WORKFLOWS.parents[1] / "scripts" / "ci" / "install-runner.sh").read_text()
        self.assertIn("--runnergroup oneiron-trusted", installer)
        self.assertIn("--url https://github.com/oneiron-dev --runnergroup", installer)
        for workflow in sorted(WORKFLOWS.glob("*.yml")):
            text = workflow.read_text()
            jobs = dict(blocks(workflow_sections(text)["jobs"], 2))
            for name, body in jobs.items():
                fields = dict(blocks(body, 4))
                runner = fields.get("runs-on", "")
                if "self-hosted" not in runner:
                    continue
                with self.subTest(workflow=workflow.name, job=name):
                    self.assertIn("group: oneiron-trusted", runner)
                    self.assertNotRegex(workflow_sections(text)["on"], r"(?m)^  pull_request:")
                    self.assertIn(
                        "oneiron-dev/oneiron/.github/workflows/"
                        + workflow.name + "@refs/heads/main",
                        config["selected_workflows"],
                    )

    def test_fork_submitted_workflows_cannot_select_restricted_group(self):
        # The org policy is keyed by workflow path AND trusted workflow ref.
        # This simulates an approved fork removing guards or adding a job/file.
        import json

        policy = json.loads((WORKFLOWS.parents[1] / "scripts" / "ci" /
                             "trusted-runner-group.json").read_text())
        allowed = set(policy["selected_workflows"])
        main = "oneiron-dev/oneiron/.github/workflows/ci.yml@refs/heads/main"
        changed = "oneiron-dev/oneiron/.github/workflows/ci.yml@refs/pull/42/merge"
        added = "oneiron-dev/oneiron/.github/workflows/attack.yml@refs/pull/42/merge"
        self.assertIn(main, allowed)
        self.assertNotIn(changed, allowed)
        self.assertNotIn(added, allowed)

    def test_trusted_ci_posts_explicit_pr_head_contexts(self):
        ci = (WORKFLOWS / "ci.yml").read_text()
        self.assertIn("  pull_request_target:", workflow_sections(ci)["on"])
        self.assertIn("scripts/ci/pr_status.py admission", ci)
        self.assertIn("scripts/ci/pr_status.py completion", ci)
        self.assertEqual(2, ci.count("uses: actions/create-github-app-token@v2"))
        self.assertEqual(2, ci.count("GITHUB_TOKEN: ${{ steps.app-token.outputs.token }}"))
        self.assertNotIn("GITHUB_TOKEN: ${{ github.token }}", ci)
        self.assertIn("github.event_name == 'push' && github.ref == 'refs/heads/main'", ci)

    def test_step_guard_does_not_protect_runner_admission(self):
        example = """on:
  pull_request:
jobs:
  unsafe:
    runs-on: [self-hosted]
    steps:
      - if: (github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == 'oneiron-dev/oneiron')
        run: echo safe
"""
        self.assertEqual(["unsafe"], unguarded_jobs(example))

    def test_comment_cannot_supply_guard(self):
        example = """on: [pull_request]
jobs:
  unsafe:
    runs-on: ${{ fromJSON('["self-hosted"]') }}
    if: vars.CI_PAUSED != 'true' # (github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == 'oneiron-dev/oneiron')
"""
        self.assertEqual(["unsafe"], unguarded_jobs(example))

    def test_push_only_workflow_needs_no_pr_guard(self):
        example = """on:
  push:
jobs:
  main:
    runs-on: [self-hosted]
"""
        self.assertEqual([], unguarded_jobs(example))


if __name__ == "__main__":
    unittest.main()
