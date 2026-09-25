"""Job admission check: untrusted fork PRs must not allocate persistent runners."""

import re
import unittest
from pathlib import Path


WORKFLOWS = Path(__file__).resolve().parents[2] / ".github" / "workflows"
FORK_GUARD = (
    "(github.event_name != 'pull_request' || "
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
    if not re.search(r"\bpull_request\b", triggers):
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
