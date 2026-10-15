"""Fork pull requests never reach a persistent self-hosted runner (F32, H313/H330).

Two layers. The boundary is the runner's own job-started hook
(runner-job-started.sh, installed by install-runner.sh): it refuses any job
whose event carries a pull request from another repository, before the job's
first step, whatever the PR's copy of the workflow asks for. The routing layer
is the workflows themselves: every job a PR reaches picks a GitHub-hosted
runner for a fork, so a fork PR still runs the required contexts (a skipped
job reports success on a required check) instead of being refused.

The workflows are read with a small line parser for the subset they use and
the expressions with a small evaluator, so the check needs no PyYAML. Anything
outside that subset, and any context path the model does not declare, fails
the test rather than passing it.
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github/workflows"
HOOK = ROOT / "scripts/ci/runner-job-started.sh"
INSTALLER = ROOT / "scripts/ci/install-runner.sh"
PR_TRIGGERS = {"pull_request", "pull_request_target"}
# The only runners a fork PR job may name: GitHub's ephemeral hosted images.
HOSTED_LABELS = {"ubuntu-latest", "macos-latest"}
REPO = "oneiron-dev/oneiron"
# ci.yml's required contexts on main and the job they need.
REQUIRED_CI_JOBS = ("changes", "checks", "test-linux", "test-linux-featureless")


def _event(head_repo, draft=False, event_name="pull_request"):
    return {
        "github": {
            "event_name": event_name,
            "repository": REPO,
            "ref": "refs/pull/1/merge",
            "event": {"pull_request": {"draft": draft, "head": {"repo": {"full_name": head_repo}}}},
        },
        "vars": {"CI_PAUSED": None},
        "inputs": {"cache_proof": None, "host": None},
        "needs": {},
    }


def _push():
    return {
        "github": {
            "event_name": "push",
            "repository": REPO,
            "ref": "refs/heads/main",
            "event": {"pull_request": None},
        },
        "vars": {"CI_PAUSED": None},
        "inputs": {"cache_proof": None, "host": None},
        "needs": {},
    }


# --- the workflow subset -----------------------------------------------------


def _block_value(lines, i, indent):
    """The value of the key on lines[i]: inline, or a folded/literal block below it."""
    value = lines[i].split(":", 1)[1].strip()
    if value not in (">", ">-", "|", "|-"):
        return value, i + 1
    parts = []
    j = i + 1
    while j < len(lines) and (not lines[j].strip() or _indent(lines[j]) > indent):
        parts.append(lines[j].strip())
        j += 1
    return " ".join(p for p in parts if p), j


def _indent(line):
    return len(line) - len(line.lstrip(" "))


def _significant(text):
    return [l for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#")]


def _name(token):
    name = token.strip().strip("\"'")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", name):
        raise AssertionError(f"cannot read trigger or job name {token!r}")
    return name


def _children(lines, start):
    """Indices of the direct children of the block opened on lines[start]."""
    parent = _indent(lines[start])
    child = None
    out = []
    for i in range(start + 1, len(lines)):
        indent = _indent(lines[i])
        if indent <= parent:
            break
        child = indent if child is None else child
        if indent == child:
            out.append(i)
        elif indent < child:
            raise AssertionError(f"irregular indentation at {lines[i]!r}")
    return out


def triggers(text):
    lines = _significant(text)
    for i, line in enumerate(lines):
        m = re.match(r"^(on|\"on\"|'on'|true):\s*(.*)$", line)
        if not m:
            continue
        inline = m.group(2).strip()
        if inline.startswith("[") and inline.endswith("]"):
            return {_name(t) for t in inline[1:-1].split(",") if t.strip()}
        if inline:
            return {_name(inline)}
        names = {_name(lines[c].split(":", 1)[0]) for c in _children(lines, i)}
        if not names:
            raise AssertionError("empty `on:` block")
        return names
    raise AssertionError("no `on:` block")


def jobs(text):
    """{job id: {"if": str | None, "runs-on": str}} for the top-level `jobs:` map."""
    lines = _significant(text)
    start = next(i for i, l in enumerate(lines) if l.rstrip() == "jobs:")
    found = {}
    for j in _children(lines, start):
        current = _name(lines[j].rstrip().rstrip(":"))
        if not lines[j].rstrip().endswith(":"):
            raise AssertionError(f"job {current}: not a block")
        found[current] = {"if": None, "runs-on": None}
        for k in _children(lines, j):
            key = lines[k].strip().split(":", 1)[0]
            if key in ("if", "runs-on"):
                found[current][key] = _block_value(lines, k, _indent(lines[k]))[0]
            if key == "uses":
                raise AssertionError(f"job {current}: reusable workflows are outside this check's subset")
    if not found:
        raise AssertionError("no jobs")
    for job, keys in found.items():
        if keys["runs-on"] is None:
            raise AssertionError(f"job {job}: no runs-on")
    return found


# --- GitHub expressions ------------------------------------------------------

_TOKEN = re.compile(
    r"\s*(?:(?P<str>'(?:[^']|'')*')|(?P<num>\d+(?:\.\d+)?)|(?P<op>==|!=|<=|>=|&&|\|\||[()!<>.,\[\]])"
    r"|(?P<name>[A-Za-z_][A-Za-z0-9_-]*))"
)


def _tokens(expr):
    pos, out = 0, []
    expr = expr.strip()
    while pos < len(expr):
        m = _TOKEN.match(expr, pos)
        if not m or m.end() == pos:
            raise AssertionError(f"cannot read expression at {expr[pos:]!r}")
        pos = m.end()
        kind = m.lastgroup
        out.append((kind, m.group(kind)))
    return out


def _truthy(v):
    return v not in (None, False, 0, "") and v == v


def _number(v):
    if v is None:
        return 0.0
    if isinstance(v, bool):
        return float(v)
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        try:
            return float(v) if v.strip() else 0.0
        except ValueError:
            return float("nan")
    return float("nan")


def _equal(a, b):
    if isinstance(a, str) and isinstance(b, str):
        return a.lower() == b.lower()
    if type(a) is type(b):
        return a == b
    return _number(a) == _number(b)


class _Eval:
    def __init__(self, tokens, context):
        self.t = tokens
        self.i = 0
        self.c = context

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else (None, None)

    def take(self, value=None):
        tok = self.peek()
        if value is not None and tok[1] != value:
            raise AssertionError(f"expected {value!r}, got {tok[1]!r}")
        self.i += 1
        return tok

    def run(self):
        v = self.or_()
        if self.i != len(self.t):
            raise AssertionError(f"trailing tokens: {self.t[self.i:]}")
        return v

    def or_(self):
        v = self.and_()
        while self.peek()[1] == "||":
            self.take()
            rhs = self.and_()
            v = v if _truthy(v) else rhs
        return v

    def and_(self):
        v = self.cmp()
        while self.peek()[1] == "&&":
            self.take()
            rhs = self.cmp()
            v = rhs if _truthy(v) else v
        return v

    def cmp(self):
        v = self.unary()
        while self.peek()[1] in ("==", "!=", "<", ">", "<=", ">="):
            op = self.take()[1]
            rhs = self.unary()
            if op == "==":
                v = _equal(v, rhs)
            elif op == "!=":
                v = not _equal(v, rhs)
            else:
                a, b = _number(v), _number(rhs)
                v = {"<": a < b, ">": a > b, "<=": a <= b, ">=": a >= b}[op]
        return v

    def unary(self):
        if self.peek()[1] == "!":
            self.take()
            return not _truthy(self.unary())
        return self.primary()

    def primary(self):
        kind, value = self.take()
        if kind == "str":
            return value[1:-1].replace("''", "'")
        if kind == "num":
            return float(value)
        if value == "(":
            v = self.or_()
            self.take(")")
            return v
        if kind != "name":
            raise AssertionError(f"unexpected token {value!r}")
        if value in ("true", "false"):
            return value == "true"
        if value == "null":
            return None
        if self.peek()[1] == "(":
            return self.call(value)
        if value not in self.c:
            raise AssertionError(f"unknown context {value!r}")
        v = self.c[value]
        path = value
        while self.peek()[1] == ".":
            self.take()
            key = self.take()[1]
            path += "." + key
            if isinstance(v, dict):
                # An undeclared path is unknown, never absent: it fails.
                if key not in v:
                    raise AssertionError(f"context path {path} is not modelled")
                v = v[key]
            elif v is not None:
                raise AssertionError(f"context path {path} reads into a scalar")
        return v

    def call(self, name):
        self.take("(")
        args = []
        while self.peek()[1] != ")":
            args.append(self.or_())
            if self.peek()[1] == ",":
                self.take()
        self.take(")")
        if name == "always":
            return True
        if name == "startsWith":
            return str(args[0] or "").lower().startswith(str(args[1] or "").lower())
        if name == "fromJSON":
            import json

            return json.loads(args[0])
        raise AssertionError(f"function {name!r} is outside this check's subset")


def evaluate(expr, context):
    expr = expr.strip()
    m = re.fullmatch(r"\$\{\{(.*)\}\}", expr, re.S)
    if m:
        expr = m.group(1)
    elif "${{" in expr:
        raise AssertionError(f"mixed literal and expression: {expr!r}")
    return _Eval(_tokens(expr), context).run()


def runs(job, context):
    return job["if"] is None or _truthy(evaluate(job["if"], context))


def labels(job, context):
    value = job["runs-on"].strip()
    if value.startswith("${{"):
        out = evaluate(value, context)
    elif value.startswith("[") and value.endswith("]"):
        out = [v.strip().strip("'\"") for v in value[1:-1].split(",") if v.strip()]
    elif value.startswith("{") or "${{" in value:
        raise AssertionError(f"runner selection outside this check's subset: {value!r}")
    else:
        out = value.strip("'\"")
    if isinstance(out, str):
        out = [out]
    if not isinstance(out, list) or not all(isinstance(label, str) for label in out):
        raise AssertionError(f"runner selection is not a label list: {out!r}")
    return out


def pr_workflows():
    """(path, the PR triggers it declares, its jobs) for every PR-triggered workflow."""
    for path in sorted(WORKFLOWS.glob("*.y*ml")):
        text = path.read_text()
        declared = triggers(text) & PR_TRIGGERS
        if declared:
            yield path, sorted(declared), jobs(text)


def fork_runs(head_repo="someone/oneiron-fork", draft=False):
    """(workflow, job, labels) for every job a fork PR event reaches."""
    reached = []
    for path, declared, found in pr_workflows():
        for event_name in declared:
            context = _event(head_repo, draft=draft, event_name=event_name)
            for job_id, job in found.items():
                if runs(job, context):
                    reached.append((path.name, job_id, labels(job, context)))
    return reached


def _hook(event, repository=REPO):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "event.json"
        if event is not None:
            path.write_text(json.dumps(event))
        env = {**os.environ, "GITHUB_EVENT_PATH": str(path), "GITHUB_REPOSITORY": repository}
        return subprocess.run(["bash", str(HOOK)], env=env, capture_output=True, text=True).returncode


class RunnerHookTests(unittest.TestCase):
    """The boundary: the runner refuses a fork PR job before its first step."""

    def pr(self, head):
        return {"action": "opened", "pull_request": {"head": {"repo": head and {"full_name": head}}}}

    def test_fork_pull_request_events_are_refused(self):
        self.assertEqual(_hook(self.pr("someone/oneiron-fork")), 1)
        # pull_request_review and pull_request_target payloads carry the PR too.
        self.assertEqual(_hook({"review": {}, **self.pr("someone/oneiron-fork")}), 1)
        # A deleted fork has no head repo.
        self.assertEqual(_hook(self.pr(None)), 1)
        self.assertEqual(_hook({"pull_request": None}), 1)

    def test_unreadable_event_payload_is_refused(self):
        self.assertEqual(_hook(None), 1)

    def test_in_repo_pull_requests_and_trusted_events_run(self):
        self.assertEqual(_hook(self.pr(REPO)), 0)
        self.assertEqual(_hook(self.pr(REPO.upper())), 0)
        self.assertEqual(_hook({"ref": "refs/heads/main", "before": "0" * 40}), 0)
        self.assertEqual(_hook({"schedule": "0 18 * * *"}), 0)
        self.assertEqual(_hook({"inputs": {}}), 0)

    def test_installer_wires_the_hook_outside_the_checkout(self):
        home = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, home, ignore_errors=True)
        runner = home / "actions-runner"
        runner.mkdir()
        # An installed, registered runner: the script downloads and registers nothing.
        (runner / "config.sh").write_text("#!/bin/sh\nexit 1\n")
        (runner / "config.sh").chmod(0o755)
        (runner / ".runner").write_text("{}")
        done = subprocess.run(
            ["bash", str(INSTALLER), "test-runner", "self-hosted,linux,x64", "linux-x64", str(home / "target")],
            env={**os.environ, "HOME": str(home)},
            capture_output=True,
            text=True,
        )
        self.assertEqual(done.returncode, 0, done.stderr)
        env = (runner / ".env").read_text().splitlines()
        hook = runner / "job-started.sh"
        self.assertIn(f"ACTIONS_RUNNER_HOOK_JOB_STARTED={hook}", env)
        self.assertEqual(hook.read_bytes(), HOOK.read_bytes())
        self.assertTrue(os.access(hook, os.X_OK))


class ForkRunnerTests(unittest.TestCase):
    """The routing: an unchanged workflow sends a fork PR to hosted runners."""

    def test_fork_pr_jobs_name_only_hosted_runners(self):
        reached = fork_runs()
        self.assertTrue(reached, "a fork PR runs no job at all")
        persistent = [r for r in reached if not all(l.lower() in HOSTED_LABELS for l in r[2])]
        self.assertEqual(persistent, [], "fork PR jobs that may land on a persistent runner")

    def test_deleted_fork_head_is_treated_as_a_fork(self):
        persistent = [r for r in fork_runs(head_repo=None) if not all(l.lower() in HOSTED_LABELS for l in r[2])]
        self.assertEqual(persistent, [])

    def test_fork_pr_still_runs_the_required_contexts(self):
        # A skipped job reports success on a required check, so a fork PR must
        # run the required contexts on its hosted runner, not skip them.
        found = jobs((WORKFLOWS / "ci.yml").read_text())
        fork = _event("someone/oneiron-fork")
        for job_id in REQUIRED_CI_JOBS:
            self.assertTrue(runs(found[job_id], fork), job_id)

    def test_in_repo_pr_and_main_push_keep_the_self_hosted_runners(self):
        found = jobs((WORKFLOWS / "ci.yml").read_text())
        for context in (_event(REPO), _push()):
            for job_id in REQUIRED_CI_JOBS:
                self.assertTrue(runs(found[job_id], context), job_id)
                self.assertEqual(labels(found[job_id], context), ["self-hosted", "linux", "x64"], job_id)

    def test_draft_prs_still_skip_every_job(self):
        self.assertEqual(fork_runs(draft=True), [])


class LintFailsClosedTests(unittest.TestCase):
    """Workflow text the lint cannot model fails it; it never reads as safe."""

    def test_quoted_and_flow_triggers_are_read_or_refused(self):
        self.assertEqual(triggers('on: ["pull_request"]\njobs:\n'), {"pull_request"})
        self.assertEqual(triggers("'on':\n    'pull_request':\n      types: [opened]\n"), {"pull_request"})
        with self.assertRaises(AssertionError):
            triggers("on: {pull_request: {}}\n")

    def test_unmodelled_state_and_runner_forms_are_refused(self):
        fork = _event("someone/oneiron-fork")
        dependent = {"if": "needs.changes.result == 'success'", "runs-on": "[self-hosted]"}
        with self.assertRaises(AssertionError):
            runs(dependent, fork)
        with self.assertRaises(AssertionError):
            runs({"if": "failure()", "runs-on": "[self-hosted]"}, fork)
        with self.assertRaises(AssertionError):
            labels({"if": None, "runs-on": "{group: persistent}"}, fork)

    def test_target_event_and_bare_labels_are_caught(self):
        target = _event("someone/oneiron-fork", event_name="pull_request_target")
        job = {"if": "github.event_name == 'pull_request_target'", "runs-on": "[linux, x64]"}
        self.assertTrue(runs(job, target))
        self.assertFalse(all(l.lower() in HOSTED_LABELS for l in labels(job, target)))


if __name__ == "__main__":
    unittest.main()
