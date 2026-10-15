"""Fork pull requests never reach a persistent self-hosted runner (F32, H313/H330).

Each workflow with a pull_request trigger is read, and every job's `if` and
`runs-on` are evaluated under a fork PR event. A job that runs must land on a
GitHub-hosted runner; the required contexts must still run (a skipped job
reports success on a required check). In-repo PRs and main pushes keep the
self-hosted runners.

The workflows are read with a small line parser for the subset they use and
the expressions with a small evaluator, so the check needs no PyYAML. Anything
outside that subset fails the test rather than passing it.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github/workflows"
PR_TRIGGERS = {"pull_request", "pull_request_target"}
REPO = "oneiron-dev/oneiron"
# ci.yml's required contexts on main and the job they need.
REQUIRED_CI_JOBS = ("changes", "checks", "test-linux", "test-linux-featureless")


def _event(head_repo, draft=False):
    return {
        "github": {
            "event_name": "pull_request",
            "repository": REPO,
            "ref": "refs/pull/1/merge",
            "event": {"pull_request": {"draft": draft, "head": {"repo": {"full_name": head_repo}}}},
        },
        "vars": {},
        "inputs": {},
        "needs": {},
    }


def _push():
    return {
        "github": {"event_name": "push", "repository": REPO, "ref": "refs/heads/main", "event": {}},
        "vars": {},
        "inputs": {},
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


def triggers(text):
    lines = _significant(text)
    for i, line in enumerate(lines):
        m = re.match(r"^(on|\"on\"|'on'):\s*(.*)$", line)
        if not m:
            continue
        inline = m.group(2).strip()
        if inline:
            return {t.strip() for t in inline.strip("[]").split(",") if t.strip()}
        names = set()
        for child in lines[i + 1 :]:
            if _indent(child) == 0:
                break
            if _indent(child) == 2:
                names.add(child.strip().split(":", 1)[0])
        return names
    raise AssertionError("no `on:` block")


def jobs(text):
    """{job id: {"if": str | None, "runs-on": str}} for the top-level `jobs:` map."""
    lines = _significant(text)
    start = next(i for i, l in enumerate(lines) if l.rstrip() == "jobs:")
    found = {}
    current = None
    i = start + 1
    while i < len(lines):
        line = lines[i]
        if _indent(line) == 0:
            break
        if _indent(line) == 2:
            current = line.strip().rstrip(":")
            found[current] = {"if": None, "runs-on": None}
            i += 1
            continue
        if _indent(line) == 4 and current is not None:
            key = line.strip().split(":", 1)[0]
            if key in ("if", "runs-on"):
                value, i = _block_value(lines, i, 4)
                found[current][key] = value
                continue
            if key == "uses":
                raise AssertionError(f"job {current}: reusable workflows are outside this check's subset")
        i += 1
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
        while self.peek()[1] == ".":
            self.take()
            key = self.take()[1]
            v = v.get(key) if isinstance(v, dict) else None
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
        if name == "cancelled":
            return False
        if name in ("success", "failure"):
            return name == "success"
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
    elif value.startswith("["):
        out = [v.strip().strip("'\"") for v in value.strip("[]").split(",") if v.strip()]
    else:
        out = value.strip("'\"")
    return [out] if isinstance(out, str) else list(out)


def pr_workflows():
    for path in sorted(WORKFLOWS.glob("*.y*ml")):
        text = path.read_text()
        if triggers(text) & PR_TRIGGERS:
            yield path, jobs(text)


class ForkRunnerTests(unittest.TestCase):
    def test_fork_pr_jobs_never_select_a_self_hosted_runner(self):
        fork = _event("someone/oneiron-fork")
        reached = []
        for path, found in pr_workflows():
            for job_id, job in found.items():
                if runs(job, fork):
                    reached.append((path.name, job_id, labels(job, fork)))
        self.assertTrue(reached, "a fork PR runs no job at all")
        on_self_hosted = [r for r in reached if "self-hosted" in r[2]]
        self.assertEqual(on_self_hosted, [], "fork PR jobs on a persistent self-hosted runner")

    def test_deleted_fork_head_is_treated_as_a_fork(self):
        gone = _event(None)
        for path, found in pr_workflows():
            for job_id, job in found.items():
                if runs(job, gone):
                    self.assertNotIn("self-hosted", labels(job, gone), f"{path.name}:{job_id}")

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
        draft = _event("someone/oneiron-fork", draft=True)
        for path, found in pr_workflows():
            for job_id, job in found.items():
                self.assertFalse(runs(job, draft), f"{path.name}:{job_id}")


if __name__ == "__main__":
    unittest.main()
