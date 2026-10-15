#!/bin/bash
# Self-hosted runner job-started hook (F32). install-runner.sh copies it into
# the runner directory and names it in ACTIONS_RUNNER_HOOK_JOB_STARTED, so it
# runs on the runner before any step of every job, outside anything a pull
# request can edit. A job whose event carries a pull request from another
# repository is refused: a fork's code never runs on a persistent runner, even
# when the fork edits a workflow to ask for one. Merge-queue runs and
# unreadable payloads are refused too.
#
# A failed hook alone only marks the job failed; the runner still dispatches
# later `always()` steps and action pre-entrypoints. So a refusal SIGKILLs the
# Runner.Worker process running this job before anything else is dispatched.
set -u
exec python3 - "${GITHUB_EVENT_PATH:-}" "${GITHUB_REPOSITORY:-}" "${GITHUB_EVENT_NAME:-}" <<'PY'
import json
import os
import signal
import subprocess
import sys

path, repository, event_name = sys.argv[1], sys.argv[2], sys.argv[3]


def worker():
    """The nearest Runner.Worker ancestor of this hook, if any."""
    pid = os.getppid()
    for _ in range(16):
        if pid <= 1:
            return None
        out = subprocess.run(
            ["ps", "-o", "ppid=", "-o", "comm=", "-p", str(pid)],
            capture_output=True,
            text=True,
        ).stdout.strip()
        if not out:
            return None
        ppid, _, comm = out.partition(" ")
        if os.path.basename(comm.strip()) == "Runner.Worker":
            return pid
        pid = int(ppid)
    return None


def refuse(reason):
    print(f"::error::self-hosted runner: {reason}; job refused")
    sys.stdout.flush()
    target = worker()
    if target is not None:
        os.kill(target, signal.SIGKILL)
    sys.exit(1)


try:
    with open(path, encoding="utf-8") as handle:
        event = json.load(handle)
except (OSError, ValueError):
    refuse("no readable event payload")
if not isinstance(event, dict):
    refuse("no readable event payload")
if event_name == "merge_group" or "merge_group" in event:
    refuse("a merge-queue run may carry fork changes")
if "pull_request" not in event:
    if event_name.startswith("pull_request"):
        refuse("a pull request event without its pull request")
    sys.exit(0)
pull_request = event["pull_request"]
head = pull_request.get("head") if isinstance(pull_request, dict) else None
repo = head.get("repo") if isinstance(head, dict) else None
name = repo.get("full_name") if isinstance(repo, dict) else None
if not repository or not isinstance(name, str) or name.lower() != repository.lower():
    refuse("a pull request from a fork never runs here")
PY
