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
# later `always()` steps and action pre-entrypoints. So a refusal, or any error
# while reading the event, SIGKILLs the Runner.Worker running this job before
# anything else is dispatched. The worker launches this script directly and
# it execs Python, so the worker is Python's parent: no lookup can fail.
set -u
exec python3 - "${GITHUB_EVENT_PATH:-}" "${GITHUB_REPOSITORY:-}" "${GITHUB_EVENT_NAME:-}" <<'PY'
import json
import os
import signal
import sys

WORKER = os.getppid()


def refuse(reason):
    try:
        print(f"::error::self-hosted runner: {reason}; job refused", flush=True)
    finally:
        if WORKER > 1:
            os.kill(WORKER, signal.SIGKILL)
        sys.exit(1)


def admit(path, repository, event_name):
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
        return
    pull_request = event["pull_request"]
    head = pull_request.get("head") if isinstance(pull_request, dict) else None
    repo = head.get("repo") if isinstance(head, dict) else None
    name = repo.get("full_name") if isinstance(repo, dict) else None
    if not repository or not isinstance(name, str) or name.lower() != repository.lower():
        refuse("a pull request from a fork never runs here")


try:
    admit(*sys.argv[1:4])
except SystemExit:
    raise
except BaseException:
    refuse("the job-started hook failed")
PY
