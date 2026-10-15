#!/bin/bash
# Self-hosted runner job-started hook (F32). install-runner.sh copies it into
# the runner directory and names it in ACTIONS_RUNNER_HOOK_JOB_STARTED, so it
# runs on the runner before any step of every job, outside anything a pull
# request can edit. A job whose event carries a pull request from another
# repository is refused: a fork's code never runs on a persistent runner, even
# when the fork edits a workflow to ask for one. A non-zero exit fails the job
# before it starts; an unreadable event payload is refused too.
set -u
exec python3 - "${GITHUB_EVENT_PATH:-}" "${GITHUB_REPOSITORY:-}" <<'PY'
import json
import sys

path, repository = sys.argv[1], sys.argv[2]
try:
    with open(path, encoding="utf-8") as handle:
        event = json.load(handle)
except (OSError, ValueError):
    print("::error::self-hosted runner: no readable event payload; job refused")
    sys.exit(1)
if not isinstance(event, dict) or "pull_request" not in event:
    sys.exit(0 if isinstance(event, dict) else 1)
pull_request = event["pull_request"]
head = None
if isinstance(pull_request, dict):
    repo = (pull_request.get("head") or {}).get("repo") or {}
    head = repo.get("full_name") if isinstance(repo, dict) else None
if not repository or not isinstance(head, str) or head.lower() != repository.lower():
    print("::error::self-hosted runner: a pull request from a fork never runs here; job refused")
    sys.exit(1)
PY
