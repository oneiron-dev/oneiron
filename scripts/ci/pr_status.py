#!/usr/bin/env python3
"""Publish trusted required commit statuses; never check out a fork in this job.

Runs in the base-owned pull_request_target workflow or on a main push,
on a hosted runner. A fork cannot obtain this GitHub App's status token.
"""

import json
import os
import re
import sys
from pathlib import Path
from urllib.request import Request, urlopen


REPOSITORY = "oneiron-dev/oneiron"


def desired_states(event, stage, checks_result=None, test_result=None):
    if stage not in {"admission", "completion"}:
        raise ValueError("unknown PR status stage")
    if "pull_request" in event:
        head = event["pull_request"]["head"]
        if (head.get("repo") or {}).get("full_name") != REPOSITORY:
            return {"Checks": "failure", "Test": "failure"}
        if stage == "admission":
            return {"Checks": "pending", "Test": "pending"}
    elif event.get("ref") != "refs/heads/main" or stage != "completion":
        raise ValueError("only main pushes can publish non-PR statuses")
    return {
        "Checks": "success" if checks_result == "success" else "failure",
        "Test": "success" if test_result == "success" else "failure",
    }


def publish(event, stage, checks_result=None, test_result=None):
    kind = os.environ["GITHUB_EVENT_NAME"]
    if kind not in {"pull_request_target", "push"}:
        raise ValueError("status publishing requires a trusted event")
    if os.environ["GITHUB_REPOSITORY"] != REPOSITORY:
        raise ValueError("unexpected repository")
    if kind == "pull_request_target":
        pr = event["pull_request"]
        head_sha = pr["head"]["sha"]
        merge_sha = pr.get("merge_commit_sha")
        shas = list(dict.fromkeys(sha for sha in (merge_sha, head_sha) if sha))
    elif event.get("ref") == "refs/heads/main" and stage == "completion":
        pr = None
        shas = [event["after"]]
    else:
        raise ValueError("only main pushes can publish non-PR statuses")
    if not shas or any(not re.fullmatch(r"[a-f0-9]{40}", sha) for sha in shas):
        raise ValueError("invalid PR commit SHA")
    token = os.environ["GITHUB_TOKEN"]
    states = desired_states(event, stage, checks_result, test_result)
    # GitHub may require statuses on the test-merge commit instead of the head.
    # Mark the merge commit FIRST: it is the one an attacker can give skipped
    # success check runs by changing a PR-sourced workflow.
    for sha in shas:
        for context, state in states.items():
            payload = json.dumps({
                "context": context,
                "state": state,
                "description": (
                    "Fork PR: promote to an internal branch for testing"
                    if state == "failure" and pr is not None and (pr["head"].get("repo") or {}).get("full_name") != REPOSITORY
                    else f"Trusted CI {stage}: {state}"
                ),
            }).encode()
            request = Request(
                f"https://api.github.com/repos/{REPOSITORY}/statuses/{sha}",
                data=payload,
                headers={
                    "Accept": "application/vnd.github+json",
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                method="POST",
            )
            with urlopen(request, timeout=20) as response:
                if response.status != 201:
                    raise RuntimeError("GitHub did not create a commit status")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: pr_status.py admission|completion")
    publish(
        json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text()),
        sys.argv[1],
        os.environ.get("CHECKS_RESULT"),
        os.environ.get("TEST_RESULT"),
    )
