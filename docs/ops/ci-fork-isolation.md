# Fork PR admission on persistent runners

Do **not** merge the workflow change or approve a fork run until the organization
runner group is active and every repository-scoped runner is removed. A job-level
`if` alone is not a trust boundary: a fork can change its submitted workflow.

## Organization setting to apply

Organization admin access (`admin:org` and organization self-hosted-runner
management permission) is required. The current writer account gets HTTP 403
from `GET /orgs/oneiron-dev/actions/runner-groups`. The policy file
`scripts/ci/trusted-runner-group.json` pins all seven workflows to
`@refs/heads/main`, limits access to this public repository, and permits public
repository use explicitly. Verify its repository id against
`gh api repos/oneiron-dev/oneiron --jq .id` (currently `1113618625`). Create it:

```sh
gh api --method POST /orgs/oneiron-dev/actions/runner-groups \
  --input scripts/ci/trusted-runner-group.json
```

If a group with this name exists already, inspect its ID and use `PATCH`
instead; do not create a second unrestricted group. Verify the returned
`restricted_to_workflows: true`, `visibility: selected`,
`allows_public_repositories: true`, exact `selected_repository_ids`, and exact
`selected_workflows` from the policy file. The policy must not allow a PR
merge ref or any wildcard workflow/ref. These server-side restrictions must
be in force before trusting the YAML job guards.

All MacBook, Mac mini, Arch and cloud runners must be **organization** runners
in `oneiron-trusted`, not repository runners and not in an unrestricted
organization/enterprise group accessible to this repository. For each host,
stop its service, remove the old repository registration using its existing
`./config.sh remove` command and a fresh repository removal token, then get an
organization registration token from
`gh api --method POST /orgs/oneiron-dev/actions/runners/registration-token`.
Pass that short-lived token only in the environment to
`scripts/ci/install-runner.sh`; it now registers at
`https://github.com/oneiron-dev --runnergroup oneiron-trusted` and refuses an
existing repository registration. Do not paste or commit registration tokens.
Check `GET /orgs/oneiron-dev/actions/runner-groups/{group_id}/runners` for all
expected hosts, and `GET /repos/oneiron-dev/oneiron/actions/runners` plus the
organization runner inventory for any old unrestricted registration. Remove
old registrations rather than leaving them offline; an offline runner can be
restarted later. A runner left reachable outside this group invalidates the
isolation claim.

## Required-check source setting to apply

Create a dedicated GitHub App owned by `oneiron-dev` with **Commit statuses:
Read and write** and no other repository write permissions. Install it only
on `oneiron-dev/oneiron`. Put its ID in repository secret
`ONEIRON_CI_STATUS_APP_ID` and its private key in
`ONEIRON_CI_STATUS_APP_PRIVATE_KEY` (for example with `gh secret set
ONEIRON_CI_STATUS_APP_ID -R oneiron-dev/oneiron -b "$APP_ID"` and
`gh secret set ONEIRON_CI_STATUS_APP_PRIVATE_KEY -R oneiron-dev/oneiron <
/path/to/private-key.pem` on the admin host; never put the key in the repo or
this workpad). GitHub App creation/installation and secret provisioning
require org/repo admin authority; this writer has not performed them.

Pin the existing `main` ruleset's **two** required contexts to that App's
numeric ID. This is essential: a PR-sourced Actions job can forge the name
`Checks` or `Test` on a hosted runner, but it cannot forge a commit status
from a different required App. When `pull_request_target` does not fire (for
example, a SHA-like fork branch name), the App statuses are **absent**, so
the merge remains blocked. Do not pin these contexts to the GitHub Actions
App itself. Generate the update payload from the **current** live ruleset,
which preserves its other rules and refuses unexpected required contexts:

```sh
gh api repos/oneiron-dev/oneiron/rulesets/22633759 > /tmp/ci-fork-current-ruleset.json
python3 scripts/ci/pin_status_app.py "$APP_ID" < /tmp/ci-fork-current-ruleset.json \
  > /tmp/ci-fork-pinned-ruleset.json
gh api --method PUT /repos/oneiron-dev/oneiron/rulesets/22633759 \
  --input /tmp/ci-fork-pinned-ruleset.json
```

Read back with `gh api repos/oneiron-dev/oneiron/rulesets/22633759` and
verify `required_status_checks` contains exactly `Checks` and `Test`, each
with `integration_id` equal to the dedicated App's ID. This is a separate
server-side enforcement setting from the runner-group policy. The App also
reports real Checks/Test results for main pushes so the source pin does not
strand main.

## PR results and acceptance

`pull_request_target` runs the base-branch workflow. Its GitHub-hosted admission
job never checks out a fork. It posts `failure` commit statuses for **both**
required contexts `Checks` and `Test` on a fork head **and** its test-merge SHA
when available: GitHub can evaluate required checks on the merge commit rather
than the head. This does not rely on skipped Actions jobs (which GitHub calls
successful). For an internal PR it posts `pending` to the same SHAs; the
GitHub-hosted completion job posts `success` only after the real Checks/Test
jobs succeed, and `failure` otherwise. These statuses
use the read-only checkout of the base commit and a short-lived installation
token with only commit-status write permission; PR build jobs receive only
`contents: read`. The runner group restricts which workflow *refs* may
select persistent runners independently of any workflow
text a fork submits. A maintainer tests fork code by pushing it to an internal
branch and opening an internal PR; no fork code is checked out by admission.

After the settings are applied, verify with an approved disposable fork PR
that changes `.github/workflows/ci.yml` to add a self-hosted job and removes
the local guard. Confirm no job from its `refs/pull/*/merge` workflow allocates
an organization runner. Confirm the trusted target admission posts `failure`
statuses from the dedicated App on the fork's head and test-merge SHAs for both
`Checks` and `Test`, and that the required ruleset does **not** permit merging.
Repeat with a SHA-like fork branch name: if admission does not fire, required
App statuses must be absent and merging must still be denied. Separately,
open an internal PR and verify it runs the real jobs against the merge ref and
reports success only
when both pass; verify a `main` push retains the existing checks. Keep the
branch unmerged until this server-side acceptance has been witnessed. The
Python fixture tests are a local policy simulation, not proof that the live
runner-group setting exists.
