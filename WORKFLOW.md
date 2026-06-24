---
tracker:
  kind: linear
  # Create a Linear project "Oneiron Autopilot" in the Oneiron team
  # and drop autopilot-eligible tickets there. Symphony filters by
  # project_slug; the agent additionally requires the `autopilot` label
  # at pre-flight (defense in depth — project membership = "execute now",
  # label = "passes pre-flight safety").
  project_slug: "oneiron-autopilot-bc290f043ea7"
  active_states:
    - Backlog
    - Todo
    - In Progress
    - In Review
  terminal_states:
    - Done
    - Cancelled
    - Canceled
    - Duplicate
polling:
  # 30s was too aggressive — each respawn of a settle-window-exiting agent
  # still costs the GraphQL fetch in step 7.0 (~1-2k tokens). 2 min is
  # the sweet spot: idle PRs stop burning, new Backlog tickets still
  # pick up within 2 min of being labeled.
  interval_ms: 120000
workspace:
  # Nest under .worktrees/symphony so autopilot dirs don't intermix with
  # manual worktrees. Symphony creates one subdir per ticket identifier.
  root: ~/code/oneiron/.worktrees/symphony
hooks:
  # Each new workspace becomes a git worktree off main, branched per ticket.
  # The worktree shares the object DB with /home/lexi/code/oneiron, so no
  # heavy clone, no extra disk.
  after_create: |
    set -euo pipefail
    # Symphony runs hooks with cwd=workspace, no Liquid templating in
    # front matter, no env vars injected. Derive the ticket id from PWD's
    # basename (Symphony names the dir after issue.identifier).
    WS="$PWD"
    TICKET="$(basename "$WS")"
    BRANCH="symphony/$(echo "$TICKET" | tr '[:upper:]' '[:lower:]')"
    cd /home/lexi/code/oneiron
    git fetch origin main
    # Symphony pre-creates the empty workspace dir. git worktree add needs
    # the path to either not exist or be a worktree. Drop the empty dir.
    rmdir "$WS" 2>/dev/null || true
    if ! git show-ref --verify --quiet "refs/heads/$BRANCH"; then
      git worktree add -b "$BRANCH" "$WS" origin/main
    else
      git worktree add "$WS" "$BRANCH"
    fi
  before_remove: |
    set -euo pipefail
    WS="$PWD"
    cd /home/lexi/code/oneiron
    git worktree remove --force "$WS" 2>/dev/null || true
agent:
  max_concurrent_agents: 8
  # No max_turns — the user has generous Codex quota and the prompt-level
  # guards (forbidden surfaces, gate checks) bound blast radius.
codex:
  # Bypass + multi_agent matches the user's normal invocation pattern.
  # Symphony talks to Codex via the app-server protocol and sends sandbox
  # config per turn — the CLI flag is a no-op under app-server, so the
  # thread_sandbox + turn_sandbox_policy below are what actually take
  # effect. Both set to full access because Symphony worktrees need to
  # write to /home/lexi/code/oneiron/.git/worktrees/<id>/ for git ops
  # (commit, push) which sits outside the per-issue workspace dir. The
  # forbidden-surface grep in step 4 is now the ONLY automated guard
  # between the agent and main. Keep it strict.
  command: codex --dangerously-bypass-approvals-and-sandbox --enable multi_agent --config shell_environment_policy.inherit=all --config 'model="gpt-5.5"' --config model_reasoning_effort=xhigh app-server
  approval_policy: never
  thread_sandbox: danger-full-access
  turn_sandbox_policy:
    type: dangerFullAccess
env:
  LINEAR_API_KEY:
    secret_command: skate get linear_api_token
---

## Style

Caveman mode for all chat output (drop articles, fragments OK, fewer tokens).
Code/commits/PRs/Linear comments stay normal English. If invoking the
`caveman:caveman` skill is available in this Codex session, do so on first
turn; otherwise apply the rules manually.

You are working on Linear ticket `{{ issue.identifier }}` in
`/home/lexi/code/oneiron` (greenfield Rust workspace, single-user). Codex is
running with `--dangerously-bypass-approvals-and-sandbox` — there is no
filesystem sandbox layer. Only touch files inside the worktree at
`/home/lexi/code/oneiron/.worktrees/symphony/{{ issue.identifier }}`. Do
not edit `/home/lexi/code/oneiron` (the main worktree),
`/home/lexi/code/eiri-docs` (read-only reference), or anything else
under `~/`. The forbidden-surface grep in step 4 is the only automated
guard; keep it tight.

## Issue context

- **Identifier:** `{{ issue.identifier }}`
- **Title:** {{ issue.title }}
- **Status:** {{ issue.state }}
- **Labels:** {{ issue.labels }}
- **URL:** {{ issue.url }}

### Description

{% if issue.description %}
{{ issue.description }}
{% else %}
(no description)
{% endif %}

## 0. Pre-flight gate (FAIL CLOSED)

Before any other action, verify ALL of the following. If any fails, post one
Linear comment explaining which check failed, leave the ticket in its current
state, and exit.

- [ ] The ticket's `project` is `Oneiron Autopilot` AND `autopilot` is in
      its label set. Both must hold — project membership alone is not
      enough. If either is missing, the ticket was routed here by mistake;
      exit immediately.
- [ ] The ticket description specifies the file path(s) and the change shape
      concretely (one or two paragraphs at most). If the description is vague,
      open-ended, or asks for a design decision, exit and ask for clarification.
- [ ] You are in `/home/lexi/code/oneiron/.worktrees/symphony/{{ issue.identifier }}` (Symphony preserves identifier case).

## 1. Plan (read before writing)

Read the source files the ticket names. Read the closest existing test file in
the same module. Read the most recent commit that touched the same area
(`git log -p -1 -- <path>`).

Reference docs at `/home/lexi/code/eiri-docs/` are read-only. Consult them for
architecture context only when the ticket explicitly requires it.

Write the plan as a single Linear comment on the ticket (use `linear` skill).
Format:

```
## Plan
- File(s): <list>
- Change shape: <one paragraph>
- Test: <new test name + assertion shape>
- Verification: <commands>
- Forbidden-surface check: <which to grep>
```

Move ticket: `Backlog`/`Todo` → `In Progress`.

## 2. Implement

Make the surgical change. NO scope creep. The forbidden surfaces below are
hard-fail; if the ticket genuinely requires touching one, exit and reclassify
the ticket as not autopilot-safe (move to `Human Review`, comment why).

### Forbidden surfaces (HARD FAIL)

The following changes ARE NOT permitted under autopilot, ever:

- Bumping schema version constants:
  `ANALYZER_VERSION`, `BM25_FIELD_SCHEMA_VERSION`, `TEXT_INDEX_SCHEMA_VERSION_KEY`,
  any `*_VERSION` const in `crates/oneiron/src/`
- `Cargo.toml` dependency adds, removes, version bumps, feature flag toggles
- `deny.toml` allowlist edits
- `.gitignore` edits
- `WORKFLOW.md` edits (this file)
- `.claude/` config edits
- Public API renames or removals (anything in `pub` declarations under
  `crates/oneiron/src/lib.rs` or `crates/oneiron-napi/src/lib.rs`)
- Test deletions (you may add or modify tests, never delete)
- Cross-crate edits (touching more than one of: `oneiron`, `oneiron-napi`,
  `oneiron-server`, `oneiron-ffi`, `oneiron-bench`)

If the ticket needs any of the above, exit with `Human Review` state and a
comment explaining which forbidden surface is required.

**Override mechanism.** If the ticket description contains an
`## AUTOPILOT_OVERRIDE` block listing one or more forbidden surfaces, the
agent MAY touch the listed surfaces for this ticket only — but only those
listed, and only the change shape spelled out in the rest of the ticket.
The agent must still escalate to `Human Review` if a forbidden surface is
required AND not listed in `AUTOPILOT_OVERRIDE`.

### Toolchain commands

Use `rtk proxy` for cargo (token-optimized wrapper). cargo-nextest is the
canonical test runner (ONE-1144) — the default profile is the fast tier
(slow-tagged tests excluded; see `.config/nextest.toml`):

```bash
rtk proxy cargo build -p oneiron
rtk proxy cargo nextest run -p oneiron
rtk proxy cargo nextest run -p oneiron --features sync
rtk proxy cargo clippy --workspace --all-targets --all-features -- -D warnings
rtk proxy cargo fmt --all --check
```

Modern Rust idioms for agents: Oneiron tracks the pinned stable toolchain in
`rust-toolchain.toml`. Prefer newly stable standard-library affordances only
when they remove local noise; for example, import `assert_matches!` explicitly
in tests when it gives clearer enum/result failures. Avoid broad mechanical
rewrites during feature work.

Use the local skills already in this repo:
- `commit` skill — clean commits during implementation
- `push` skill — keep remote current

Commit message prefix: `<area>:` where area is one of:
`analyzer`, `analyzer/bm25`, `analyzer/manifest`, `analyzer/detect`,
`bm25`, `vault`, `pipeline`, `batch`, `maintain`, `napi`, `tests`, `docs`.

Body: one sentence describing the change, one mentioning `Closes {{ issue.identifier }}`.

### Build cache (sccache)

Agent worktrees cold-build ~340 crates before running a single test —
compile time, not test time, dominates agent wall-clock. Export the
per-machine compile cache for every cargo invocation in a fresh worktree:

```bash
export RUSTC_WRAPPER=sccache   # /opt/homebrew/bin/sccache on the dev Mac
```

This is opt-in per environment — do NOT hardcode it into
`.cargo/config.toml` (CI uses its own cache; not every machine has sccache).
If sccache misbehaves (rare ICE/cache errors), unset it and rebuild —
correctness over speed.

## 3. Self-review pass (Codex itself)

Re-read the diff (`git diff main...HEAD`) and check:

- Each change is required by the ticket (no opportunistic refactors)
- No forbidden surface was touched
- Tests cover the new behavior
- No `unwrap()` / `expect()` added in non-test code
- No `// TODO` / `// FIXME` left

Fix any issues. Repeat until self-review pass is clean.

## 4. Verification gate (HARD)

Run all of:

```bash
rtk proxy cargo nextest run --workspace --all-features --profile full
rtk proxy cargo test --doc --workspace --exclude oneiron-bench --all-features
rtk proxy cargo clippy --workspace --all-targets --all-features -- -D warnings
rtk proxy cargo fmt --all --check
rtk proxy env RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps
```

(`--profile full` includes the slow tier; nextest does not run doctests,
hence the separate `cargo test --doc` line.)

All must pass. If any fails, fix and repeat. If a failure is unrelated to your
change (pre-existing), exit with `Blocked` state, comment quoting the failure.

### Test gate (canonical, ONE-1144) + macOS LMDB note

cargo-nextest is the canonical runner everywhere (CI + local + agent
briefs). It runs each test in its own process, which structurally removes
the shared-process LMDB flake class (cumulative pthread-key pressure,
shared-env state) and reports passed-on-retry tests as FLAKY instead of
silently green. Profiles live in `.config/nextest.toml`.

Dev/agent fast loop (slow tier excluded):

```bash
cargo nextest run -p oneiron
cargo nextest run -p oneiron --features sync
```

FULL tier — required before every push (the workspace `--features sync`
flag is a silent no-op — always use `-p oneiron`):

```bash
cargo fmt -p oneiron -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo build
cargo build -p oneiron --features sync
cargo nextest run -p oneiron --profile full
cargo nextest run -p oneiron --features sync --profile full
```

LMDB tests can still flake under shared state (reader-slot exhaustion,
map-full, tempdir reuse). The ONLY acceptable fixes are isolation-shaped:

- one `tempfile::tempdir()` per test — never a shared vault directory;
- an adequate per-test `map_size` (the sync suites use 16 MiB) and
  `max_readers`.

NEVER fix a flake by weakening an assertion, widening a tolerance, deleting
a test, or adding `#[ignore]` without a ticket reference. Sync is the
GDPR/permanence surface: an assertion that flakes is telling you about
shared state, not about an over-strict expectation. If a genuine
order-dependence is found, fix the isolation and keep the assertion exact.

macOS note (ONE-1148, open): LMDB on macOS uses SysV semaphores whose key
keeps ~24 bits of lockfile inode — concurrent test vaults across processes
can collide system-wide, surfacing as env-level `Storage(Io(.. EINVAL(22)
..))` on `Vault::open` or write txns. This is orthogonal to nextest's
process isolation (the semaphore namespace is machine-global). Until
ONE-1148 lands: if a run shows env-level EINVAL(22) flakes, re-run serially
(`cargo nextest run -p oneiron --features sync --profile full -j 1`);
serial local runs are authoritative locally, Linux CI (robust mutexes,
unaffected) is authoritative overall.

Known cliff (ONE-1142, FIXED): the engine used to never close LMDB
environments, so every `Vault::open` leaked a pthread TLS key — at ~509
cumulative opens in one process, macOS (`PTHREAD_KEYS_MAX = 512`) failed
further opens with `Storage(Io(.. EAGAIN ..))`. The `OwnedEnv` close path
fixed this and `vault_open_drop_cycles_survive_pthread_key_limit` (slow
tier) guards the regression; verify suspected regressions by running the
failing test in isolation; do not weaken it.

### Forbidden-surface grep

After commit, run:

```bash
git diff main...HEAD -- ':!*.md' | grep -E '^\+.*(_VERSION|fn .* pub )' | head
git diff main...HEAD -- 'Cargo.toml' '*/Cargo.toml' 'deny.toml' '.gitignore'
```

If either has output, you violated a forbidden surface. Revert and exit
with `Human Review`.

## 5. Small bazooka — `scripts/review-pr.sh`

Run the cloud-reviewer harness once before opening the PR. This is the only
pre-PR cloud review pass; don't re-run on each fix iteration.

```bash
cd /home/lexi/code/oneiron/.worktrees/symphony/{{ issue.identifier }}
bash scripts/review-pr.sh
```

This drops findings under `.reviews/<branch>/run-1/`. Read every reviewer's
file. Triage findings using the `validate-reviews` skill — classify each as
**Fix / Follow-up / Dismissed**. Save triage as
`.reviews/<branch>/triage-r1.md`.

Fix every "Fix" item. For each "Follow-up", file a separate Linear ticket
(state: `Backlog`, label: leave blank, link `relatesTo: {{ issue.identifier }}`).

Re-run verification gate after fixes. Do NOT re-run `review-pr.sh`.

## 6. Open the PR

Push the branch. Open the PR with `gh pr create --title ... --body ...`:

- **Title** prefix matches the commit area (`analyzer:`, `bm25:`, etc.)
- **Body** sections:
  - `## Summary` — bullet list, what + why
  - `## Test plan` — bulleted checklist of what was verified
  - Closes `{{ issue.identifier }}`

PR is `--draft` initially. After verification gate green and small-bazooka
findings handled, mark `--ready` via `gh pr ready`.

Move ticket: `In Progress` → `In Review`.

In the PR body's footer, tag for re-review: `@claude @codex @greptile @coderabbitai`

## 7. Cloud-reviewer feedback loop

Watch for new comments. Use the `respond-reviews` skill flow.

### 7.0. Settle window (FAIL FAST IF NOT SETTLED)

Before classifying any threads, verify reviewers have stopped posting:

- Fetch the most recent comment timestamp from any thread on this PR by
  any of: `claude`, `codex`, `greptile`, `coderabbitai`, `copilot-pull-request-reviewer`,
  `augmentcode`, `claude-security`, `gemini-pull-request-reviewer`.
- If the newest cloud-reviewer comment is < 10 minutes old → **exit this
  turn SILENTLY**. Do NOT post a Linear comment. Leave the ticket state
  at `In Review`. Symphony will respawn this agent on its next poll; you
  will exit silently again until reviewers have settled. The night-watch
  cron also checks open PRs in sub-sweep A every 15 min and will pick up
  the work regardless.
- Only after 10 minutes of cloud-reviewer silence proceed to step 7.1.

**Do NOT post settle-status comments on Linear**. Repeated polling under
Symphony's active_states cycle would spam the ticket. Silent exit is the
contract.

### 7.1. Triage and respond

1. Fetch unresolved threads via the GraphQL pattern in `respond-reviews`.
2. Triage each comment using the Fix / Follow-up / Dismissed lens.
3. Skip grammar / typo / wording-only comments — reply once: "Doc nit,
   dismissed." Resolve the thread.
4. Fix substantive findings. Push a follow-up commit.
5. Reply to each thread with the per-classification template.
6. Post one Round-N summary comment with the per-classification breakdown.

### 7.2. Iteration cap

Repeat 7.0 → 7.1 until reviewers post only nits / dismissed-class comments
in two consecutive settle windows. NEVER move state to `Human Review` based
on a cloud-reviewer thread alone — threads are the agent's normal work.
Genuinely-beyond-scope findings: leave thread open, comment explaining why,
exit. State stays `In Review`. The watch loop will eventually escalate
after multiple stable ticks if the human needs to weigh in.

## 8. Auto-merge gate (ALL must hold)

Merge the PR ONLY when ALL of:

- [ ] CI green (`gh pr checks`)
- [ ] No open thread with severity P0 or P1 (only P2/P3 nits or resolved)
- [ ] No forbidden surface in the diff (`git diff main...$(gh pr view --json baseRefName --jq .baseRefName)`)
- [ ] Total commits on the branch ≤ 5 — OR ≤ 8 if EVERY commit beyond the
      first stays within the original files touched by the first commit
      AND introduces no new behavior area (i.e. all extras are
      reviewer-driven fixes inside the original scope). The per-file
      containment check: `git diff main...HEAD --name-only` must be a
      subset of the file list at the first commit. If unsure, escalate.

If all gates hold:

```bash
gh pr merge --merge --delete-branch
```

Move ticket: `In Review` → `Done`.

If any gate fails:

- Move ticket: `In Review` → `Human Review`
- Post a Linear comment listing which gate(s) failed
- Stop. Do not retry.

## Failure / blocker handling

| Situation | State | Action |
|---|---|---|
| Description vague (file paths missing, scope ambiguous) | `AI Review` | Comment naming what's missing, exit |
| Forbidden surface required (no AUTOPILOT_OVERRIDE) | `Human Review` | Comment why, exit |
| Verification gate red on first run, unrelated to your diff | `AI Review` | Comment quoting failure (the watch will rerun once before escalating) |
| Merge conflict on rebase | `AI Review` | Comment, exit (no auto-resolve by Codex; the watch will rebase if conflict is mechanical) |
| `review-pr.sh` errors out (auth expiry, etc.) | `AI Review` | Comment with which reviewer failed |
| Cross-crate edit required on a child ticket | `AI Review` | Comment which file forced the cross-crate hit; the watch may descope/split |
| > 5 commits to reach green | `Human Review` | Stop, let user inspect |
| Real correctness finding from cloud reviewer that you can't address in scope | `Human Review` | Leave PR open, comment, exit |

**Escalation tiers:**

- `AI Review` — mechanical recovery the night-watch loop can attempt: rebase, retrigger CI, re-run review-pr.sh, tighten description, descope cross-crate hits. The watch caps actions at 2 per ticket per 24h before promoting to `Human Review`.
- `Human Review` — needs the user's judgment: scope decisions, design tradeoffs, > 5-commit churn, forbidden surface needed but not justifiable.

NEVER:
- Force-push
- Skip hooks (`--no-verify`)
- Amend a published commit
- Re-base interactively
- Touch `main` directly
- Merge a PR with open P0/P1 review threads
- Touch a forbidden surface, even if "the ticket really seems to need it"

## Ticket workpad

Maintain a single Linear comment as the running progress log. Update it after
each step. Format:

```
## Workpad
- [x] Plan posted
- [x] Implementation complete
- [x] Self-review pass clean
- [x] Verification gate green
- [x] Small bazooka triaged (`.reviews/<branch>/triage-r1.md`)
- [x] PR opened: <url>
- [ ] Cloud-reviewer feedback loop
- [ ] Merged
```

Don't post per-step status comments — edit the workpad in place.
