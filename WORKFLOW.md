# Oneiron Agent Workflow

This file is the operational workflow for agent-authored Oneiron PRs. Ticket
contracts may add scope or sequencing, but they do not weaken the verification
gate below.

Reports, workpads, and reviewer summaries are claims. The PR diff, local gate
logs, GitHub checks, and resolved review threads are the evidence that wins.

## 1. Worktree And Scope

- Use one dedicated git worktree per PR, outside the repository checkout. Do not
  create in-repo worktrees or share one worktree between writer agents.
- Branch from current `origin/main` unless the user or ticket says otherwise.
  Use `codex/<ticket-or-short-slug>` by default.
- Treat dirty files in other checkouts as user-owned. Do not move, rewrite, or
  clean them for ticket work.
- Keep the diff scoped to the ticket. No opportunistic refactors, dependency
  churn, config churn, test deletion, or public API movement unless the ticket
  requires it.
- Use `rtk` for shell commands, `rg` for text search, `ast-grep` for syntax
  shape or codemod work, and semantic tooling for symbol identity or references.
- Never run `scripts/review-pr.sh`. It is a stale local reviewer harness and is
  not part of the current workflow.

## 2. Linear Lifecycle

- Claim the Linear ticket and move it to `In Progress` before implementation.
- Maintain one Linear workpad comment with plan, PR link, gate results, review
  status, and blockers. Avoid routine per-step status comments.
- Open the PR as a draft while work is still converging. Link it from Linear.
- When the local gate and GitHub checks are green, required review policy has
  been satisfied, and blocking comments are resolved, move the ticket to
  `In Review` with the PR link and gate summary.
- Do not manually close Linear tickets. Let the GitHub integration move tickets
  to `Done` on merge.

## 3. Verification Gate

Run the full gate from the PR worktree after the final change. Repeat until all
commands pass on the final branch tip.

```bash
rtk proxy cargo fmt --all --check
rtk proxy cargo clippy --workspace --all-targets --all-features -- -D warnings
rtk proxy cargo nextest run --workspace --all-features --profile full
rtk proxy cargo test --doc --workspace --exclude oneiron-bench --all-features
rtk proxy env RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
rtk proxy cargo nextest run -p oneiron --features sync --profile full
```

`nextest --profile full` is the canonical test tier and includes slow tests.
Doctests run separately because nextest does not run them.

For docs-only or comment-only PRs, still run formatting and no-op checks, then
run the full cargo gate when practical. If a manager explicitly scopes the gate
down, record the exact exception in the PR and Linear summary.

## 4. Review Policy

Use risk-scaled review:

- Run `/fusion` once for keystone, security, delete-safety, and
  ONE-1193-class changes.
- For medium-risk PRs, run `/fusion` only when implementation found real
  technical issues, the design is contested, or the PR changes a shared
  contract.
- For tiny docs, comments, and mechanical cleanup PRs, do not run `/fusion`.
  Use GitHub CI plus GitHub cloud-reviewer bots.

GitHub cloud-reviewer bots are part of the normal review loop. Triage every
substantive bot thread as `Fix`, `Follow-up`, or `Dismissed`; fix in-scope
correctness or safety issues before undrafting.

There is no default human-review gate. Stop for human review only when there is
a true unresolved correctness or safety blocker, or when the change would deploy
an irreversible production effect.

## 5. PR Flow

1. Commit the scoped change with a normal area-prefixed message such as
   `docs: update workflow policy`.
2. Push the branch and open a draft PR with `## Summary` and `## Test plan`.
3. Keep the PR in draft while local gate, GitHub CI, required cloud-reviewer
   bot checks, and required `/fusion` review are still unresolved.
4. When local gate and GitHub checks are green and blocking comments are fixed
   or explicitly resolved, mark the PR ready for review.
5. Before merge, rehearse mergeability against current `origin/main` without
   touching `main`.
6. Enable GitHub auto-merge once the merge rehearsal is clean and the PR remains
   green.

Do not force-push a published branch, skip hooks, amend a published commit, run
interactive rebase, merge locally into `main`, or merge with unresolved blocking
review threads.

## 6. Diff And Merge Checks

Before publishing and again before auto-merge, inspect the PR surface:

```bash
rtk git fetch origin main
rtk git diff origin/main...HEAD --name-status
rtk git diff origin/main...HEAD -- ':!*.md'
```

For merge rehearsal, confirm the branch merges cleanly with current
`origin/main`:

```bash
rtk proxy git merge-tree --write-tree origin/main HEAD
```

The merge gate is:

- Local verification gate is green on the final branch tip.
- GitHub CI is green.
- GitHub cloud-reviewer bot threads have no unresolved blocking coding
  comments.
- Required `/fusion`, if any, has been triaged.
- Required human review, if any, has resolved the blocker that required it.
- Merge rehearsal against current `origin/main` is clean.

When all merge-gate conditions are true, use GitHub auto-merge and let the
normal repository integration delete the branch and update Linear.

## 7. Blockers

Stop only for a real blocker:

- The verification gate cannot be run anywhere.
- No local worktree can be created for the PR.
- The ticket has a genuine design ambiguity that cannot be resolved from the
  SOW, code, or Linear context.
- A correctness, safety, or irreversible-deployment issue needs human judgment.

Tooling friction, optional reviewer outages, missing nonessential integrations,
or a single unavailable machine are not blockers. Route around them and keep the
PR moving.
