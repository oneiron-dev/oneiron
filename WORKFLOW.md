# Oneiron Agent Workflow

This file is the local gate authority for agent-written PRs in this repo.
Ticket wave contracts may add scope, sequencing, or human-review requirements,
but they do not weaken the verification gate below.

## 0. Worktree And Scope

- One ticket should produce one PR unless the ticket explicitly asks for a split.
- Work in a dedicated git worktree outside the main repo checkout. Never run two
  writer agents in the same worktree.
- Use `codex/<ticket-or-short-slug>` for branches unless the user requests a
  different branch name.
- Do not edit the main checkout directly for ticket work. Treat unrelated dirty
  files as user-owned and leave them alone.
- Read the ticket SOW, this workflow, nearby source, nearby tests, and recent
  history for the touched files before editing.
- Keep the diff scoped to the ticket. No opportunistic refactors, dependency
  changes, config churn, test deletion, or public API movement unless the ticket
  explicitly requires it.
- Use `rtk` for shell commands. Use `rg` for text search, `ast-grep` for syntax
  shape/codemod work, and semantic tools for symbol/reference questions.

## 1. Linear Lifecycle

- Claim the ticket and move it to `In Progress` before implementation.
- Maintain one Linear workpad comment with plan, PR link, gate results, review
  status, and blockers. Do not post routine per-step status comments.
- When the PR is ready for review, move the ticket to `In Review`, link the PR,
  and comment the local gate summary.
- Do not manually close Linear tickets. Let the GitHub integration move tickets
  to `Done` on merge.

## 2. Implementation

- Make the smallest coherent change that satisfies the ticket.
- Add or update tests at the behavior boundary touched by the change.
- Do not add `unwrap()` or `expect()` in non-test code unless the invariant is
  already locally proven and the surrounding codebase uses that pattern.
- Do not leave `TODO` or `FIXME` comments for work required by the ticket.
- Use normal commits with an area prefix, for example `sync: ...`,
  `analyzer: ...`, `server: ...`, `tests: ...`, or `docs: ...`.

## 3. Local Verification Gate

This gate blocks every PR. Run it after the final code change and repeat until
all commands pass.

Use `sccache` when available:

```bash
if command -v sccache >/dev/null 2>&1; then
  export RUSTC_WRAPPER=sccache
fi
```

Required commands:

```bash
rtk proxy cargo fmt --all --check
rtk proxy cargo clippy --workspace --all-targets --all-features -- -D warnings
rtk proxy cargo nextest run --workspace --all-features --profile full
rtk proxy cargo test --doc --workspace --exclude oneiron-bench --all-features
rtk proxy env RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps
rtk proxy cargo nextest run -p oneiron --features sync --profile full
```

`nextest --profile full` is the canonical test tier and includes slow tests.
`cargo test --doc` is separate because nextest does not run doctests.

Docs-only PRs still run the same cargo gate. They only skip Fusion unless the
user explicitly asks for it.

## 4. Diff Scope Checks

After committing, inspect the PR diff before publishing:

```bash
rtk git diff main...HEAD --name-status
rtk git diff main...HEAD -- ':!*.md' | grep -E '^\+.*(_VERSION|pub (fn|struct|enum|trait|type|const|static|mod|use))' | head
rtk git diff main...HEAD -- 'Cargo.toml' ':(glob)**/Cargo.toml' 'Cargo.lock' 'rust-toolchain.toml' 'deny.toml' '.gitignore'
```

Output from the version/public-surface grep or Cargo/config diff is not
automatically fatal when the ticket explicitly requires that surface, but it
must be called out in the PR and Linear gate summary. If the ticket does not
authorize it, stop and ask for human review.

## 5. PR Flow

1. Push the branch.
2. Open the PR as a draft with:
   - `## Summary`
   - `## Test plan`
   - `Closes <ticket>`
3. Wait for the local verification gate to be green.
4. Run the risk-scaled review policy below.
5. Mark the PR ready.
6. Move the Linear ticket to `In Review` with the PR link and gate summary.

Never force-push a published branch, skip hooks, amend a published commit, run
interactive rebase, or merge with unresolved blocking review threads.

## 6. Review Policy

The blocking review gate is:

- Local cargo verification gate is green.
- GitHub CI is green.
- GitHub cloud-reviewer bots have no unresolved blocking coding comments.

Use Fusion for deep multi-model review. Do not use stale local reviewer
harnesses.

Risk scale:

- Keystone, security, and delete-safety tickets require one Fusion run and
  human review before merge. Current wave examples: `ONE-1188`, `ONE-1190`,
  `ONE-1192`, `ONE-1167`, `ONE-1168`, and `ONE-151`.
- Medium-risk tickets use Fusion once only if implementation hit real technical
  issues, the design is contested, or the PR changes a shared contract.
- Tiny or docs-only tickets use CI plus cloud-reviewer bots only.
- Use Fusion mid-implementation when a worker is stuck on a hard problem.

If a Fusion member abstains because a vendor CLI is unavailable, unauthenticated,
rate-limited, or out of quota, record the abstention and continue with the
available panel. Do not block a PR solely on an optional reviewer outage.

## 7. Cloud-Reviewer Loop

- Check GitHub review threads and PR checks after the PR is ready.
- Classify each substantive thread as `Fix`, `Follow-up`, or `Dismissed`.
- Fix all in-scope correctness or safety findings, push a follow-up commit, and
  rerun the local verification gate.
- Reply to resolved threads with the classification and what changed.
- For out-of-scope findings, reply with the ticket boundary and create or note a
  follow-up ticket when useful.
- Grammar, typo, or wording-only nits can be dismissed or fixed directly.

Cloud-reviewer comments are advisory until triaged. Do not hand off an
unresolved blocking coding comment to the user unless it is genuinely outside
the ticket scope or requires a product/design decision.

## 8. Merge Gate

Merge only when all are true:

- Local verification gate is green on the final branch tip.
- GitHub CI is green.
- Blocking cloud-reviewer coding comments are fixed or explicitly resolved.
- Required Fusion review, if any, has been triaged.
- Required human review, if any, has approved merge.
- The branch is mergeable against `main`.

Use the normal GitHub merge flow and delete the branch after merge. Do not touch
`main` directly.

## 9. Blockers

Stop only for a real blocker:

- The verification gate cannot be run anywhere.
- No worker or local worktree can be created for the ticket.
- The ticket has a genuine design ambiguity that cannot be resolved from the
  SOW, code, or wave contract.
- A keystone/security/delete-safety PR has reached the required human-review
  boundary.

Tooling friction, optional reviewer outages, missing nonessential integrations,
or a single unavailable machine are not blockers. Route around them and keep the
PR moving.
