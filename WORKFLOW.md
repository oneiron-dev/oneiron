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
- Use `rg` for text search; use `rtk`, `ast-grep`, and semantic tooling when
  available. Missing optional wrappers do not block the native commands.
- `scripts/review-pr.sh` does not exist; it was deleted as dead. Any reference
  to it is stale — do not try to run it.

### Parallel agents and build ownership

- Give each writer a file scope and a dedicated worktree. The coordinator
  integrates changes and runs the final gate; context-only agents need no builds.
- Before Cargo starts, assign a host CPU/RAM budget and a target directory.
  Concurrent writers use separate targets: the worktree's default `target/`, or
  an explicitly assigned absolute `CARGO_TARGET_DIR`. Check inherited environment
  settings first; do not accidentally reuse a runner's `~/ci/target`.
- A shared target is an explicit, **serialized** mode. Never run Cargo or cache
  cleanup there while another writer/runner owns it. Cargo lock waits are not a
  reason to launch duplicate builds or delete artifacts. Separate targets avoid
  target-lock contention, but do not create more CPU, RAM, or disk capacity.
- The coordinator bounds Cargo compilation (`CARGO_BUILD_JOBS` or `-j`) and
  nextest execution (`--test-threads`) separately. Do not give every agent the
  host's full core count. Record host, target, feature set, and these limits in
  gate evidence. Scope overrides to the task, not global Cargo config.
- Use Arch Linux for reference full-gate coverage. Mac mini and MacBook use the
  same commands and toolchain, with the documented macOS exceptions in
  `AGENTS.md`. Do not apply macOS `TMPDIR` paths on Linux or silently weaken a
  full gate to make it pass on a different host.
- Find the owning module through `docs/CODEMAP.md` and the per-crate map before
  broad searches. Regenerate the maps after mapped facts change; never hand-edit
  generated navigation. See `AGENTS.md` for generation and cheap fixture tests.

## 2. Linear Lifecycle

- Claim the Linear ticket and move it to `In Progress` before implementation.
- Maintain one Linear workpad comment with plan, PR link, gate results, review
  status, and blockers. Avoid routine per-step status comments.
- When publication is authorized, open the PR ready for review (never draft)
  so CI and cloud-reviewer bots run. Link it from Linear.
- When the local gate and GitHub checks are green, required review policy has
  been satisfied, and blocking comments are resolved, move the ticket to
  `In Review` with the PR link and gate summary.
- Do not manually close Linear tickets. Let the GitHub integration move tickets
  to `Done` on merge.

## 3. Verification Gate

Run the full gate from the PR worktree after the final change. Repeat until all
commands pass on the final branch tip.

`scripts/verify.sh` is the single source of truth for the scripted gate. Use
`scripts/verify.sh --list` to see the exact commands without running them;
`--help` is also build-free. Scoped iteration commands are in `AGENTS.md` and
are not substitutes for this gate.

The nine scripted stages are code-map pin, fmt, workspace clippy, featureless
clippy, server-production clippy, strict rustdoc, full workspace nextest,
featureless library tests, and doctests. All compiling Cargo steps in the scripted and
distributed gates, and in scoped CI, use `--locked`: stale manifests must fail rather
than rewrite the committed `Cargo.lock`. Keep `cargo fmt --check` separate; it does
not resolve dependencies. Formatting is members-only (`cargo fmt --check`, never `--all`,
which follows the ONE-218 heed vendor). Server clippy deliberately omits
`--all-targets` so test-only features cannot hide production errors. Workspace
nextest retains its `oneiron-napi` exclusion; the crate's separate Linux Rust tests now
use a dev-only dynamic-symbol feature, while JS ABI tests still need a real Node host.
Doctests exclude `oneiron-bench`. The rustdoc stage runs
`env -u CARGO_ENCODED_RUSTDOCFLAGS RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps`
after server clippy and before runtime tests. CI `Checks` runs the same command
for Rust-relevant changes; documentation warnings are not a manual-only gate.
The child command unsets inherited `CARGO_ENCODED_RUSTDOCFLAGS` because it overrides
`RUSTDOCFLAGS` even when empty. Other stages keep their inherited environment.

`nextest --profile full` is the canonical test tier and includes slow tests.
Doctests run separately because nextest does not run them. Linux is the
reference full-gate host: the unfiltered script still encounters the known
macOS bench failures described in `AGENTS.md`. The macOS CI recipe is a separate,
explicit platform lane; do not describe it as an unfiltered full-script pass.

One current policy command is not yet wired into `scripts/verify.sh` — run the
narrow sync lane by hand until that gap closes:

```bash
cargo nextest run -p oneiron --features sync,test-hooks --profile full
```

For distributed runs, `scripts/verify-leg.sh` covers the code-map pin, fmt,
workspace clippy, partitioned full nextest, and doctests. The test legs exclude
napi only on Linux; macOS keeps its existing napi coverage, unlike the full
script's unconditional exclusion. Select `LEG=fmt-clippy`, `LEG=tests:1/2`,
or `LEG=tests:2/2`.
A pass across all three legs still needs **five** commands to close the gate:

```bash
cargo clippy -p oneiron --all-targets --no-default-features -- -D warnings
cargo clippy -p oneiron-server --all-features -- -D warnings
cargo test -p oneiron --lib --no-default-features
env -u CARGO_ENCODED_RUSTDOCFLAGS RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
cargo nextest run -p oneiron --features sync,test-hooks --profile full
```

Keep gate logs with the exact command, worktree revision, host, and environment
choices. Discovery output is not gate evidence: only an executing full script
can print `VERIFY-OK`, and the additional sync policy command needs its own log.

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
correctness or safety issues before merge.

There is no default human-review gate. Stop for human review only when there is
a true unresolved correctness or safety blocker, or when the change would deploy
an irreversible production effect.

## 5. PR Flow

1. Commit the scoped change with a normal area-prefixed message such as
   `docs: update workflow policy`.
2. When publication is authorized, push the branch and open a ready-for-review
   (non-draft) PR with `## Summary` and `## Test plan`. Do not use `--draft`:
   draft PRs do not trigger the required CI and cloud-reviewer bots.
3. Keep the PR ready for review while local gate, GitHub CI, required
   cloud-reviewer bot checks, and required `/fusion` review converge. Ready
   status starts review; it is not permission to merge.
4. Fix or explicitly resolve blocking comments and wait for the local gate,
   GitHub checks, and required reviews to pass on the final branch tip. Do not
   enable auto-merge while any merge-gate condition is unresolved.
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
