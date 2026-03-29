Validate and triage all review feedback for the current PR.

**Repo:** Detect from `git remote get-url origin` — works in any repo (eiri, oneiron, etc.).

## Step 0 — Re-run local reviews

**Always re-run `scripts/review-pr.sh` before triaging.** This ensures reviews reflect the current branch state, not a stale snapshot.

The script creates run-numbered subdirectories (`.reviews/{branch}/run-1/`, `run-2/`, etc.) with a `latest` symlink — previous runs are never overwritten.

```bash
cd $(git rev-parse --show-toplevel) && bash scripts/review-pr.sh
```

Wait for all 6 reviewers to complete before proceeding. Some may fail (auth expiry, tool not installed) — note failures but continue with available outputs.

## Rounds

This skill supports multiple triage rounds. Each run creates a versioned triage file:
`.reviews/{branch}/triage-r1.md`, `triage-r2.md`, etc.

On startup, check for existing `triage-r*.md` files to determine the current round number. Read previous rounds to understand what was already addressed — skip findings that match items already fixed or dismissed in earlier rounds. Only triage NEW findings.

## Inputs to gather

1. **Local agent reviews**: Read all files in `.reviews/{current-branch}/latest/` — these are the freshly generated outputs from Step 0. Check each file for actual content vs error logs (auth failures, empty output = skip that reviewer).

2. **Previous triage rounds**: Read any existing `.reviews/{current-branch}/triage-r*.md` files to know what was already handled.

3. **GitHub PR comments**: Detect repo owner/name from `git remote get-url origin`, then use `gh` to fetch all feedback:
   - `gh pr view {number} --comments --repo {owner}/{repo}` for top-level comments
   - `gh api repos/{owner}/{repo}/pulls/{number}/comments` for inline code comments
   - `gh api repos/{owner}/{repo}/pulls/{number}/reviews` for review summaries

   Determine the PR number from the current branch: `gh pr list --head $(git branch --show-current) --json number --jq '.[0].number' --repo {owner}/{repo}`

   Skip GH comments that were already replied to (have reply threads). Only triage unreplied comments.

## Triage process

For every NEW finding (not already in a previous round):

1. **Validate against actual code**: For EVERY finding, read the file and line referenced. Do NOT take reviewer claims at face value — verify the issue exists in the current code. Reviewers frequently hallucinate line numbers, misread control flow, or flag code that was already fixed in a later commit. If the reviewer says "line 42 has a bug", READ line 42 and confirm. If the code doesn't match what the reviewer describes, dismiss it.

2. **Evaluate if real**: Is this an actual issue, or a false positive / misunderstanding of the codebase? Consider project conventions in CLAUDE.md and architecture in ROADMAP.md.

3. **If real, classify**:
   - **This PR** — fix now. Group these by file and severity.
   - **Follow-up** — out of scope for this PR. Note which ROADMAP wave/PR it belongs to.

4. **If not real**: Briefly explain why it's dismissed.

## Output

Produce a triage report with these sections:

### Round N — New Findings

### Fix in This PR
| # | Source | Severity | File:Line | Issue | Fix |
|---|--------|----------|-----------|-------|-----|

### Follow-up (add to ROADMAP)
| # | Source | Issue | Suggested ROADMAP location |
|---|--------|-------|---------------------------|

### Dismissed
| # | Source | Issue | Reason |
|---|--------|-------|--------|

### Summary
- Round: N (previous rounds: N-1)
- New findings: X
- Fix now: X (critical: X, major: X, minor: X)
- Follow-up: X
- Dismissed: X
- Already addressed in prior rounds: X (skipped)

## Actions

1. **Save triage** to `.reviews/{current-branch}/triage-rN.md`.

2. **APPROVAL GATE — PR comment**: Draft a summary comment for the PR with:
   - Round number
   - What's being fixed in this PR (with brief descriptions)
   - What's tracked as follow-up (with ROADMAP references)
   - What's dismissed (with reasons)

   **Show the draft to the user and ask for explicit approval before posting.** Per CLAUDE.md policy: "Ready to comment: [preview]. Post now?" Only post via `gh pr comment` after the user says yes.

3. **Add follow-up items** to ROADMAP.md under the appropriate wave/PR.

Do NOT reply to individual GH comments yet — that happens in `/respond-reviews` after fixes are pushed.
