Triage the review feedback on the current PR.

Under the vibe build no review blocks a merge and bot comments need no answer (see `AGENTS.md`). Use this command only when you choose to triage comments.

## Review sources

There is no local reviewer harness in this repo; `scripts/review-pr.sh` does not exist. Feedback comes from GitHub (bot and human comments on the PR) and from any agent review output a caller has left under `.reviews/{branch}/latest/`. `.reviews/` is gitignored and may be absent. Never invent a review run: triage what is there, and say in the report which sources were empty.

## Gather

1. **Local agent reviews** (optional): if `.reviews/{branch}/latest/` exists, read every file in it. Skip a file that holds only an error log (auth failure, empty output).

2. **GitHub feedback.** Find the repo and PR:
   ```bash
   gh repo view --json owner,name --jq '"\(.owner.login)/\(.name)"'
   gh pr view --json number --jq .number
   ```
   Fetch every page:
   - `gh api --paginate repos/{owner}/{repo}/issues/{number}/comments` for top-level comments
   - `gh api --paginate repos/{owner}/{repo}/pulls/{number}/comments` for inline comments
   - `gh api --paginate repos/{owner}/{repo}/pulls/{number}/reviews` for review summaries

   The thread query in `/respond-reviews` shows which threads are resolved.

3. **Earlier triage**: read `.reviews/{branch}/triage.md` if it exists.

Triage every finding in an unresolved thread, and every review summary and top-level finding, on the current head. An earlier reply or triage row does not show that a finding is fixed; use it only as a hint about where to look.

## Triage

For each finding:

1. **Check the code.** Read the file and line it names. Do not take the reviewer's word for it: reviewers misplace line numbers, misread control flow, and flag code that a later commit already fixed. If the code does not match the description, dismiss the finding.

2. **Decide if it is real**, against the conventions in `AGENTS.md` and `CLAUDE.md`.

3. **If real, classify it:**
   - **Fix now**: in scope for this PR. Group these by file and severity.
   - **Follow-up**: out of scope. Add one line to the fix list (see `AGENTS.md`).

4. **If not real**, give the reason in one line.

## Output

Save the report to `.reviews/{branch}/triage.md`, replacing any older copy, and show it to the user:

### Fix now
| # | Source | Severity | File:Line | Issue | Fix |
|---|--------|----------|-----------|-------|-----|

### Follow-up (fix list)
| # | Source | Issue | Fix-list line |
|---|--------|-------|---------------|

### Dismissed
| # | Source | Issue | Reason |
|---|--------|-------|--------|

### Summary
- Findings: X
- Fix now: X (critical: X, major: X, minor: X)
- Follow-up: X
- Dismissed: X
- Empty sources: [list]

Do not reply on GitHub here. If you choose to answer, `/respond-reviews` posts the replies after the fixes are pushed.
