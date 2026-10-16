Reply to review comments on the current PR after the fixes are pushed.

Under the vibe build no review blocks a merge and bot comments need no answer (see `AGENTS.md`). Use this command only when you choose to answer comments.

## Input

- `/validate-reviews` saved `.reviews/{branch}/triage.md` (`.reviews/` is gitignored).
- The fixes are pushed.

## Steps

1. **Read the triage** in `.reviews/{branch}/triage.md`.

2. **Collect the open threads.** Find the repo and PR:
   ```bash
   gh repo view --json owner,name --jq '"\(.owner.login) \(.name)"'
   gh pr view --json number --jq .number
   ```

   Fetch every review thread, page by page:
   ```bash
   gh api graphql --paginate -f owner=OWNER -f name=REPO -F number=PR_NUMBER -f query='
   query($owner: String!, $name: String!, $number: Int!, $endCursor: String) {
     repository(owner: $owner, name: $name) {
       pullRequest(number: $number) {
         reviewThreads(first: 100, after: $endCursor) {
           pageInfo { hasNextPage endCursor }
           nodes {
             id
             isResolved
             comments(first: 100) {
               totalCount
               nodes { id author { login } path line body }
             }
           }
         }
       }
     }
   }'
   ```
   If a thread's `totalCount` is over 100, read the rest of that thread before you answer it. Fetch top-level comments with `gh api --paginate repos/OWNER/REPO/issues/PR_NUMBER/comments`.

   Work from the unresolved threads. A reply in a thread does not show that its finding is fixed.

3. **Check each finding against the current head.** Match it to its triage row, then re-read the file and line it names to confirm the triage still holds after the fixes. Reply by class:
   - **Fixed**: "Fixed: [what changed]."
   - **Follow-up**: "Valid; on the fix list: [the line]."
   - **Dismissed**: "Not an issue: [reason]."
   - **Already handled**: "Handled in [commit or file]."

4. **Post the replies.** An inline thread takes its `PRRT_` thread id:
   ```bash
   gh api graphql -f query='
   mutation {
     addPullRequestReviewThreadReply(input: {
       pullRequestReviewThreadId: "PRRT_..."
       body: "reply text"
     }) {
       comment { id }
     }
   }'
   ```
   A top-level comment: `gh api repos/OWNER/REPO/issues/PR_NUMBER/comments -f body="reply text"`.

Do not `@mention` a bot in a reply. A mention invokes that bot, and no re-review is needed.
