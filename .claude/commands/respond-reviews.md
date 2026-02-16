Respond to all review comments on the current PR after fixes have been pushed.

## Prerequisites

- `/validate-reviews` was run earlier and saved `.reviews/{current-branch}/triage-rN.md`
- Fixes have been implemented and pushed

## Steps

1. **Find the latest triage**: Read `.reviews/{current-branch}/triage-r*.md` files and use the highest round number. Also read any earlier rounds for full context of what was previously addressed.

2. **Gather all unreplied GH comments**. Determine {owner}/{repo} from: `gh repo view --json owner,name --jq '"\(.owner.login)/\(.name)"'`

   Use GraphQL to fetch review threads:
   ```bash
   gh api graphql -f query='
   query {
     repository(owner: "OWNER", name: "REPO") {
       pullRequest(number: PR_NUMBER) {
         reviewThreads(first: 50) {
           nodes {
             id
             isResolved
             comments(first: 5) {
               nodes {
                 id
                 author { login }
                 path
                 line
                 body
               }
             }
           }
         }
       }
     }
   }'
   ```

   Also fetch top-level PR comments:
   ```bash
   gh api repos/{owner}/{repo}/issues/{number}/comments
   ```

   Skip comments that already have replies from previous rounds.

3. **Match each comment to a triage classification** from the latest triage file. **Validate against actual code** — re-read the referenced file:line to confirm the triage classification is still correct after fixes. Reply format by classification:
   - **Fixed**: "Fixed — [short description of what changed]."
   - **Follow-up**: "Valid point — tracked as follow-up in ROADMAP under [wave/PR]."
   - **Dismissed**: "Not an issue — [brief reason]."
   - **Already addressed**: "This was already handled in [description]."

4. **APPROVAL GATE — batch reply preview**: Before posting ANY replies, draft ALL replies and show them to the user in a single preview batch:

   ```
   Ready to post N replies:

   1. [reviewer] on file.ts:42 → "Fixed — added null check for..."
   2. [reviewer] on file.ts:87 → "Not an issue — this is guarded by..."
   ...

   Post all replies now?
   ```

   **Only post after the user says yes.**

5. **Post replies** using GraphQL thread reply pattern (for inline comments, use `PRRT_` thread IDs):

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

   For top-level comments:
   ```bash
   gh api repos/{owner}/{repo}/issues/{number}/comments -f body="reply text"
   ```

6. **Post a summary comment** on the PR via `gh pr comment` (also with user approval):

   ```markdown
   ## Review Response — Round N

   All review feedback has been addressed:
   - **Fixed**: X items
   - **Follow-up**: X items (added to ROADMAP)
   - **Dismissed**: X items

   [If any follow-ups: list them with ROADMAP references]

   @claude @codex @greptile @coderabbitai — addressed your comments, please re-review (review only, do not push fixes).
   ```

   **IMPORTANT**: Use these EXACT tags literally — `@claude @codex @greptile @coderabbitai`. Do NOT try to derive GitHub bot usernames (like `@greptile-apps[bot]` or `@chatgpt-codex-connector[bot]`). The literal tags are what trigger the integrations.

   **WARNING**: `@mentions` invoke the agents. Do NOT `@mention` any agent name in inline replies or other comments — only in this summary comment where re-review is intended.
