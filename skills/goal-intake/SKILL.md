---
name: goal-intake
description: Interview a human for a typed project goal record and commit it via authenticated intake.
---

# Goal intake

Use this skill when a person starts a project goal or accepts a proposed change to one.
A project card is the first interview turn, not authorization to silently fill gaps.
Only a human answers the goal interview. The loop may suggest a revision but must
never apply one; return its proposal to the responsible human for a new interview.

## Interview
1. Identify the project and responsible human. Reuse known facts; ask only for
   missing answers that change admission. Confirm the goal in their words and
   **why** it matters. Keep implementation ideas separate from the outcome.
2. Ask for **primary axes**: what should improve, how each is measured online,
   and the success bound. Name evidence or receipts a different person can check.
3. Ask for **floor axes**: what must not regress, how to judge it (including a
   held-out test when relevant), and the minimum bound. A floor is not a target
   that the loop can trade away.
4. Ask for **cost axes**: what is spent, how it is measured, and its ceiling.
   Always include `human_minutes` (time answering asks, reviewing and correcting).
5. Record **preferences** only for tradeoffs the human actually chose: prefer X
   over Y and their reason. Empty is valid before the first human pick. Never
   infer a preference from a model score or a proposal.
6. Ask for the **exploration budget**: maximum spend, exploration slice within
   it, and allowed human minutes. This is a soft share, not a budget lease or
   permission to widen a Grant. Confirm responsibility, constraints and open
   questions before committing.

## Commit
Build a `GoalRecord` with `goal`, `why`, `primary_axes`, `floor_axes`,
`cost_axes`, `preferences`, and `exploration_budget`. Each `GoalAxis` has
`name`, `measure`, `bound`. Each `GoalPreference` has `prefer`, `over`, `reason`.
`GoalExplorationBudget` has `max_spend`, `exploration_slice`, `human_minutes`
(nonnegative integers in the host's budget unit; the slice cannot exceed the
maximum). Include a `human_minutes` cost axis. Do not invent bounds or convert
an unanswered question into a blank field; pause to ask. Show the draft to the
human and accept their explicit confirmation.

At attempt start the host loads this Active skill with `load_attempt_skill_pack`,
which stamps the attempt manifest. For the v1 room interview, ask the question
in the project's home room. Have the human answer with a JSON `GoalRecord`
using the fields above; ask again if any answer is missing. Show that exact
JSON draft back to the human. Ask the human to reply `confirm <digest>`, where
`<digest>` is the BLAKE3 hex digest of the draft's UTF-8 bytes. Their reply must
name the draft turn. No confirmation, no write.

The host independently authenticates that human, then calls
`Vault::write_project_goal_from_room_intake` with the attempt, project and
four witnessed turn IDs (agent question, human answer, agent draft, human
confirmation). The engine reads those stored turns, checks the skill load,
answer, draft and confirmation, and writes the typed record. The host must not
infer authentication from transcript text. Do not use `put_project`, a raw
claim or a generic batch to write the goal.
On success, read `Vault::project_intake_goal(project_id)` and return the goal
claim ID, project ID, confirmed fields and next useful task. Make a separate
bounded task brief with acceptance, constraints, responsible person, evidence
references, dependencies and open questions through the normal task door.
On rejection, report the missing or invalid field and ask again; do not claim a
record was saved. Goal data stays in the project record, never in the leader's prompt.
Later changes arrive as loop proposals, not edits; repeat this interview with
an authenticated human for any accepted change.
