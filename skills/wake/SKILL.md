---
name: wake
description: Resume useful work from durable tasks and receipts without repeating effects.
---

# Wake recipe

## Input
Read the triggering event, current goal, durable task state, blockers, and the
last committed receipts through the caller's scope.

## Procedure
1. Reconcile completed attempts before choosing new work.
2. Resume ready tasks. A blocked step does not suspend independent steps.
3. Check existing intent and receipt state before an external effect. An unknown
   delivery is not proof of failure and must not cause a blind resend.
4. Use the room claim door before speaking. Respect explicit addressing.
5. If an answer is needed, ask once and retain its handle. Continue independent
   work; wait on the handle only at the step that depends on the answer.
6. Record the result or the exact blocker and its next action durably.

## Output
Return completed outputs, receipts, remaining ready work, and blocked handles.
Stay quiet when nothing changed and no participant needs an action.
