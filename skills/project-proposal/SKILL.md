---
name: project-proposal
description: Draft a project card on a conversation message the project question answered yes on, and propose it with vault.projects.propose.
---

# Project proposal

Use this skill when the host dispatches you to draft a project card. Your
briefing names the job: `{"project_proposal": {"conversation", "turn",
"source_message", "thread", "principal"}}`. The typed project question
answered yes on that source message, and you are the house mind it named. The
briefing is a lookup hint. The stored yes decides what you may draft on.

A card is a proposal, not a project. It writes no project and grants nothing.
Only the card's person taps it, through the host's own door; no tap, no
project. The card is also the first turn of the goal-intake interview that the
new project's leader runs after the tap.

## Read the source
Read the source message and enough of its conversation to see what the person
wants: the room's turns (`vault.rooms.messages`) or the thread its turn starts
(`vault.rooms.get`). Use what the person said. If you cannot read the source
(it is gone or withheld from you), stop and draft nothing. Never draft from the
briefing alone.

## Draft
Fill every field from the conversation. Do not invent a goal the person did not
state.

1. **Goal** (`goal`): `goal` in the person's words, `why` it matters to them,
   and `axes`. Axes are names only: what should improve, what must not regress
   and what gets spent. The goal-intake interview asks for each measure and
   bound after the tap, so never put a number, measure or bound on the card.
   Keep `goal` and `why` to a sentence or two each.
2. **Leader** (`leader_agent_def_ref`): the AGENT_DEF that leads the project.
   Name the one the person asked for. Otherwise name the dispatchable definition
   that best fits the work.
3. **Board** (`board_human_refs`): the humans who answer the project's asks.
   Always include the principal. Add only people the person named who can see
   the conversation.
4. **Budget share** (`budget_share_bps`): the project's share of its parent's
   budget, in basis points from 0 to 10000. Translate a budget the person
   stated. When they stated none, propose 1000 (a tenth).
5. **Starting skills** (`starting_skill_refs`): the vault skills that fork into
   the project when it is minted, for its leader and workers. Name only skills
   the work clearly needs; an empty list is valid. Only vault skills go on the
   card. If the work needs a marketplace skill, say so in your reply; never
   import it from this run.

Every reference is a canonical lowercase hex ID with no surrounding space. A
list has no duplicates and at most 128 entries. The goal needs at least one
axis, and the board needs at least one human.

## Propose
Pick `card_id` as `project-` followed by the source message ID. A card ID uses
only ASCII letters, digits, `.`, `_` and `-`, and is at most 128 bytes. Call
`vault.projects.propose` with:

```json
{
  "card_id": "project-<source_message>",
  "source_message_ref": "<source_message>",
  "goal": {"goal": "...", "why": "...", "axes": ["..."]},
  "picks": {
    "leader_agent_def_ref": "<agent def id>",
    "board_human_refs": ["<principal>"],
    "budget_share_bps": 1000,
    "starting_skill_refs": []
  }
}
```

`source_message_ref` is the briefing's `source_message`, exactly. The person
the card is for and its thread come from the stored detection; never pass them.
The same call with the same card returns the stored card.

On a refusal, read the reason:
- "no project question answered yes on this message" or "this agent was not
  asked to draft this card": stop. Never draft on another message instead.
- "the conversation already shows an unanswered card": stop. A conversation
  shows one unanswered card at a time (in a room, one per thread).
- "this card id names another card": a card already stands under this ID. It
  stays; stop.
- A field refusal (empty text, a duplicate, a share over 10000, a malformed
  reference): fix that field and propose again.

## Never
- Never call `vault.projects.confirm`, mint, or write a project, goal record or
  raw claim. The tap belongs to the person, on the host's door.
- Never dismiss a card for the person.
- Never put a secret on the card: the person and the room's members read it.

## Reply
Return the card ID and one line on what it proposes. Nothing else happens until
the person taps or dismisses the card.
