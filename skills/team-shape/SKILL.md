---
name: team-shape
description: Choose how many agents to spawn and who decides, starting from one agent.
---

# Team shape

Models carry weak priors about collaboration, and a naive team often loses
to one agent. This skill teaches the planner (and any parent about to
spawn) how to organise a team. It is seeded from coordination research and
revised from receipts: measured payoff rows outweigh every rule below.

## The first lesson: solo first

Start from one agent with a clear brief. When one agent already succeeds
often on tasks of this type, adding agents tends to hurt: more chances to
drift, more context spent coordinating, slower convergence. A team earns
its width only when its measured payoff beats solo at equal budget — never
because the task "feels big".

## Spawning

Say what you need, separate from the prompt: `need` (required, one or two
lines), `care` (light, medium, high, xhigh, max), and `notes` for
constraints. Set `model`, `width`, `pattern` or `budget` only to steer: a
seed says where learning starts, a pin fixes the value. Everything unset
belongs to the planner.

## The patterns (who decides)

- Solo — one agent. Works well for: most tasks.
- CEO decides — the leader alone, after advice. The default team.
  Works well for: work with independent advice streams.
- Committee — a few deliberate, the chair decides. Works well for:
  researching what exists and refining. It narrows ideas, so it is late
  on generative work.
- Vote — members vote first, debate only on request. Works well for:
  judging between finished options.
- Market — a referee signed before the work decides (a test suite, a
  holdout, a pinned judge). Works well for: checkable work at width.
  No referee, no market.
- Rotation — roles rotate by turn. Works well for: reframing and open
  questions. Starts untested.

## Budget

The budget is an input to the plan, never a refusal. A 20-agent
tournament on a three-agent budget is pointless: fit the best shape the
budget allows and say what more would buy. Width has no count cap; the
spend cap is the cap. When a run nears the end of its lease, agents get a
wrap-up warning, partial results are saved in a resumable hold, and the
owner gets a notice. A suspension is a hold, not a kill.

## Care

Care spends on shape, not just effort. Light care rarely justifies a
team. High care and up is where a wider, stronger shape can pay — and
where the planner itself climbs its ladder: a cheap classifier for the
easy cases, a small thinking model next, a strong model for xhigh, max
or big plans.
