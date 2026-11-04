# Saved graph workflows on an attached agent run

`self.skills.graph` runs resident-authored graph workflow JSON from an admitted
workflow skill's source tree. It is served by the pumped run's host door. It does
not change `self.skills.call` (callable helpers) or `vault.graph.ask` (one-off
questions).

The request names `skill` (the workflow skill's hex entity id) and `reference`
(the exact JSON file path in that admitted source tree). There is no default file
and no host filesystem path. Optional `ceiling`, `unit_deadline_ms`, `posture` and
`criteria` have the same types and fallback behavior as `vault.graph.ask`.

The caller cannot supply an actor, principal, run, attempt, lease, executor or
payer. The door uses its bound actor and run. It matches that actor and the
origin's exact attempt/owner/generation to the registered run, checks the live
registered lease proof, and uses the registered executor. The core skill loader
checks the lease again and pins the loaded skill in the attempt's manifest. A
non-attached host-only call does not create a run or lease.

Saved question versions retain their existing live principal and frozen read-lane
checks. The existing decision ladder answers each input, on the existing
per-question clock and caller payer. A later stage can join earlier proposed
answers, but missing answers remain missing. A final-stage answer does not keep a
claim, send a campaign or authorize another action.

The result is tagged `done` or `failed`. Both carry `stages`, preserving the
input positions and `null` entries for unanswered or held inputs. A failure after
execution starts also names `failed_stage`, `failed_input` and the existing error
code/message, without hiding completed stages. Preparation errors remain ordinary
errors. Served answer rows are listed beside the host-door reply.

This door adds no setting, numeric default, persistent table or migration.
