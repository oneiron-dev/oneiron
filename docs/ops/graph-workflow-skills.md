# Saved graph workflows on an attached agent run

`self.skills.graph` runs resident-authored graph workflow JSON from an admitted
workflow skill's source tree. It is served by the pumped run's host door. It does
not change `self.skills.call` (callable helpers) or `vault.graph.ask` (one-off
questions).

The request names `skill` (the workflow skill's hex entity id) and `reference`
(the exact JSON file path in that admitted source tree). There is no default file
and no host filesystem path. Optional `ceiling`, `unit_deadline_ms`, `posture` and
`criteria` have the same types as `vault.graph.ask`. Each stage starts from its
actual saved question's dial, deadline and criteria. An explicit caller ceiling
only caps that dial; it never lowers the saved first rung. Explicit deadline and
criteria override those saved values. Posture always keeps the stricter of the
saved question, caller and vault.

An explicit criteria override has its own answer deduplication identity, including
when its criteria are empty or equal to the saved criteria. Different overrides
cannot reuse each other's answers or a saved-question pump's answer. The saved
question version and physical source-frontier checks stay unchanged.

The caller cannot supply an actor, principal, run, attempt, lease, executor or
payer. The door uses its bound actor and run. It matches that actor and the
origin's exact attempt/owner/generation to the registered run, checks the live
registered lease proof, and uses the registered executor. The core skill loader
checks the lease again and pins the loaded skill in the attempt's manifest. A
non-attached host-only call does not create a run or lease.

Saved question versions retain their existing live principal and frozen read-lane
checks. A run carrying a waking credential also keeps that caller's actual read
key: source preparation, media reads and the terminal source recheck meet it with
the saved version's lane in each read's transaction. The key comes from the bound
`Memory`, not the request. It keeps the credential, records, scope, destination
and room-turn checks; it never gains a local reader's extra owner authority.
A native run without a waking credential keeps the existing principal reader.
Selecting the saved target and loading the skill retain their existing checks.

The existing decision ladder answers each input, on the existing
per-question clock and caller payer. A later stage can join earlier proposed
answers, but missing answers remain missing. A final-stage answer does not keep a
claim, send a campaign or authorize another action.

The result is tagged `done` or `failed`. Both carry `stages`, preserving the
input positions and `null` entries for unanswered or held inputs. A failure after
execution starts also names `failed_stage`, `failed_input` and the existing error
code/message, without hiding completed stages. Preparation errors remain ordinary
errors. Served answer rows are listed beside the host-door reply.

This door adds no setting, numeric default, persistent table or migration.
