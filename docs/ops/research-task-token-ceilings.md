# Research task token ceilings

Every experimenter, scorer and referee dispatch reads its own persisted research
reservation. The reservation's token amount becomes part of the dispatch intent.
A replay must name the same intent; it does not replace an already-dispatched run.

With no parent spend tree, the task receives a native pinned token scope. With a
token-denominated parent, it holds only the calibrated expected amount currently
available, up to its reservation. The reservation is a separate subtree ceiling:
`cap_units` remains the amount actually held, while `ceiling_units` bounds future
spend and child holds. A launch does not refuse because its estimate or ceiling
exceeds the parent's remaining funds. Later parent top-ups can fund the same task,
but cannot silently enlarge its research reservation.

Ancestor caps, payer consent, admission and free-local accounting still apply.
A non-token parent keeps its existing spend tree unchanged. Its units are not
reinterpreted as tokens. A second, token-denominated meter alongside that tree is
still engineering work; this change does not claim to implement it.

A closed task scope remains a boundary for its descendants. Continuations in that
reservation's scope family keep the original boundary in their ancestry, rather
than receiving the same RSI allowance again. A closed parented scope needs an open
funding ancestor: its released hold is not fresh funding. Only a parentless pinned
reservation can fund a continuation from its own closed scope. Ordinary
continuations outside this new reservation class keep their existing fresh-scope
behavior. Only the unused **actual hold** is released when a task ends; an unfunded
ceiling is not money to refund. Home handoffs carry the exact ceiling in spend-tree schema 5.

Native guard charges already incurred are always recorded whole, even past the
ceiling. The ceiling limits future room; it never truncates history. These native
charges include the existing estimated/unknown usage accounting and free-work
rules. They are not a provider-measured token counter. Durable provider-known vs
unknown usage and late-child corrections to the RSI settlement remain separate
work under FIX 3476/9586. The settlement change in PR #5572 is independent.

No new numeric limit or default is introduced: the ceiling is the task's existing
admitted RSI reservation. Matching engine and generated bindings are needed when
this record shape is deployed; no configuration, worker or VM change is required.
