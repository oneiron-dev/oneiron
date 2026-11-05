# Learning own-head source references

`learning_estimate_with_sources` returns the same own estimate as
`learning_estimate`. Its source ids cover every canonical claim enumerated
for that subject before the active-head filters, not just the winning head.
The same snapshot also supplies any actor entities consulted by the machine
history checks, the history-index ids actually enumerated, and the native
history carriers used by the targeted reads. Source ids are sorted and
unique; candidate order and richest-head tie handling are unchanged.
Ordinary readers keep the complete history-index presence walk nonretaining.
A sourced reader observes that same walk directly into its source vector,
without a second scan or a temporary vector of control ids.

These are entity references, not grants, immutable byte witnesses or a
snapshot of authority, pin, consent or withdrawal metadata. The ordinary
claim and restriction readers keep their existing checks and errors.
A cell with no own head still returns `None`. This API does not read a prior
or walk the learning backoff chain.

The training-offer reader already carries these ids with the estimate into
its existing model-call source set. No model call, candidate filter, approval,
refusal, budget or default changes. This is one own-head provenance component,
not the planned team's complete decision source set. Planner priors, backoff,
other planning snapshots and launch facts still need their own source capture.
