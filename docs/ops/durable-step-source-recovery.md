# Durable step source recovery

A saved step response keeps the dispatcher facts that produced it. Recovery does not
rewrite those facts with the context of the caller that found the response.

The private `DREAMER_STEP_STATE` row uses schema version 2. Its `source` value keeps the
original write actor (entity, class, observed authority frontier and run attempt), optional
run id, subject and source time. The existing `(attempt, step hash)` key identifies the
step; the source value does not repeat that key. `Started` keeps no source value. A
`ResponseReceived` or `Logged` row keeps its source only with its response payload.

The response and source are saved before policy lookup or the terminal claim write.
Recovery uses those bytes and source facts. A malformed or missing source is a decode
error, not a memo miss or permission to pay for another provider call. There is one
current private format, with no migration or old-format reader.

The terminal claim and an oversize response's artifact version retain the original
actor, run, subject and occurrence time. The recovering call still supplies the current
vault, recording clock, deadline, budget guard and receiver rights. Ordinary Gate,
delegation and source-trust checks still run. Source metadata grants no authority,
read permission or proof of payment.

An owner's erase clears the saved source with the response. Sticky erased skeletons,
checkpoint retirement stubs and terminal-claim retirement skeletons keep no source
content. The original response owners, including an earlier claim owner, remain the
erasure fence. Archiving an owner does not erase the response.

Generated decision spend rows carry both their original durable step binding and their
memoized flag. They serve different purposes: the binding identifies the source step;
the flag preserves the existing fresh-spend fallback when a checkpoint lookup fails.
A raw or admitted generation has no durable binding and is not memoized. Neither field
is an exactly-once paid-generation fact. Durable budget-line settlement remains a
separate responsibility; source recovery must not be treated as its payment proof.

A default neighbourhood extraction slice also keeps the known usage of a fresh
response when response serialization or its first private checkpoint transaction
fails. That usage travels with the slice's original error and enters its existing
unmetered tally once, including extracted-prefix drains and thing-child extraction.
The shared guard's before/after total is not used to attribute parallel slices.

This additional usage is absent for a saved-response recovery, a memo hit, a
successful checkpoint, and failures after the checkpoint commits. It does not
change error types, messages or recovery, and it is not a payment receipt. Original
financial obligations and atomic exactly-once settlement remain separate work.

The same extraction tally also records prior corrective usage carried by a
`SpentLlm` or `SpentFallback` error. Those errors return before a response is
checkpointed. Their own usage is counted once; the original refusal and error
text stay unchanged. Metered turn-program accounting is not changed.

A native Dreamer admission also keeps its original budget line in an immutable,
attempt-bound accounting record. Serial and partition-window dispatch carry that
record on their own deadline clones. The existing crash-owed producer reads this
record before optional call observation, so an absent or failed observer does not
suppress the owed row. A child or foreign attempt cannot use the record. Admission,
reservation reuse and top-up, clocks, cancellation and call observation stay unchanged.

This record is not an execution grant, a paid receipt or a generation-level once fact.
The existing owed key, codec and settlement rules are unchanged. Late-generation
settlement, corrective-call identity and atomic exactly-once payment remain separate
work; this supplier change does not claim to close them.

A settled lower-model lease reports the units that lease actually charged, not the
guard's cumulative total. Per-call settlement keeps that call's units; absolute
settlement keeps only its increment over the prior watermark. Unmetered local
leases report zero, and a repeated settlement retains the first result. This
corrects the existing per-call observation. It does not turn that observation into
a durable paid fact or authorize subtracting it from a different meter or tally.
