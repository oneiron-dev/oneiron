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
