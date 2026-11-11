//! The side tables `drafter` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// FIX 12569: one target's active drafter pointer, stock or a retained version of the
    /// vault's own, with its generation and the version it replaced. Key: hash32 (the target's
    /// pins).
    DRAFTER_BINDING: VaultMeta b"drafter:binding:v1:" Named Engine
        // Restore class: FIX 12569: the drafter's pointers, evaluations, events, policy and
        // versions stand as the live vault holds them: no image brings back an erased version, an
        // older pointer or a policy the owner changed since. FIX 15128: nor an erased or swept
        // training example.
        [restore: live] [family: unclassified] [tier: canonical];
    /// FIX 14975: one drafter version's evaluation: the arms' identities, each case's counts,
    /// times and output digest, the allowed ties' logits, the speed comparison, the decision
    /// and the observation after an activation; never a token, a text or a key. Key: id16
    /// (the evaluation). An erase of a version it names drops it.
    DRAFTER_EVALUATION: VaultMeta b"drafter:evaluation:v1:" Named Engine
        [restore: live] [family: unclassified] [tier: canonical];
    /// FIX 12569: one content-free drafter event: a night's retrain outcome, a qualification,
    /// an activation, a rollback, a revert, an erase or a policy change. Key: id16 (the event,
    /// time-ordered).
    DRAFTER_EVENT: VaultMeta b"drafter:event:v1:" Named Engine
        [restore: live] [family: unclassified] [tier: canonical];
    /// FIX 15128: one answered chat reply's drafter training example, apart from its chat
    /// breakpoint: its conversation, reply, generation, TURN, agent, requester, the wire model
    /// its rung named, its source family, its dependency set and its sealed body's pin, never
    /// a text. Key: id16 (the example, time-ordered). An erase of a record its dependency set
    /// names drops it and retires its key.
    DRAFTER_EXAMPLE: VaultMeta b"drafter:example:v1:" Named Engine
        [restore: live] [family: unclassified] [tier: canonical];
    /// FIX 15128, FIX 15129: one example's request exactly as its rung sent it and the span
    /// the reply generated (reasoning, tool calls and text), sealed under the example's own
    /// erasable key. Key: id16 (the example).
    DRAFTER_EXAMPLE_BODY: VaultMeta b"drafter:example_body:v1:" Raw Ciphertext
        [restore: live] [family: unclassified] [tier: canonical];
    /// FIX 15128: marker that an example's dependency set names a record, for the erase of
    /// that record. Key: id16 (the record) + id16 (the example).
    DRAFTER_EXAMPLE_SOURCE: VaultMeta b"drafter:example_source:v1:" Raw Engine
        [restore: live] [family: unclassified] [tier: canonical];
    /// FIX 12569: the owner's drafter policy: on or off, the excluded worlds and the recipe, at
    /// its revision. Key: ().
    DRAFTER_POLICY: VaultMeta b"drafter:policy:v1" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// FIX 12569: one drafter version and its run: target, parent, recipe, pinned policy and
    /// cutoff, dependency set, job, state, generation and sealed artifact reference, never a
    /// key. Key: id16 (the version). Its scrub erases an actor or source from the drafter
    /// families (binding, evaluation, event, policy, version), so the others name none.
    DRAFTER_VERSION: VaultMeta b"drafter:version:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::drafter::erase_drafter_actor_in_txn;
}
