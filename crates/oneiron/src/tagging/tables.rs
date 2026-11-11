//! The side tables `tagging` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// The next tagging marker's sequence number, a part of its derived id, so no marker id is
    /// ever drawn twice, even once a settled marker has left the job ledger. Key: (). Value: u64be.
    TAGGING_MARKER_SEQUENCE: VaultMeta b"job:tagging_marker_seq:v1" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// A turn's recorded tagging traces, oldest first: job state, never synced. Key: turn id16
    /// (sixteen zero bytes for a marker whose payload named no turn) + u64be sequence.
    TAGGING_TRACE: VaultMeta b"job:tagging_trace:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Empty-marker age index over the tagging traces. Key: u64be recorded-at + turn id16 + u64be
    /// sequence.
    TAGGING_TRACE_AGE: VaultMeta b"job:tagging_trace_age:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Which turns' saved tag sets name one entity, real or provisional: derived, local, never
    /// synced. Empty marker. Key: entity id16 + turn id16.
    TAGGING_MENTION_REF: VaultMeta b"tagging:mention_ref:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// A provisional entity the tagger's save minted on an identity-key miss: local like the tags,
    /// never synced, until it is confirmed into a real entity. Key: id16.
    TAGGING_PROVISIONAL: VaultMeta b"tagging:provisional:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Local identity-hint index over the provisional entities, keyed as the engine's identity
    /// index is. Empty marker. Key: kind byte + blake3(hint) + id16.
    TAGGING_PROVISIONAL_HINT: VaultMeta b"tagging:provisional_hint:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// One turn's saved tag set under its derivation envelope: unconfirmed mentions, the turn's
    /// mood and merge evidence. Derived, local, never synced. Key: turn id16.
    TAGGING_TAG_SET: VaultMeta b"tagging:tags:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// A TURN owed a tag pass that a physical tear, with no vault in hand, could not mark (FIX
    /// 6262), until the tagging reconciler's upkeep marks it: derived, local, never synced. Empty
    /// marker. Key: id16 (turn).
    TURN_TAG_OWED: VaultMeta b"turn:tag_owed:v1:" Raw
        // Restore class: A tag pass a tear left owed is owed on the turn as the image holds it, as
        // the sieve's owed reads are (FIX 6262).
        [restore: content] [family: unclassified] [tier: canonical];
}
