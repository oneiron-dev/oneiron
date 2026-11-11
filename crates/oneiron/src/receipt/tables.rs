//! The side tables `receipt` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Named typed calls' durable queued/held status and terminal outcome, keyed by
    /// hash32(actor, class, invocation); never execution authority.
    ADMISSION_INTENT: VaultMeta b"admission:intent:v1:" Named Engine
        [restore: live] [family: unclassified] [tier: canonical];
    /// Live attempt's frozen execution context and append-only use witnesses. Key: attempt id16.
    ATTEMPT_PACK_ATTRIBUTION: VaultMeta b"attempt_attribution:v1:" Named Authored [accepts: crate::receipt::attempt_pack_attribution_accepts_masked]
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::receipt::erase_attempt_attribution_scope_in_txn;
    /// Terminal PACK RECEIPT for one attempt run under a skill pack, cited by receipt_ref lookups.
    /// Key: string ("attempt:" + hex32 attempt id).
    ATTEMPT_PACK_RECEIPT: VaultMeta b"attempt_receipt:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::receipt::erase_attempt_receipt_actor_in_txn;
    /// Native agent/time of one exact call receipt; its primary's sole actor scrub removes
    /// these witnesses in the same writer. Key: receipt id16.
    CALL_RECEIPT_AGENT_WITNESS: VaultMeta b"call_receipt_agent_witness:v1:" Named Engine
        [restore: live] [family: unclassified] [tier: canonical];
    /// Passive outbound dispatch audit observation for one attempt/try. Key: id16 + u32be.
    DISPATCH_OBSERVATION: VaultMeta b"dispatch_observation:v1/" Raw Authored [accepts: crate::receipt::dispatch_observation_accepts_masked]
        [restore: content] [family: unclassified] [tier: canonical];
    /// Deterministic receipt id -> intent id. Key: id16.
    OUTBOUND_SUPPRESSION_INDEX: VaultMeta b"outbound:suppression_index:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Device-local receipt body, `rmp_serde::to_vec_named`. Key: hash32 (intent id).
    OUTBOUND_SUPPRESSION_RECEIPT: VaultMeta b"outbound:suppression_receipt:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// Direct host dispatch receipt by content-derived hash32.
    OUTBOUND_DIRECT_RECEIPT: VaultMeta b"outbound_direct_receipt:v2:" Named Authored [accepts: crate::receipt::outbound_direct_receipt_accepts_masked]
        [restore: live] [family: unclassified] [tier: canonical];
    /// Binds one archived receipt-source ASSET to the inert holder CLAIM it documents. Key: id16
    /// (archive source id).
    RECEIPT_ARCHIVE_BINDING: VaultMeta b"receipt/archive-binding/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Marks a holder CLAIM whose archived receipt-source closure has been retired (and its payload
    /// erased). Key: id16.
    RECEIPT_ARCHIVE_HOLDER_RETIRED: VaultMeta b"receipt/archive-holder-retired/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Index of archived receipt-source ids currently owned by one holder claim. Key: id16 (holder) +
    /// id16 (source).
    RECEIPT_ARCHIVE_OWNED: VaultMeta b"receipt/archive-owned/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Dedupe slot: which archived receipt-source id currently occupies one (holder, body hash,
    /// receipt id) triple. Key: id16 (holder) + hex64 (body sha256, as text) + string (receipt id).
    RECEIPT_ARCHIVE_SLOT: VaultMeta b"receipt/archive-slot/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Marks one archived receipt-source ASSET id as retired (payload erased or never delivered).
    /// Key: id16.
    RECEIPT_ARCHIVE_SOURCE_RETIRED: VaultMeta b"receipt/archive-source-retired/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
}
