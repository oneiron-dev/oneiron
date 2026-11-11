//! The side tables `compaction` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Which executor run's fold a fold-words dependent stands for: the dependency walk reaches
    /// it when a record the fold's summary came from is withdrawn (fixed 24-byte frame: id16(run)
    /// + fold u64 BE). Key: id16(dependent).
    CODE_RUN_FOLD_WORDS: VaultMeta b"code_run:fold_words:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Node-local fold ledger of one executor run: its marks, compact ask, folds and unfold
    /// appends (JSON). Key: id16(run).
    CODE_RUN_FOLDS: VaultMeta b"code_run:folds:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// A conversation summary's check material (FIX 5040): the sealed gate request, the
    /// backend's whole reply and the gate policy of the accepted try, owned by the SUMMARY and
    /// every source of its window. The reply is a model's words: the side-row wall admits the
    /// material before its ref binds the receipt. An erase leaves the refs and digest only.
    /// Key: id16(summary).
    COMPACTION_CHECK_MATERIAL: VaultMeta b"compaction:check_material:v1:" Named Authored [accepts: crate::compaction::compaction_check_material_accepts_masked]
        // Payload family: A blocked report's captured requests (FIX 6708), a wait's deliveries
        // (FIX 6588) and a conversation check's gate material (FIX 5040); the wait index stays
        // unclassified, as only its settled rows hold a reply, which [`class_for_row`] places row
        // by row (FIX 9179).
        [restore: content] [family: dispatch Response] [tier: canonical];
    /// A conversation's landed self-written summary (FIX 4465 D): its epoch, the SESSION's turn
    /// range and the host's record of what wrote it, conversation evidence included; no words.
    /// Key: id16(summary).
    COMPACTION_CONVERSATION_RECEIPT: VaultMeta b"compaction:conversation_receipt:v1:" Named Engine
        [restore: content] [family: unclassified] [tier: canonical];
    /// Each landing receipt under its conversation (FIX 5032), written with the receipt in its
    /// mint's own writer. Ids only: the receipt is the evidence, and this row names it and grants
    /// nothing. Key: id16(conversation) + id16(summary).
    COMPACTION_CONVERSATION_RECEIPT_BY_CONVERSATION: VaultMeta b"compaction:conversation_receipt_by_conversation:v1:" Raw Engine
        [restore: content] [family: unclassified] [tier: canonical];
    /// Immutable derived text summary of one output, keyed by source content hash and summarization-
    /// recipe hash. Key: hash32 + hash32.
    COMPACTION_OUTPUT_SUMMARY: VaultMeta b"context:summary:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// TURN to SESSION membership row. Key: id16.
    SESSION_TURN_MEMBERSHIP: VaultMeta b"session_lifecycle:v0:turn_session:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// SESSION to TURN membership index. Key: id16 + id16.
    SESSION_TURNS: VaultMeta b"session_turns:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
}
