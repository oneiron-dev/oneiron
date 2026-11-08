//! The side tables `off_record` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Deduplicated marker (single byte) recording which sync window a promoted turn's replayed
    /// closure spans, picked up by later sync replay. Key: yyyy-mm ":" hex32.
    OFF_RECORD_PROMOTE_PICKUP_MARKER: SyncState b"pm:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// An entity document's state vector (document family). Key: hex32.
    DOCUMENT_STATE_VECTOR: SyncState b"sv:e:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// The secret scan's hit in one raw-output body (its reason string), keyed by the same
    /// content handle; absent for a body it found nothing in. Key: string.
    CODE_RUN_RAW_OUTPUT_SECRET: VaultMeta b"code_run:raw_output:secret:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// The taint refs beside one raw-output row, keyed by the same content handle, in the same
    /// transaction. Key: string.
    CODE_RUN_RAW_OUTPUT_TAINT: VaultMeta b"code_run:raw_output:taint:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Durable receipt that a later save copied one off-record message into a turn its stretch had
    /// already promoted. Key: id16 (the message).
    OFF_RECORD_COPY_RECEIPT: VaultMeta b"offrecord_copy:v0:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Durable retry receipt recording the outcome of promoting one off-record turn into base
    /// storage. Key: id16.
    OFF_RECORD_PROMOTE_RECEIPT: VaultMeta b"offrecord_promote:v0:" Named
        [restore: content] [family: unclassified] [tier: canonical];
}
