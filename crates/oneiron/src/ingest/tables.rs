//! The side tables `ingest` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Record-only occurrence of the accepted provider-event archive version one inbound
    /// MESSAGE landed from (FIX 10851): provenance metadata only, never read/delete
    /// authority. Key: id16 (MESSAGE).
    CONNECTOR_MESSAGE_ARCHIVE: VaultMeta b"connector.conversation_archive.v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Classifier-derived annotation (derivation envelope + annotation body) for one imported docs
    /// page/asset. Key: hex32 ":" hex32.
    INGEST_DOCS_ANNOTATION: VaultMeta b"docs-annotation:v1:" LegacyJson Admitted
        [restore: content] [family: unclassified] [tier: canonical];
    /// Approved docs source ceiling (source hash, owner, approval), keyed by the asset's hex32 id.
    INGEST_DOCS_DEEP_CEILING: VaultMeta b"docs-deep-ceiling:v1:" LegacyJson
        [restore: live] [family: unclassified] [tier: canonical];
    /// Last deep-ingest receipt for one docs asset, keyed by its hex32 id.
    INGEST_DOCS_DEEP_RECEIPT: VaultMeta b"docs-deep-receipt:v1:" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// Stable-ref index from a deterministic docs-extraction id (corpus/page/segment) to the minted
    /// entity id. Key: string.
    INGEST_DOCS_EXTRACTION: VaultMeta b"docs-extraction:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Set of chunk/summary member content-refs recorded for one imported docs asset. Key: hex32.
    INGEST_DOCS_MEMBERSHIP: VaultMeta b"docs-membership:v1:" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// The history import ledger: one row per imported source message (the conversation it landed
    /// in, its MESSAGE and TURN ids, the hash of what was imported, its revision). Key: string
    /// (`source:native message id`).
    INGEST_HISTORY_LEDGER: VaultMeta b"history-import:v1:" Named Authored [accepts: crate::ingest::ingest_history_ledger_accepts_masked]
        [restore: content] [family: unclassified] [tier: canonical];
    /// One sensitive-topic cluster of imported claims (OF-492): its topic label, the claims
    /// and import reviews seen in it, and whether it was found clear, asked of the owner
    /// (the frozen question, evidence and options) or settled as a standing rule. Key: id16
    /// (the topic id).
    IMPORT_AUDIENCE_CLUSTER: VaultMeta b"import-audience:cluster:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
}
