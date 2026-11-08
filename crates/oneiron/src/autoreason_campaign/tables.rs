//! The side tables `autoreason_campaign` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// One-shot consumption marker and promotion receipt for a specific authoring strategy's sealed
    /// BEAM measurement. Two shapes share this key over its lifetime (a non-JSON consumption
    /// sentinel, then a JSON receipt) and no reader ever decodes it — every access is a raw
    /// presence or byte-equality check — so the codec is `Raw`, not `LegacyJson`.
    /// Key: hex64 (sha256 hex digest of the content-pinned strategy).
    AUTOREASON_BEAM_ONCE: VaultMeta b"authoring/beam-once/" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Pointer to the current default (winning) authoring strategy pin and its promotion receipt.
    /// Key: ().
    AUTOREASON_BEAM_DEFAULT: VaultMeta b"authoring/default-beam-winner" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// One claim-authoring campaign (OF-366): its strategy skill pin, fixed config, strategy pin
    /// and BEAM promotion receipt. Key: id16 (root attempt).
    AUTORESEARCH_AUTHORING: VaultMeta b"autoresearch:authoring:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// One finalized claim-authoring tournament run: winner, landed approval, team receipt ref,
    /// terminal receipt ref and settled outcome. Key: id16 (root attempt) + id16 (run attempt).
    AUTORESEARCH_AUTHORING_RUN: VaultMeta b"autoresearch:authoring_run:v2:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// One autoresearch candidate's held-out basis, its one sealed confirmation (consumed before
    /// the cohort is released) and its promotion receipt. Key: id16 (root attempt) + id16
    /// (candidate attempt).
    AUTORESEARCH_BASIS: VaultMeta b"autoresearch:basis:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// One bound autoresearch campaign: its ruler, goal pin, policy digest, cohort and budget
    /// share, written once. Key: id16 (root attempt).
    AUTORESEARCH_BINDING: VaultMeta b"autoresearch:binding:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// One autoresearch host continuation (FIX 886): the bootstrap measure or one selection
    /// round's work, its pending tasks, the run in flight with its reservation, and the runs it
    /// dispatched. Key: id16 (root attempt) + u64be (0 bootstrap, n + 1 round n).
    AUTORESEARCH_CONTINUATION: VaultMeta b"autoresearch:continuation:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::autoreason_campaign::research::erase_release_source_rows_in_txn;
    /// Round-robin cursor of the research continuation sweep: the last served root id16.
    /// Key: ().
    AUTORESEARCH_CONTINUATION_CURSOR: VaultMeta b"autoresearch:continuation_cursor:v1" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// One held-out selection benchmark of an autoresearch parent-selection estimator version
    /// against the DGM formula, recorded once. Key: string (estimator version).
    AUTORESEARCH_ESTIMATOR: VaultMeta b"autoresearch:estimator:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// One autoresearch experiment node annotating an existing attempt: lineage, candidate pin,
    /// search and held-out evidence, buggy, weave and prune receipts. Key: id16 (root attempt) +
    /// id16 (node attempt).
    AUTORESEARCH_NODE: VaultMeta b"autoresearch:node:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Immutable output descriptor and original placement/scoring receipts. Key: root attempt id16.
    AUTORESEARCH_OUTPUT_ARCHIVE: VaultMeta b"autoresearch:output-archive:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Exact output refs produced by one campaign replay arm. Key: root id16 + node id16.
    AUTORESEARCH_OUTPUT_REPLAY: VaultMeta b"autoresearch:output-replay:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// One RSI reservation an autoresearch campaign holds or held. Key: id16 (root attempt) +
    /// id16 (reservation id).
    AUTORESEARCH_RESERVATION: VaultMeta b"autoresearch:reservation:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// One autoresearch selection round's receipt. Key: id16 (root attempt) + u64be (round).
    AUTORESEARCH_ROUND: VaultMeta b"autoresearch:round:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// One deferred tournament-lineage walk's persisted position (FIX 9581).
    /// Key: id16 (team leader attempt) + id16 (tournament run attempt).
    AUTORESEARCH_TOURNAMENT_CURSOR: VaultMeta b"autoresearch:tournament_cursor:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
}
