//! Legacy dreamer-consolidation digests stored or compared by existing records.
//!
//! Call-label bindings, follower cache and route pins, note fingerprints,
//! partition and round keys, child judgements, summary params and message
//! attributions retain their exact bytes through the K door (K, PLAN-UC-04
//! stage 7).

purposes! {}

legacy_purposes! {
    /// Arc composition params: the `serde_json` bytes of the tuple (instruction,
    /// model id, the Arc output schema, "oneiron:arc-summary-composition:v1"), no
    /// length or hashed tag (the tag is a registry name only). Stored as the
    /// composed summary derivation's params_hash, which also keys its memo.
    ARC_COMPOSITION_PARAMS = (Blake3, NotHashed, "oneiron.dreamer_consolidation.arc_composition_params.v1");

    /// Arc parts params: the `serde_json` bytes of the tuple (instruction, model
    /// id, the Arc output schema, "oneiron:arc-summary-parts:v1", window), no
    /// length or hashed tag (the tag is a registry name only). Stored as
    /// ArcPins.params_hash in ARC_WORK.
    ARC_PARTS_PARAMS = (Blake3, NotHashed, "oneiron.dreamer_consolidation.arc_parts_params.v1");

    /// Call labels: the tag; an absent mint `[0]`, or `[1]`, its u64-BE byte
    /// length and bytes; each label kind in LabelKind order and each id in
    /// assignment order: the label text (prefix letter, then the number from 1)
    /// as a u64-BE byte length and UTF-8, then the raw 16-byte id; then each
    /// choice question in EntityId order: "choices", the raw 16-byte question
    /// id, the option count as u64-BE, each option as a u64-BE byte length and
    /// UTF-8. Its lowercase hex is sent as the request's call_labels digest.
    CALL_LABELS = (Blake3, HashedFirst, "oneiron:dreamer-call-labels:v1");

    /// Child judgement: the `serde_json` bytes of a ConsolidationJudgement, no
    /// length or hashed tag (the tag is a registry name only). Stored as
    /// ConsolidationChildReceipt.judgement_hash in ROOTS; the bridge compares
    /// each child's rebuilt hash with it.
    CHILD_JUDGEMENT = (Blake3, NotHashed, "oneiron.dreamer_consolidation.child_judgement.v1");

    /// Follower reported cache: the tag, then the `serde_json` bytes of the last
    /// non-empty cache identity the backend reported, without a length. Stored
    /// as the follower session's reported_cache in DREAMER_FOLLOWER_STATE.
    FOLLOWER_REPORTED_CACHE = (Blake3, HashedFirst, "oneiron:dreamer-follower:cache-identity:v1");

    /// Follower route: the tag, the model id's u64-BE byte length and UTF-8,
    /// then the locality's `Debug` name UTF-8 without a length. Stored as the
    /// follower session's route and compared: a change resends the prefix cold
    /// under a new epoch.
    FOLLOWER_ROUTE = (Blake3, HashedFirst, "oneiron:dreamer-follower:route:v1");

    /// Message attribution: the tag, the author count as u64-BE, each raw
    /// 16-byte author id in the order given, then an absent speaker `[0]`, or
    /// `[1]` and the raw 16-byte speaker id. Stored as a MESSAGE slice's
    /// attribution pin and compared when the projection is read again.
    MESSAGE_ATTRIBUTION = (Blake3, HashedFirst, "oneiron:message-attribution:v1");

    /// Note text: the tag, the read mode's u64-BE byte length and UTF-8, then the
    /// text's u64-BE byte length and UTF-8. Stored as a summary source note's
    /// fingerprint pin.
    NOTE_TEXT = (Blake3, HashedFirst, "oneiron:dreamer-note-text:v1");

    /// Partition: the tag (the v1 bucket domain, DESIGN-PIN A2), "partition",
    /// the raw 16-byte conversation id, then world and facet, each as absent
    /// `[0]` or `[1]` and the raw 16-byte id. Unless the project is the
    /// default project, append "project" and the project in the same optional
    /// id encoding. Keys DREAMER_CURSOR rows and queue rows.
    PARTITION = (Blake3, HashedFirst, "oneiron:dreamer-bucket:v1");

    /// Partition round: the tag, the TURN count as u64-BE, then each TURN in
    /// batch order: learned_at as u64-BE and the raw 16-byte selection id (its
    /// re-dirty carrier's id when carried, else the TURN id). The exact-batch
    /// part of a consolidation attempt's stored dedupe key.
    PARTITION_ROUND = (Blake3, HashedFirst, "oneiron:dreamer-partition-round:v1");

    /// Session pages params: the `serde_json` bytes of the tuple (instruction,
    /// model id, the session output schema, "oneiron:session-summary-pages:v1",
    /// window), no length or hashed tag (the tag is a registry name only).
    /// Compared with the stored summary derivation's params_hash before a paged
    /// composition is reused.
    SESSION_PAGES_PARAMS = (Blake3, NotHashed, "oneiron.dreamer_consolidation.session_pages_params.v1");
}
