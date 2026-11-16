//! Purposes of the Dreamer (`crates/oneiron/src/dreamer_consolidation`,
//! `crates/oneiron/src/dreamer_promotion`, `dreamer_runner`).

purposes! {
    /// An intent ask's question (`dreamer_consolidation::gap::intent`). Parts: its TURN, the
    /// words it quotes.
    INTENT_ASK_QUESTION = "oneiron.dreamer.intent_ask.question.v1";

    /// The intent a yes lands (`dreamer_consolidation::gap::intent`). Parts: the ask.
    INTENT_ASK_CLAIM = "oneiron.dreamer.intent_ask.claim.v1";

    /// Each answer part's NOTE (`dreamer_consolidation::task_realize::landing`). Parts: the
    /// record, the part's index (u64 little-endian).
    TASK_REALIZE_NOTE = "oneiron.dreamer.task_realize.note.v1";

    /// A thing's host parent run (`dreamer_consolidation::thing_agent::proposals`). Parts:
    /// attempt, generation (big-endian).
    THING_PARENT_RUN = "oneiron:dreamer-thing-parent:v1";

    /// A staged draft candidate (`dreamer_consolidation::thing_agent::proposals`). Parts: step
    /// hash, index (big-endian).
    THING_DRAFT = "oneiron:dreamer-thing-draft:v1";

    /// An amendment label's source, one per settled cause row and label
    /// (`dreamer_runner::maintenance::agent_health::environment`). Parts: source, label.
    AGENT_HEALTH_AMENDMENT_CAUSE = "oneiron:agent-health-amendment-cause:v1";
}

legacy_purposes! {
    /// A multi-part consolidation branch's identity
    /// (`dreamer_consolidation::branch::ConsolidationBranchPlan::identity`). Plain BLAKE3,
    /// the tag first; the world and the facet, each `1` and the id's 16 bytes, or `0`; the
    /// thing: `0` for none, else `1`, its entity (as the world) and its grouping identity
    /// (`1` and a thread's 16 bytes, `2` and a person's, or `0` for none); the part count
    /// (u64 big-endian); for each part, its partition hash and its TURN count (u64
    /// big-endian). A one-part branch is its partition's hash instead. Its hex is in the
    /// child attempt's dedupe key and in the branch's gap, output and signals projection keys.
    BRANCH_IDENTITY = (Blake3, HashedFirst, "oneiron:dreamer-branch:v1");

    /// An evidence attachment's id (`dreamer_promotion::scoped::attachment_digests`). Plain
    /// BLAKE3, the tag first; the head's and the source's ids; the content hashes of their
    /// stored bodies; the evidence meet's name; then for each verified citation, a presence
    /// byte and its claim id, a presence byte and its byte range (start and end, u64
    /// big-endian), its quote hash and each MESSAGE slice it covers. A slice writes its
    /// MESSAGE id, its start and end (u64 big-endian), its revision, `1`, the document
    /// frontier's length (u64 big-endian) and bytes, or `0`, then, when it carries one,
    /// `source_attribution` and the attribution hash. The first 16 bytes are the support
    /// assertion's provenance claim id.
    EVIDENCE_ATTACHMENT = (Blake3, HashedFirst, "oneiron:dreamer-evidence-attachment:v1");

    /// The source revision an evidence attachment pins
    /// (`dreamer_promotion::scoped::attachment_digests`), when its citations name MESSAGE
    /// slices. Plain BLAKE3, the tag first; the content hash of the source's stored body;
    /// each slice as the attachment id writes it. The first 16 bytes are the provenance
    /// record's `source_revision_ref`; a citation that names no slice pins the body's
    /// content hash instead.
    EVIDENCE_SOURCE_REVISION = (Blake3, HashedFirst, "oneiron:dreamer-evidence-source-revision:v1");
}
