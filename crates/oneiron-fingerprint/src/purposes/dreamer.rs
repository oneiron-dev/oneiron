//! Purposes of the Dreamer (`crates/oneiron/src/dreamer_consolidation`, `dreamer_promotion`,
//! `dreamer_runner`, `dreamer_wake`).
//!
//! The legacy purposes from `NIGHTLY_MERGE` to `WEAVE_RECIPE_CLAIM` are ids by the legacy
//! material rule (`EntityId::derive_legacy_material`): plain BLAKE3, the tag's bytes first, then
//! a u64 little-endian salt, then each part as its u64 little-endian length and its bytes. The
//! id is the first 16 bytes, with no version stamp; a reserved result takes the next salt.
//! Every one of these ids is a key that vaults already hold, so its bytes are kept until the
//! launch reset (PLAN-UC-04 stage 9). The three after them are digests; each entry says what
//! it hashes.

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
    /// Each claim a nightly merge attempt writes (`dreamer_consolidation::nightly_merge`,
    /// through `NightlyWrite`). Parts: the attempt, the claim's index among its drafts (u64
    /// big-endian).
    NIGHTLY_MERGE = (Blake3, HashedFirst, "oneiron:nightly:merge:v1");

    /// Each claim a nightly link continuation writes (`dreamer_consolidation::nightly_links`,
    /// through `NightlyWrite`). Parts: as `NIGHTLY_MERGE`.
    NIGHTLY_LINKS = (Blake3, HashedFirst, "oneiron:nightly:links:v1");

    /// An agent's own-time cycle at one boundary (`dreamer_runner::free_time::cycle::cycle_id`).
    /// Parts: the agent, the boundary (big-endian).
    FREE_TIME_CYCLE = (Blake3, HashedFirst, "oneiron:free_time:cycle:v1");

    /// A cycle's item of one kind, the same for every try of it
    /// (`dreamer_runner::free_time::cycle::item_id`). Parts: the cycle, the kind's code byte.
    FREE_TIME_ITEM = (Blake3, HashedFirst, "oneiron:free_time:item:v1");

    /// A cycle's extra own-time item of one round, the same for every try of that round (FIX
    /// 7763; `dreamer_runner::free_time::cycle::round_item_id`). Parts: the cycle, the round
    /// (big-endian).
    FREE_TIME_ROUND_ITEM = (Blake3, HashedFirst, "oneiron:free_time:item:round:v1");

    /// An item's proposed suggestion claim, one per item so a replay proposes nothing twice
    /// (`dreamer_runner::free_time::items::propose_suggestion`). Parts: the item.
    FREE_TIME_SUGGESTION = (Blake3, HashedFirst, "oneiron:free_time:suggestion:v1");

    /// The vault's one Dreamer tuning config artifact
    /// (`dreamer_runner::maintenance::evaluation::tuning_artifact`). No parts.
    TUNING_CONFIG = (Blake3, HashedFirst, "oneiron:dreamer-tuning-config:v1");

    /// An OF-360 harness baseline (`dreamer_runner::maintenance::evaluation::of360`). Parts: one
    /// part, the JSON of the tuple (artifact hex, dataset digest, metric, metric definition
    /// digest).
    HARNESS_OF360_BASELINE = (Blake3, HashedFirst, "oneiron:dreamer-harness-of360-baseline:v1");

    /// A maintenance finding, under its content's id so the same finding lands once
    /// (`dreamer_runner::maintenance::proposals::finding_id`). Parts: the subject, the
    /// predicate, the JSON value.
    MAINTENANCE_PROPOSAL = (Blake3, HashedFirst, "oneiron:dreamer-maintenance-proposal:v1");

    /// A Dreamer representation (`dreamer_runner::maintenance::representation`). Parts: its
    /// encoded bytes.
    REPRESENTATION = (Blake3, HashedFirst, "oneiron:dreamer-representation:v1");

    /// A wake's weave recipe claim (`dreamer_wake::recipe::claim_id`). Parts: the attempt.
    WEAVE_RECIPE_CLAIM = (Blake3, HashedFirst, "oneiron:dreamer:weave-recipe-claim:v1");

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
