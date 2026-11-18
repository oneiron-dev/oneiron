//! Purposes of the Dreamer (`crates/oneiron/src/dreamer_consolidation`,
//! `crates/oneiron/src/dreamer_promotion`, `crates/oneiron/src/dreamer_runner`,
//! `crates/oneiron/src/dreamer_wake`).
//!
//! A proactivity digest's locator is the key it is stored under, and the name every
//! notification and the board pointer carry; its content hash is stored in the digest and
//! compared on every read. A free-time policy's digest is stored as the next policy's
//! `prior` and signed into the authority log's policy setting act, a receipt that cites
//! it. So each keeps its bytes (K, PLAN-UC-04 6.2). Each of these three is BLAKE3 of a
//! value's JSON and writes no tag: their names are registry names only. The entries after
//! them say what each one hashes.
//!
//! The extraction reads (`crates/oneiron/src/snapshot_read`) send their pins and equality
//! tokens to the Dreamer's extraction job, which compares them across its reads. Main has
//! sent them since the reads landed, so they keep their bytes too (the `EXTRACTION_*`
//! entries).

purposes! {}

legacy_purposes! {
    /// A proactivity digest's locator (`digest_id`): every field it shows, as assembled.
    PROACTIVITY_DIGEST_LOCATOR =
        (Blake3, NotHashed, "oneiron.dreamer.proactivity_digest_locator.v1");

    /// A proactivity digest's content hash (`content_hash`): its locator and every field it
    /// shows, as admitted.
    PROACTIVITY_DIGEST_CONTENT_HASH =
        (Blake3, NotHashed, "oneiron.dreamer.proactivity_digest_content_hash.v1");

    /// A free-time policy's digest (`policy_digest`): the policy as JSON, `null` for none.
    FREE_TIME_POLICY_DIGEST = (Blake3, NotHashed, "oneiron.dreamer.free_time_policy_digest.v1");

    /// An agent-health trend DIAGNOSTIC's replay hash
    /// (`dreamer_runner::maintenance::agent_health::trend_output`). BLAKE3: the tag first;
    /// the margin (`actor` and the actor id, or `project` and the project id, 16 zero bytes
    /// when none; the words and ids not framed); the task-type node; the model, or one
    /// `0xff` byte when none; the metric token; then per side, prior then latest, its first
    /// and last day, numerator, denominator, known and eligible counts (each 8 bytes, u64
    /// little-endian), the attempt count and each attempt id, the ref count and each ref id,
    /// and the scope count and each scope. Every string is framed by its length and every
    /// count is written, each as a u64 little-endian. Stored as the DIAGNOSTIC body's
    /// `replay.content_hash`, which the row id binds, and returned in diagnostic reads.
    AGENT_HEALTH_TREND = (Blake3, HashedFirst, "oneiron.coach.agent_health.trend.v1");

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

    /// An extraction observation's identity equality token
    /// (`snapshot_read::extraction_observations::tokens`). Plain BLAKE3, the tag first, one
    /// zero byte, then the `serde_json` bytes of the native conflict identity as the array
    /// (subject, predicate, world, facet, relationships, project, topic), each id as hex
    /// text, with no length. Its lowercase hex is sent with the fact rows of an
    /// observations page, and the extraction job compares two rows' tokens for equality.
    EXTRACTION_IDENTITY_TOKEN = (Blake3, HashedFirst, "oneiron:extraction:identity-token:v1");

    /// An extraction observations read's facts pin
    /// (`snapshot_read::extraction_observations::paging::observation_facts_pin`). Plain
    /// BLAKE3, the tag first, one zero byte, then the `serde_json` bytes of the tuple
    /// (attempt, clock, candidates, policy pin, complete fact set), with no length. Its
    /// lowercase hex is sent on every page and inside every cursor: the read refuses a
    /// cursor whose pin differs, and the extraction job compares the pin across its pages
    /// and with the selection it routes from.
    EXTRACTION_OBSERVATION_FACTS = (Blake3, HashedFirst, "oneiron:extraction:observations-facts:v1");

    /// The effective extraction policy's pin
    /// (`snapshot_read::extraction_inputs::extraction_policy_pin`). Plain BLAKE3, the tag
    /// first, then the `serde_json` bytes of the policy, with no separator and no length.
    /// Its lowercase hex is sent on every inputs page and every observations page, and the
    /// extraction job compares it across its reads, its config and its selection.
    EXTRACTION_POLICY = (Blake3, HashedFirst, "oneiron.dreamer.extraction.policy.v1");

    /// An extraction observation's same-slice equality token: the recipe of
    /// [`EXTRACTION_IDENTITY_TOKEN`] under its own tag, over the `serde_json` bytes of the
    /// array (subject, world, facet, relationships, project).
    EXTRACTION_SLICE_TOKEN = (Blake3, HashedFirst, "oneiron:extraction:slice-token:v1");

    /// An extraction observation's question equality token: the recipe of
    /// [`EXTRACTION_IDENTITY_TOKEN`] under its own tag, over the native topic key's bytes.
    EXTRACTION_TOPIC_TOKEN = (Blake3, HashedFirst, "oneiron:extraction:topic-token:v1");

    /// An extraction observation's value equality token: the recipe of
    /// [`EXTRACTION_IDENTITY_TOKEN`] under its own tag, over the normalized native value
    /// key's bytes.
    EXTRACTION_VALUE_TOKEN = (Blake3, HashedFirst, "oneiron:extraction:value-token:v1");

    /// A Coach site-skill candidate's fingerprint, the key of its seen marker
    /// (`dreamer_runner::maintenance::site_skills::distill::digest`): plain BLAKE3, the tag's
    /// bytes, then each part as its u64 big-endian length and its bytes. Parts: the distill
    /// version (u32 big-endian), the site, and the candidate's JSON body. It differs from
    /// `browser_library::PROGRAM_CANDIDATE`, so the two facets never share a seen marker.
    SITE_SKILL_DISTILL = (Blake3, HashedFirst, "oneiron:coach-site-skill-distill:v1");
}
