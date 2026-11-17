//! Purposes of the Dreamer (`crates/oneiron/src/dreamer_consolidation`,
//! `crates/oneiron/src/dreamer_promotion`).

purposes! {}

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
