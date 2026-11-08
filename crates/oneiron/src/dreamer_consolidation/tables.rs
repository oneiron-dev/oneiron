//! The side tables `dreamer_consolidation` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// FIX 2425: one candidate a Dreamer attempt decided a correction for, kept before the
    /// branch builds, filters or selects it: its subject, the claim it corrects and its kept
    /// decisions, never its value. Key: id16 (attempt) + u64be(position).
    DREAMER_CANDIDATE_DECISION: VaultMeta b"dreamer:candidate_decision:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Operator-set predicate key rules governing which claim keys the consolidator may fold;
    /// defaults from key_defaults.json when absent. Key: ().
    /// Resident-owned v1 failure rules, stored as the validated JSON payload with its author.
    /// Key: ().
    DREAMER_FAILURE_RULES: VaultMeta b"dreamer:consolidation:failure_rules:v1" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    DREAMER_CONSOLIDATION_KEY_RULES: VaultMeta b"dreamer:consolidation:keys:v1" LegacyJson
        [restore: live] [family: unclassified] [tier: canonical];
    /// Owner-root reference pins and immutable child evidence accounting. Key: id16(root).
    DREAMER_CONSOLIDATION_ROOT: VaultMeta b"dreamer:consolidation:root:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::dreamer_consolidation::root_evidence::erase_actor_in_txn;
    /// FIX 7729: the buckets a MACRO run its preparation narrowed holds, under its lease
    /// generation; node-local lease state. Key: id16(attempt).
    DREAMER_CONSOLIDATION_RUNNING_BUCKETS: VaultMeta b"dreamer:consolidation:running_buckets:v1:"
        Named Engine
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// Operator-set consolidation candidate-selection config (strength weights, caps). Key: ().
    DREAMER_CONSOLIDATION_SELECTION: VaultMeta b"dreamer:consolidation:selection:v1" LegacyJson
        [restore: live] [family: unclassified] [tier: canonical];
    /// Parent-verified promotion evidence observations. Key: id16(claim).
    DREAMER_CONSOLIDATION_STRENGTH: VaultMeta b"dreamer:consolidation:strength:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Pre-archive claim revision and strength policy. Key: id16(claim) + u64be(at_ms).
    DREAMER_CONSOLIDATION_STRENGTH_ARCHIVE: VaultMeta b"dreamer:consolidation:strength_archive:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Operator-set archive-only strength lifecycle. Key: ().
    DREAMER_CONSOLIDATION_STRENGTH_POLICY: VaultMeta b"dreamer:consolidation:strength_policy:v1" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// Per-scope, per-partition consolidation cursor row. Key: u8 + hash32.
    DREAMER_CURSOR: VaultMeta b"dreamer:cursor:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Operator-set conversation ids excluded from Dreamer consolidation. Key: ().
    DREAMER_EXCLUDED_CONVERSATIONS: VaultMeta b"dreamer:excluded_conversations:v1" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// Branch-scoped reflection-gap queue namespaced by partition hash and the branch's
    /// relationship/project scope axes. Key: hex64 ":" hex32-or-"none" ":" hex32-or-"none" ":"
    /// hash32.
    DREAMER_GAP_BRANCH: VaultMeta b"dreamer:gap-branch:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Global reflection-gap queue row keyed by a hash of (kind, subject). Key: hash32.
    DREAMER_GAP: VaultMeta b"dreamer:gap:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// The first try of one Dreamer retry's lineage, pinned when the retry is minted (FIX 9350)
    /// so a compaction that folds that try never moves the namespace its people mint under. Key:
    /// id16(retry); value: the origin attempt id.
    DREAMER_LINEAGE_ORIGIN: VaultMeta b"dreamer:lineage-origin:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// The entity and claim ids one Dreamer attempt's extraction listed for its model, or one
    /// NOTE's within a NOTE review attempt (FIX 7578), so a replay lists the same ones. Ids only,
    /// never their text. Key: id16(attempt), then id16(note) for a NOTE's listing.
    DREAMER_NEIGHBOURHOOD: VaultMeta b"dreamer:neighbourhood:v1:" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// Atomic merge/narrative outputs for one nightly fan-in receipt. Key: id16.
    DREAMER_NIGHTLY_MERGED: VaultMeta b"dreamer:nightly:merged:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Promoted/attached proposal ids returned by one nightly child. Key: id16.
    DREAMER_NIGHTLY_OUTPUT: VaultMeta b"dreamer:nightly:output:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// The NOTE review's page cursor: the last NOTE id a review finished. Key: ().
    DREAMER_NOTE_REVIEW_CURSOR: VaultMeta b"dreamer:note-review:cursor:v1" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// What a NOTE review last read and decided for one NOTE: the BLAKE3 of the markdown, so an
    /// unchanged NOTE is not read again, its verdict and importance, and a sealed pad's missed
    /// keep lines with the re-asks spent on them (FIX 2240). Key: id16.
    DREAMER_NOTE_REVIEW_SEEN: VaultMeta b"dreamer:note-review:seen:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// The NOTE review's topic index (FIX 7457): one row per reviewed NOTE under the topic
    /// membership its review record keeps, written in that record's own write. Key: topic
    /// digest(32) + id16(facet) + id16(project) + id16(note).
    DREAMER_NOTE_REVIEW_TOPIC: VaultMeta b"dreamer:note-review:topic:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// OF-490: the diary entry one resident dreaming attempt landed, so a replay writes none.
    /// Key: id16 (attempt).
    DREAMER_RESIDENT_LANDED: VaultMeta b"dreamer:resident:landed:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// OF-490: a sealed scratchpad a resident's dreaming already read. Value: one byte. Key:
    /// id16 (resident) + id16 (pad).
    DREAMER_RESIDENT_PADS: VaultMeta b"dreamer:resident:pads:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// OF-490: what a resident's dreaming has read so far: newest receipt and INBOX times, last
    /// dreaming, entries written. Key: id16 (resident).
    DREAMER_RESIDENT_PROGRESS: VaultMeta b"dreamer:resident:progress:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// FIX 7753: the rows and revisions one resident dreaming read, keyed by the diary entry it
    /// landed. Key: id16 (entry).
    DREAMER_RESIDENT_READ: VaultMeta b"dreamer:resident:read:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Pinned effective scope attenuation bound to one Dreamer attempt, inherited by retry
    /// successors. Key: id16.
    DREAMER_SELECTION_SCOPE: VaultMeta b"dreamer:selection_scope:v1:" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// Latest consolidation carrier of a TURN re-dirtied without moving its row: second, a
    /// store-minted order id, the row learned_at it was taken against and the scopes that consumed
    /// it. Key: id16(turn).
    DREAMER_TURN_REDIRTY: VaultMeta b"dreamer:turn-redirty:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Per-scope (micro/meso/macro) consolidation watermark: last learned_at/turn_id progress. Key:
    /// u8.
    DREAMER_WATERMARK: VaultMeta b"dreamer:watermark:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// One person's PEOPLE `about` lines, one per sensitivity band, and the fact digests they stand
    /// on. Key: id16 (PERSON).
    PEOPLE_ABOUT: VaultMeta b"people:about:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
}
