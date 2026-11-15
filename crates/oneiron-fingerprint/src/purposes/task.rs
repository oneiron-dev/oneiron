//! Purposes of tasks (`crates/oneiron/src/task_verb`, `task_type`, `campaign`).

purposes! {}

legacy_purposes! {
    /// The request one `tasks.post` binds (`task_verb::highway_post::request_digest`): plain
    /// BLAKE3, the tag's bytes, then the named MessagePack of (actor, key, brief digest,
    /// assignee, spec, ttl, label, parent, due time, watch), unframed. The TASK's provenance
    /// and the parked post's stamp keep it; a replay under the same key with another digest
    /// is refused.
    POST_REQUEST = (Blake3, HashedFirst, "oneiron.tasks.post.request.v1");

    /// One prepared campaign request (`campaign::enrollment::approval`): plain BLAKE3, the
    /// tag's bytes, then the query, campaign, entity, program, step and sender ids (16 bytes
    /// each), the epoch (u64 big-endian), the consequence id, the call sequence (u64
    /// big-endian), the payload digest, the channel and the verb (each a u64 big-endian
    /// length and its bytes) and the idempotency byte. The third part of the retained
    /// table's key: a later ask under it reuses the retained target.
    CAMPAIGN_RETAINED_REQUEST =
        (Blake3, HashedFirst, "oneiron.campaign.enrollment.retained_request.v1");
}
