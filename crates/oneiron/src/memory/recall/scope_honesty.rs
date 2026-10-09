//! Scope-honesty world names come only from actor-admitted claim rows.
use super::*;

impl Memory<'_> {
    /// Scope honesty: worlds holding surfaceable claims outside the worlds
    /// this recall read, base reality included under its reserved id. The
    /// census reads the first [`SCOPE_HONESTY_SCAN_CAP`] claims the actor may
    /// read and says when it stopped there.
    pub(super) fn out_of_scope_worlds(
        &self,
        lane: &ScopedRead<'_>,
        receipt: &mut ScopedReadReceipt,
        read: &crate::pipeline::WorldAuthoritySet,
    ) -> MemoryResult<ScopeHonesty> {
        // Bounded page primitive, not `entities_by_type().take(cap)`: the
        // latter materializes the whole CLAIM index and errors with
        // IndexOverflow past MAX_TYPE_QUERY_RESULTS before `take` can run, so
        // a large vault would hard-fail world-scoped recall.
        let ids =
            self.vault
                .entities_by_type_page(ENTITY_TYPE_CLAIM, None, SCOPE_HONESTY_SCAN_CAP)?;
        let mut worlds = BTreeSet::new();
        for chunk in ids.chunks(128) {
            let reads: Vec<_> = chunk.iter().copied().map(PointRead::id).collect();
            let scoped = lane.read(&reads, None)?;
            receipt.restrict_with(&scoped.receipt);
            for row in scoped.value.into_iter().flatten() {
                let Some(bytes) = row.body else { continue };
                let body = crate::claim::decode_claim_body(&bytes, true)?;
                if !claim_surfaceable(&body) {
                    continue;
                }
                if !read.admits(body.world) {
                    worlds.insert(
                        body.world
                            .unwrap_or_else(crate::claim::base_world_id)
                            .to_hex(),
                    );
                }
            }
        }
        Ok(ScopeHonesty {
            out_of_scope_worlds: worlds.into_iter().collect(),
            census_capped: ids.len() >= SCOPE_HONESTY_SCAN_CAP,
        })
    }
}
