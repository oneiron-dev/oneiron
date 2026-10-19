//! Scope-honesty world names come only from actor-admitted claim rows.
use super::*;

impl Memory<'_> {
    /// Scope honesty: worlds holding surfaceable claims outside the worlds
    /// this recall read, base reality included under its reserved id. The
    /// census reads the first [`SCOPE_HONESTY_SCAN_CAP`] claims the actor may
    /// read and says when it stopped there, or when the recall's answer came
    /// due before it finished.
    pub(super) fn out_of_scope_worlds(
        &self,
        lane: &ScopedRead<'_>,
        receipt: &mut ScopedReadReceipt,
        read: &crate::pipeline::WorldAuthoritySet,
        deadline: Option<&crate::retrieval_depth::RetrievalDeadline>,
    ) -> MemoryResult<ScopeHonesty> {
        let mut stopped = false;
        let ids = self.census_claim_ids(lane, deadline, &mut stopped)?;
        let mut worlds = BTreeSet::new();
        for chunk in ids.chunks(128) {
            if deadline.is_some_and(crate::retrieval_depth::RetrievalDeadline::answer_due) {
                stopped = true;
                break;
            }
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
            census_capped: stopped || ids.len() >= SCOPE_HONESTY_SCAN_CAP,
        })
    }

    /// The first [`SCOPE_HONESTY_SCAN_CAP`] CLAIM ids the census reads. Off
    /// this device a CLAIM a device-local world keeps is passed over before
    /// it takes a place, so the cap and the capped flag count none of them
    /// (DEC-0005). A recall whose answer comes due stops the scan.
    fn census_claim_ids(
        &self,
        lane: &ScopedRead<'_>,
        deadline: Option<&crate::retrieval_depth::RetrievalDeadline>,
        stopped: &mut bool,
    ) -> MemoryResult<Vec<EntityId>> {
        // Bounded page primitive, not `entities_by_type().take(cap)`: the
        // latter materializes the whole CLAIM index before `take` can run.
        let page = |after: Option<&EntityId>| {
            self.vault
                .entities_by_type_page(ENTITY_TYPE_CLAIM, after, SCOPE_HONESTY_SCAN_CAP)
        };
        if !lane.off_device() {
            return Ok(page(None)?);
        }
        let mut ids = Vec::new();
        let mut after = None;
        loop {
            if deadline.is_some_and(crate::retrieval_depth::RetrievalDeadline::answer_due) {
                *stopped = true;
                return Ok(ids);
            }
            let raw = page(after.as_ref())?;
            let exhausted = raw.len() < SCOPE_HONESTY_SCAN_CAP;
            after = raw.last().copied();
            let readable = self
                .vault
                .off_device_readable_for(raw, lane.actor_key().destination())?;
            let room = SCOPE_HONESTY_SCAN_CAP - ids.len();
            ids.extend(readable.into_iter().take(room));
            if exhausted || ids.len() >= SCOPE_HONESTY_SCAN_CAP {
                return Ok(ids);
            }
        }
    }
}
