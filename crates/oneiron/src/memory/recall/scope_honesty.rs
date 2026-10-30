//! Scope-honesty world names come only from actor-admitted claim rows.
use super::*;

/// Claims the census judges in one read, as recall reads rows.
const CENSUS_PAGE: usize = 128;

impl Memory<'_> {
    /// Scope honesty: worlds holding surfaceable claims outside the worlds
    /// this recall read, base reality included under its reserved id. The
    /// census walks the claim world index: a world the recall read is passed
    /// over at one key read, and in any other world it judges claims as the
    /// actor reads them until one it may read is surfaceable, which names the
    /// world. The index only finds candidates: each name comes from a claim
    /// row the actor's read admitted, judged by its own body. It judges at
    /// most [`SCOPE_HONESTY_SCAN_CAP`] claims and says when it stopped there,
    /// or when the recall's answer came due before it finished. The receipt
    /// counts the rows it judged.
    pub(super) fn out_of_scope_worlds(
        &self,
        lane: &ScopedRead<'_>,
        receipt: &mut ScopedReadReceipt,
        read: &crate::pipeline::WorldAuthoritySet,
        deadline: Option<&crate::retrieval_depth::RetrievalDeadline>,
    ) -> MemoryResult<ScopeHonesty> {
        let mut worlds = BTreeSet::new();
        let mut judged = 0;
        let mut stopped = false;
        let mut after_world = None;
        'worlds: loop {
            let Some(world) = self.next_census_world(after_world)? else {
                break;
            };
            after_world = Some(world);
            if read.admits(Some(world)) {
                continue;
            }
            let mut after = None;
            loop {
                if deadline.is_some_and(crate::retrieval_depth::RetrievalDeadline::answer_due) {
                    stopped = true;
                    break 'worlds;
                }
                let room = SCOPE_HONESTY_SCAN_CAP - judged;
                if room == 0 {
                    break 'worlds;
                }
                let Some((ids, last)) = self.census_world_page(lane, world, after, room)? else {
                    break;
                };
                after = Some(last);
                if ids.is_empty() {
                    continue;
                }
                judged += ids.len();
                let reads: Vec<_> = ids.into_iter().map(PointRead::id).collect();
                let scoped = lane.read(&reads, None)?;
                receipt.restrict_with(&scoped.receipt);
                for row in scoped.value.into_iter().flatten() {
                    let Some(bytes) = row.body else { continue };
                    let body = crate::claim::decode_claim_body(&bytes, true)?;
                    if claim_surfaceable(&body) && !read.admits(body.world) {
                        worlds.insert(
                            body.world
                                .unwrap_or_else(crate::claim::base_world_id)
                                .to_hex(),
                        );
                    }
                }
                if worlds.contains(&world.to_hex()) {
                    break;
                }
            }
        }
        Ok(ScopeHonesty {
            out_of_scope_worlds: worlds.into_iter().collect(),
            census_capped: stopped || judged >= SCOPE_HONESTY_SCAN_CAP,
        })
    }

    /// The next world after `after` that the claim world index holds.
    fn next_census_world(&self, after: Option<EntityId>) -> MemoryResult<Option<EntityId>> {
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(crate::error::Error::from)?;
        Ok(crate::claim::next_claim_world_in_txn(
            &self.vault.store,
            &txn,
            after,
        )?)
    }

    /// The next page of `world`'s claims after `after`, at most `room` of
    /// them, and the last id the page read; `None` once the world is read
    /// through. Off this device a claim a device-local world keeps is passed
    /// over before the census judges it, so the cap counts none of them
    /// (DEC-0005).
    fn census_world_page(
        &self,
        lane: &ScopedRead<'_>,
        world: EntityId,
        after: Option<EntityId>,
        room: usize,
    ) -> MemoryResult<Option<(Vec<EntityId>, EntityId)>> {
        let page = {
            let txn = self
                .vault
                .store
                .env
                .read_txn()
                .map_err(crate::error::Error::from)?;
            crate::claim::claim_ids_for_world_page_in_txn(
                &self.vault.store,
                &txn,
                world,
                after,
                room.min(CENSUS_PAGE),
            )?
        };
        let Some(last) = page.last().copied() else {
            return Ok(None);
        };
        let ids = if lane.off_device() {
            self.vault
                .off_device_readable_for(page, lane.actor_key().destination())?
        } else {
            page
        };
        Ok(Some((ids, last)))
    }
}
