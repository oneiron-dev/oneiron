//! The items of one operation's first recall, rebuilt for its replay
//! (RESEARCH-0363 p5): at the revisions that answer served, through the item
//! builder every recall uses, on the lane a recall of the same scope reads,
//! under the caller's current read.
use super::*;
use crate::memory::recall_replay::RecallReplayPin;

impl Memory<'_> {
    /// The pack `pins` name, each item read again at its served revision
    /// under this handle's current read, its retrieval accounting the first
    /// answer's (`scope_honesty`, `retrieval_meta`). `None` when an item no
    /// longer reads (it was erased or retracted, or the read narrowed past
    /// it), or when a world the first answer's census named is no longer
    /// one this read's census names. The lane is a recall's: surfaceable
    /// claims, the scope's worlds and facet, `as_of`'s judgment, the bound
    /// filter and a room turn's ceiling.
    pub(in crate::memory) fn recall_replay_pack(
        &self,
        scope: &RecallScope,
        as_of: Option<u64>,
        pins: &[RecallReplayPin],
        scope_honesty: ScopeHonesty,
        retrieval_meta: RetrievalMeta,
    ) -> MemoryResult<Option<MemoryPack>> {
        let unfaceted = self.recall_selection(scope, None)?;
        let lane = self.read_lane(ClaimReadStatus::Surfaceable)?;
        // The census lane is a recall's: the actor's whole read, past the
        // scope's worlds, under the same judgment and filter.
        let census = self
            .vault
            .scoped_read(lane.actor_key().clone())
            .with_judged_at(as_of)
            .with_read_filter(self.read_filter.as_ref());
        let lane = match unfaceted.worlds() {
            Some(worlds) => lane.within_worlds(worlds.clone()),
            None => lane,
        };
        let lane = lane
            .with_judged_at(as_of)
            .with_read_filter(self.read_filter.as_ref());
        let mut receipt = lane.search_receipt(None, 0)?;
        if receipt.applied.deny_all {
            // A read that admits nothing reads no item, names no world and
            // looks up no facet (FIX 5008): only an empty first answer
            // replays under it.
            if !pins.is_empty() || !scope_honesty.out_of_scope_worlds.is_empty() {
                return Ok(None);
            }
            let mut pack = MemoryPack {
                items: Vec::new(),
                scope_honesty,
                retrieval_meta,
                pack_version: MEMORY_PACK_VERSION,
                rendered: None,
                narrowing: Box::new(receipt),
                retrieval_run_id: None,
                residence: None,
            };
            pack.stamp_residence(home::local_residence(self.vault, None));
            return Ok(Some(pack));
        }
        let store = lane.store_read();
        let selection = self.recall_faceted(unfaceted, scope, None, &store)?;
        let mut items = Vec::with_capacity(pins.len());
        for pin in pins {
            let mode = match &pin.revision {
                Some(revision) => {
                    crate::vault::ReadMode::Pinned(crate::vault::RevisionRef::from_hex(revision)?)
                }
                None => crate::vault::ReadMode::Indexed,
            };
            let Some(mut item) = self.memory_item_for(
                &lane,
                &pin.entity,
                selection.facet,
                mode,
                &pin.cited,
                &mut receipt,
            )?
            else {
                return Ok(None);
            };
            item.embedding_matches.clone_from(&pin.embedding_matches);
            items.push(item);
        }
        // The first census's world names are a disclosure: each must still
        // be one this read's census names, or the replay answers none.
        if !scope_honesty.out_of_scope_worlds.is_empty() {
            let Some(worlds) = &selection.worlds else {
                return Ok(None);
            };
            let now = self.out_of_scope_worlds(&census, &mut receipt, worlds, None)?;
            if !scope_honesty
                .out_of_scope_worlds
                .iter()
                .all(|world| now.out_of_scope_worlds.contains(world))
            {
                return Ok(None);
            }
        }
        let mut pack = MemoryPack {
            items,
            scope_honesty,
            retrieval_meta,
            pack_version: MEMORY_PACK_VERSION,
            rendered: None,
            narrowing: Box::new(receipt),
            retrieval_run_id: None,
            residence: None,
        };
        pack.stamp_residence(home::local_residence(self.vault, Some(&selection)));
        Ok(Some(pack))
    }
}
