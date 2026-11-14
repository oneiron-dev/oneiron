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
    /// longer reads: it was erased or retracted, or the read narrowed past
    /// it. The lane is a recall's: surfaceable claims, the scope's worlds and
    /// facet, `as_of`'s judgment, the bound filter and a room turn's ceiling.
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
        let lane = match unfaceted.worlds() {
            Some(worlds) => lane.within_worlds(worlds.clone()),
            None => lane,
        };
        let lane = lane
            .with_judged_at(as_of)
            .with_read_filter(self.read_filter.as_ref());
        let mut receipt = lane.search_receipt(None, 0)?;
        if receipt.applied.deny_all && !pins.is_empty() {
            return Ok(None);
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
