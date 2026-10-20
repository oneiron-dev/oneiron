//! Bind OF-108 to the same credential, selected worlds and policy as recall.
use std::sync::Arc;

use super::{Memory, MemoryError, MemoryResult, RecallScope};
use crate::pipeline::WorldScope;
use crate::speculative::scoped::SpeculativeReadScope;
use crate::speculative::{SpeculativeSession, SpeculativeSessionConfig};

impl Memory<'_> {
    /// Opens an utterance on this handle's own read. The Arc must name this
    /// vault; no actor id, scope or alternate vault can stand in for its proof.
    pub fn speculative_session(
        &self,
        vault: Arc<crate::Vault>,
        config: SpeculativeSessionConfig,
        scope: &RecallScope,
    ) -> MemoryResult<SpeculativeSession> {
        if !std::ptr::eq(self.vault(), Arc::as_ptr(&vault)) {
            return Err(MemoryError::bad_request(
                "speculative session belongs to another vault",
            ));
        }
        // The one resolution recall reads its scope by (FIX 5006). A reader
        // its policy denies everything reads nothing, so its facet ref is not
        // looked up first, as recall's is not (FIX 6694).
        let selection = self.recall_selection(scope, None)?;
        let lane = self.read_lane(crate::claim::ClaimReadStatus::Surfaceable)?;
        let lane = match selection.worlds() {
            Some(worlds) => lane.within_worlds(worlds.clone()),
            None => lane,
        };
        let selection = if lane.read_receipt(None, 0)?.applied.deny_all {
            selection.denied()
        } else {
            self.recall_faceted(selection, scope, None)?
        };
        let mut key = self.read_key()?;
        if let Some(worlds) = &selection.worlds {
            key = key.within_worlds(worlds.clone());
        }
        let read = SpeculativeReadScope {
            key,
            worlds: selection
                .worlds
                .map_or(WorldScope::All, WorldScope::WorldSet),
            corpus: selection.projects,
            facet: selection.facet,
            kinds: selection.kinds.listed().map(<[u8]>::to_vec),
        };
        Ok(SpeculativeSession::new(vault, config).with_scope(read))
    }
}
