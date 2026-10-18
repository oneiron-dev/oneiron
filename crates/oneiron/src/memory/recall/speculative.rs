//! Bind OF-108 to the same credential, selected worlds and policy as recall.
use std::sync::Arc;

use super::{Memory, MemoryError, MemoryResult, RecallScope, recall_kinds};
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
        let worlds = self.recall_worlds(scope)?;
        let mut key = self.read_key()?;
        if let Some(worlds) = &worlds {
            key = key.within_worlds(worlds.clone());
        }
        let read = SpeculativeReadScope {
            key,
            worlds: worlds.map_or(WorldScope::All, WorldScope::WorldSet),
            corpus: self.selected_projects(scope)?,
            facet: scope
                .facet
                .as_deref()
                .map(|reference| self.resolve_ref(reference))
                .transpose()?,
            kinds: recall_kinds(scope)?,
        };
        Ok(SpeculativeSession::new(vault, config).with_scope(read))
    }
}
