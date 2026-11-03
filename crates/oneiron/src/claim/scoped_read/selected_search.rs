//! A text search narrowed by a device's resolved recall scope (FIX 2905):
//! the home's side of an opened device's recall. The scope narrows the
//! candidates before the search's cut, by the worlds, projects, facet and
//! kinds the device's recall read, and folds messages into turns as recall
//! does, inside this read's own authority. It grants nothing.

use super::*;
use crate::pipeline::{FacetMode, WorldAuthoritySet, WorldScope};
use crate::sync::residence::ResolvedRecallSelection;

impl ScopedRead<'_> {
    /// [`Self::search_text`] narrowed by `scope` before its cut, returning
    /// the unit recall returns (a matched message as its turn). The read's
    /// authority, note visibility and fresh-read recheck are those of the
    /// plain search. A facet that is no FACET, a kind the registry does not
    /// name or a world set past its cap is refused with its typed error,
    /// never searched unscoped; a valid scope with no match is empty.
    pub(crate) fn search_text_selected(
        self,
        query: &str,
        limit: usize,
        scope: &ResolvedRecallSelection,
    ) -> Result<ScopedReadResult<Vec<ScoredEntity>>> {
        if let Some(kinds) = &scope.kinds
            && let Some(kind) = kinds
                .iter()
                .find(|kind| crate::registry::entity_type_registry_entry(**kind).is_none())
        {
            return Err(Error::InvalidConfig(format!(
                "recall scope names unregistered kind {kind}"
            )));
        }
        if let Some(facet) = scope.facet {
            let txn = self.vault.store.env.read_txn()?;
            let found = self
                .store_read()
                .port_entity_record(&txn, &facet)?
                .map(|row| row.entity_type);
            if found != Some(crate::registry::ENTITY_TYPE_FACET) {
                return Err(Error::Registry(crate::error::RegistryError::InvalidFacet {
                    facet,
                    found,
                }));
            }
        }
        let worlds = scope
            .worlds
            .as_ref()
            .map(|worlds| WorldAuthoritySet::new(worlds.include_base, worlds.world_ids.clone()))
            .transpose()?;
        let world_scope = match &worlds {
            None => WorldScope::All,
            Some(worlds) if worlds.include_base() && worlds.worlds().is_empty() => WorldScope::Base,
            Some(worlds) => WorldScope::WorldSet(worlds.clone()),
        };
        let corpus = if scope.project_ids.is_empty() {
            crate::corpus::CorpusScope::All
        } else {
            crate::corpus::CorpusScope::AnyOf(scope.project_ids.clone())
        };
        let kinds = crate::memory::RecallKinds::new(scope.kinds.clone());
        let read = match worlds {
            Some(worlds) => self.within_worlds(worlds),
            None => self,
        };
        let (filter, policy) = read.resolve_retrieval_filter(None)?;
        if filter.deny_all {
            return Ok(ScopedReadResult {
                value: Vec::new(),
                receipt: read.receipt_for(None, &policy, &filter, 0),
            });
        }
        let excluded = read.request_exclusions(&policy, None)?;
        let plan = read.plan_admits(&filter, &policy, &excluded);
        let conversations = scope.conversation_ids.as_ref().map(|ids| {
            ids.iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
        });
        let vault = read.vault;
        // Recall's own kinds rule, then authority, then conversation provenance.
        let admitted =
            |store: &crate::store::StoreRead<'_>, txn: &heed::RoTxn<'_>, id: &EntityId| {
                let Some(kind) = store
                    .port_entity_record(txn, id)?
                    .map(|row| row.entity_type)
                else {
                    return Ok(false);
                };
                if !kinds.admits(kind) || !plan(store, txn, id)? {
                    return Ok(false);
                }
                crate::memory::conversation_candidate_admits(vault, store, txn, id, &conversations)
            };
        let mut pipeline = read
            .vault
            .query()
            .reading(read.store_read())
            .authority_filter(filter.clone())
            .scoped_note_reader(read.actor_key.clone())
            .filter_candidates(&admitted)
            .search_text(query, limit)
            .fold_messages_into_turns(kinds.turn_fold())
            .world(world_scope)
            .corpus(corpus)
            .limit(limit);
        if let Some(facet) = scope.facet {
            pipeline = pipeline.facet(&facet, FacetMode::Strict);
        }
        let results = pipeline.run_for_pack()?;
        read.filter_search_results(
            results.scores,
            limit,
            None,
            &filter,
            &policy,
            results.read_suppressed.saturating_add(excluded.count()?),
            &results.revisions,
        )
    }
}
