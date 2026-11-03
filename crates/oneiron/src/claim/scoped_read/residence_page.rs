//! The home's paged residence search (FIX 8865): one ranked text list as
//! deep as a device's whole request, past the read lane's candidate window.
//! Its authority, note visibility, recall scope and fresh-read recheck are
//! those of [`ScopedRead::search_text`] and
//! [`ScopedRead::search_text_selected`]; its time words and recency read one
//! fixed second, so every page of one search ranks the same list.

use super::*;
use crate::pipeline::{FacetMode, WorldAuthoritySet, WorldScope};
use crate::sync::residence::ResolvedRecallSelection;

impl ScopedRead<'_> {
    /// Ranks `window` rows for `query` at `as_of` (unix seconds), narrowed by
    /// `scope` as a recall's search is, and returns the admitted hits with
    /// how many rows the ranking held before the fresh-read recheck: fewer
    /// than `window` only once the matches ran out. A scope the read refuses
    /// is refused with its typed error, never searched unscoped.
    pub(crate) fn residence_search_page(
        self,
        query: &str,
        window: usize,
        scope: Option<&ResolvedRecallSelection>,
        as_of: u64,
    ) -> Result<(Vec<ScoredEntity>, usize)> {
        let Some(scope) = scope else {
            return self.residence_page_ranked(query, window, as_of, None);
        };
        // The checks and world scope of `search_text_selected`.
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
        let read = match worlds {
            Some(worlds) => self.within_worlds(worlds),
            None => self,
        };
        read.residence_page_ranked(query, window, as_of, Some((scope, world_scope)))
    }

    /// The ranked run of [`Self::residence_search_page`], its scope checked.
    fn residence_page_ranked(
        &self,
        query: &str,
        window: usize,
        as_of: u64,
        selected: Option<(&ResolvedRecallSelection, WorldScope)>,
    ) -> Result<(Vec<ScoredEntity>, usize)> {
        let scope = selected.as_ref().map(|(scope, _)| *scope);
        let (filter, policy) = self.resolve_retrieval_filter(None)?;
        if filter.deny_all {
            return Ok((Vec::new(), 0));
        }
        let excluded = self.request_exclusions(&policy, None)?;
        let plan = self.plan_admits(&filter, &policy, &excluded);
        let kinds = crate::memory::RecallKinds::new(scope.and_then(|scope| scope.kinds.clone()));
        let conversations = scope.and_then(|scope| {
            scope.conversation_ids.as_ref().map(|ids| {
                ids.iter()
                    .copied()
                    .collect::<std::collections::BTreeSet<_>>()
            })
        });
        // Recall's own kinds rule, then authority, then conversation provenance.
        let admitted = |store: &crate::store::StoreRead<'_>,
                        txn: &heed::RoTxn<'_>,
                        id: &EntityId| {
            if scope.is_some() {
                let Some(kind) = store
                    .port_entity_record(txn, id)?
                    .map(|row| row.entity_type)
                else {
                    return Ok(false);
                };
                if !kinds.admits(kind) {
                    return Ok(false);
                }
            }
            if !plan(store, txn, id)? {
                return Ok(false);
            }
            crate::memory::conversation_candidate_admits(self.vault, store, txn, id, &conversations)
        };
        let mut pipeline = self
            .vault
            .query()
            .reading(self.store_read())
            .authority_filter(filter.clone())
            .scoped_note_reader(self.actor_key.clone())
            .filter_candidates(&admitted)
            .search_text(query, window)
            .limit(window)
            .with_temporal_now(as_of)
            .residence_page();
        if let Some((scope, world_scope)) = selected {
            let corpus = if scope.project_ids.is_empty() {
                crate::corpus::CorpusScope::All
            } else {
                crate::corpus::CorpusScope::AnyOf(scope.project_ids.clone())
            };
            pipeline = pipeline
                .fold_messages_into_turns(kinds.turn_fold())
                .world(world_scope)
                .corpus(corpus);
            if let Some(facet) = scope.facet {
                pipeline = pipeline.facet(&facet, FacetMode::Strict);
            }
        }
        let results = pipeline.run_for_pack()?;
        let ranked = results.scores.len();
        let filtered = self.filter_search_results(
            results.scores,
            window,
            None,
            &filter,
            &policy,
            results.read_suppressed.saturating_add(excluded.count()?),
            &results.revisions,
        )?;
        Ok((filtered.value, ranked))
    }
}
