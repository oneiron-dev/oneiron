use super::*;

/// The rows a bounded search's plan refused that its key's own ceiling
/// admits: rows the request excluded, which its receipt counts (B7). A row
/// the key cannot read is never among them. A text scan checks every
/// matching posting; a vector walk checks only the nodes it visits.
pub(super) struct RequestExclusions {
    ceiling: Option<ResolvedRetrievalFilter>,
    ids: Mutex<HashSet<EntityId>>,
}

impl RequestExclusions {
    pub(super) fn count(&self) -> Result<usize> {
        Ok(self
            .ids
            .lock()
            .map_err(|_| Error::InvariantViolation("request exclusions lock"))?
            .len())
    }
}

impl ScopedRead<'_> {
    /// Resolve a bounded query's actor/proof ceiling once. The terminal read
    /// checks fresh authority again, so this snapshot can never widen it.
    pub(crate) fn recall_plan(
        &self,
    ) -> Result<(ResolvedRetrievalFilter, PolicyManifestResolution)> {
        let txn = self.vault.store.env.read_txn()?;
        let plan = self.resolve_retrieval_filter_in(&txn, None)?;
        let fold = self.vault.authority_fold_readonly_in_txn(&txn)?;
        *self
            .recall_authority
            .lock()
            .map_err(|_| Error::InvariantViolation("recall authority lock"))? = Some(fold);
        Ok(plan)
    }

    /// The final result and receipt must recheck authority in a fresh read.
    pub(crate) fn end_recall_plan(&self) -> Result<()> {
        *self
            .recall_authority
            .lock()
            .map_err(|_| Error::InvariantViolation("recall authority lock"))? = None;
        Ok(())
    }

    /// The exclusions a search under `requested` counts. With no request
    /// the plan is the key's own ceiling, so it refuses none the key reads.
    pub(super) fn request_exclusions(
        &self,
        policy: &PolicyManifestResolution,
        requested: Option<&RetrievalFilter>,
    ) -> Result<RequestExclusions> {
        Ok(RequestExclusions {
            ceiling: requested
                .map(|_| self.filter_under(policy, None))
                .transpose()?,
            ids: Mutex::default(),
        })
    }

    /// The plan admission a bounded search runs inside its retrieval: a
    /// candidate the plan's authority refuses takes no place in any channel,
    /// so the search needs no fetch past what it was asked for. A refused
    /// row the key's own ceiling admits lands in `excluded`.
    pub(super) fn plan_admits<'p>(
        &'p self,
        filter: &'p ResolvedRetrievalFilter,
        policy: &'p PolicyManifestResolution,
        excluded: &'p RequestExclusions,
    ) -> impl Fn(&crate::store::StoreRead<'_>, &heed::RoTxn<'_>, &EntityId) -> Result<bool>
    + Send
    + Sync
    + 'p {
        move |store, txn, id| {
            // A CLAIM whose body does not decode is no candidate, as the D19
            // gate holds; it does not end the search.
            if let Some(row) = crate::ports::EntityStoreRead::port_entity_record(store, txn, id)?
                && row.entity_type == crate::registry::ENTITY_TYPE_CLAIM
                && crate::claim::decode_claim_body(&row.body, true).is_err()
            {
                return Ok(false);
            }
            if self.recall_candidate_in(txn, policy, filter, id)? {
                return Ok(true);
            }
            if let Some(ceiling) = &excluded.ceiling
                && self.recall_candidate_in(txn, policy, ceiling, id)?
            {
                excluded
                    .ids
                    .lock()
                    .map_err(|_| Error::InvariantViolation("request exclusions lock"))?
                    .insert(*id);
            }
            Ok(false)
        }
    }

    /// Admit one candidate in the retrieval transaction under the query plan.
    pub(crate) fn recall_candidate_in(
        &self,
        txn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        filter: &ResolvedRetrievalFilter,
        id: &EntityId,
    ) -> Result<bool> {
        self.is_entity_retrievable_with_policy_in(txn, policy, filter, id)
    }

    /// Searches within this actor's resolved read authority. Unset means the floor.
    pub fn search(
        &self,
        query: &str,
        vector: &[f32],
        limit: usize,
        requested: Option<&RetrievalFilter>,
    ) -> Result<ScopedReadResult<Vec<ScoredEntity>>> {
        let (filter, policy) = self.resolve_retrieval_filter(requested)?;
        if filter.deny_all {
            return Ok(ScopedReadResult {
                value: Vec::new(),
                receipt: self.receipt_for(requested, &policy, &filter, 0),
            });
        }
        let excluded = self.request_exclusions(&policy, requested)?;
        let admitted = self.plan_admits(&filter, &policy, &excluded);
        let results = self
            .vault
            .query()
            .reading(self.store_read())
            .authority_filter(filter.clone())
            .scoped_note_reader(self.actor_key.clone())
            .filter_candidates(&admitted)
            .search(query, vector, None, limit)
            .run_for_pack()?;
        self.filter_search_results(
            results.scores,
            limit,
            requested,
            &filter,
            &policy,
            results.read_suppressed.saturating_add(excluded.count()?),
            &results.revisions,
        )
    }

    /// [`Self::search`] over any of its seeds within this actor's resolved read authority: a
    /// text query, a vector into the vault's own index, and media queries into declared
    /// embedding spaces (OF-370), each `(space id, the tower that encoded it, its vector, the
    /// kinds its list keeps)` (every kind the space holds when empty) and each its own ranked
    /// list beside the others. `query_affect` is the affect the query is asked in (OF-423):
    /// emotion congruence scales each candidate's final score by it, as on the context pack.
    pub fn search_seeded(
        &self,
        query: Option<&str>,
        vector: Option<&[f32]>,
        media: &[(
            &str,
            crate::embed::InputKind,
            &[f32],
            &[crate::embed::InputKind],
        )],
        limit: usize,
        requested: Option<&RetrievalFilter>,
        query_affect: Option<crate::affect::Vad>,
    ) -> Result<ScopedReadResult<Vec<ScoredEntity>>> {
        let (filter, policy) = self.resolve_retrieval_filter(requested)?;
        if filter.deny_all {
            return Ok(ScopedReadResult {
                value: Vec::new(),
                receipt: self.receipt_for(requested, &policy, &filter, 0),
            });
        }
        let excluded = self.request_exclusions(&policy, requested)?;
        let admitted = self.plan_admits(&filter, &policy, &excluded);
        let mut pipeline = self
            .vault
            .query()
            .reading(self.store_read())
            .authority_filter(filter.clone())
            .scoped_note_reader(self.actor_key.clone())
            .filter_candidates(&admitted);
        if let Some(query) = query {
            pipeline = pipeline.search_text(query, limit);
        }
        if let Some(vector) = vector {
            pipeline = pipeline.search_vector(vector, limit);
        }
        for (space, kind, vector, kinds) in media {
            pipeline = pipeline.search_media(space, *kind, vector, kinds, limit);
        }
        if let Some(vad) = query_affect {
            pipeline = pipeline.query_affect(vad);
        }
        let results = pipeline.limit(limit).run_for_pack()?;
        self.filter_search_results(
            results.scores,
            limit,
            requested,
            &filter,
            &policy,
            results.read_suppressed.saturating_add(excluded.count()?),
            &results.revisions,
        )
    }

    pub fn search_text(
        &self,
        query: &str,
        limit: usize,
        requested: Option<&RetrievalFilter>,
    ) -> Result<ScopedReadResult<Vec<ScoredEntity>>> {
        self.search_text_as_of(query, limit, requested, None)
    }

    /// [`Self::search_text`] with the query's time words read against
    /// `as_of` (unix seconds) instead of now.
    pub(crate) fn search_text_as_of(
        &self,
        query: &str,
        limit: usize,
        requested: Option<&RetrievalFilter>,
        as_of: Option<u64>,
    ) -> Result<ScopedReadResult<Vec<ScoredEntity>>> {
        let result = self.search_text_revisioned_as_of(query, limit, requested, as_of)?;
        Ok(ScopedReadResult {
            value: result.hits,
            receipt: result.receipt,
        })
    }

    pub fn search_vector(
        &self,
        query: &[f32],
        limit: usize,
        requested: Option<&RetrievalFilter>,
    ) -> Result<ScopedReadResult<Vec<ScoredEntity>>> {
        let result = self.search_vector_revisioned(query, limit, requested)?;
        Ok(ScopedReadResult {
            value: result.hits,
            receipt: result.receipt,
        })
    }

    pub(super) fn resolve_retrieval_filter(
        &self,
        requested: Option<&RetrievalFilter>,
    ) -> Result<(ResolvedRetrievalFilter, PolicyManifestResolution)> {
        let txn = self.grant_read_txn()?;
        self.resolve_retrieval_filter_in(&txn, requested)
    }

    pub(super) fn resolve_retrieval_filter_in(
        &self,
        txn: &heed::RoTxn<'_>,
        requested: Option<&RetrievalFilter>,
    ) -> Result<(ResolvedRetrievalFilter, PolicyManifestResolution)> {
        if !self.proof_live_in(txn)? {
            return Err(Error::InvalidClaimBody(
                "scoped read credential no longer live",
            ));
        }
        self.owner_live_in(txn)?;
        let policy = crate::gate::resolve_policy_manifest(&self.vault.store, txn)?;
        let filter = self.filter_under(&policy, requested)?;
        Ok((filter, policy))
    }

    /// This key's read filter under `policy`, narrowed by `requested`; with
    /// no request, the key's own ceiling.
    fn filter_under(
        &self,
        policy: &PolicyManifestResolution,
        requested: Option<&RetrievalFilter>,
    ) -> Result<ResolvedRetrievalFilter> {
        Ok(crate::gate::narrow_retrieval_filter(
            &policy.retrieval_floor_for_actor(Some(&self.actor_key)),
            requested,
        )?
        .under_credential_of(&self.actor_key))
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "final scoring admission conjoins plan authority, fresh authority and source frontiers"
    )]
    pub(super) fn filter_search_results(
        &self,
        results: Vec<ScoredEntity>,
        limit: usize,
        requested: Option<&RetrievalFilter>,
        filter: &ResolvedRetrievalFilter,
        policy: &PolicyManifestResolution,
        previously_suppressed: usize,
        revisions: &std::collections::HashMap<EntityId, crate::vault::RevisionRef>,
    ) -> Result<ScopedReadResult<Vec<ScoredEntity>>> {
        let txn = self.grant_read_txn()?;
        // The scoring txn may have completed before a revocation. The final
        // read must satisfy BOTH the plan authority and this fresh snapshot.
        let (fresh_filter, fresh_policy) = self.resolve_retrieval_filter_in(&txn, requested)?;
        let mut value = Vec::new();
        let mut suppressed = 0;
        for result in results {
            let admitted = self.admit_in(&txn, &result.id, || {
                let allowed = self
                    .is_entity_retrievable_with_policy_in(&txn, policy, filter, &result.id)?
                    && self.is_entity_retrievable_with_policy_in(
                        &txn,
                        &fresh_policy,
                        &fresh_filter,
                        &result.id,
                    )?
                    && match revisions.get(&result.id) {
                        Some(revision) => {
                            let mode = crate::vault::ReadMode::Pinned(*revision);
                            self.entity_raw_with_mode_in(&txn, policy, filter, &result.id, mode)?
                                .is_some()
                                && self
                                    .entity_raw_with_mode_in(
                                        &txn,
                                        &fresh_policy,
                                        &fresh_filter,
                                        &result.id,
                                        mode,
                                    )?
                                    .is_some()
                        }
                        None => true,
                    };
                Ok(allowed.then_some(result))
            })?;
            suppressed += admitted.suppression();
            if let Some(row) = admitted.into_option()
                && value.len() < limit
            {
                value.push(row);
            }
        }
        let mut receipt = self.receipt_for(requested, policy, filter, previously_suppressed);
        receipt.restrict_with(&self.receipt_for(
            requested,
            &fresh_policy,
            &fresh_filter,
            suppressed,
        ));
        Ok(ScopedReadResult { value, receipt })
    }

    /// ONE-207: the effort-dialed read.
    ///
    /// The ONE door a depth request enters this lane through, and deliberately
    /// a THIN one: `retrieval_depth` owns the tier policy, the caps and the
    /// deep-lease rule, while every channel it runs comes back through the
    /// three search doors above and through
    /// `crate::ppr::PprNodeVisibility`, which conjoins
    /// `Self::is_entity_readable_with_policy_in` with the resolved retrieval
    /// floor so graph expansion cannot bypass the direct-search constraints.
    ///
    /// So the effort dial cannot widen admission. It changes how many
    /// admitted channels run, never which entities an admitted channel is
    /// allowed to return, and the deep tier's host-proposed queries are
    /// ordinary text searches on this same lane rather than a second read
    /// path that would need its own gate.
    ///
    /// Errors retain actual reported spend; settle it just as on success.
    pub fn search_with_effort(
        &self,
        request: &crate::retrieval_depth::DepthSearchRequest<'_>,
    ) -> crate::retrieval_depth::RetrievalResult<crate::retrieval_depth::DepthSearchResult> {
        crate::retrieval_depth::execute(self, request)
    }

    /// How many candidates a caller that filters this reader's rows after
    /// its own read fetches for `requested`: the request when no grant,
    /// audience or peer read narrows the reader, otherwise the whole
    /// [`crate::memory::caps::MAX_SEARCH_LIMIT`] window. Never past it,
    /// however many rows the vault holds; the page is short when the window
    /// holds fewer readable rows.
    pub fn search_candidate_limit(&self, requested: usize) -> Result<usize> {
        if requested == 0 {
            return Ok(0);
        }

        let rtxn = self.grant_read_txn()?;
        let policy = self.policy_manifest_in(&rtxn)?;
        let diagnostics = policy.diagnostics();
        if self.audience.is_none()
            && self.peer_reads.is_empty()
            && !diagnostics.loaded_manifest_forces_fail_closed()
            && !policy.has_scoped_read_grants()
        {
            return Ok(requested.min(crate::memory::caps::MAX_SEARCH_LIMIT));
        }
        Ok(crate::memory::caps::narrowed_candidate_window(requested))
    }

    pub fn filter_scored_entities(
        &self,
        results: Vec<ScoredEntity>,
    ) -> Result<ScopedReadResult<Vec<ScoredEntity>>> {
        self.filter_scored_entities_requested(results, None)
    }

    pub(crate) fn filter_scored_entities_requested(
        &self,
        results: Vec<ScoredEntity>,
        requested: Option<&RetrievalFilter>,
    ) -> Result<ScopedReadResult<Vec<ScoredEntity>>> {
        let before = results.len();
        let txn = self.grant_read_txn()?;
        let (filter, policy) = self.resolve_retrieval_filter_in(&txn, requested)?;
        let mut value = Vec::with_capacity(before);
        let mut suppressed = 0;
        for result in results {
            let admitted = self.admit_in(&txn, &result.id, || {
                self.is_entity_retrievable_with_policy_in(&txn, &policy, &filter, &result.id)
                    .map(|visible| visible.then_some(result))
            })?;
            suppressed += admitted.suppression();
            if let Some(row) = admitted.into_option() {
                value.push(row);
            }
        }
        let receipt = self.receipt_for(requested, &policy, &filter, suppressed);
        Ok(ScopedReadResult { value, receipt })
    }
}
