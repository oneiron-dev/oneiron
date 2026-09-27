use super::*;

impl ScopedRead<'_> {
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
        let fetch_limit = self
            .vault
            .scoped_read_search_candidate_limit(limit, true, true)?;
        let results = self
            .vault
            .query()
            .authority_filter(filter.clone())
            .search(query, vector, None, fetch_limit)
            .run_for_pack()?;
        self.filter_search_results(
            results.scores,
            limit,
            requested,
            &filter,
            &policy,
            results.read_suppressed,
            &results.revisions,
        )
    }

    pub fn search_text(
        &self,
        query: &str,
        limit: usize,
        requested: Option<&RetrievalFilter>,
    ) -> Result<ScopedReadResult<Vec<ScoredEntity>>> {
        let result = self.search_text_revisioned(query, limit, requested)?;
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
        let policy = crate::gate::resolve_policy_manifest(&self.vault.store, txn)?;
        let filter = crate::gate::narrow_retrieval_filter(
            &policy.retrieval_floor_for_actor(Some(&self.actor_key)),
            requested,
        )?;
        Ok((filter, policy))
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
            if self.is_entity_retrievable_with_policy_in(&txn, policy, filter, &result.id)?
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
                }
            {
                if value.len() < limit {
                    value.push(result);
                }
            } else if self.entity_record_in(&txn, &result.id)?.is_some() {
                suppressed += 1;
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

    pub fn search_candidate_limit(
        &self,
        requested: usize,
        include_text: bool,
        include_vector: bool,
    ) -> Result<usize> {
        if requested == 0 {
            return Ok(0);
        }

        let rtxn = self.grant_read_txn()?;
        let policy = self.policy_manifest_in(&rtxn)?;
        let diagnostics = policy.diagnostics();
        if self.audience.is_none()
            && !diagnostics.loaded_manifest_forces_fail_closed()
            && !policy.has_scoped_read_grants()
        {
            return Ok(requested);
        }
        drop(rtxn);

        self.vault
            .scoped_read_search_candidate_limit(requested, include_text, include_vector)
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
            if self.is_entity_retrievable_with_policy_in(&txn, &policy, &filter, &result.id)? {
                value.push(result);
            } else if self.entity_record_in(&txn, &result.id)?.is_some() {
                suppressed += 1;
            }
        }
        let receipt = self.receipt_for(requested, &policy, &filter, suppressed);
        Ok(ScopedReadResult { value, receipt })
    }
}
