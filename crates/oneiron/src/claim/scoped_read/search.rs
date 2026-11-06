use super::access_gate::HeldAuthority;
use super::*;

mod native_query;

/// The rows a bounded search's plan refused that its key's own ceiling
/// admits: rows the request excluded, which its receipt counts (B7). A row
/// the key cannot read is never among them. A text scan checks every
/// matching posting; a vector walk checks only the nodes it visits.
pub(super) struct RequestExclusions {
    ceiling: Option<ResolvedRetrievalFilter>,
    ids: Mutex<HashSet<EntityId>>,
}

pub(super) enum SuppressedSearchRows {
    Count(usize),
    Candidates {
        pipeline: HashSet<EntityId>,
        excluded: HashSet<EntityId>,
    },
}

impl RequestExclusions {
    pub(super) fn count(&self) -> Result<usize> {
        Ok(self
            .ids
            .lock()
            .map_err(|_| Error::InvariantViolation("request exclusions lock"))?
            .len())
    }

    pub(super) fn snapshot_ids(&self) -> Result<HashSet<EntityId>> {
        Ok(self
            .ids
            .lock()
            .map_err(|_| Error::InvariantViolation("request exclusions lock"))?
            .clone())
    }
}

/// One search's authority, resolved in one snapshot (FIX 7528).
pub(crate) struct SearchPlan {
    /// The key's own filter (B), resolved from the search's request: every
    /// row gate judges a candidate under it first, then under each of the
    /// reader's own live Grants alone (A).
    pub(crate) filter: ResolvedRetrievalFilter,
    /// The rows the search's pipeline may rank: `filter`'s and those each of
    /// the reader's own live Grants reads under the same request
    /// (`candidate_filter_in`). A prefilter, never an authorization; a
    /// search whose candidates deny every row reads nothing.
    pub(crate) candidates: ResolvedRetrievalFilter,
    pub(crate) policy: PolicyManifestResolution,
}

impl ScopedRead<'_> {
    /// [`SearchPlan`] for a search under `requested`, in a fresh snapshot.
    pub(super) fn search_plan(&self, requested: Option<&RetrievalFilter>) -> Result<SearchPlan> {
        let txn = self.grant_read_txn()?;
        self.search_plan_in(&txn, requested)
    }

    /// [`SearchPlan`] for a search under `requested`, in `txn`.
    pub(super) fn search_plan_in(
        &self,
        txn: &heed::RoTxn<'_>,
        requested: Option<&RetrievalFilter>,
    ) -> Result<SearchPlan> {
        let (filter, policy) = self.resolve_retrieval_filter_in(txn, requested)?;
        let candidates = self.candidate_filter_in(txn, &policy, &filter, requested);
        Ok(SearchPlan {
            filter,
            candidates,
            policy,
        })
    }

    /// Resolve a bounded query's actor/proof ceiling once, with no request,
    /// and the candidates its pipeline may rank ([`SearchPlan`]). The
    /// terminal read checks fresh authority again, so this snapshot can never
    /// widen it.
    pub(crate) fn recall_plan(&self) -> Result<SearchPlan> {
        let txn = self.vault.store.env.read_txn()?;
        let plan = self.search_plan_in(&txn, None)?;
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
    /// row the key's own ceiling admits lands in `excluded`. `filter` is the
    /// one resolved from `requested`: a row it refuses is judged under each of
    /// the reader's own live Grants with that same request (A, FIX 7528).
    pub(super) fn plan_admits<'p>(
        &'p self,
        filter: &'p ResolvedRetrievalFilter,
        policy: &'p PolicyManifestResolution,
        excluded: &'p RequestExclusions,
        requested: Option<&'p RetrievalFilter>,
    ) -> impl Fn(&crate::store::StoreRead<'_>, &heed::RoTxn<'_>, &EntityId) -> Result<bool>
    + Send
    + Sync
    + 'p {
        move |store, txn, id| {
            if !plan_row_decodes(store, txn, id)? {
                return Ok(false);
            }
            let held = HeldAuthority::for_request(requested);
            if self.is_entity_retrievable_held_in(txn, policy, filter, id, &held)? {
                return Ok(true);
            }
            if let Some(ceiling) = &excluded.ceiling
                && self.is_entity_retrievable_held_in(
                    txn,
                    policy,
                    ceiling,
                    id,
                    &HeldAuthority::for_request(None),
                )?
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

    /// Searches within this actor's resolved read authority. Unset means the floor.
    pub fn search(
        &self,
        query: &str,
        vector: &[f32],
        limit: usize,
        requested: Option<&RetrievalFilter>,
    ) -> Result<ScopedReadResult<Vec<ScoredEntity>>> {
        let SearchPlan {
            filter,
            candidates,
            policy,
        } = self.search_plan(requested)?;
        if candidates.deny_all {
            return Ok(ScopedReadResult {
                value: Vec::new(),
                receipt: self.receipt_for(requested, &policy, &candidates, 0),
            });
        }
        let excluded = self.request_exclusions(&policy, requested)?;
        let admitted = self.plan_gate(&filter, &policy, &excluded, requested);
        let results = self
            .vault
            .query()
            .reading(self.store_read())
            .authority_filter(candidates.clone())
            .scoped_note_reader(self.actor_key.clone())
            .filter_candidates(&plan_row_decodes)
            .gate_candidates(&admitted)
            .search(query, vector, None, limit)
            .run_for_pack()?;
        self.filter_search_results_with_suppression(
            results.scores,
            limit,
            requested,
            &filter,
            &policy,
            SuppressedSearchRows::Candidates {
                pipeline: results.read_suppressed_candidates,
                excluded: excluded.snapshot_ids()?,
            },
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
            crate::store::embedding::InputKind,
            &[f32],
            &[crate::store::embedding::InputKind],
        )],
        limit: usize,
        requested: Option<&RetrievalFilter>,
        query_affect: Option<oneiron_contracts::affect::Vad>,
        media_memory: Option<&crate::host_memory::MachineMemory>,
    ) -> Result<ScopedReadResult<Vec<ScoredEntity>>> {
        let SearchPlan {
            filter,
            candidates,
            policy,
        } = self.search_plan(requested)?;
        if candidates.deny_all {
            return Ok(ScopedReadResult {
                value: Vec::new(),
                receipt: self.receipt_for(requested, &policy, &candidates, 0),
            });
        }
        let excluded = self.request_exclusions(&policy, requested)?;
        let admitted = self.plan_gate(&filter, &policy, &excluded, requested);
        let mut pipeline = self
            .vault
            .query()
            .reading(self.store_read())
            .authority_filter(candidates.clone())
            .scoped_note_reader(self.actor_key.clone())
            .filter_candidates(&plan_row_decodes)
            .gate_candidates(&admitted);
        if let Some(memory) = media_memory {
            pipeline = pipeline.media_query_memory(memory);
        }
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
        self.filter_search_results_with_suppression(
            results.scores,
            limit,
            requested,
            &filter,
            &policy,
            SuppressedSearchRows::Candidates {
                pipeline: results.read_suppressed_candidates,
                excluded: excluded.snapshot_ids()?,
            },
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
        let result = self.search_text_revisioned_as_of(query, limit, requested, as_of, None)?;
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
        let result = self.search_vector_revisioned(query, limit, requested, None)?;
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
    pub(crate) fn filter_search_results(
        &self,
        results: Vec<ScoredEntity>,
        limit: usize,
        requested: Option<&RetrievalFilter>,
        filter: &ResolvedRetrievalFilter,
        policy: &PolicyManifestResolution,
        previously_suppressed: usize,
        revisions: &std::collections::HashMap<EntityId, crate::vault::RevisionRef>,
    ) -> Result<ScopedReadResult<Vec<ScoredEntity>>> {
        self.filter_search_results_with_suppression(
            results,
            limit,
            requested,
            filter,
            policy,
            SuppressedSearchRows::Count(previously_suppressed),
            revisions,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "final scoring admission conjoins plan authority, fresh authority and source frontiers"
    )]
    pub(super) fn filter_search_results_with_suppression(
        &self,
        results: Vec<ScoredEntity>,
        limit: usize,
        requested: Option<&RetrievalFilter>,
        filter: &ResolvedRetrievalFilter,
        policy: &PolicyManifestResolution,
        mut previously_suppressed: SuppressedSearchRows,
        revisions: &std::collections::HashMap<EntityId, crate::vault::RevisionRef>,
    ) -> Result<ScopedReadResult<Vec<ScoredEntity>>> {
        let txn = self.grant_read_txn()?;
        // The scoring txn may have completed before a revocation. The final
        // read must satisfy BOTH the plan authority and this fresh snapshot.
        let (fresh_filter, fresh_policy) = self.resolve_retrieval_filter_in(&txn, requested)?;
        // One held authority for every hit's checks in this txn (FIX 7462).
        let held = HeldAuthority::for_request(requested);
        // A withheld row counts only inside the key's own ceiling under both
        // snapshots: a request or pinned projection excluded it. A row the
        // key's baseline authority denies stays opaque (FIX 8670).
        let ceiling = self.filter_under(policy, None)?;
        let fresh_ceiling = self.filter_under(&fresh_policy, None)?;
        let ceilings = [(policy, &ceiling), (&fresh_policy, &fresh_ceiling)];
        let ceiling_held = HeldAuthority::for_request(None);
        let mut value = Vec::new();
        let mut suppressed = 0;
        if let SuppressedSearchRows::Candidates { pipeline, excluded } = &mut previously_suppressed
        {
            for result in &results {
                pipeline.remove(&result.id);
                excluded.remove(&result.id);
            }
        }
        for result in results {
            let id = result.id;
            let admitted = self.admit_in(&txn, &result.id, || {
                let allowed = self
                    .is_entity_retrievable_held_in(&txn, policy, filter, &result.id, &held)?
                    && self.is_entity_retrievable_held_in(
                        &txn,
                        &fresh_policy,
                        &fresh_filter,
                        &result.id,
                        &held,
                    )?
                    && match revisions.get(&result.id) {
                        Some(revision) => {
                            let mode = crate::vault::ReadMode::Pinned(*revision);
                            self.entity_raw_with_mode_held_in(
                                &txn, policy, filter, &result.id, mode, &held,
                            )?
                            .is_some()
                                && self
                                    .entity_raw_with_mode_held_in(
                                        &txn,
                                        &fresh_policy,
                                        &fresh_filter,
                                        &result.id,
                                        mode,
                                        &held,
                                    )?
                                    .is_some()
                        }
                        None => true,
                    };
                Ok(allowed.then_some(result))
            })?;
            if admitted.suppression() > 0
                && self.within_ceilings_in(&txn, &id, &ceilings, &ceiling_held)?
            {
                suppressed += 1;
            }
            if let Some(row) = admitted.into_option()
                && value.len() < limit
            {
                value.push(row);
            }
        }
        let previously_suppressed = match previously_suppressed {
            SuppressedSearchRows::Count(count) => count,
            SuppressedSearchRows::Candidates { pipeline, excluded } => pipeline
                .union(&excluded)
                .filter(|&id| {
                    self.within_ceilings_in(&txn, id, &ceilings, &ceiling_held)
                        .unwrap_or(false)
                        && self
                            .admit_in(&txn, id, || Ok(None::<()>))
                            .map(|admitted| admitted.suppression() > 0)
                            .unwrap_or(false)
                })
                .count(),
        };
        // A search's receipt reports the candidates it ranked: the key's own
        // filter's rows and its own live Grants' (FIX 7528), so a later page
        // asked under it never refuses a row this search admitted.
        let candidates = self.candidate_filter_in(&txn, policy, filter, requested);
        let fresh_candidates =
            self.candidate_filter_in(&txn, &fresh_policy, &fresh_filter, requested);
        let mut receipt = self.receipt_for(requested, policy, &candidates, previously_suppressed);
        receipt.restrict_with(&self.receipt_for(
            requested,
            &fresh_policy,
            &fresh_candidates,
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
    /// audience or peer read narrows the reader, otherwise the request over
    /// the [`crate::memory::caps::MAX_SEARCH_LIMIT`] floor
    /// ([`crate::request_limits::narrowed_candidate_window`]). Never the
    /// index's population; the page is short when the window holds fewer
    /// readable rows.
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
            return Ok(requested);
        }
        Ok(crate::request_limits::narrowed_candidate_window(requested))
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
        self.filter_scored_entities_observed(results, requested, |_, _| {})
    }

    /// [`Self::filter_scored_entities_requested`], with `observe` run over
    /// each hit it admits in the read that admits it, before that read
    /// closes (FIX 6130).
    pub(crate) fn filter_scored_entities_observed(
        &self,
        results: Vec<ScoredEntity>,
        requested: Option<&RetrievalFilter>,
        mut observe: impl FnMut(&heed::RoTxn<'_>, EntityId),
    ) -> Result<ScopedReadResult<Vec<ScoredEntity>>> {
        let before = results.len();
        let txn = self.grant_read_txn()?;
        let (filter, policy) = self.resolve_retrieval_filter_in(&txn, requested)?;
        let held = HeldAuthority::for_request(requested);
        // A withheld row counts only inside the key's own ceiling: with no
        // request every withheld row is the key's own denial, which stays
        // opaque (FIX 8670).
        let ceiling = requested
            .map(|_| self.filter_under(&policy, None))
            .transpose()?;
        let ceiling_held = HeldAuthority::for_request(None);
        let mut value = Vec::with_capacity(before);
        let mut suppressed = 0;
        for result in results {
            let id = result.id;
            let admitted = self.admit_in(&txn, &result.id, || {
                self.is_entity_retrievable_held_in(&txn, &policy, &filter, &result.id, &held)
                    .map(|visible| visible.then_some(result))
            })?;
            if let Some(ceiling) = &ceiling
                && admitted.suppression() > 0
                && self.within_ceilings_in(&txn, &id, &[(&policy, ceiling)], &ceiling_held)?
            {
                suppressed += 1;
            }
            if let Some(row) = admitted.into_option() {
                observe(&txn, row.id);
                value.push(row);
            }
        }
        let receipt = self.receipt_for(requested, &policy, &filter, suppressed);
        Ok(ScopedReadResult { value, receipt })
    }
}

impl ScopedRead<'_> {
    /// Whether every `ceilings` snapshot of the key's own read, with no
    /// request, admits `id`: only then is a row a ranked filter withheld a
    /// request or projection exclusion its receipt counts (FIX 8670).
    fn within_ceilings_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        ceilings: &[(&PolicyManifestResolution, &ResolvedRetrievalFilter)],
        held: &HeldAuthority,
    ) -> Result<bool> {
        for (policy, ceiling) in ceilings {
            if !self.is_entity_retrievable_held_in(txn, policy, ceiling, id, held)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// A CLAIM whose body does not decode is no candidate, as the D19 gate holds;
/// it does not end the search.
fn plan_row_decodes(
    store: &crate::store::StoreRead<'_>,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    Ok(
        match crate::ports::EntityStoreRead::port_entity_record(store, txn, id)? {
            Some(row) if row.entity_type == crate::registry::ENTITY_TYPE_CLAIM => {
                crate::claim::decode_claim_body(&row.body, true).is_ok()
            }
            _ => true,
        },
    )
}

impl<'v> ScopedRead<'v> {
    /// The candidates of one read in `txn`, each through the row gate under
    /// `filter` (resolved from `requested`, which A asks again under each of
    /// the reader's own live Grants, FIX 7528), under one relationship
    /// authority for them all (FIX 11648).
    pub(crate) fn recall_candidates_in<'t>(
        &'t self,
        txn: &'t heed::RoTxn<'t>,
        policy: &'t PolicyManifestResolution,
        filter: &'t ResolvedRetrievalFilter,
        requested: Option<&RetrievalFilter>,
    ) -> impl Fn(&EntityId) -> Result<bool> + 't {
        let held = HeldAuthority::for_request(requested);
        move |id| self.is_entity_retrievable_held_in(txn, policy, filter, id, &held)
    }

    /// The row gate for a candidate of the retrieval snapshot read in
    /// `snapshot`, under the relationship authority `held` holds for it (FIX
    /// 11648); a candidate checked in any other transaction loads its own,
    /// asking what `held` asks (FIX 7528). The caller borrows `snapshot` for
    /// as long as `held`, so no other transaction stands at its address.
    fn snapshot_candidate_in(
        &self,
        snapshot: &heed::RoTxn<'_>,
        held: &HeldAuthority,
        txn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        filter: &ResolvedRetrievalFilter,
        id: &EntityId,
    ) -> Result<bool> {
        if std::ptr::eq(txn, snapshot) {
            return self.is_entity_retrievable_held_in(txn, policy, filter, id, held);
        }
        self.is_entity_retrievable_held_in(txn, policy, filter, id, &held.for_another_txn())
    }

    /// A recall's candidate admission under its query plan ([`Self::recall_plan`],
    /// resolved with no request): the row gate, B and then A under each of the
    /// reader's own live Grants (FIX 7528), under one relationship authority
    /// for each retrieval snapshot (FIX 11648).
    pub(crate) fn recall_candidate_gate<'p>(
        &'p self,
        policy: &'p PolicyManifestResolution,
        filter: &'p ResolvedRetrievalFilter,
    ) -> RecallCandidateGate<'p, 'v> {
        RecallCandidateGate {
            read: self,
            policy,
            filter,
        }
    }

    /// [`Self::plan_admits`] past its decode check (`plan_row_decodes`, the
    /// search's candidate filter), under one relationship authority for each
    /// retrieval snapshot (FIX 11648). `filter` is the one resolved from
    /// `requested`, which A asks again under each Grant (FIX 7528).
    pub(super) fn plan_gate<'p>(
        &'p self,
        filter: &'p ResolvedRetrievalFilter,
        policy: &'p PolicyManifestResolution,
        excluded: &'p RequestExclusions,
        requested: Option<&'p RetrievalFilter>,
    ) -> PlanGate<'p, 'v> {
        PlanGate {
            read: self,
            policy,
            filter,
            excluded,
            requested,
        }
    }
}

/// [`ScopedRead::recall_candidate_gate`].
pub(crate) struct RecallCandidateGate<'p, 'v> {
    read: &'p ScopedRead<'v>,
    policy: &'p PolicyManifestResolution,
    filter: &'p ResolvedRetrievalFilter,
}

impl crate::store::retrieval_values::CandidateGate for RecallCandidateGate<'_, '_> {
    fn in_txn<'t>(
        &'t self,
        txn: &'t heed::RoTxn<'t>,
    ) -> Box<crate::store::retrieval_values::SnapshotCandidateFilter<'t>> {
        // A recall plan resolves its filter with no request.
        let held = HeldAuthority::for_request(None);
        Box::new(
            move |_: &crate::store::StoreRead<'_>, rtxn: &heed::RoTxn<'_>, id: &EntityId| {
                self.read
                    .snapshot_candidate_in(txn, &held, rtxn, self.policy, self.filter, id)
            },
        )
    }
}

/// [`ScopedRead::plan_gate`].
pub(super) struct PlanGate<'p, 'v> {
    read: &'p ScopedRead<'v>,
    policy: &'p PolicyManifestResolution,
    filter: &'p ResolvedRetrievalFilter,
    excluded: &'p RequestExclusions,
    requested: Option<&'p RetrievalFilter>,
}

impl crate::store::retrieval_values::CandidateGate for PlanGate<'_, '_> {
    fn in_txn<'t>(
        &'t self,
        txn: &'t heed::RoTxn<'t>,
    ) -> Box<crate::store::retrieval_values::SnapshotCandidateFilter<'t>> {
        let held = HeldAuthority::for_request(self.requested);
        // The key's own ceiling resolves with no request.
        let ceiling_held = HeldAuthority::for_request(None);
        Box::new(
            move |_: &crate::store::StoreRead<'_>, rtxn: &heed::RoTxn<'_>, id: &EntityId| {
                let read = self.read;
                if read.snapshot_candidate_in(txn, &held, rtxn, self.policy, self.filter, id)? {
                    return Ok(true);
                }
                if let Some(ceiling) = &self.excluded.ceiling
                    && read.snapshot_candidate_in(
                        txn,
                        &ceiling_held,
                        rtxn,
                        self.policy,
                        ceiling,
                        id,
                    )?
                {
                    self.excluded
                        .ids
                        .lock()
                        .map_err(|_| Error::InvariantViolation("request exclusions lock"))?
                        .insert(*id);
                }
                Ok(false)
            },
        )
    }
}
