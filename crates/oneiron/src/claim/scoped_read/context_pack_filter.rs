//! Final actor-bound context-pack filtering before rendering and telemetry.
use super::*;
use crate::context_pack::{ContextPack, EmptyContext, EmptyReason};

impl ScopedRead<'_> {
    pub fn filter_context_pack(&self, pack: &mut ContextPack) -> Result<ScopedReadReceipt> {
        self.filter_context_pack_under(pack, None)
    }

    /// [`Self::filter_context_pack`] for a pack assembled under `disclosure`.
    /// This filter joins each TURN's text from its messages, in its own read,
    /// so a turn keeps the clamp's admission here
    /// (`DisclosureContext::admits`): a message withheld since the assembly
    /// takes its turn out of the pack.
    pub fn filter_context_pack_under(
        &self,
        pack: &mut ContextPack,
        disclosure: Option<&crate::disclosure::DisclosureContext>,
    ) -> Result<ScopedReadReceipt> {
        let rtxn = self.grant_read_txn()?;
        let (filter, policy) = self.resolve_retrieval_filter_in(&rtxn, None)?;
        // One authority fold for this read snapshot, not one per claim in a
        // 1,000-row pack. Drop it before any later read can observe revocation.
        let fold = self.vault.authority_fold_readonly_in_txn(&rtxn)?;
        *self
            .recall_authority
            .lock()
            .map_err(|_| Error::InvariantViolation("recall authority lock"))? = Some(fold);
        let result = (|| {
            let had_l2_base = pack.l2_base.is_some();
            let mut auxiliary_suppressed = 0;
            if let Some(summary) = pack.l2_base.as_ref() {
                let visibility = self.retrieval_visibility_in(&rtxn, None)?;
                let mut admitted = true;
                for id in summary.evidence_ids() {
                    let evidence = self.admit_in(&rtxn, id, || {
                        crate::ppr::PprNodeVisibility::ppr_node_visible(&visibility, &rtxn, id)
                            .map(|visible| visible.then_some(()))
                    })?;
                    auxiliary_suppressed += evidence.suppression();
                    if !evidence.visible() {
                        admitted = false;
                        break;
                    }
                }
                if !admitted {
                    pack.l2_base = None;
                }
            }
            let had_capabilities = !pack.capabilities.is_empty();
            let mut capabilities = Vec::new();
            for hit in std::mem::take(&mut pack.capabilities) {
                let item = self.admit_in(&rtxn, &hit.id, || {
                    if !self
                        .is_entity_retrievable_with_policy_in(&rtxn, &policy, &filter, &hit.id)?
                    {
                        return Ok(None);
                    }
                    crate::pipeline::capability_hit(&self.vault.store, &rtxn, hit.id)
                })?;
                auxiliary_suppressed += item.suppression();
                if let Some(current) = item.into_option() {
                    capabilities.push(current);
                }
            }
            pack.capabilities = capabilities;
            let previously_suppressed = pack.stats.claims_suppressed;
            let previous_count = pack.results.len() + pack.neighbors.len();
            let (results, result_suppressed, result_rows_suppressed) = self
                .filter_context_entities(
                    &rtxn,
                    &policy,
                    &filter,
                    disclosure,
                    std::mem::take(&mut pack.results),
                )?;
            let (mut neighbors, neighbor_suppressed, neighbor_rows_suppressed) = self
                .filter_context_entities(
                    &rtxn,
                    &policy,
                    &filter,
                    disclosure,
                    std::mem::take(&mut pack.neighbors),
                )?;
            let (reachability_claims, reachability_rows) = self
                .retain_neighbors_reachable_from_results(
                    &rtxn,
                    &policy,
                    &filter,
                    &mut neighbors,
                    &results,
                )?;
            let suppressed = previously_suppressed
                .saturating_add(auxiliary_suppressed)
                .saturating_add(result_rows_suppressed)
                .saturating_add(neighbor_rows_suppressed)
                .saturating_add(reachability_rows);
            pack.results = results;
            pack.neighbors = neighbors;
            pack.stats.claims_suppressed +=
                result_suppressed + neighbor_suppressed + reachability_claims;

            if (previous_count > 0 || had_capabilities || had_l2_base)
                && pack.capabilities.is_empty()
                && pack.results.is_empty()
                && pack.neighbors.is_empty()
                && pack.l2_base.is_none()
            {
                pack.empty = Some(EmptyContext {
                    retrieval_quality: pack.retrieval_quality.clone(),
                    reason: EmptyReason::FilterMatchedNone,
                    total_in_scope: 0,
                    hint: "scoped_read returned no actor-readable entities".to_owned(),
                });
            }
            Ok(self.receipt_for(None, &policy, &filter, suppressed))
        })();
        self.end_recall_plan()?;
        result
    }
}

impl ScopedRead<'_> {
    fn filter_context_entities(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        filter: &ResolvedRetrievalFilter,
        disclosure: Option<&crate::disclosure::DisclosureContext>,
        entities: Vec<ContextEntity>,
    ) -> Result<(Vec<ContextEntity>, usize, usize)> {
        let mut kept = Vec::with_capacity(entities.len());
        let mut claims_suppressed = 0;
        let mut suppressed = 0;
        for mut entity in entities {
            let admission =
                self.admit_in(rtxn, &entity.id, || {
                    Ok((self
                        .is_entity_retrievable_with_policy_in(rtxn, policy, filter, &entity.id)?
                        && self.context_entity_revision_is_readable_in(
                            rtxn, policy, filter, &entity,
                        )?)
                    .then_some(()))
                })?;
            suppressed += admission.suppression();
            if admission.suppression() > 0 && entity.entity_type == ENTITY_TYPE_CLAIM {
                claims_suppressed += 1;
            }
            if admission.visible()
                && self.add_turn_content(rtxn, policy, disclosure, &mut entity)?
            {
                self.filter_context_entity_edges(rtxn, policy, filter, &mut entity)?;
                kept.push(entity);
            }
        }
        Ok((kept, claims_suppressed, suppressed))
    }

    fn retain_neighbors_reachable_from_results(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        filter: &ResolvedRetrievalFilter,
        neighbors: &mut Vec<ContextEntity>,
        results: &[ContextEntity],
    ) -> Result<(usize, usize)> {
        let mut reachable_ids = HashSet::new();
        for entity in results {
            if let Some(edges) = entity.edges.as_ref() {
                reachable_ids.extend(
                    edges
                        .iter()
                        .filter(|edge| context_pack_edge_can_reach_neighbor(edge))
                        .map(|edge| edge.target),
                );
                continue;
            }
            let admitted = self.admitted_edges_in(
                rtxn,
                policy,
                filter,
                &entity.id,
                EdgeDirection::Out,
                None,
                usize::MAX,
                usize::MAX,
                false,
            )?;
            for edge in admitted.edges {
                let info = edge.info();
                if context_pack_edge_can_reach_neighbor(&info) {
                    reachable_ids.insert(info.target);
                }
            }
        }
        let mut claims_suppressed = 0;
        let mut rows_suppressed = 0;
        let mut kept = Vec::with_capacity(neighbors.len());
        for entity in std::mem::take(neighbors) {
            if reachable_ids.contains(&entity.id) {
                kept.push(entity);
            } else {
                claims_suppressed += usize::from(entity.entity_type == ENTITY_TYPE_CLAIM);
                // A withheld private NOTE relation cannot disclose itself as
                // a dropped-neighbor count or a row_authority hint.
                rows_suppressed += self
                    .admit_in(rtxn, &entity.id, || Ok(None::<()>))?
                    .suppression();
            }
        }
        *neighbors = kept;
        Ok((claims_suppressed, rows_suppressed))
    }

    /// The claim's `FacetOf` targets, read through the same accessor as every
    /// other edge scan in this type.
    ///
    /// A facet-scoped `core:read` grant matches on the facets a claim carries,
    /// so those facets ARE the grant's subject matter. Scanning base
    /// `edges_out` directly is right for the canonical handle and wrong inside
    /// a session: a `FacetOf` edge staged in the room would not authorize, and
    /// one the room tombstoned would go on authorizing — the session's own
    /// view of who may read what, decided against a graph that is not the
    /// session's.
    ///
    /// Composes through the same session-aware edge port as reachability.
    pub(crate) fn claim_facet_refs_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Vec<EntityId>> {
        let mut facets = Vec::new();
        for entry in self.out_edges_in(rtxn, id, Some(EdgeKind::FacetOf))? {
            if facets.len() >= crate::vault::MAX_EDGE_QUERY_RESULTS {
                return Err(Error::IndexOverflow("claim_facet_refs"));
            }
            facets.push(entry?.target);
        }
        Ok(facets)
    }

    fn filter_context_entity_edges(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        filter: &ResolvedRetrievalFilter,
        entity: &mut ContextEntity,
    ) -> Result<()> {
        let Some(edges) = entity.edges.as_mut() else {
            return Ok(());
        };
        let admitted = self.admitted_edges_in(
            rtxn,
            policy,
            filter,
            &entity.id,
            EdgeDirection::Out,
            None,
            usize::MAX,
            usize::MAX,
            false,
        )?;
        let permitted: HashSet<_> = admitted
            .edges
            .into_iter()
            .map(|edge| {
                let info = edge.info();
                (info.kind, info.target)
            })
            .collect();
        edges.retain(|edge| permitted.contains(&(edge.kind, edge.target)));
        Ok(())
    }

    /// A TURN's text is its messages' (ARCH-0004), which its own body does
    /// not hold: a hydrated turn gets as `txt` those this read may see, and
    /// its revision becomes the text revision that pins them, read in this
    /// snapshot (`entity_revision::served_turn_text_in_txn`). A turn read at
    /// a text revision gets the words it was served with. Added after
    /// admission, whose snapshot check compares each field with the turn's
    /// own body. Returns whether the turn stays: under a disclosure clamp,
    /// only while the clamp still admits each of its messages.
    fn add_turn_content(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        disclosure: Option<&crate::disclosure::DisclosureContext>,
        entity: &mut ContextEntity,
    ) -> Result<bool> {
        if entity.entity_type != crate::registry::ENTITY_TYPE_TURN {
            return Ok(true);
        }
        if let Some(clamp) = disclosure
            && !clamp.admits(
                &self.vault.store,
                rtxn,
                &entity.id,
                crate::registry::ENTITY_TYPE_TURN,
                None,
            )?
        {
            return Ok(false);
        }
        let Some(fields) = entity.fields.as_mut() else {
            return Ok(true);
        };
        let mode = entity
            .source_revision_ref
            .map_or(crate::vault::ReadMode::Live, |revision| {
                crate::vault::ReadMode::Pinned(crate::vault::RevisionRef(revision))
            });
        let Some(served) = crate::vault::entity_revision::served_turn_text_in_txn(
            self.vault, rtxn, &entity.id, mode,
        )?
        else {
            return Ok(true);
        };
        let revision = served.revision;
        let messages = served
            .readable(|message| self.is_entity_readable_with_policy_in(rtxn, policy, message))?;
        if let Some(text) = crate::embed::joined_turn_text(&messages) {
            fields.insert("txt".to_owned(), serde_json::Value::String(text));
            if entity.source_revision_ref.is_some() {
                entity.source_revision_ref = Some(revision.0);
            }
        }
        Ok(true)
    }
}

fn context_pack_edge_can_reach_neighbor(edge: &EdgeInfo) -> bool {
    !matches!(edge.kind, EdgeKind::ChildOf | EdgeKind::AssignedTo)
        && !edge
            .provenance
            .is_some_and(|flags| flags.confirmation_status == EdgeConfirmationStatus::Retracted)
}
