//! Final actor-bound context-pack filtering before rendering and telemetry.
use super::*;
use crate::context_pack::{ContextPack, EmptyContext, EmptyReason};

impl ScopedRead<'_> {
    pub fn filter_context_pack(&self, pack: &mut ContextPack) -> Result<ScopedReadReceipt> {
        let rtxn = self.vault.store.env.read_txn()?;
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
                    if !crate::ppr::PprNodeVisibility::ppr_node_visible(&visibility, &rtxn, id)? {
                        admitted = false;
                        auxiliary_suppressed +=
                            usize::from(self.entity_record_in(&rtxn, id)?.is_some());
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
                if self.is_entity_retrievable_with_policy_in(&rtxn, &policy, &filter, &hit.id)?
                    && let Some(current) =
                        crate::pipeline::capability_hit(&self.vault.store, &rtxn, hit.id)?
                {
                    capabilities.push(current);
                } else if self.entity_record_in(&rtxn, &hit.id)?.is_some() {
                    auxiliary_suppressed += 1;
                }
            }
            pack.capabilities = capabilities;
            let previously_suppressed = pack.stats.claims_suppressed;
            let previous_results = pack.results.len();
            let previous_count = previous_results + pack.neighbors.len();
            let (results, result_suppressed, result_rows_suppressed) = self
                .filter_context_entities(
                    &rtxn,
                    &policy,
                    &filter,
                    std::mem::take(&mut pack.results),
                )?;
            let (mut neighbors, neighbor_suppressed, neighbor_rows_suppressed) = self
                .filter_context_entities(
                    &rtxn,
                    &policy,
                    &filter,
                    std::mem::take(&mut pack.neighbors),
                )?;
            let readable_neighbors = neighbors.len();
            let reachability_suppressed = if results.len() < previous_results {
                self.retain_neighbors_reachable_from_results(&rtxn, &mut neighbors, &results)?
            } else {
                0
            };
            let suppressed = previously_suppressed
                .saturating_add(auxiliary_suppressed)
                .saturating_add(result_rows_suppressed)
                .saturating_add(neighbor_rows_suppressed)
                .saturating_add(readable_neighbors.saturating_sub(neighbors.len()));
            pack.results = results;
            pack.neighbors = neighbors;
            pack.stats.claims_suppressed +=
                result_suppressed + neighbor_suppressed + reachability_suppressed;

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
