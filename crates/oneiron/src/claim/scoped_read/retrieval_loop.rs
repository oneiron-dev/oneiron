//! Scoped admission shared by the read-only retrieval loop's verbs.

use super::*;
use crate::pipeline::PipelineBuilder;
use crate::pipeline::retrieval_loop::{LoopSearch, RetrievalHandle, point_read};
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN};

impl ScopedRead<'_> {
    /// Execute the host's composed plan, intersecting its candidate predicate
    /// with this reader before top-k, fusion, graph expansion and telemetry.
    pub(crate) fn retrieval_loop_search(
        &self,
        plan: PipelineBuilder<'_>,
        host_filter: Option<&crate::store::retrieval_values::CandidateFilter<'_>>,
        requested: Option<&RetrievalFilter>,
    ) -> Result<LoopSearch> {
        // The plan ranks the key's own rows and those its own live Grants
        // add (FIX 7528); each candidate takes the row gate, B first.
        let super::search::SearchPlan {
            filter,
            candidates,
            policy,
        } = self.search_plan(requested)?;
        let excluded = self.request_exclusions(&policy, requested)?;
        let lane_admits = self.plan_admits(&filter, &policy, &excluded, requested);
        let admitted =
            |store: &crate::store::StoreRead<'_>, txn: &heed::RoTxn<'_>, id: &EntityId| {
                Ok(host_filter.map_or(Ok(true), |host| host(store, txn, id))?
                    && lane_admits(store, txn, id)?)
            };
        let limit = plan.result_limit();
        let output = plan
            .reading(self.store_read())
            .authority_filter(candidates)
            .scoped_note_reader(self.actor_key.clone())
            .filter_candidates(&admitted)
            .run_for_pack()?;
        let final_read = self.filter_search_results_with_suppression(
            output.scores,
            limit,
            requested,
            &filter,
            &policy,
            super::search::SuppressedSearchRows::Candidates {
                pipeline: output.read_suppressed_candidates,
                excluded: excluded.snapshot_ids()?,
            },
            &output.revisions,
        )?;
        Ok(LoopSearch {
            handles: final_read
                .value
                .into_iter()
                .map(|hit| RetrievalHandle {
                    id: hit.id,
                    score: hit.score,
                    revision: output.revisions.get(&hit.id).copied(),
                })
                .collect(),
            receipt: final_read.receipt,
            quality: output.retrieval_quality,
        })
    }

    /// Recheck both the current row and the exact ranked frontier before a
    /// handle is used. No body leaves this projection.
    pub(crate) fn retrieval_loop_refresh(
        &self,
        handles: &[RetrievalHandle],
        requested: &RetrievalFilter,
    ) -> Result<ScopedReadResult<Vec<RetrievalHandle>>> {
        let reads: Vec<_> = handles.iter().map(point_read).collect();
        self.loop_read_projected(&reads, requested, |_, rows| {
            Ok(rows
                .into_iter()
                .zip(handles)
                .filter_map(|(row, handle)| row.and_then(|row| row.body.map(|_| handle.clone())))
                .collect())
        })
    }

    /// The rows the loop's Read action takes as evidence, under `requested`,
    /// with the loop's receipt ([`Self::loop_read_projected`]).
    pub(crate) fn retrieval_loop_read(
        &self,
        reads: &[PointRead<'_>],
        requested: &RetrievalFilter,
    ) -> Result<ScopedReadResult<Vec<Option<ReadRow>>>> {
        self.loop_read_projected(reads, requested, |_, rows| Ok(rows))
    }

    /// [`Self::read_projected`] for the retrieval loop (FIX 7528): its
    /// receipt's applied scope is the candidates a search under `requested`
    /// ranks, read in the same snapshot, so the loop's next step, asked under
    /// it, never refuses a row this read admitted under one of the reader's
    /// own live Grants. Every row check is the point read's own.
    fn loop_read_projected<T>(
        &self,
        reads: &[PointRead<'_>],
        requested: &RetrievalFilter,
        project: impl FnOnce(&heed::RoTxn<'_>, Vec<Option<ReadRow>>) -> Result<T>,
    ) -> Result<ScopedReadResult<T>> {
        let read = self.read_projected(reads, Some(requested), |txn, rows| {
            let plan = self.search_plan_in(txn, Some(requested))?;
            Ok::<_, Error>((project(txn, rows)?, plan))
        })?;
        let (value, plan) = read.value;
        let receipt = self.receipt_for(
            Some(requested),
            &plan.policy,
            &plan.candidates,
            read.receipt.suppressed_count,
        );
        Ok(ScopedReadResult { value, receipt })
    }

    /// One step of the message ⊂ turn ⊂ session spine, using exact admitted
    /// relations. Other neighbors, DAG parents and task trees are not grain.
    pub(crate) fn retrieval_loop_drill(
        &self,
        anchor: &RetrievalHandle,
        up: bool,
        limit: usize,
        requested: &RetrievalFilter,
    ) -> Result<ScopedReadResult<Vec<RetrievalHandle>>> {
        let mut result =
            self.loop_read_projected(&[point_read(anchor)], requested, |txn, rows| {
                let Some(row) = rows.into_iter().next().flatten() else {
                    return Ok((Vec::new(), 0));
                };
                let (direction, edge_kind, target_type) = match (up, row.entity_type) {
                    (true, ENTITY_TYPE_MESSAGE) => {
                        (EdgeDirection::Out, EdgeKind::PartOf, ENTITY_TYPE_TURN)
                    }
                    (true, ENTITY_TYPE_TURN) => {
                        (EdgeDirection::Out, EdgeKind::BelongsTo, ENTITY_TYPE_SESSION)
                    }
                    (false, ENTITY_TYPE_SESSION) => {
                        (EdgeDirection::In, EdgeKind::BelongsTo, ENTITY_TYPE_TURN)
                    }
                    (false, ENTITY_TYPE_TURN) => {
                        (EdgeDirection::In, EdgeKind::PartOf, ENTITY_TYPE_MESSAGE)
                    }
                    _ => return Ok((Vec::new(), 0)),
                };
                let (filter, policy) = self.resolve_retrieval_filter_in(txn, Some(requested))?;
                let store = self.store_read();
                let edges = match direction {
                    EdgeDirection::Out => self.out_edges_in(txn, &anchor.id, Some(edge_kind))?,
                    _ => store.port_edges(txn, &anchor.id, direction, Some(edge_kind), None)?,
                };
                let mut handles = Vec::new();
                let mut suppressed = 0;
                let mut seen = HashSet::new();
                // One relationship authority for every peer (FIX 11648).
                let retrievable = self.recall_candidates_in(txn, &policy, &filter, Some(requested));
                let floor_held = super::access_gate::HeldAuthority::for_request(None);
                for edge in edges {
                    let edge = edge?;
                    let peer = edge.target;
                    let (source, target) = if up {
                        (anchor.id, peer)
                    } else {
                        (peer, anchor.id)
                    };
                    let admitted = super::edge_admission::admit_stored_edge_in(
                        self.vault,
                        txn,
                        source,
                        target,
                        edge,
                        || Ok(super::admission::ReadAdmission::Visible(())),
                        // The peer under the loop's request, A included (FIX 7528).
                        || self.admit_in(txn, &peer, || Ok(retrievable(&peer)?.then_some(()))),
                    )?;
                    if admitted.suppression() > 0
                        && self
                            .actor_retrieval_floor(&policy)
                            .and_then(|floor| {
                                self.is_entity_retrievable_held_in(
                                    txn,
                                    &policy,
                                    &floor,
                                    &peer,
                                    &floor_held,
                                )
                            })
                            .unwrap_or(false)
                    {
                        suppressed += 1;
                    }
                    if !admitted.visible() || !seen.insert(peer) {
                        continue;
                    }
                    let Some(row) = self.entity_record_in(txn, &peer)? else {
                        continue;
                    };
                    // Relevance floors and authority both applied to every
                    // grain in the peer's admission above.
                    if row.entity_type != target_type {
                        continue;
                    }
                    handles.push(RetrievalHandle {
                        id: peer,
                        score: anchor.score,
                        revision: self.vault.indexed_revision_in_txn(txn, &peer)?,
                    });
                    if handles.len() >= limit {
                        break;
                    }
                }
                Ok::<_, Error>((handles, suppressed))
            })?;
        result.receipt.add_suppressed(result.value.1);
        Ok(result.map(|(handles, _)| handles))
    }

    /// The loop's frontier (FIX 7798): how many distinct one-hop graph
    /// neighbours of the `observed` handles, along an edge either way, this
    /// reader may retrieve now under `requested`, and are not themselves
    /// observed. Each anchor and each neighbour passes the drill's own
    /// admission (the exact edge pair and both endpoints, then the retrieval
    /// floors) in one fresh read. Only the count leaves it.
    pub(crate) fn retrieval_loop_frontier_size(
        &self,
        observed: &HashSet<EntityId>,
        requested: &RetrievalFilter,
    ) -> Result<usize> {
        let txn = self.grant_read_txn()?;
        let (filter, policy) = self.resolve_retrieval_filter_in(&txn, Some(requested))?;
        let store = self.store_read();
        let mut frontier = HashSet::new();
        // One relationship authority for every anchor and peer (FIX 11648).
        let retrievable = self.recall_candidates_in(&txn, &policy, &filter, Some(requested));
        for anchor in observed {
            if !retrievable(anchor)? {
                continue;
            }
            for direction in [EdgeDirection::Out, EdgeDirection::In] {
                let edges = match direction {
                    EdgeDirection::Out => self.out_edges_in(&txn, anchor, None)?,
                    _ => store.port_edges(&txn, anchor, direction, None, None)?,
                };
                for edge in edges {
                    let edge = edge?;
                    let peer = edge.target;
                    if observed.contains(&peer) || frontier.contains(&peer) {
                        continue;
                    }
                    let (source, target) = match direction {
                        EdgeDirection::Out => (*anchor, peer),
                        _ => (peer, *anchor),
                    };
                    let admitted = super::edge_admission::admit_stored_edge_in(
                        self.vault,
                        &txn,
                        source,
                        target,
                        edge,
                        || Ok(super::admission::ReadAdmission::Visible(())),
                        // The peer under the loop's request, A included (FIX 7528).
                        || self.admit_in(&txn, &peer, || Ok(retrievable(&peer)?.then_some(()))),
                    )?;
                    if admitted.visible() {
                        frontier.insert(peer);
                    }
                }
            }
        }
        Ok(frontier.len())
    }
}
