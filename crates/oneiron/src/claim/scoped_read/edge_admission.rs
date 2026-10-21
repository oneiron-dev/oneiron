//! The one scoped graph projection: exact relation + both endpoints, then limits.
use super::access_gate::HeldAuthority;
use super::{ScopedRead, ScopedReadResult, admission::ReadAdmission};
use crate::edge::{EdgeInfo, EdgeKind};
use crate::gate::{PolicyManifestResolution, ResolvedRetrievalFilter};
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::scan_check::{EngineScan, ScanCount};
use crate::vault::ReadMode;
use crate::{EntityId, Error, Result};
use std::collections::HashSet;

/// An edge cannot be constructed from raw adjacency outside this projection.
pub(crate) struct AdmittedEdge(EdgeInfo);
impl AdmittedEdge {
    pub(crate) fn info(self) -> EdgeInfo {
        self.0
    }
}
/// One authority snapshot supplies source, relation and target admission.
/// Callers may provide different row-policy doors but cannot yield an edge
/// without the exact diary-pair check. `relation_target` is the stored
/// endpoint; inbound views carry the SOURCE in `edge.target` instead.
/// `OpaqueAbsent` never spends a slot.
pub(crate) fn admit_stored_edge_in<E: From<Error>>(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    source: EntityId,
    relation_target: EntityId,
    edge: EdgeInfo,
    admit_source: impl FnOnce() -> std::result::Result<ReadAdmission<()>, E>,
    admit_target: impl FnOnce() -> std::result::Result<ReadAdmission<()>, E>,
) -> std::result::Result<ReadAdmission<AdmittedEdge>, E> {
    if !crate::note::diary_edge_access_in(vault, txn, source, edge.kind, relation_target)
        .map_err(E::from)?
    {
        return Ok(ReadAdmission::OpaqueAbsent);
    }
    match admit_source()? {
        ReadAdmission::Visible(()) => {}
        ReadAdmission::Suppressed => return Ok(ReadAdmission::Suppressed),
        ReadAdmission::OpaqueAbsent => return Ok(ReadAdmission::OpaqueAbsent),
    }
    match admit_target()? {
        ReadAdmission::Visible(()) => Ok(ReadAdmission::Visible(AdmittedEdge(edge))),
        ReadAdmission::Suppressed => Ok(ReadAdmission::Suppressed),
        ReadAdmission::OpaqueAbsent => Ok(ReadAdmission::OpaqueAbsent),
    }
}

pub(super) struct AdmittedEdgeScan {
    pub(super) source: ReadAdmission<()>,
    pub(super) edges: Vec<AdmittedEdge>,
    pub(super) suppressed: usize,
}
impl ScopedRead<'_> {
    /// Project a known stored edge with both endpoints under this reader's
    /// policy. Weave and other scoped projections cannot assemble an edge
    /// from separate endpoint and relation checks.
    pub(super) fn admit_stored_edge_in(
        &self,
        txn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        filter: &ResolvedRetrievalFilter,
        source: EntityId,
        edge: EdgeInfo,
    ) -> Result<ReadAdmission<AdmittedEdge>> {
        let target = edge.target;
        admit_stored_edge_in(
            self.vault,
            txn,
            source,
            target,
            edge,
            || self.admit_entity_in(txn, policy, filter, &source),
            || self.admit_entity_in(txn, policy, filter, &target),
        )
    }

    /// In one read txn, admit source, exact SameAs pair, then target. A
    /// withheld pair never spends a result/scan/dedup slot. In a session the
    /// edge iterator composes its overlay, while consent is base-only and an
    /// overlay cannot manufacture a base-authorized SameAs link.
    #[expect(
        clippy::too_many_arguments,
        reason = "snapshot, policy, direction and two visible budgets are distinct axes"
    )]
    pub(super) fn admitted_edges_in(
        &self,
        txn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        filter: &ResolvedRetrievalFilter,
        center: &EntityId,
        direction: EdgeDirection,
        kind: Option<EdgeKind>,
        limit: usize,
        scan_limit: usize,
        unique_targets: bool,
    ) -> Result<AdmittedEdgeScan> {
        let source = self.admit_entity_in(txn, policy, filter, center)?;
        let mut result = AdmittedEdgeScan {
            source,
            edges: Vec::new(),
            suppressed: 0,
        };
        if !result.source.visible() || limit == 0 || scan_limit == 0 {
            return Ok(result);
        }
        let rows = match direction {
            EdgeDirection::Out => self.out_edges_in(txn, center, kind)?,
            EdgeDirection::In => match self.session_view {
                Some(view) => view.port_edges(txn, center, EdgeDirection::In, kind, None)?,
                None => self
                    .vault
                    .port_edges(txn, center, EdgeDirection::In, kind, None)?,
            },
            EdgeDirection::Both => {
                return Err(Error::InvariantViolation("directed scoped edge read"));
            }
        };
        // Every row read counts, withheld or not: the check is the owner's,
        // never the reader's, so it spends no visible slot (DEC-0005).
        let scope = [
            &[direction as u8][..],
            center.as_bytes(),
            &[kind.map_or(u8::MAX, |kind| kind as u8)][..],
        ]
        .concat();
        let mut count =
            ScanCount::start(&self.vault.store, txn, EngineScan::ScopedEdgeRows, &scope)?;
        let mut seen = HashSet::new();
        seen.insert(*center);
        for row in rows {
            count.row();
            let edge = row?;
            let peer = edge.target;
            let (src, tgt) = if direction == EdgeDirection::Out {
                (*center, peer)
            } else {
                (peer, *center)
            };
            let admitted = admit_stored_edge_in(
                self.vault,
                txn,
                src,
                tgt,
                edge,
                || Ok(ReadAdmission::Visible(())),
                || self.admit_entity_in(txn, policy, filter, &peer),
            )?;
            result.suppressed += admitted.suppression();
            if let Some(edge) = admitted.into_option() {
                if unique_targets && !seen.insert(peer) {
                    continue;
                }
                result.edges.push(edge);
                if result.edges.len() >= limit || result.edges.len() >= scan_limit {
                    break;
                }
            }
        }
        count.defer(&self.vault.store);
        Ok(result)
    }

    /// An anchor's weighted neighborhood from ONE snapshot under one receipt:
    /// out-edges, then in-edges, each admitted with its exact relation and
    /// its peer. A withheld pair or an edge under `min_weight` never spends
    /// one of the `limit` slots. The value is `None` when the anchor itself is
    /// withheld or missing. `project` labels the rows in the same snapshot.
    pub(crate) fn neighborhood_projected<T, E: From<Error>>(
        &self,
        center: &EntityId,
        kind: Option<EdgeKind>,
        min_weight: Option<f32>,
        limit: usize,
        project: impl FnOnce(
            &heed::RoTxn<'_>,
            Option<Vec<AdmittedNeighbor>>,
        ) -> std::result::Result<T, E>,
    ) -> std::result::Result<ScopedReadResult<T>, E> {
        let txn = self.grant_read_txn()?;
        let (filter, policy) = self.resolve_retrieval_filter_in(&txn, None)?;
        let anchor = self.admit_entity_in(&txn, &policy, &filter, center)?;
        let mut suppressed = anchor.suppression();
        let mut neighbors = Vec::new();
        if anchor.visible() && limit > 0 {
            'scan: for direction in [EdgeDirection::Out, EdgeDirection::In] {
                let rows = match self.session_view {
                    Some(view) => view.port_edges(&txn, center, direction, kind, None)?,
                    None => self.vault.port_edges(&txn, center, direction, kind, None)?,
                };
                for row in rows {
                    let edge = row?;
                    if min_weight.is_some_and(|min| edge.weight < min) {
                        continue;
                    }
                    let peer = edge.target;
                    let outbound = direction == EdgeDirection::Out;
                    let (src, tgt) = if outbound {
                        (*center, peer)
                    } else {
                        (peer, *center)
                    };
                    let admitted = admit_stored_edge_in(
                        self.vault,
                        &txn,
                        src,
                        tgt,
                        edge,
                        || Ok(ReadAdmission::Visible(())),
                        || self.admit_entity_in(&txn, &policy, &filter, &peer),
                    )?;
                    suppressed += admitted.suppression();
                    let Some(edge) = admitted.into_option() else {
                        continue;
                    };
                    neighbors.push(AdmittedNeighbor {
                        outbound,
                        edge: edge.info(),
                        peer_type: self
                            .entity_record_in(&txn, &peer)?
                            .map(|row| row.entity_type),
                    });
                    if neighbors.len() >= limit {
                        break 'scan;
                    }
                }
            }
        }
        let receipt = self.receipt_for(None, &policy, &filter, suppressed);
        Ok(ScopedReadResult {
            value: project(&txn, anchor.visible().then_some(neighbors))?,
            receipt,
        })
    }

    /// The `ChildOf` tree under `root` from ONE snapshot under one receipt:
    /// the root at depth zero, then breadth-first each child whose exact
    /// relation and both endpoints are admitted, down to `max_depth`. `node`
    /// decodes each admitted live row; a row it declines is not in the tree
    /// and is not descended. The value is `None` when the root is withheld,
    /// missing or declined. `project` labels the nodes in the same snapshot.
    pub(crate) fn child_of_tree_projected<N, T, E: From<Error>>(
        &self,
        root: &EntityId,
        max_depth: u32,
        node: impl Fn(&[u8]) -> std::result::Result<Option<N>, E>,
        project: impl FnOnce(
            &heed::RoTxn<'_>,
            Option<Vec<ChildOfTreeNode<N>>>,
        ) -> std::result::Result<T, E>,
    ) -> std::result::Result<ScopedReadResult<T>, E> {
        let txn = self.grant_read_txn()?;
        let (filter, policy) = self.resolve_retrieval_filter_in(&txn, None)?;
        // One held authority for the tree's node reads in this txn (FIX 7462).
        let held = HeldAuthority::for_request(None);
        let anchor = self.admit_entity_in(&txn, &policy, &filter, root)?;
        let mut suppressed = anchor.suppression();
        let mut tree = None;
        if anchor.visible()
            && let Some(row) = self.entity_raw_with_mode_held_in(
                &txn,
                &policy,
                &filter,
                root,
                ReadMode::Live,
                &held,
            )?
            && let Some(value) = node(&row.raw)?
        {
            let mut nodes = vec![ChildOfTreeNode {
                id: *root,
                parent: None,
                depth: 0,
                node: value,
            }];
            // `ChildOf` is single-parent and acyclic, so each id is walked once.
            let mut next = 0;
            while let Some(at) = nodes.get(next) {
                let (parent, depth) = (at.id, at.depth);
                next += 1;
                if depth >= max_depth {
                    continue;
                }
                let admitted = self.admitted_edges_in(
                    &txn,
                    &policy,
                    &filter,
                    &parent,
                    EdgeDirection::In,
                    Some(EdgeKind::ChildOf),
                    usize::MAX,
                    usize::MAX,
                    true,
                )?;
                suppressed += admitted.suppressed;
                // Inbound views carry the child in `edge.target`.
                let mut children: Vec<EntityId> = admitted
                    .edges
                    .into_iter()
                    .map(|edge| edge.info().target)
                    .collect();
                children.sort_unstable();
                for child in children {
                    let Some(row) = self.entity_raw_with_mode_held_in(
                        &txn,
                        &policy,
                        &filter,
                        &child,
                        ReadMode::Live,
                        &held,
                    )?
                    else {
                        continue;
                    };
                    if let Some(value) = node(&row.raw)? {
                        nodes.push(ChildOfTreeNode {
                            id: child,
                            parent: Some(parent),
                            depth: depth + 1,
                            node: value,
                        });
                    }
                }
            }
            tree = Some(nodes);
        }
        let receipt = self.receipt_for(None, &policy, &filter, suppressed);
        Ok(ScopedReadResult {
            value: project(&txn, tree)?,
            receipt,
        })
    }
}

/// One admitted neighbor of an anchor: the stored edge as the anchor sees it
/// (`edge.target` is the peer in either direction) and the peer's stored type.
pub(crate) struct AdmittedNeighbor {
    pub(crate) outbound: bool,
    pub(crate) edge: EdgeInfo,
    pub(crate) peer_type: Option<u8>,
}

/// One admitted node of a `ChildOf` tree: its tree parent (`None` at the
/// root), its depth below the root, and what the walk's decoder read from it.
pub(crate) struct ChildOfTreeNode<N> {
    pub(crate) id: EntityId,
    pub(crate) parent: Option<EntityId>,
    pub(crate) depth: u32,
    pub(crate) node: N,
}
