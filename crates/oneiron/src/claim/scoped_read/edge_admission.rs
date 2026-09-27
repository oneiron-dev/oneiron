//! The one scoped graph projection: exact relation + both endpoints, then limits.
use super::{ScopedRead, admission::ReadAdmission};
use crate::edge::{EdgeInfo, EdgeKind};
use crate::gate::{PolicyManifestResolution, ResolvedRetrievalFilter};
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::{EntityId, Error, Result};
use std::collections::HashSet;

/// An edge cannot be constructed from raw adjacency outside this projection.
pub(super) struct AdmittedEdge(EdgeInfo);
impl AdmittedEdge {
    pub(super) fn info(self) -> EdgeInfo {
        self.0
    }
}
pub(super) struct AdmittedEdgeScan {
    pub(super) source: ReadAdmission<()>,
    pub(super) edges: Vec<AdmittedEdge>,
    pub(super) suppressed: usize,
}
impl ScopedRead<'_> {
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
        let mut seen = HashSet::new();
        seen.insert(*center);
        for row in rows {
            let edge = row?;
            let peer = edge.target;
            let (src, tgt) = if direction == EdgeDirection::Out {
                (*center, peer)
            } else {
                (peer, *center)
            };
            if !crate::note::diary_edge_access_in(self.vault, txn, src, edge.kind, tgt)? {
                continue;
            }
            match self.admit_entity_in(txn, policy, filter, &peer)? {
                ReadAdmission::Visible(()) => {
                    if unique_targets && !seen.insert(peer) {
                        continue;
                    }
                    result.edges.push(AdmittedEdge(edge));
                    if result.edges.len() >= limit || result.edges.len() >= scan_limit {
                        break;
                    }
                }
                ReadAdmission::Suppressed => result.suppressed += 1,
                ReadAdmission::OpaqueAbsent => {}
            }
        }
        Ok(result)
    }
}
