//! The one scoped graph projection: exact relation + both endpoints, then limits.
use super::{ScopedRead, admission::ReadAdmission};
use crate::edge::{EdgeInfo, EdgeKind};
use crate::gate::{PolicyManifestResolution, ResolvedRetrievalFilter};
use crate::ports::{EdgeDirection, EdgeStoreRead};
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
        Ok(result)
    }
}
