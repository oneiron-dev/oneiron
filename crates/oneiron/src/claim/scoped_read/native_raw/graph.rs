//! Directed edges, type scans and graph walks under one serving snapshot.

use super::*;
use crate::store::{EngineScan, scan_count::ScanCount};

impl NativeRawRead<'_> {
    /// Admitted edges in the selected direction; inbound targets name sources.
    pub fn edges(&self, id: &EntityId, outbound: bool) -> Result<Vec<EdgeInfo>> {
        self.edge_peers(id, outbound, None, None)
    }

    /// Admitted directed peers with the original optional type filter.
    pub fn peers(
        &self,
        id: &EntityId,
        kind: EdgeKind,
        peer_type: Option<u8>,
        outbound: bool,
    ) -> Result<Vec<EntityId>> {
        Ok(self
            .edge_peers(id, outbound, Some(kind), peer_type)?
            .into_iter()
            .map(|edge| edge.target)
            .collect())
    }

    fn edge_peers(
        &self,
        id: &EntityId,
        outbound: bool,
        kind: Option<EdgeKind>,
        peer_type: Option<u8>,
    ) -> Result<Vec<EdgeInfo>> {
        let lane = &self.lane;
        let txn = lane.grant_read_txn()?;
        let (filter, policy) = lane.resolve_retrieval_filter_in(&txn, None)?;
        let scan = lane.admitted_edges_in(
            &txn,
            &policy,
            &filter,
            id,
            if outbound {
                EdgeDirection::Out
            } else {
                EdgeDirection::In
            },
            kind,
            usize::MAX,
            usize::MAX,
            false,
        )?;
        let mut kept = Vec::new();
        for edge in scan.edges {
            let edge = edge.info();
            if let Some(expected) = peer_type
                && lane
                    .store_read()
                    .port_entity_record(&txn, &edge.target)?
                    .is_none_or(|row| row.entity_type != expected)
            {
                continue;
            }
            kept.push(edge);
        }
        let _receipt = lane.receipt_for(
            None,
            &policy,
            &filter,
            scan.source.suppression() + scan.suppressed,
        );
        Ok(kept)
    }

    /// Every admitted live row of this type, selected and read in one snapshot.
    pub fn entities_by_type(&self, entity_type: u8) -> Result<Vec<EntityId>> {
        let lane = &self.lane;
        let _bodies = crate::store::ASSET_FILE_PLANE.then(|| lane.vault.pin_all_result_bodies());
        let txn = lane.grant_read_txn()?;
        let (filter, policy) = lane.resolve_retrieval_filter_in(&txn, None)?;
        let store = lane.store_read();
        let mut count = ScanCount::start(&store, &txn, EngineScan::TypeIndexRows, &[entity_type])?;
        let authority = lane.held_for(None);
        let mut kept = Vec::new();
        let mut suppressed = 0;
        for id in store.port_entity_ids_by_type(&txn, entity_type, None)? {
            count.row();
            let id = id?;
            let (row, withheld) = lane.id_row_in(
                &txn,
                &policy,
                &filter,
                id,
                crate::vault::ReadMode::Live,
                &authority,
            )?;
            suppressed += withheld;
            if row.is_some_and(|row| row.body.is_some() && row.entity_type == entity_type) {
                kept.push(id);
            }
        }
        count.defer(&store);
        let _receipt = lane.receipt_for(None, &policy, &filter, suppressed);
        Ok(kept)
    }

    /// Admitted descendants only, excluding the root as the raw API does.
    pub fn subtree(&self, root: &EntityId, max_depth: u32) -> Result<Vec<(EntityId, u32)>> {
        let read = self.lane.child_of_tree_projected(
            root,
            max_depth,
            |_| Ok::<_, Error>(Some(())),
            |_, nodes| {
                let mut rows: Vec<_> = nodes
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|node| node.depth > 0)
                    .map(|node| (node.id, node.depth))
                    .collect();
                rows.sort_unstable_by(|a, b| {
                    a.1.cmp(&b.1)
                        .then_with(|| a.0.as_bytes().cmp(b.0.as_bytes()))
                });
                Ok::<_, Error>(rows)
            },
        )?;
        Ok(read.value)
    }

    /// Nearest-first ancestors in the admitted graph, not a global topology proof.
    pub fn ancestors(&self, node: &EntityId) -> Result<Vec<EntityId>> {
        Ok(self.ancestor_walk(node, None)?.0)
    }

    /// Whether the proposed relation closes a cycle IN THE ADMITTED GRAPH.
    /// False is never permission to mutate; writes retain global validation.
    pub fn would_create_cycle(&self, node: &EntityId, target: &EntityId) -> Result<bool> {
        Ok(self.ancestor_walk(target, Some(node))?.1)
    }

    fn ancestor_walk(
        &self,
        start: &EntityId,
        sought: Option<&EntityId>,
    ) -> Result<(Vec<EntityId>, bool)> {
        let lane = &self.lane;
        let txn = lane.grant_read_txn()?;
        let (filter, policy) = lane.resolve_retrieval_filter_in(&txn, None)?;
        let anchor = lane.admit_entity_in(&txn, &policy, &filter, start)?;
        let mut suppressed = anchor.suppression();
        let mut current = *start;
        let mut seen = HashSet::from([current]);
        let mut parents = Vec::new();
        let mut cyclic = anchor.visible() && sought == Some(start);
        if anchor.visible() && !cyclic {
            loop {
                let scan = lane.admitted_edges_in(
                    &txn,
                    &policy,
                    &filter,
                    &current,
                    EdgeDirection::Out,
                    Some(EdgeKind::ChildOf),
                    usize::MAX,
                    usize::MAX,
                    false,
                )?;
                suppressed += scan.source.suppression() + scan.suppressed;
                let Some(parent) = scan.edges.into_iter().next().map(|edge| edge.info().target)
                else {
                    break;
                };
                if sought == Some(&parent) {
                    cyclic = true;
                    break;
                }
                if !seen.insert(parent) {
                    break;
                }
                parents.push(parent);
                current = parent;
            }
        }
        let _receipt = lane.receipt_for(None, &policy, &filter, suppressed);
        Ok((parents, cyclic))
    }
}
