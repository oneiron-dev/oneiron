//! Claim listings in id order, `/claims/by-id` and an entity's `claims`: each
//! page reads one bounded run of ids, and resumes after the last id it read.

use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EdgeDirection;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::EngineScan;
use crate::store::scan_count::ScanCount;
use crate::vault::IdScanPage;

use super::model::{GRAPH_FS_MAX_PAGE_ENTRIES, GraphFsEntry, GraphFsPage, GraphFsResolver};
use super::paging::PageBuilder;
use super::readdir::empty_page;

/// The scope of a subject's claim walk: the subject's inbound `ClaimOf`
/// edges, as the vault's own edge-peer scans scope them.
pub(super) fn claim_edge_scope(subject: &EntityId) -> Vec<u8> {
    [
        &[EdgeDirection::In as u8][..],
        subject.as_bytes(),
        &[EdgeKind::ClaimOf as u8][..],
    ]
    .concat()
}

impl GraphFsResolver<'_, '_> {
    pub(super) fn listdir_claims_by_id(
        &self,
        path: &str,
        cursor: Option<&str>,
    ) -> Result<GraphFsPage> {
        self.listdir_claims_by_id_with_fetch(path, cursor, GRAPH_FS_MAX_PAGE_ENTRIES)
    }

    pub(super) fn listdir_claims_by_id_with_fetch(
        &self,
        path: &str,
        cursor: Option<&str>,
        fetch: usize,
    ) -> Result<GraphFsPage> {
        let vault = self.scoped_read.vault();
        let count = self.claim_walk_count(EngineScan::TypeIndexRows, &[ENTITY_TYPE_CLAIM])?;
        self.claim_id_page(path, cursor, fetch, count, |after, limit| {
            let ids = vault.entities_by_type_page(ENTITY_TYPE_CLAIM, after, limit)?;
            let resume_after = (ids.len() >= limit).then(|| ids.last().copied()).flatten();
            Ok(IdScanPage { ids, resume_after })
        })
    }

    pub(super) fn listdir_claims_for_subject(
        &self,
        path: &str,
        subject: &EntityId,
        cursor: Option<&str>,
    ) -> Result<GraphFsPage> {
        if !self.scoped_read.is_entity_readable(subject)? {
            return Ok(empty_page(path, self.options.mount));
        }
        let vault = self.scoped_read.vault();
        let count = self.claim_walk_count(EngineScan::EdgePeerRows, &claim_edge_scope(subject))?;
        self.claim_id_page(
            path,
            cursor,
            GRAPH_FS_MAX_PAGE_ENTRIES,
            count,
            |after, limit| {
                vault.sources_page(
                    subject,
                    EdgeKind::ClaimOf,
                    Some(ENTITY_TYPE_CLAIM),
                    after,
                    limit,
                )
            },
        )
    }

    /// A count of the rows a claim walk reads, against `scan`'s threshold
    /// row (rule 5). Only the walk off this device adds to it
    /// ([`Self::device_admitted_run`]).
    fn claim_walk_count(&self, scan: EngineScan, scope: &[u8]) -> Result<ScanCount> {
        let vault = self.scoped_read.vault();
        let rtxn = vault.store.env.read_txn()?;
        ScanCount::start(&vault.store, &rtxn, scan, scope)
    }

    /// One page of the claims `ids_after` names in id order, of those this
    /// reader may read. A run of `fetch` ids that fills before the page does
    /// may stop on a claim the page passed over, so the cursor is sealed.
    /// `count` counts the walk's rows; past its row it raises its check.
    fn claim_id_page(
        &self,
        path: &str,
        cursor: Option<&str>,
        fetch: usize,
        mut count: ScanCount,
        ids_after: impl FnMut(Option<&EntityId>, usize) -> Result<IdScanPage>,
    ) -> Result<GraphFsPage> {
        let scope = self.cursor_scope(path);
        let after: Option<EntityId> = scope.open(cursor)?;
        let mut builder = PageBuilder::new(path, self.options);
        let mut next_cursor = None;
        let mut last_listed = after;
        let mut receipt = self.scoped_read.read_receipt(None, 0)?;
        let run = self.device_admitted_run(after, fetch, &mut count, ids_after)?;
        count.finish(self.scoped_read.vault());
        for id in &run.ids {
            if self.read_live_into(*id, &mut receipt)?.is_none() {
                continue;
            }
            let entry = GraphFsEntry::file(id.to_hex(), None);
            if !builder.try_push_after(entry, scope.seal(id)) {
                next_cursor = last_listed.map(|id| scope.seal(&id));
                break;
            }
            last_listed = Some(*id);
        }
        if next_cursor.is_none() {
            next_cursor = run.resume_after.map(|id| scope.seal(&id));
        }
        Ok(builder.finish(next_cursor).with_read_receipt(receipt))
    }

    /// Up to `fetch` ids `ids_after` names after `after`. On this device the
    /// run reads a bounded number of rows (F13), and a short run resumes where
    /// it stopped. Off this device the scan pages past every claim a
    /// device-local world keeps: such a claim takes no place in the run, never
    /// fills it and never ends it, so neither the page nor its cursor hints at
    /// one (DEC-0005). That walk has no bound, so `count` counts every id it
    /// reads, a withheld one too, and the owner's check sees a large walk
    /// (rule 5). The bounded run on this device adds nothing to `count`.
    pub(super) fn device_admitted_run(
        &self,
        after: Option<EntityId>,
        fetch: usize,
        count: &mut ScanCount,
        mut ids_after: impl FnMut(Option<&EntityId>, usize) -> Result<IdScanPage>,
    ) -> Result<IdScanPage> {
        if !self.scoped_read.off_device() {
            return ids_after(after.as_ref(), fetch);
        }
        let mut ids = Vec::new();
        let mut scanned = after;
        loop {
            let run = ids_after(scanned.as_ref(), fetch)?;
            scanned = run.resume_after;
            count.rows(run.ids.len());
            ids.extend(
                self.scoped_read
                    .vault()
                    .off_device_readable_for(run.ids, self.scoped_read.actor_key().destination())?,
            );
            if scanned.is_none() || ids.len() >= fetch {
                break;
            }
        }
        if ids.len() >= fetch {
            ids.truncate(fetch);
            scanned = ids.last().copied();
        }
        Ok(IdScanPage {
            ids,
            resume_after: scanned,
        })
    }
}
