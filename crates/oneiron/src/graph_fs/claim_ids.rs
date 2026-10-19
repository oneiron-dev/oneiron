//! Claim listings in id order, `/claims/by-id` and an entity's `claims`: each
//! page reads one bounded run of ids, and resumes after the last id it read.

use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::vault::IdScanPage;

use super::model::{GRAPH_FS_MAX_PAGE_ENTRIES, GraphFsEntry, GraphFsPage, GraphFsResolver};
use super::paging::PageBuilder;
use super::readdir::empty_page;

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
        self.claim_id_page(path, cursor, fetch, |after, limit| {
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
        self.claim_id_page(path, cursor, GRAPH_FS_MAX_PAGE_ENTRIES, |after, limit| {
            vault.sources_page(
                subject,
                EdgeKind::ClaimOf,
                Some(ENTITY_TYPE_CLAIM),
                after,
                limit,
            )
        })
    }

    /// One page of the claims `ids_after` names in id order, of those this
    /// reader may read. A run of `fetch` ids that fills before the page does
    /// may stop on a claim the page passed over, so the cursor is sealed.
    fn claim_id_page(
        &self,
        path: &str,
        cursor: Option<&str>,
        fetch: usize,
        ids_after: impl FnMut(Option<&EntityId>, usize) -> Result<IdScanPage>,
    ) -> Result<GraphFsPage> {
        let scope = self.cursor_scope(path);
        let after: Option<EntityId> = scope.open(cursor)?;
        let mut builder = PageBuilder::new(path, self.options);
        let mut next_cursor = None;
        let mut last_listed = after;
        let mut receipt = self.scoped_read.read_receipt(None, 0)?;
        let run = self.device_admitted_run(after, fetch, ids_after)?;
        for id in &run.ids {
            if self.read_live_into(*id, &mut receipt)?.is_none() {
                continue;
            }
            if !builder.try_push(GraphFsEntry::file(id.to_hex(), None)) {
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
    /// one (DEC-0005).
    fn device_admitted_run(
        &self,
        after: Option<EntityId>,
        fetch: usize,
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
