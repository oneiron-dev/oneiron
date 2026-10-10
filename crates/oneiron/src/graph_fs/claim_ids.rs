//! Claim listings in id order, `/claims/by-id` and an entity's `claims`: each
//! page reads one bounded run of ids, and resumes after the last id it read.

use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_CLAIM;

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
            vault.entities_by_type_page(ENTITY_TYPE_CLAIM, after, limit)
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
        ids_after: impl FnOnce(Option<&EntityId>, usize) -> Result<Vec<EntityId>>,
    ) -> Result<GraphFsPage> {
        let scope = self.cursor_scope(path);
        let after: Option<EntityId> = scope.open(cursor)?;
        let mut builder = PageBuilder::new(path, self.options);
        let mut next_cursor = None;
        let mut last_listed = after;
        let mut receipt = self.scoped_read.read_receipt(None, 0)?;
        let ids = ids_after(after.as_ref(), fetch)?;
        for id in &ids {
            if self.read_live_into(*id, &mut receipt)?.is_none() {
                continue;
            }
            if !builder.try_push(GraphFsEntry::file(id.to_hex(), None)) {
                next_cursor = last_listed.map(|id| scope.seal(&id));
                break;
            }
            last_listed = Some(*id);
        }
        if next_cursor.is_none() && ids.len() >= fetch {
            next_cursor = ids.last().map(|id| scope.seal(id));
        }
        Ok(builder.finish(next_cursor).with_read_receipt(receipt))
    }
}
