//! The one store of exact publish requests (`ORIGIN_PUBLISH_REQUEST`, LIVE):
//! each request's row and, beside it, the pages of its review. A request
//! changes only by a compare-and-set on its state in one write transaction,
//! so two callers can never both take its one dispatch. An actor's erase
//! scrubs every act that names it and keeps the rest of the record; a
//! request row that does not decode is dropped there instead, never an
//! abort of the erase or restore.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::types::{
    OriginPublishRefusal, OriginPublishRequestView, OriginPublishReviewItem,
    OriginPublishReviewPage, OriginPublishState,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};

/// The domain of a request id an idempotency key fixes.
const ORIGIN_PUBLISH_REQUEST_ID_DOMAIN: &[u8] = b"oneiron:origin-publish-request:v1";

/// The longest idempotency key, in bytes.
pub(super) const ORIGIN_PUBLISH_MAX_KEY_BYTES: usize = 128;

/// The WARN code of a request row an actor scrub dropped because it does
/// not decode (CALLS "FIX 6866 undecodable request on scrub").
const ORIGIN_PUBLISH_REQUEST_UNDECODABLE_DROPPED: &str =
    "origin_publish_request_undecodable_dropped";

/// Repo id, request id, then nothing for the request or a u64be page.
type PublishKey = (EntityId, EntityId, Vec<u8>);

/// One row of the store.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum PublishRow {
    Request(Box<OriginPublishRequestView>),
    ReviewPage(OriginPublishReviewPage),
}

const REQUESTS: SideTable<PublishKey, PublishRow, Named> =
    SideTable::new(&side_table::ORIGIN_PUBLISH_REQUEST);

fn request_key(repo_id: EntityId, request_id: EntityId) -> PublishKey {
    (repo_id, request_id, Vec::new())
}

fn page_key(repo_id: EntityId, request_id: EntityId, page: u64) -> PublishKey {
    (repo_id, request_id, page.to_be_bytes().to_vec())
}

/// The request id `key` fixes for one repository.
pub(super) fn keyed_request_id(repo_id: &EntityId, key: &str) -> Result<EntityId> {
    crate::codebase::entity_id_from_hash_material(
        ORIGIN_PUBLISH_REQUEST_ID_DOMAIN,
        &[repo_id.as_bytes(), key.as_bytes()],
    )
}

impl Vault {
    /// One request, as `txn` reads it.
    pub(super) fn publish_request_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        repo_id: EntityId,
        request_id: EntityId,
    ) -> Result<Option<OriginPublishRequestView>> {
        match REQUESTS.get(&self.store, txn, &request_key(repo_id, request_id))? {
            Some(PublishRow::Request(view)) => Ok(Some(*view)),
            Some(PublishRow::ReviewPage(_)) => {
                Err(Error::CorruptedIndex("origin publish request row"))
            }
            None => Ok(None),
        }
    }

    /// One request, read now.
    pub(super) fn publish_request(
        &self,
        repo_id: EntityId,
        request_id: EntityId,
    ) -> Result<Option<OriginPublishRequestView>> {
        let txn = self.store.env.read_txn()?;
        self.publish_request_in_txn(&txn, repo_id, request_id)
    }

    /// Writes a new request and its review pages, in the transaction that
    /// admitted its caller.
    pub(super) fn put_publish_request_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        view: &OriginPublishRequestView,
        pages: &[OriginPublishReviewPage],
    ) -> Result<()> {
        for (index, page) in (0_u64..).zip(pages) {
            let key = page_key(view.repo_id, view.request_id, index);
            REQUESTS.put(
                &self.store,
                txn,
                &key,
                &PublishRow::ReviewPage(page.clone()),
            )?;
        }
        self.write_publish_request_in_txn(txn, view)
    }

    fn write_publish_request_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        view: &OriginPublishRequestView,
    ) -> Result<()> {
        let key = request_key(view.repo_id, view.request_id);
        REQUESTS.put(
            &self.store,
            txn,
            &key,
            &PublishRow::Request(Box::new(view.clone())),
        )
    }

    /// One page of a request's review.
    pub(super) fn publish_review_page_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        view: &OriginPublishRequestView,
        page: u64,
    ) -> Result<Option<OriginPublishReviewPage>> {
        let key = page_key(view.repo_id, view.request_id, page);
        match REQUESTS.get(&self.store, txn, &key)? {
            Some(PublishRow::ReviewPage(page)) => Ok(Some(page)),
            Some(PublishRow::Request(_)) => {
                Err(Error::CorruptedIndex("origin publish review page"))
            }
            None => Ok(None),
        }
    }

    /// Every path a request's review names, read from its pages. A page the
    /// count names that is missing is an error: no admission stands on part
    /// of a review.
    pub(super) fn publish_review_paths_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        view: &OriginPublishRequestView,
    ) -> Result<BTreeSet<String>> {
        let mut paths = BTreeSet::new();
        for index in 0..view.review.pages {
            let page = self
                .publish_review_page_in_txn(txn, view, index)?
                .ok_or(Error::CorruptedIndex("origin publish review page"))?;
            for item in page.items {
                if let OriginPublishReviewItem::Path { path, .. } = item {
                    paths.insert(path);
                }
            }
        }
        Ok(paths)
    }

    /// Moves a request from one of `from` to `to` in `txn`, applying
    /// `change` beside it; a request in any other state is left as it is.
    /// Returns the row as it stands and whether this call moved it.
    pub(super) fn transition_publish_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        view: &OriginPublishRequestView,
        from: &[OriginPublishState],
        to: OriginPublishState,
        change: impl FnOnce(&mut OriginPublishRequestView),
    ) -> Result<(OriginPublishRequestView, bool)> {
        let mut current = self
            .publish_request_in_txn(txn, view.repo_id, view.request_id)?
            .ok_or(Error::EntityNotFound)?;
        if !from.contains(&current.state) {
            return Ok((current, false));
        }
        change(&mut current);
        current.state = to;
        if to.is_terminal() {
            current.finished_at = Some(self.now_recorded_at());
        }
        self.write_publish_request_in_txn(txn, &current)?;
        Ok((current, true))
    }

    /// [`Self::transition_publish_in_txn`] in its own transaction, ending the
    /// request in `to` with `refusal`. A terminal move releases the
    /// request's pin on its commit.
    pub(super) fn settle_publish(
        &self,
        view: &OriginPublishRequestView,
        from: &[OriginPublishState],
        to: OriginPublishState,
        refusal: Option<OriginPublishRefusal>,
    ) -> Result<OriginPublishRequestView> {
        let mut txn = self.store.env.write_txn()?;
        let (settled, moved) = self.transition_publish_in_txn(&mut txn, view, from, to, |row| {
            row.refusal = refusal;
        })?;
        txn.commit()?;
        if moved && settled.state.is_terminal() {
            self.release_publish_pin(&settled);
        }
        Ok(settled)
    }
}

/// Scrubs an erased actor from every request act that names it (the
/// side-table erase callback, which a restore runs again). The tuple, review
/// and outcome stay: the record of what left the vault outlives who asked.
/// A request row that does not decode is dropped with its review pages (its
/// actor bytes go with it; it could never dispatch) under a typed WARN
/// naming its key, and the scrub goes on; a store error still ends it.
pub(crate) fn erase_publish_request_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    let mut rows = Vec::new();
    let mut undecodable = Vec::new();
    for row in REQUESTS.iter_raw_from(&vault.store, wtxn, &[])? {
        let (key, bytes) = row?;
        if key.len() != 32 {
            continue;
        }
        let mut view = match REQUESTS.decode_value(&bytes) {
            Ok(PublishRow::Request(view)) => view,
            Ok(PublishRow::ReviewPage(_)) => continue,
            Err(error) => {
                undecodable.push((key, error.kind()));
                continue;
            }
        };
        let mut scrubbed = false;
        let row = &mut *view;
        let acts = std::iter::once(&mut row.requested)
            .chain(row.approved.as_mut())
            .chain(row.dispatched.as_mut());
        for act in acts {
            if act.actor == Some(*actor) {
                act.actor = None;
                scrubbed = true;
            }
        }
        if scrubbed {
            rows.push(view);
        }
    }
    for view in rows {
        vault.write_publish_request_in_txn(wtxn, &view)?;
    }
    for (key, kind) in undecodable {
        REQUESTS.delete_from(&vault.store, wtxn, &key)?;
        tracing::warn!(
            code = ORIGIN_PUBLISH_REQUEST_UNDECODABLE_DROPPED,
            repo_id = %crate::entity_id::bytes_to_hex_lower(&key[..16]),
            request_id = %crate::entity_id::bytes_to_hex_lower(&key[16..]),
            kind = ?kind,
            "an exact publish request that does not decode was dropped; it can never dispatch"
        );
    }
    Ok(())
}
