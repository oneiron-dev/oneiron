//! The ASSET each AG-UI capture lands as (Engine RULING L2-15-CAPTURE-SUBJECT
//! = C): the file the owner chose, scoped to its project. The capture claim
//! is about this asset, as a docs review claim is about its page's asset, so
//! imported evidence never meets the project hub or the owner's own
//! neighbourhood. Deleting the capture deletes its asset.
//!
//! The asset holds no copy of the capture's bytes: the exact JSONL stays in
//! the claim's snapshot, the one row the reader's projection decides on. It
//! names no blob and no text, so it is never embedded.

use serde::{Deserialize, Serialize};

use super::AG_UI_SOURCE_ID;
use super::file::AG_UI_FILE_PREDICATE;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimSource, ClaimSubject};
use crate::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_CLAIM};
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::{EntityId, Error, Result, Vault};

/// The capture assets whose capture claim was erased, owed their own delete
/// once that erase commits. Key: the asset. Value: when it was owed.
const ASSET_ERASE_OWED: SideTable<EntityId, u64, Named> =
    SideTable::new(&side_table::INGEST_AG_UI_CAPTURE_ASSET_ERASE);

/// How many owed asset deletes one collection runs.
const ERASES_PER_COLLECTION: usize = 64;

/// The `source` every capture asset names: imported evidence.
const CAPTURE_ASSET_SOURCE: &str = "imported";

/// The body of a capture's ASSET: where the capture came from, the project it
/// is scoped to, the app the owner named and the capture claim about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CaptureAssetBody {
    source: String,
    source_id: String,
    project_ref: String,
    app_id: String,
    claim_ref: String,
}

impl CaptureAssetBody {
    /// The body of the asset the capture `claim` of `app_id` in `project`
    /// lands as.
    pub(super) fn new(project: EntityId, app_id: &str, claim: EntityId) -> Self {
        Self {
            source: CAPTURE_ASSET_SOURCE.to_owned(),
            source_id: AG_UI_SOURCE_ID.to_owned(),
            project_ref: project.to_hex(),
            app_id: app_id.to_owned(),
            claim_ref: claim.to_hex(),
        }
    }

    /// The stored bytes: MessagePack with field names, as the docs and web
    /// assets are stored.
    pub(super) fn encode(&self) -> Result<Vec<u8>> {
        rmp_serde::to_vec_named(self)
            .map_err(|_| Error::InvalidClaimBody("AG-UI capture asset encoding failed"))
    }
}

/// The capture body `asset` holds when it is a live ASSET; `None` for an
/// absent, deleted or other row, or a body of another shape.
fn live_capture_asset_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    asset: &EntityId,
) -> Result<Option<CaptureAssetBody>> {
    if crate::ports::TombstoneStoreRead::port_deletion_state(store, txn, asset)?.deleted {
        return Ok(None);
    }
    let Some(raw) = store.entities.get(txn, asset.as_bytes())? else {
        return Ok(None);
    };
    if EntityMetadataHeader::parse(&raw)
        .is_none_or(|header| header.entity_type != ENTITY_TYPE_ASSET)
    {
        return Ok(None);
    }
    Ok(rmp_serde::from_slice(&raw[ENTITY_METADATA_HEADER_LEN..]).ok())
}

/// Whether `asset` is the live capture ASSET of the capture `claim` of
/// `app_id` in `project`: the binding every reader holds a capture to.
pub(super) fn capture_asset_binds_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    asset: &EntityId,
    claim: EntityId,
    project: EntityId,
    app_id: &str,
) -> Result<bool> {
    Ok(live_capture_asset_in_txn(store, txn, asset)?
        .is_some_and(|body| body == CaptureAssetBody::new(project, app_id, claim)))
}

/// The capture asset the row `id` is the capture claim of: a CLAIM under
/// [`AG_UI_FILE_PREDICATE`] from an import, about a live capture asset that
/// names it. `None` for every other row, and for a claim whose body is gone.
fn capture_asset_of_claim_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<EntityId>> {
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(None);
    };
    if EntityMetadataHeader::parse(&raw)
        .is_none_or(|header| header.entity_type != ENTITY_TYPE_CLAIM)
    {
        return Ok(None);
    }
    let Ok(claim) = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)
    else {
        return Ok(None);
    };
    if claim.predicate != AG_UI_FILE_PREDICATE || claim.source != Some(ClaimSource::Imported) {
        return Ok(None);
    }
    let ClaimSubject::Entity(asset) = claim.subject else {
        return Ok(None);
    };
    Ok(live_capture_asset_in_txn(store, txn, &asset)?
        .filter(|body| body.claim_ref == id.to_hex())
        .map(|_| asset))
}

/// The eraser line (`deletion::derived_rows`): an erased capture claim owes
/// its asset's delete. An eraser cannot delete another row in its writer, so
/// [`collect_capture_asset_erases`] runs the delete once this erase commits.
pub(crate) fn owe_capture_asset_erase_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let Some(asset) = capture_asset_of_claim_in_txn(store, txn, id)? else {
        return Ok(());
    };
    ASSET_ERASE_OWED.put(store, txn, &asset, &crate::unix_seconds_now())
}

/// Deletes the assets of erased captures, a bounded batch at a time: after
/// every delete commits, and at each capture. An asset stays owed until its
/// delete has committed, so one that fails, or a crash between, is tried
/// again; a failure is logged. A collection the deletes it runs reach again
/// returns at once.
pub(crate) fn collect_capture_asset_erases(vault: &Vault) {
    let Some(_running) = Collecting::enter() else {
        return;
    };
    if let Err(error) = collect_owed_asset_erases(vault) {
        tracing::warn!(
            reason = "ag_ui_capture_asset_erase_owed",
            %error,
            "an erased AG-UI capture's asset is owed its delete; the next delete or capture retries"
        );
    }
}

thread_local! {
    /// Whether this thread is collecting owed capture asset deletes now.
    static COLLECTING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// This thread's one collection while it runs.
struct Collecting;

impl Collecting {
    fn enter() -> Option<Self> {
        if COLLECTING.with(|running| running.replace(true)) {
            return None;
        }
        Some(Self)
    }
}

impl Drop for Collecting {
    fn drop(&mut self) {
        COLLECTING.with(|running| running.set(false));
    }
}

fn collect_owed_asset_erases(vault: &Vault) -> Result<()> {
    let owed: Vec<EntityId> = {
        let txn = vault.store.env.read_txn()?;
        let mut owed = Vec::new();
        for row in ASSET_ERASE_OWED.iter_from(&vault.store, &txn, &[])? {
            if owed.len() >= ERASES_PER_COLLECTION {
                break;
            }
            owed.push(row?.0);
        }
        owed
    };
    for asset in owed {
        let live = {
            let txn = vault.store.env.read_txn()?;
            live_capture_asset_in_txn(&vault.store, &txn, &asset)?.is_some()
        };
        if live {
            vault.delete_entity_with_reason(&asset, crate::deletion::DeleteReason::UserDelete)?;
        }
        vault.with_write_txn_grouped(|txn| {
            ASSET_ERASE_OWED.delete(&vault.store, txn, &asset).map(drop)
        })?;
    }
    Ok(())
}
