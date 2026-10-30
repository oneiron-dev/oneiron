//! Typed bodies on the owner lane (FIX 2458): an own device takes an office
//! body as it takes a NOTE, under the same lane rules and refusals.
//!
//! An own device subscribes every typed body it holds, and every office
//! artifact that may take one, with the empty `ds:e:{id}` row a NOTE's owner
//! subscription writes, replayed as an owner REQUEST on every connect. The
//! owner export sends the body as its frame, judged by the NOTE's refusals
//! for an entity that holds a typed body.

use heed::RoTxn;

use super::{DS_E, DocumentRegistry, eligible};
use crate::edit_roundtrip::OfficeFormat;
use crate::error::{Error, Result, SyncProtocolValidation};
use crate::side_table::HexId;
use crate::sync::window::Withhold;
use crate::typed_body::sync_frame::{has_typed_body_in_txn, typed_body_entities_in_txn};
use crate::{EntityId, Vault};

impl DocumentRegistry {
    /// Owner subscriptions for every typed body this device holds, and every
    /// office artifact that may take one, without one; returns their REQUEST
    /// frames.
    pub(crate) fn subscribe_owner_typed_bodies(&self) -> Result<Vec<Vec<u8>>> {
        let artifacts = self
            .vault
            .entities_by_type(crate::registry::ENTITY_TYPE_BLOB_ARTIFACT)?;
        let fresh = {
            let txn = self.vault.store.env.read_txn()?;
            let mut held = typed_body_entities_in_txn(&self.vault.store, &txn)?;
            held.extend(artifacts);
            held.sort_unstable();
            held.dedup();
            let mut fresh = Vec::new();
            for id in held {
                if !DS_E.contains(&self.vault.store, &txn, &HexId(id))?
                    && owner_body_candidate(&self.vault, &txn, id)?
                {
                    fresh.push(id);
                }
            }
            fresh
        };
        if fresh.is_empty() {
            return Ok(Vec::new());
        }
        self.vault.with_write_txn_grouped(|txn| {
            for id in &fresh {
                DS_E.put(&self.vault.store, txn, &HexId(*id), &Vec::new())?;
            }
            Ok(())
        })?;
        fresh
            .into_iter()
            .map(|id| self.owner_request_frame(id))
            .collect()
    }
}

/// What an own device may never receive as a typed body on the owner lane:
/// a NOTE's refusals, for an entity that holds a typed body here, judged for
/// the machine the export serves.
pub(super) fn owner_body_admission_for(
    vault: &Vault,
    txn: &RoTxn<'_>,
    id: EntityId,
    withhold: Withhold<'_>,
) -> Result<()> {
    eligible(vault, txn, id)?;
    if !has_typed_body_in_txn(&vault.store, txn, &id)?
        || crate::settings::device_only_withholds(
            &vault.store,
            txn,
            &withhold.worlds_in(vault, txn)?,
            &id,
        )?
    {
        return Err(Error::sync_protocol(
            SyncProtocolValidation::DocumentAdmissionDenied,
        ));
    }
    Ok(())
}

/// Whether an own device subscribes `id` as a typed body: past a NOTE's
/// refusals, it holds a typed body here, or it is an office artifact that
/// may take one.
fn owner_body_candidate(vault: &Vault, txn: &RoTxn<'_>, id: EntityId) -> Result<bool> {
    if eligible(vault, txn, id).is_err()
        || crate::settings::device_only_withholds(
            &vault.store,
            txn,
            &Withhold::Unknown.worlds_in(vault, txn)?,
            &id,
        )?
    {
        return Ok(false);
    }
    if has_typed_body_in_txn(&vault.store, txn, &id)? {
        return Ok(true);
    }
    Ok(vault
        .get_blob_artifact_in_txn(txn, &id)
        .ok()
        .flatten()
        .is_some_and(|body| OfficeFormat::from_media_type(&body.media_type).is_ok()))
}
