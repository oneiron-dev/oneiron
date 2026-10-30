//! Typed bodies on the owner lane (FIX 2458): an own device takes an office
//! body as it takes a NOTE, under the same lane rules and refusals, and its
//! home takes the device's body back.
//!
//! An own device subscribes every typed body it holds, and every office
//! artifact that may take one, with the empty `ds:e:{id}` row a NOTE's owner
//! subscription writes, replayed as an owner REQUEST on every connect. The
//! owner export sends the body as its frame, judged by the NOTE's refusals
//! for an entity that holds a typed body.
//!
//! The way back: a device answers its home's frame with the operations that
//! frame's head lacks, and a home that holds no body yet asks the device for
//! its own. The home joins a proven own device's frame as any typed body's
//! frame joins: through the office merge preflight, a fork where it fails.

use heed::{RoTxn, RwTxn};

use super::{DS_E, DocumentRegistry, EntityDocument, eligible};
use crate::authority::PeerMachine;
use crate::edit_roundtrip::OfficeFormat;
use crate::error::{Error, Result, SyncProtocolValidation};
use crate::side_table::HexId;
use crate::sync::window::Withhold;
use crate::typed_body::sync_frame::{
    has_typed_body_in_txn, is_typed_body_frame, typed_body_entities_in_txn, typed_body_lack_in_txn,
};
use crate::{EntityId, Vault};

fn denied() -> Error {
    Error::sync_protocol(SyncProtocolValidation::DocumentAdmissionDenied)
}

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

    /// The owner REQUEST a home sends an own device for `id` when the home
    /// holds no typed body for it: the device answers with its body's frame.
    pub(crate) fn owner_body_request(&self, id: EntityId) -> Result<Vec<u8>> {
        self.owner_request_frame(id)
    }
}

impl EntityDocument {
    /// Joins `payload`, a typed body's frame an owner's own device sent on
    /// the owner lane, in one writer: the device's credential, the machine's
    /// standing and the entity's admission are read there, then the frame
    /// joins the body through the office merge preflight, a fork where it
    /// fails, never an overwrite. Any other payload, and a NOTE, refuse.
    /// Whether the body here moved or a fork opened.
    pub fn import_owner_body(
        &self,
        payload: &[u8],
        peer: PeerMachine,
        session_is_live: impl FnOnce(&RwTxn<'_>) -> bool,
    ) -> Result<bool> {
        if !is_typed_body_frame(payload) || self.is_note()? {
            return Err(denied());
        }
        let _writer = self.lock()?;
        let moved = self.vault.with_write_txn_grouped(|txn| {
            eligible(&self.vault, txn, self.id)?;
            if !session_is_live(txn) {
                return Err(denied());
            }
            super::admit_document_destination_in_txn(&self.vault, txn, self.id, peer)?;
            crate::entity_doc::join_sync_update_in_txn(&self.vault, txn, &self.id, payload, None)
        })?;
        crate::sync::bridge::wake_regenerates_after_document(&self.vault, &[self.id]);
        Ok(moved)
    }

    /// This device's typed body as a frame for its home, the machine
    /// `home`, which holds `remote_vv`; `None` when it holds no typed body
    /// or the owner lane's refusals keep it here.
    pub(crate) fn owner_body_frame(
        &self,
        remote_vv: &[u8],
        home: PeerMachine,
    ) -> Result<Option<Vec<u8>>> {
        let admitted = {
            let txn = self.vault.store.env.read_txn()?;
            owner_body_admission_for(&self.vault, &txn, self.id, Withhold::Peer(home)).is_ok()
        };
        if !admitted {
            return Ok(None);
        }
        self.export_owner(remote_vv, Withhold::Peer(home)).map(Some)
    }

    /// The frame this device answers `payload`, its home's typed body frame
    /// it just took, with: the operations the home's head lacks. `None` when
    /// it lacks none, or `payload` is no typed body's frame.
    pub(crate) fn owner_body_reply(
        &self,
        payload: &[u8],
        home: PeerMachine,
    ) -> Result<Option<Vec<u8>>> {
        let lack = {
            let txn = self.vault.store.env.read_txn()?;
            typed_body_lack_in_txn(&self.vault.store, &txn, &self.id, payload)?
        };
        match lack {
            Some(theirs) => self.owner_body_frame(&theirs.encode(), home),
            None => Ok(None),
        }
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
        return Err(denied());
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
