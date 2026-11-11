//! Delivery of the bodies a confirmed staged import still owes (FIX 12408).
//!
//! A confirmation lands an artifact's metadata and whatever bodies came with
//! it; each by-ref ASSET body still absent stays owed under the receipt,
//! beside the admitted content and staged stamps the confirmation keeps for
//! it. These doors land owed bodies later under that same receipt, without a
//! second confirmation or a reimport: each is checked against the
//! digest-pinned admitted part, today's claim and facet policy for that part,
//! the live carrier and the body's measured facts, lands at the receipt's
//! federated tier through the usual body landing door, keeps the born-with
//! text the part carried for the row, and releases the stamps its birth
//! frees. A body that does not land stays owed; the
//! confirmation stands either way.

use std::collections::HashMap;

use super::base::SyncClient;
use super::federated::map_federated_admission_err;
use crate::EntityId;
use crate::batch::export::{
    OwedBody, StagedImportBodyProgress, VaultImportStageReceipt, VaultImportStageStatus,
    attach_staged_import_body_source, cancel_staged_import_body_work, decode_staged_import_parts,
    settle_staged_import_body_work, staged_import_body_work, vault_import_stage_receipt,
    vault_import_staged_content,
};
use crate::sync::asset_body::references::bound_refs;
use crate::sync::asset_body::session::{AssetBodyLane, land_carried_body, with_manager_peer};
use crate::sync::ingest::watch_births;
use crate::sync::selector::{
    CarriedText, carried_born_with, keep_carried_born_with, release_staged_landed_stamps,
    revalidate_admitted_facet_stamps, revalidate_admitted_federated_claims,
};
use crate::sync::transport::TransportError;

impl SyncClient {
    /// Lands the supplied `bodies` the confirmed staged import `receipt_id`
    /// still owes, each at the receipt's federated tier through the usual
    /// body landing door, and releases the stamps each birth frees. A body
    /// the receipt does not owe is ignored; one that does not land stays
    /// owed. The last owed body landed drops the content and stamps the
    /// confirmation kept for delivery.
    ///
    /// # Errors
    ///
    /// A receipt that is missing or not confirmed, kept content that no
    /// longer matches its receipt, and storage errors.
    pub fn deliver_staged_vault_import_bodies(
        &mut self,
        receipt_id: [u8; 32],
        bodies: &HashMap<EntityId, Vec<u8>>,
    ) -> std::result::Result<StagedImportBodyProgress, TransportError> {
        // The confirmation's lock: a delivery never interleaves with the
        // confirmation that decides what is owed.
        let vault = std::sync::Arc::clone(&self.vault);
        let _guard = vault
            .store
            .staged_import_confirm_lock
            .lock()
            .map_err(|_| TransportError::Storage("staged import lock poisoned".into()))?;
        let receipt = confirmed_receipt(&self.vault, &receipt_id)?;
        self.deliver_staged_bodies_locked(&receipt, bodies)
    }

    /// What the confirmed staged import `receipt_id` still owes.
    ///
    /// # Errors
    ///
    /// A receipt that is missing or not confirmed, and storage errors.
    pub fn staged_vault_import_body_progress(
        &self,
        receipt_id: [u8; 32],
    ) -> std::result::Result<StagedImportBodyProgress, TransportError> {
        confirmed_receipt(&self.vault, &receipt_id)?;
        let owed = staged_import_body_work(&self.vault, &receipt_id)
            .map_err(map_federated_admission_err)?
            .map(|work| work.owed)
            .unwrap_or_default();
        Ok(StagedImportBodyProgress::of(&owed, Vec::new()))
    }

    /// Attaches the producer the host registered as `source`
    /// ([`super::SyncClientConfig::staged_import_body_sources`]) to the bodies
    /// the confirmed staged import `receipt_id` still owes: this client then
    /// fetches them from it on a socket of its own, and each lands as a
    /// supplied body does, at the receipt's federated tier and under today's
    /// policy for its part. A producer serves only the import source it is
    /// registered for, so a receipt from any other source refuses it.
    /// Attaching another producer stops a fetch begun under the earlier one.
    /// Returns whether any body was owed.
    ///
    /// # Errors
    ///
    /// A receipt that is missing or not confirmed, a producer not registered
    /// or registered for another source, and storage errors.
    pub fn attach_staged_vault_import_body_source(
        &mut self,
        receipt_id: [u8; 32],
        source: [u8; 32],
    ) -> std::result::Result<bool, TransportError> {
        let vault = std::sync::Arc::clone(&self.vault);
        let _guard = vault
            .store
            .staged_import_confirm_lock
            .lock()
            .map_err(|_| TransportError::Storage("staged import lock poisoned".into()))?;
        let receipt = confirmed_receipt(&self.vault, &receipt_id)?;
        let registered = self
            .config
            .staged_import_body_sources
            .iter()
            .find(|registered| registered.id == source)
            .ok_or(TransportError::InvalidPayload(
                "staged import body source not registered",
            ))?;
        if registered.serves != receipt.source {
            return Err(TransportError::InvalidPayload(
                "staged import body source serves another source",
            ));
        }
        let attached = attach_staged_import_body_source(&self.vault, &receipt_id, source)
            .map_err(map_federated_admission_err)?;
        if attached.is_some() {
            self.staged_body_pulls.wake();
        }
        Ok(attached.is_some())
    }

    /// Stops delivering the bodies the confirmed staged import `receipt_id`
    /// still owes: its owed bodies, the content and the stamps kept for them
    /// go, and the rows stay pending. The confirmation stands. Returns
    /// whether any body was owed.
    ///
    /// # Errors
    ///
    /// A receipt that is missing or not confirmed, and storage errors.
    pub fn cancel_staged_vault_import_body_delivery(
        &mut self,
        receipt_id: [u8; 32],
    ) -> std::result::Result<bool, TransportError> {
        let vault = std::sync::Arc::clone(&self.vault);
        let _guard = vault
            .store
            .staged_import_confirm_lock
            .lock()
            .map_err(|_| TransportError::Storage("staged import lock poisoned".into()))?;
        confirmed_receipt(&self.vault, &receipt_id)?;
        cancel_staged_import_body_work(&self.vault, &receipt_id)
            .map_err(map_federated_admission_err)
    }

    /// [`Self::deliver_staged_vault_import_bodies`] under the confirmation
    /// lock its caller holds, for the confirmed `receipt`.
    pub(super) fn deliver_staged_bodies_locked(
        &mut self,
        receipt: &VaultImportStageReceipt,
        bodies: &HashMap<EntityId, Vec<u8>>,
    ) -> std::result::Result<StagedImportBodyProgress, TransportError> {
        let receipt_id = receipt.receipt_id;
        let Some(work) = staged_import_body_work(&self.vault, &receipt_id)
            .map_err(map_federated_admission_err)?
        else {
            return Ok(StagedImportBodyProgress::default());
        };
        let content = vault_import_staged_content(&self.vault, &receipt_id)
            .map_err(map_federated_admission_err)?
            .ok_or(TransportError::Storage(
                "owed staged import content missing".into(),
            ))?;
        if receipt.admitted_update_digest != Some(*blake3::hash(&content).as_bytes()) {
            return Err(TransportError::InvalidPayload(
                "admitted update digest mismatch",
            ));
        }
        let parts = decode_staged_import_parts(&content).map_err(map_federated_admission_err)?;
        let mut owed = Vec::new();
        let mut landed = Vec::new();
        for part in &parts {
            let key = &part.key;
            let mine: Vec<&OwedBody> = work
                .owed
                .iter()
                .filter(|body| body.window == key.as_str())
                .collect();
            if mine.is_empty() {
                continue;
            }
            // Rows of this part that are live now and still need the text the
            // part carried for them: the confirmation kept text only for rows
            // live then. A row born through another lane while owed here
            // takes it unless it already holds one; its debt ends only once
            // the text is kept, on every path below.
            let mut keep = Vec::new();
            let mut absent = Vec::new();
            for body in mine {
                let id = EntityId::from_bytes(body.entity)
                    .map_err(|_| TransportError::InvalidPayload("owed body row"))?;
                if self.row_present(body.entity)? {
                    if carried_born_with(&self.vault, &id)
                        .map_err(map_federated_admission_err)?
                        .is_empty()
                    {
                        keep.push(id);
                    }
                } else {
                    absent.push((id, body));
                }
            }
            let supplied = absent.iter().any(|(id, _)| bodies.contains_key(id));
            // Today's policy for the admitted part, as the confirmation
            // checked it: a part it now refuses lands nothing and keeps its
            // absent bodies owed.
            let admitted_now = supplied
                && match revalidate_admitted_federated_claims(
                    &self.vault,
                    key,
                    &part.update,
                    receipt.role,
                )
                .and_then(|()| revalidate_admitted_facet_stamps(key, &part.update))
                {
                    Ok(()) => true,
                    Err(error) => {
                        tracing::warn!(%error, window = %key, "staged import part refused its owed bodies");
                        false
                    }
                };
            if admitted_now {
                let admitted =
                    crate::sync::schema::create_window_doc("federation-staged-bodies", key);
                admitted.import(&part.update).map_err(|_| {
                    TransportError::InvalidPayload("admitted body references unreadable")
                })?;
                let refs = bound_refs(&admitted);
                let entities = admitted.get_map("entities");
                self.ensure_window(key.as_str())?;
                for (id, body) in absent {
                    let found = refs.iter().find(|bound| bound.id == id);
                    let carrier = crate::sync::loro_support::map_get_bytes(&entities, &id.to_hex());
                    let (Some(bytes), Some(bound), Some(carrier)) =
                        (bodies.get(&id), found, carrier)
                    else {
                        owed.push(body.clone());
                        continue;
                    };
                    let lane = AssetBodyLane::FederationReceive { role: receipt.role };
                    let vault = std::sync::Arc::clone(&self.vault);
                    let born = watch_births(&vault, &[(id, carrier.clone())], || {
                        with_manager_peer(&self.manager, lane, None, |peer| {
                            land_carried_body(peer, key, bound, bytes)
                        })
                        .map(|_| ())
                    });
                    match born {
                        Ok(born) if born.contains(&id) => {
                            let released = release_staged_landed_stamps(
                                &vault,
                                key,
                                &receipt_id,
                                (id, carrier),
                            )
                            .map_err(map_federated_admission_err)?;
                            self.import_released_stamps(key.as_str(), released)?;
                        }
                        Ok(_) => {}
                        Err(error) => {
                            tracing::warn!(%error, entity = %id.to_hex(), "owed staged asset body not landed");
                        }
                    }
                    if self.row_present(body.entity)? {
                        landed.push(id);
                        keep.push(id);
                    } else {
                        owed.push(body.clone());
                    }
                }
            } else {
                owed.extend(absent.into_iter().map(|(_, body)| body.clone()));
            }
            // Before the work settles: the last owed body gone drops the
            // content, the only retained copy of this text. A keep that
            // fails returns before the settle, so work and content stay.
            let carried: Vec<CarriedText> = part
                .born_with
                .iter()
                .filter(|(id, _, _)| keep.contains(id))
                .cloned()
                .collect();
            keep_carried_born_with(&self.vault, &carried).map_err(map_federated_admission_err)?;
        }
        settle_staged_import_body_work(&self.vault, &receipt_id, owed.clone())
            .map_err(map_federated_admission_err)?;
        Ok(StagedImportBodyProgress::of(&owed, landed))
    }

    /// Whether the row `entity` names is stored here.
    fn row_present(&self, entity: [u8; 16]) -> std::result::Result<bool, TransportError> {
        let id = EntityId::from_bytes(entity)
            .map_err(|_| TransportError::InvalidPayload("owed body row"))?;
        Ok(self
            .vault
            .get_raw(&id)
            .map_err(map_federated_admission_err)?
            .is_some())
    }
}

/// The confirmed receipt `receipt_id`, or why it is none.
pub(super) fn confirmed_receipt(
    vault: &crate::Vault,
    receipt_id: &[u8; 32],
) -> std::result::Result<VaultImportStageReceipt, TransportError> {
    let receipt = vault_import_stage_receipt(vault, receipt_id)
        .map_err(|_| TransportError::Storage("receipt unreadable".into()))?
        .ok_or(TransportError::InvalidPayload("missing durable receipt"))?;
    if receipt.status != VaultImportStageStatus::Confirmed {
        return Err(TransportError::InvalidPayload(
            "staged import not confirmed",
        ));
    }
    Ok(receipt)
}
