//! Native custody for an origin claim's optional derived copy.
//! Every original actor and the source owner must open the same frozen copy.

use std::collections::BTreeSet;
use std::path::PathBuf;

use getrandom::SysRng;
use heed::RwTxn;
use oneiron_crypto::backup::{ARTIFACT_SEAL_EPOCH as EPOCH, ARTIFACT_SEAL_SUITE as AEAD};
use oneiron_crypto::{
    Argon2Cost, Envelope, Kek, OpenKey, OpenPolicy, SealKey, SealParams, WrapType, seal_with_aad,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::retained_copy::RetainedHomeClaimSender;
use super::{HomeClaimVector, ReceivedHomeClaimVector, own_peer_in_txn};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::origin::actor_erase::{OriginClaimKind, claim_actors};
use crate::store::checkpoint_payload::instance::{self, Lifecycle};
use crate::store::checkpoint_payload::rows::OwnerRef;
use crate::store::checkpoint_payload::{
    CompartmentAccess, PAYLOAD_PURPOSE, PayloadItem, Subtype, compartment_access,
};
use crate::store::key_custody::{
    CustodyBinding, CustodyKind, CustodyPlan, binding_in_txn, retirement_in_txn,
};
use crate::store::restore_admission::Rejected;
use crate::write_envelope::claim_body::decode_claim_body;
use crate::{EntityId, Error, Result, Vault};

const COPY_DOMAIN: &[u8] = b"oneiron/home-claim-copy/actor-custody/v1\0";

fn crypto_error(error: oneiron_crypto::Error) -> Error {
    match error {
        oneiron_crypto::Error::OutOfMemory => {
            Error::Io(std::io::Error::from(std::io::ErrorKind::OutOfMemory))
        }
        _ => invalid(),
    }
}

fn invalid() -> Error {
    Error::CorruptedIndex("home CLAIM actor copy")
}

/// An item selected by the native instance table, never a key derived from an id.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Required {
    owner: EntityId,
    incarnation: [u8; 16],
    generation: u64,
}

impl Required {
    fn item(&self) -> Result<PayloadItem> {
        PayloadItem::new(
            Subtype::EntityTree,
            OwnerRef::entity(&self.owner).owner32,
            self.incarnation,
        )
    }

    fn custody_id(&self) -> Result<Vec<u8>> {
        let mut id = vec![CustodyKind::CheckpointPayload.tag()];
        id.extend_from_slice(&self.item()?.encode());
        id.extend_from_slice(&self.generation.to_be_bytes());
        Ok(id)
    }
}

/// Ciphertext and frozen native requirements, not permission or a receipt.
/// No queue or wire producer stores this until its native carrier is complete.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetainedHomeClaimActors {
    vault_id: [u8; 32],
    entity_id: EntityId,
    source_digest: [u8; 32],
    sender: RetainedHomeClaimSender,
    required: Vec<Required>,
    envelope: Vec<u8>,
}

/// The original receive and its already sealed native copy stay together.
/// No key, read guard or reconstructed source crosses into the writer.
pub(crate) struct PreparedHomeClaimActors {
    path: PathBuf,
    binding: CustodyBinding,
    received: ReceivedHomeClaimVector,
    copy: RetainedHomeClaimActors,
}

/// Only the actual origin codec supplies actors. Other CLAIM families are not
/// declared actor-free by this port, even when they are not responses.
fn origin_owners(vector: &HomeClaimVector) -> Result<Option<BTreeSet<EntityId>>> {
    if !EntityMetadataHeader::parse(&vector.source)
        .is_some_and(|header| header.entity_type == crate::registry::ENTITY_TYPE_CLAIM)
    {
        return Ok(None);
    }
    let body = decode_claim_body(&vector.source[ENTITY_METADATA_HEADER_LEN..], true)?;
    let Some(kind) = OriginClaimKind::of(&body.predicate) else {
        return Ok(None);
    };
    let Some(actors) = claim_actors(kind, &body) else {
        return Ok(None);
    };
    let mut owners = BTreeSet::from([vector.entity_id]);
    owners.extend(actors.pusher.id());
    owners.extend(actors.host.and_then(|actor| actor.id()));
    Ok(Some(owners))
}

impl ReceivedHomeClaimVector {
    /// Prepares only the derived copy, outside the canonical writer. The caller
    /// keeps the raw delivery and native job when preparation fails or misses.
    pub(crate) fn prepare_origin_actor_copy(
        self,
        vault: &Vault,
    ) -> Result<Option<PreparedHomeClaimActors>> {
        let Some(owners) = origin_owners(&self.vector)? else {
            return Ok(None);
        };
        let Some(sender) = RetainedHomeClaimSender::from_peer(self.peer) else {
            return Ok(None);
        };
        let _guard = vault.store.core.key_custody.read_guard()?;
        let vault_id = {
            let txn = vault.store.env.read_txn()?;
            if !own_peer_in_txn(vault, &txn, self.peer)? {
                return Ok(None);
            }
            for owner in &owners {
                if vault.carrier_actor_erased_in_txn(&txn, owner)? {
                    return Ok(None);
                }
            }
            let Some(id) = vault.authority_view_readonly_in_txn(&txn)?.vault_id else {
                return Ok(None);
            };
            id
        };
        let native_owners = owners.iter().map(OwnerRef::entity).collect();
        let Some((binding, compartments)) = vault
            .store
            .checkpoint_payload_compartments_bound(&native_owners)?
        else {
            return Ok(None);
        };
        // Native capture omits erased owners. A missing actor cannot turn an
        // ALL-owner copy into a copy sealed under only the remaining owners.
        if compartments.len() != owners.len() {
            return Ok(None);
        }
        let mut required = Vec::with_capacity(owners.len());
        let mut keys = Vec::with_capacity(owners.len());
        for (owner, (found, key)) in owners.iter().zip(compartments) {
            let expected = OwnerRef::entity(owner);
            if found.item.subtype() != expected.subtype || *found.item.owner() != expected.owner32 {
                return Err(invalid());
            }
            required.push(Required {
                owner: *owner,
                incarnation: *found.item.incarnation(),
                generation: found.generation,
            });
            keys.push(key);
        }
        let mut copy = RetainedHomeClaimActors {
            vault_id,
            entity_id: self.vector.entity_id,
            source_digest: *blake3::hash(&self.vector.source).as_bytes(),
            sender,
            required,
            envelope: Vec::new(),
        };
        let mut plain =
            Zeroizing::new(rmp_serde::to_vec_named(&self.vector).map_err(|_| invalid())?);
        for (index, key) in keys.iter().enumerate() {
            let aad = copy.aad(index)?;
            let key_id = *blake3::hash(&aad).as_bytes();
            let recipient = copy.required[index].custody_id()?;
            let kek = Kek::from_bytes_ref(key);
            let params = SealParams {
                suite: AEAD,
                purpose: PAYLOAD_PURPOSE,
                epoch: EPOCH,
                key_id: &key_id,
                recipient: &recipient,
                vault_id: &copy.vault_id,
            };
            plain = Zeroizing::new(
                seal_with_aad(
                    &params,
                    SealKey::SymmetricKek(&kek),
                    &plain,
                    &aad,
                    &mut SysRng,
                )
                .map_err(crypto_error)?
                .to_bytes(),
            );
        }
        copy.envelope = plain.to_vec();
        Ok(Some(PreparedHomeClaimActors {
            path: vault.store.env.path().to_path_buf(),
            binding,
            received: self,
            copy,
        }))
    }
}

impl PreparedHomeClaimActors {
    /// Stores only the optional copy under this writer's already pending job.
    /// The holder must outlive the actual outer commit, not just its callback.
    pub(crate) fn entity_id(&self) -> EntityId {
        self.copy.entity_id
    }

    pub(crate) fn retain_in_txn(
        &self,
        vault: &Vault,
        txn: &mut RwTxn<'_>,
    ) -> Result<super::retained::RetainedHomeClaimState> {
        use super::retained::RetainedHomeClaimState;

        let Some(copy) = self.copy_for_current_source_in_txn(vault, txn)? else {
            return Ok(RetainedHomeClaimState::SourceChanged);
        };
        let bytes = rmp_serde::to_vec_named(copy).map_err(|_| invalid())?;
        if crate::sync::queue::retain_embed_job_home_claim_copy_in_txn(
            &vault.store,
            txn,
            &copy.entity_id,
            &bytes,
        )? {
            Ok(RetainedHomeClaimState::Stored)
        } else {
            Ok(RetainedHomeClaimState::NoPendingJob)
        }
    }

    /// Borrows the ciphertext only in the native writer holding the exact
    /// canonical source. The caller still owns the real outer commit and carrier.
    pub(crate) fn copy_for_current_source_in_txn(
        &self,
        vault: &Vault,
        txn: &RwTxn<'_>,
    ) -> Result<Option<&RetainedHomeClaimActors>> {
        if self.path != vault.store.env.path()
            || binding_in_txn(&vault.store, txn)?.as_ref() != Some(&self.binding)
            || vault.authority_view_readonly_in_txn(txn)?.vault_id != Some(self.copy.vault_id)
            || self.received.peer != self.copy.sender.peer()
            || self.received.source_facts_in_txn(vault, txn)?.is_none()
        {
            return Ok(None);
        }
        Ok(self
            .copy
            .requirements_current_in_txn(vault, txn, &self.binding)?
            .then_some(&self.copy))
    }
}

impl RetainedHomeClaimActors {
    pub(crate) fn sender_peer(&self) -> crate::authority::PeerMachine {
        self.sender.peer()
    }

    pub(crate) fn requirements_current_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        binding: &CustodyBinding,
    ) -> Result<bool> {
        if vault.authority_view_readonly_in_txn(txn)?.vault_id != Some(self.vault_id) {
            return Ok(false);
        }
        for required in &self.required {
            let item = required.item()?;
            let Some(found) = instance::instance_in_txn(&vault.store, txn, &item)? else {
                return Ok(false);
            };
            if found.lifecycle != Lifecycle::Active
                || found.generation != required.generation
                || vault.carrier_actor_erased_in_txn(txn, &required.owner)?
            {
                return Ok(false);
            }
            let subject = item.subject(binding)?;
            if retirement_in_txn(&vault.store, txn, &subject)?
                .is_some_and(|intent| intent.through >= required.generation)
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
    pub(crate) fn entity_id(&self) -> EntityId {
        self.entity_id
    }

    fn aad(&self, index: usize) -> Result<Vec<u8>> {
        rmp_serde::to_vec(&(
            COPY_DOMAIN,
            self.vault_id,
            self.entity_id,
            self.source_digest,
            &self.sender,
            &self.required,
            index,
        ))
        .map_err(|_| invalid())
    }

    /// The original native items, never a later current source's owners.
    pub(crate) fn required(&self) -> Result<Vec<(PayloadItem, u64)>> {
        let mut previous = None;
        let mut source_owner = false;
        let mut required = Vec::with_capacity(self.required.len());
        for entry in &self.required {
            if previous.is_some_and(|owner| owner >= entry.owner) {
                return Err(invalid());
            }
            previous = Some(entry.owner);
            source_owner |= entry.owner == self.entity_id;
            required.push((entry.item()?, entry.generation));
        }
        if !source_owner {
            return Err(invalid());
        }
        Ok(required)
    }

    /// Reads live keys under the native guard before opening any layer.
    /// The consumer must still rejudge its actual source, model and destination.
    pub(crate) fn open_in_vault(&self, vault: &Vault) -> Result<Option<HomeClaimVector>> {
        let txn = vault.store.custody_snapshot()?;
        if vault.authority_view_readonly_in_txn(&txn)?.vault_id != Some(self.vault_id) {
            return Err(invalid());
        }
        let required = self.required()?;
        let mut access = Vec::with_capacity(required.len());
        for (item, generation) in required {
            let Some(found) = instance::instance_in_txn(&vault.store, &txn, &item)? else {
                return Err(invalid());
            };
            if found.lifecycle == Lifecycle::Erased {
                return Ok(None);
            }
            access.push(CompartmentAccess::Open(
                vault.store.checkpoint_payload_key(&item, generation)?,
            ));
        }
        self.open_with_access(&access)
    }

    /// Records every frozen requirement in the restore's one native plan.
    /// Any retired leaf drops the whole optional copy, never a partial vector.
    pub(crate) fn open_for_restore(
        &self,
        vault_id: &[u8; 32],
        plan: &mut CustodyPlan,
    ) -> std::result::Result<Option<HomeClaimVector>, Rejected> {
        if vault_id != &self.vault_id {
            return Err(invalid().into());
        }
        let required = self.required()?;
        let access = compartment_access(plan, &required)?;
        self.open_with_access(&access).map_err(Into::into)
    }

    fn open_with_access(&self, access: &[CompartmentAccess]) -> Result<Option<HomeClaimVector>> {
        if access.len() != self.required.len() {
            return Err(invalid());
        }
        if access
            .iter()
            .any(|entry| matches!(entry, CompartmentAccess::Retired))
        {
            return Ok(None);
        }
        let mut plain = Zeroizing::new(self.envelope.clone());
        for (index, access) in access.iter().enumerate().rev() {
            let CompartmentAccess::Open(key) = access else {
                return Ok(None);
            };
            let aad = self.aad(index)?;
            let key_id = *blake3::hash(&aad).as_bytes();
            let recipient = self.required[index].custody_id()?;
            let kek = Kek::from_bytes_ref(key);
            let policy = OpenPolicy {
                purpose: PAYLOAD_PURPOSE,
                vault_id: &self.vault_id,
                recipient: &recipient,
                key_id: &key_id,
                wraps: &[WrapType::SymmetricKek],
                aead_suites: &[AEAD],
                kem_suites: &[],
                min_epoch: EPOCH,
                argon2_max: Argon2Cost::RFC9106_SECOND,
            };
            plain = Envelope::parse(&plain)
                .map_err(crypto_error)?
                .open_with_aad(OpenKey::SymmetricKek(&kek), &policy, &aad)
                .map_err(crypto_error)?;
        }
        let vector: HomeClaimVector = rmp_serde::from_slice(&plain).map_err(|_| invalid())?;
        let Some(owners) = origin_owners(&vector)? else {
            return Err(invalid());
        };
        if vector.entity_id != self.entity_id
            || blake3::hash(&vector.source).as_bytes() != &self.source_digest
            || !owners
                .iter()
                .copied()
                .eq(self.required.iter().map(|entry| entry.owner))
        {
            return Err(invalid());
        }
        Ok(Some(vector))
    }
}
