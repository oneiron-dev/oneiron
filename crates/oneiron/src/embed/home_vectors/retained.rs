//! Receipt-time storage for a retained inline response's default CLAIM vector.
//! The receive producer stays disconnected until canonical receipt coupling
//! and the source-owner lifetimes are complete.

use heed::RwTxn;
use serde::{Deserialize, Serialize};

use super::source::HomeClaimResponseSource;
use super::{HomeClaimVector, ReceivedHomeClaimVector};
use crate::store::{
    BodyInstance, ManifestDbs, ResponseBinding, ResponseCarriage, ResponseDb, ResponseFamily,
    Store, bind_missing_response_owners_in_txn, bind_response_in_txn, pin_body_custody_in_txn,
    response_binding_in_txn, response_carrier,
};
use crate::{EntityId, Error, Result, Vault};

/// Original source facts, not a replacement binding for the current claim.
/// The copied stream has its own digest and length at checkpoint capture.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetainedResponseSource {
    pub(crate) instance: [u8; 16],
    pub(crate) source_digest: [u8; 32],
    pub(crate) owners: Vec<EntityId>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetainedHomeClaimResponse {
    pub(crate) response: RetainedResponseSource,
    pub(crate) vector: HomeClaimVector,
}

/// In-memory receive data and its real native key lease. This is not a
/// serialized receipt or permission. Keep it outside the canonical writer
/// until commit, including while a world update waits in the staged queue.
pub(crate) struct PreparedHomeClaimResponse {
    received: ReceivedHomeClaimVector,
    instance: Option<BodyInstance>,
}

impl PreparedHomeClaimResponse {
    pub(crate) fn entity_id(&self) -> EntityId {
        self.received.vector.entity_id
    }

    /// Called only from the writer that materialized the canonical source.
    /// Borrow the outer holder here; do not drop it before that writer commits.
    pub(crate) fn retain_in_txn(
        &self,
        vault: &Vault,
        txn: &mut RwTxn<'_>,
    ) -> Result<RetainedHomeClaimResponseState> {
        self.received
            .retain_response_in_txn(vault, txn, self.instance.as_ref())
    }
}

/// A source-only storage result. Every non-stored case keeps the native job;
/// none refuses or drops the canonical source import.
pub(crate) enum RetainedHomeClaimResponseState {
    SourceChanged,
    OtherSource,
    UnboundResponse,
    NoPendingJob,
    Stored,
}

fn step_claim_carriage(store: &Store, id: &EntityId, source: &[u8]) -> Option<ResponseCarriage> {
    if ResponseFamily::of_row(ResponseDb::Entities, id.as_bytes(), source)
        != Some(ResponseFamily::StepClaim)
    {
        return None;
    }
    match ResponseFamily::StepClaim
        .scan(
            store.attempt_operations,
            store.voice_bank_response,
            id.as_bytes(),
            source,
        )
        .carriage()
    {
        Some((carriage, false)) => Some(carriage),
        _ => None,
    }
}

impl ReceivedHomeClaimVector {
    /// Prepares a copy's native lease outside the canonical writer, before
    /// any in-memory world deferral. Failure affects this derived copy only;
    /// it must never be propagated as a refusal of the canonical import.
    pub(crate) fn prepare_response_copy(self, vault: &Vault) -> Result<PreparedHomeClaimResponse> {
        let instance = self.prepare_response_instance(vault)?;
        Ok(PreparedHomeClaimResponse {
            received: self,
            instance,
        })
    }

    /// This does not establish that the received source is the current winner.
    fn prepare_response_instance(&self, vault: &Vault) -> Result<Option<BodyInstance>> {
        if step_claim_carriage(&vault.store, &self.vector.entity_id, &self.vector.source).is_none()
            || !super::own_peer(vault, self.peer)?
        {
            return Ok(None);
        }
        Ok(Some(vault.store.body_mint()?.mint()?))
    }

    /// Retains the original instance and obligations in the pending job's own
    /// writer, only while this exact full source is its canonical winner.
    /// `prepared` was minted before this writer and stays leased through commit.
    /// Without one, an unbound source keeps its native pending work unchanged.
    fn retain_response_in_txn(
        &self,
        vault: &Vault,
        txn: &mut RwTxn<'_>,
        prepared: Option<&BodyInstance>,
    ) -> Result<RetainedHomeClaimResponseState> {
        let Some(facts) = self.source_facts_in_txn(vault, txn)? else {
            return Ok(RetainedHomeClaimResponseState::SourceChanged);
        };
        // Ordinary actor-bearing sources need their own native split. The
        // response instance is not a substitute for any actor's custody.
        if facts.origin_kind.is_some() {
            return Ok(RetainedHomeClaimResponseState::OtherSource);
        }
        // This port implements the native StepClaim copy's shared lifetime,
        // not every CLAIM response family's ownership rules.
        if step_claim_carriage(&vault.store, &self.vector.entity_id, &self.vector.source).is_none()
        {
            return Ok(RetainedHomeClaimResponseState::OtherSource);
        }
        let (binding, owners) = match facts.response {
            HomeClaimResponseSource::NotResponse => {
                return Ok(RetainedHomeClaimResponseState::OtherSource);
            }
            HomeClaimResponseSource::Unbound { digest, owners } => {
                let carrier =
                    response_carrier(ResponseDb::Entities, self.vector.entity_id.as_bytes());
                let existing = response_binding_in_txn(&vault.store, txn, &carrier)?
                    .filter(|binding| binding.digest == digest);
                let (binding, history) = if let Some(binding) = existing {
                    let history = bind_missing_response_owners_in_txn(
                        &vault.store,
                        txn,
                        &carrier,
                        binding,
                        &owners,
                    )?;
                    (binding, history)
                } else {
                    let Some(prepared) = prepared else {
                        return Ok(RetainedHomeClaimResponseState::UnboundResponse);
                    };
                    pin_body_custody_in_txn(&vault.store, txn)?;
                    let binding = ResponseBinding {
                        instance: *prepared.instance(),
                        digest,
                    };
                    let history =
                        bind_response_in_txn(&vault.store, txn, &carrier, binding, &owners)?;
                    (binding, history)
                };
                vault.store.key_custody().journal_body_history(history)?;
                (binding, owners)
            }
            HomeClaimResponseSource::Bound { binding, owners } => (binding, owners),
        };
        let response = RetainedResponseSource {
            instance: binding.instance,
            source_digest: binding.digest,
            owners,
        };
        #[derive(Serialize)]
        struct Copy<'a> {
            response: RetainedResponseSource,
            vector: &'a HomeClaimVector,
        }
        let copy = rmp_serde::to_vec_named(&Copy {
            response,
            vector: &self.vector,
        })
        .map_err(|_| Error::CorruptedIndex("retained home CLAIM response"))?;
        if crate::sync::queue::retain_embed_job_home_claim_copy_in_txn(
            &vault.store,
            txn,
            &self.vector.entity_id,
            &copy,
        )? {
            Ok(RetainedHomeClaimResponseState::Stored)
        } else {
            Ok(RetainedHomeClaimResponseState::NoPendingJob)
        }
    }
}

impl RetainedHomeClaimResponse {
    /// Decodes the original copy, never the source's later current binding.
    /// This validates its data; it does not grant custody or read permission.
    pub(crate) fn decode(store: &crate::store::Store, id: &EntityId, bytes: &[u8]) -> Result<Self> {
        let copy: Self = rmp_serde::from_slice(bytes)
            .map_err(|_| Error::CorruptedIndex("retained home CLAIM response"))?;
        copy.validate(store, id)?;
        Ok(copy)
    }

    pub(crate) fn validate(&self, store: &crate::store::Store, id: &EntityId) -> Result<()> {
        if self.vector.entity_id != *id || self.response.owners.as_slice() != [*id] {
            return Err(Error::CorruptedIndex("retained home CLAIM response"));
        }
        let Some(carriage) = step_claim_carriage(store, id, &self.vector.source) else {
            return Err(Error::CorruptedIndex("retained home CLAIM response"));
        };
        if blake3::hash(&self.vector.source[carriage.keep..]).as_bytes()
            != &self.response.source_digest
        {
            return Err(Error::CorruptedIndex("retained home CLAIM response"));
        }
        Ok(())
    }
}
