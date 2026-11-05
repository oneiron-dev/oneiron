//! Receipt-time storage for a retained inline response's default CLAIM vector.
//! The receive producer stays disconnected until checkpoint custody and restore
//! carry this copy under the original response instance.

use heed::RwTxn;
use serde::{Deserialize, Serialize};

use super::source::HomeClaimResponseSource;
use super::{HomeClaimVector, ReceivedHomeClaimVector};
use crate::store::ResponseFamily;
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

/// A source-only storage result. Every non-stored case keeps the native job;
/// none refuses or drops the canonical source import.
pub(crate) enum RetainedHomeClaimResponseState {
    SourceChanged,
    OtherSource,
    UnboundResponse,
    NoPendingJob,
    Stored,
}

impl ReceivedHomeClaimVector {
    /// Retains the original instance and obligations in the pending job's own
    /// writer, only while this exact full source is its canonical winner.
    /// A genuinely unbound source still needs the native binding pass.
    pub(crate) fn retain_response_in_txn(
        &self,
        vault: &Vault,
        txn: &mut RwTxn<'_>,
    ) -> Result<RetainedHomeClaimResponseState> {
        let Some(facts) = self.source_facts_in_txn(vault, txn)? else {
            return Ok(RetainedHomeClaimResponseState::SourceChanged);
        };
        // Ordinary actor-bearing sources need their own native split. The
        // response instance is not a substitute for any actor's custody.
        if facts.origin_kind.is_some() {
            return Ok(RetainedHomeClaimResponseState::OtherSource);
        }
        let (binding, owners) = match facts.response {
            HomeClaimResponseSource::NotResponse => {
                return Ok(RetainedHomeClaimResponseState::OtherSource);
            }
            HomeClaimResponseSource::Unbound { .. } => {
                return Ok(RetainedHomeClaimResponseState::UnboundResponse);
            }
            HomeClaimResponseSource::Bound { binding, owners } => (binding, owners),
        };
        // This port implements the native StepClaim copy's shared lifetime,
        // not every CLAIM response family's ownership rules.
        if ResponseFamily::of_row(
            crate::store::ResponseDb::Entities,
            self.vector.entity_id.as_bytes(),
            &self.vector.source,
        ) != Some(ResponseFamily::StepClaim)
            || !matches!(
                ResponseFamily::StepClaim
                    .scan(
                        vault.store.attempt_operations,
                        vault.store.voice_bank_response,
                        self.vector.entity_id.as_bytes(),
                        &self.vector.source,
                    )
                    .carriage(),
                Some((_, false))
            )
        {
            return Ok(RetainedHomeClaimResponseState::OtherSource);
        }
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
        let family = ResponseFamily::of_row(
            crate::store::ResponseDb::Entities,
            id.as_bytes(),
            &copy.vector.source,
        );
        if copy.vector.entity_id != *id
            || family != Some(ResponseFamily::StepClaim)
            || copy.response.owners.as_slice() != [*id]
        {
            return Err(Error::CorruptedIndex("retained home CLAIM response"));
        }
        let Some((carriage, false)) = ResponseFamily::StepClaim
            .scan(
                store.attempt_operations,
                store.voice_bank_response,
                id.as_bytes(),
                &copy.vector.source,
            )
            .carriage()
        else {
            return Err(Error::CorruptedIndex("retained home CLAIM response"));
        };
        if blake3::hash(&copy.vector.source[carriage.keep..]).as_bytes()
            != &copy.response.source_digest
        {
            return Err(Error::CorruptedIndex("retained home CLAIM response"));
        }
        Ok(copy)
    }
}
