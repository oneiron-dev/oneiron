//! Receipt-source observations for retaining a default CLAIM copy.
//! These are not serialized permissions or a substitute for body custody.

use heed::RwTxn;

use super::{ReceivedHomeClaimVector, claim_source_in_txn, own_peer_in_txn};
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::origin::actor_erase::{OriginClaimActors, OriginClaimKind, claim_actors};
use crate::store::{
    ResponseBinding, ResponseDb, ResponseFamily, response_binding_in_txn, response_carrier,
    response_owners_bound_in_txn,
};
use crate::write_envelope::claim_body::decode_claim_body;
use crate::{EntityId, Result, Vault};

/// The native response home of the actual source, not its claim id.
pub(crate) enum HomeClaimResponseSource {
    /// No native inline response; other owner and actor splits still apply.
    NotResponse,
    /// The native binding pass must bind this source and its obligations.
    Unbound {
        digest: [u8; 32],
        owners: Vec<EntityId>,
    },
    /// The bytes and owner obligations match; actual key availability still
    /// belongs to the native custody requirement and sealing ports.
    Bound {
        binding: ResponseBinding,
        owners: Vec<EntityId>,
    },
}

pub(crate) struct HomeClaimSourceFacts {
    pub(crate) response: HomeClaimResponseSource,
    pub(crate) origin_kind: Option<OriginClaimKind>,
    /// None with a known origin kind means its actor stamps are unresolved,
    /// not that the original source named no one.
    pub(crate) original_origin_actors: Option<OriginClaimActors>,
}

impl ReceivedHomeClaimVector {
    /// Reads the retained source only when it is this writer's actual canonical
    /// winner and the received peer still stands. The caller must retain these
    /// original facts, never recover them from a later redacted current row.
    /// An unbound response is work for native custody, not an entity-tree home
    /// or a reason to refuse or discard the source import.
    pub(crate) fn source_facts_in_txn(
        &self,
        vault: &Vault,
        txn: &RwTxn<'_>,
    ) -> Result<Option<HomeClaimSourceFacts>> {
        let id = self.vector.entity_id;
        if !own_peer_in_txn(vault, txn, self.peer)?
            || claim_source_in_txn(vault, txn, &id)?.as_deref()
                != Some(self.vector.source.as_slice())
        {
            return Ok(None);
        }
        let source = self.vector.source.as_slice();
        let body = decode_claim_body(&source[ENTITY_METADATA_HEADER_LEN..], true)?;
        let origin_kind = OriginClaimKind::of(&body.predicate);
        let original_origin_actors = origin_kind.and_then(|kind| claim_actors(kind, &body));
        let response = match ResponseFamily::of_row(ResponseDb::Entities, id.as_bytes(), source) {
            Some(family) => match family
                .scan(
                    vault.store.attempt_operations,
                    vault.store.voice_bank_response,
                    id.as_bytes(),
                    source,
                )
                .carriage()
            {
                Some((carriage, _)) => {
                    let digest = *blake3::hash(&source[carriage.keep..]).as_bytes();
                    let owners = family.owners(&vault.store, txn, id.as_bytes(), source)?;
                    let carrier = response_carrier(ResponseDb::Entities, id.as_bytes());
                    let binding = response_binding_in_txn(&vault.store, txn, &carrier)?
                        .filter(|binding| binding.digest == digest);
                    match binding {
                        Some(binding)
                            if response_owners_bound_in_txn(
                                &vault.store,
                                txn,
                                &binding.instance,
                                &owners,
                            )? =>
                        {
                            HomeClaimResponseSource::Bound { binding, owners }
                        }
                        _ => HomeClaimResponseSource::Unbound { digest, owners },
                    }
                }
                None => HomeClaimResponseSource::NotResponse,
            },
            None => HomeClaimResponseSource::NotResponse,
        };
        Ok(Some(HomeClaimSourceFacts {
            response,
            origin_kind,
            original_origin_actors,
        }))
    }
}
