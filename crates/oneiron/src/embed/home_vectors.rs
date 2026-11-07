//! Default CLAIM vectors move only over an authenticated own-machine read,
//! never through a canonical window's retained operation history.

mod pending;

use heed::RoTxn;
use serde::{Deserialize, Serialize};

use super::{
    EmbedderLocality, EmbeddingProvenance, PendingEmbeddingInput, PendingEmbeddingPayload,
};
use crate::authority::PeerMachine;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::ports::{IndexMetaKey, RetrievalIndexInventory};
use crate::{EntityId, Error, ModelId, ModelLocality, Result, Vault};

/// One settled default CLAIM vector and the complete source image it embeds.
/// A transport receipt, not a read grant or canonical claim history.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HomeClaimVector {
    pub entity_id: EntityId,
    pub source: Vec<u8>,
    /// Source identities retained for the socket's final destination judgment.
    pub release_rows: Vec<EntityId>,
    pub model_id: String,
    pub transform: Option<String>,
    pub route: String,
    /// 1 is OwnerServer; 2 is ThirdParty. OnDevice never travels.
    pub locality: u8,
    pub provenance: EmbeddingProvenance,
    /// The exact persisted EMB-3 f16 row.
    pub row: Vec<u8>,
}

pub(crate) struct ReceivedHomeClaimVector {
    pub(crate) peer: PeerMachine,
    pub(crate) vector: HomeClaimVector,
}

fn own_peer_in_txn(vault: &Vault, txn: &RoTxn<'_>, peer: PeerMachine) -> Result<bool> {
    let PeerMachine::Proven { machine, key } = peer else {
        return Ok(false);
    };
    Ok(vault
        .authority_fold_readonly_in_txn(txn)?
        .machine_proof_key(machine)
        == Some(key))
}

pub(crate) fn own_peer(vault: &Vault, peer: PeerMachine) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    own_peer_in_txn(vault, &txn, peer)
}

fn read_meta_text(vault: &Vault, txn: &RoTxn<'_>, key: IndexMetaKey) -> Result<Option<String>> {
    vault.store.port_index_meta_with_raw(txn, key, |bytes| {
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| Error::CorruptedIndex("embedding space record"))
    })
}

fn model_in_txn(vault: &Vault, txn: &RoTxn<'_>) -> Result<Option<String>> {
    Ok(read_meta_text(vault, txn, IndexMetaKey::ModelId)?
        .or_else(|| vault.config.embedding_model.clone()))
}

fn transform_in_txn(vault: &Vault, txn: &RoTxn<'_>) -> Result<Option<String>> {
    Ok(
        read_meta_text(vault, txn, IndexMetaKey::EmbeddingTransform)?
            .or_else(|| vault.config.embedding_transform.clone()),
    )
}

fn claim_source_in_txn(vault: &Vault, txn: &RoTxn<'_>, id: &EntityId) -> Result<Option<Vec<u8>>> {
    if crate::ports::stale_in_txn(&vault.store, txn, id)? {
        return Ok(None);
    }
    let Some(raw) = vault
        .get_raw_in(txn, id)?
        .and_then(|raw| crate::world_keys::live_route_row(&vault.store, raw))
    else {
        return Ok(None);
    };
    if !crate::ports::raw_readable_in_txn(&vault.store, txn, id, &raw)? {
        return Ok(None);
    }
    if !EntityMetadataHeader::parse(&raw)
        .is_some_and(|header| header.entity_type == crate::registry::ENTITY_TYPE_CLAIM)
    {
        return Ok(None);
    }
    let Some(body) = raw.get(ENTITY_METADATA_HEADER_LEN..) else {
        return Ok(None);
    };
    if !matches!(
        super::embeddable_payload_in_txn(vault, txn, id, crate::registry::ENTITY_TYPE_CLAIM, body,)?,
        Some(PendingEmbeddingPayload::ClaimBody(_))
    ) {
        return Ok(None);
    }
    Ok(Some(raw))
}

fn locality(value: u8) -> Option<(EmbedderLocality, ModelLocality)> {
    match value {
        1 => Some((EmbedderLocality::OwnerServer, ModelLocality::OwnServer)),
        2 => Some((EmbedderLocality::ThirdParty, ModelLocality::ThirdParty)),
        _ => None,
    }
}

fn route(model_id: &str, runtime: &str, locality: ModelLocality) -> Option<String> {
    let model = ModelId::new(model_id).ok()?;
    for (at, _) in runtime.match_indices('@') {
        let base = &runtime[at + 1..];
        if !base.contains("://") {
            continue;
        }
        let place = crate::llm::run_admission::offer_place(locality, base);
        if !place.is_empty() && place != locality.as_str() {
            return Some(crate::llm::run_admission::offer_id(&model, &place));
        }
    }
    None
}

impl Vault {
    /// Whether this connection still proves one of this vault's machines.
    pub fn home_claim_vector_peer_stands(&self, peer: PeerMachine) -> Result<bool> {
        own_peer(self, peer)
    }

    /// Reads an own machine's settled CLAIM vector, with its actual full source,
    /// marks and model in one snapshot. The caller must keep the source id on
    /// the queued reply so its send door rejudges the destination before release.
    pub fn home_claim_vector_for_peer(
        &self,
        peer: PeerMachine,
        id: &EntityId,
    ) -> Result<Option<HomeClaimVector>> {
        let _acceptance = self.device_only_acceptance();
        let txn = self.store.env.read_txn()?;
        if !own_peer_in_txn(self, &txn, peer)? {
            return Ok(None);
        }
        let destination = crate::settings::ReadDestination::toward(peer);
        let flagged = crate::settings::device_local_worlds_for(self, &txn, &destination)?;
        if crate::settings::device_only_withholds(&self.store, &txn, &flagged, id)? {
            return Ok(None);
        }
        let Some(source) = claim_source_in_txn(self, &txn, id)? else {
            return Ok(None);
        };
        let (locality, model_locality) = match self.settled_embedding_locality_in_txn(&txn, id)? {
            Some(EmbedderLocality::OwnerServer) => (1, ModelLocality::OwnServer),
            Some(EmbedderLocality::ThirdParty) => (2, ModelLocality::ThirdParty),
            _ => return Ok(None),
        };
        let Some(model_id) = model_in_txn(self, &txn)? else {
            return Ok(None);
        };
        let Some(provenance) = self.embedding_provenance_in_txn(&txn, id)? else {
            return Ok(None);
        };
        let Some(route) = route(&model_id, &provenance.runtime, model_locality) else {
            return Ok(None);
        };
        let Some(row) = self
            .store
            .port_vector_with_raw(&txn, id, |bytes| Ok(bytes.to_vec()))?
        else {
            return Ok(None);
        };
        let values = crate::store::decode_vector_row(&row, self.config.dimensions)?;
        if !values.iter().all(|value| value.is_finite()) {
            return Ok(None);
        }
        let mut release_rows: Vec<_> = crate::settings::carried_worlds_in(&self.store, &txn, id)?
            .worlds
            .into_iter()
            .collect();
        release_rows.push(*id);
        Ok(Some(HomeClaimVector {
            entity_id: *id,
            source,
            release_rows,
            model_id,
            transform: transform_in_txn(self, &txn)?,
            route,
            locality,
            provenance,
            row,
        }))
    }
}

pub(super) fn replica_matches_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    input: &PendingEmbeddingInput,
    received: &ReceivedHomeClaimVector,
) -> Result<bool> {
    let replica = &received.vector;
    if replica.entity_id != input.entity_id || !own_peer_in_txn(vault, txn, received.peer)? {
        return Ok(false);
    }
    let PendingEmbeddingPayload::ClaimBody(body) = &input.payload else {
        return Ok(false);
    };
    let Some((_, model_locality)) = locality(replica.locality) else {
        return Ok(false);
    };
    if replica.source.get(ENTITY_METADATA_HEADER_LEN..) != Some(body.as_slice())
        || claim_source_in_txn(vault, txn, &input.entity_id)?.as_deref()
            != Some(replica.source.as_slice())
        || model_in_txn(vault, txn)?.as_deref() != Some(replica.model_id.as_str())
        || transform_in_txn(vault, txn)? != replica.transform
        || route(
            &replica.model_id,
            &replica.provenance.runtime,
            model_locality,
        )
        .as_deref()
            != Some(replica.route.as_str())
    {
        return Ok(false);
    }
    let worlds = crate::settings::carried_worlds_in(&vault.store, txn, &input.entity_id)?;
    Ok(vault
        .world_model_routes_in_txn(txn, worlds.worlds)?
        .admits(&replica.route))
}

impl super::PendingEmbeddingReconciler {
    /// Runs on the caller's existing blocking worker. Only the bounded home
    /// RPC runs in `runtime`; synchronous model clients run after it exits.
    pub fn reconcile_once_into_with_home(
        &self,
        runtime: &tokio::runtime::Handle,
        report: &mut super::PendingEmbeddingReconcileReport,
    ) -> Result<()> {
        let work = self.prepare_reconcile_pass(super::unix_millis_now(), report)?;
        let work = self.reuse_home_claim_vectors(runtime, work, report)?;
        self.reconcile_prepared_work(work, report)
    }

    fn reuse_home_claim_vectors(
        &self,
        runtime: &tokio::runtime::Handle,
        work: Vec<super::LeasedPendingEmbedding>,
        report: &mut super::PendingEmbeddingReconcileReport,
    ) -> Result<Vec<super::LeasedPendingEmbedding>> {
        let Some(home) = self.vault.embedding_home() else {
            return Ok(work);
        };
        let mut remaining = Vec::with_capacity(work.len());
        for item in work {
            if item.entity_type == crate::registry::ENTITY_TYPE_CLAIM
                && let Some(received) =
                    runtime.block_on(home.default_claim_vector(item.input.entity_id))?
                && let Some((locality, _)) = locality(received.vector.locality)
                && let Ok(vector) = crate::store::decode_vector_row(
                    &received.vector.row,
                    self.vault.config.dimensions,
                )
                && vector.iter().all(|value| value.is_finite())
                && self.complete_leased_work(
                    &item,
                    &vector,
                    locality,
                    &received.vector.provenance,
                    Some(&received),
                )?
            {
                report.filled += 1;
            } else {
                remaining.push(item);
            }
        }
        Ok(remaining)
    }
}
