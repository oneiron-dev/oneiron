//! Actual deferred payloads and their identity-bound, idempotent completion.

use super::{FederationPeer, corrupt, observations};
use crate::llm::NormalizedBurstInputs;
use crate::sync::transport::MAX_DECODED_PAYLOAD_BYTES;
use crate::sync::{WindowKey, encode_sync_selector};
use crate::{Result, Vault};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::sync) enum WorkKind {
    Selector,
    MemberUpdate,
    GuestUpdate,
}

#[derive(Debug, Clone)]
pub(in crate::sync) struct DeferredWork {
    pub(in crate::sync) id: [u8; 32],
    pub(in crate::sync) window: String,
    pub(in crate::sync) kind: WorkKind,
    pub(in crate::sync) payload: Vec<u8>,
    pub(super) inputs: NormalizedBurstInputs,
    peer: [u8; 32],
    selector: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct StoredWork {
    id: [u8; 32],
    peer: [u8; 32],
    selector: Vec<u8>,
    window: String,
    kind: WorkKind,
    payload: Vec<u8>,
    rate_ratio: f32,
    streak: u32,
}

fn prefix(peer: &FederationPeer) -> Result<Vec<u8>> {
    let mut prefix = b"m:federation-deferred:v1:".to_vec();
    prefix.extend_from_slice(&peer.digest());
    // Delivery is additionally bound to the exact requested selector. The
    // observation bucket intentionally is not: narrowing cannot reset rate.
    prefix.extend_from_slice(blake3::hash(&encode_sync_selector(&peer.selector)?).as_bytes());
    Ok(prefix)
}

impl DeferredWork {
    pub(super) fn new(
        peer: &FederationPeer,
        key: &WindowKey,
        kind: WorkKind,
        payload: &[u8],
    ) -> Result<Self> {
        if payload.len() > MAX_DECODED_PAYLOAD_BYTES {
            return Err(crate::Error::InvalidConfig(
                "federation payload exceeds transport bound".into(),
            ));
        }
        let selector = encode_sync_selector(&peer.selector)?;
        let mut hash = blake3::Hasher::new();
        hash.update(b"oneiron/federation-work/v1");
        hash.update(&peer.digest());
        hash.update(blake3::hash(&selector).as_bytes());
        hash.update(key.as_str().as_bytes());
        hash.update(&[match kind {
            WorkKind::Selector => 0,
            WorkKind::MemberUpdate => 1,
            WorkKind::GuestUpdate => 2,
        }]);
        hash.update(payload);
        Ok(Self {
            id: *hash.finalize().as_bytes(),
            peer: peer.digest(),
            selector,
            window: key.as_str().to_owned(),
            kind,
            payload: payload.to_vec(),
            inputs: NormalizedBurstInputs {
                rate_ratio: 0.0,
                streak: 0,
            },
        })
    }

    pub(super) fn with_inputs(mut self, inputs: NormalizedBurstInputs) -> Self {
        self.inputs = inputs;
        self
    }

    fn key(&self) -> Vec<u8> {
        let mut key = b"m:federation-deferred:v1:".to_vec();
        key.extend_from_slice(&self.peer);
        key.extend_from_slice(blake3::hash(&self.selector).as_bytes());
        key.extend_from_slice(&self.id);
        key
    }

    fn completion_key(&self) -> Vec<u8> {
        let mut key = b"m:federation-completed:v1:".to_vec();
        key.extend_from_slice(&self.peer);
        key.extend_from_slice(&self.id);
        key
    }

    pub(super) fn completed_selector_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
    ) -> Result<bool> {
        if self.kind != WorkKind::Selector {
            return Ok(false);
        }
        match vault.store.sync_queue.get(txn, &self.completion_key())? {
            None => Ok(false),
            Some(value) if &value[..] == self.id.as_slice() => Ok(true),
            Some(_) => Err(corrupt()),
        }
    }

    pub(super) fn load_in_txn(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Option<Self>> {
        let Some(value) = vault.store.sync_queue.get(txn, &self.key())? else {
            return Ok(None);
        };
        let saved = Self::decode(&value)?;
        if saved.id != self.id
            || saved.peer != self.peer
            || saved.selector != self.selector
            || saved.window != self.window
            || saved.kind != self.kind
            || saved.payload != self.payload
        {
            return Err(corrupt());
        }
        Ok(Some(saved))
    }

    pub(super) fn put_in_txn(&self, vault: &Vault, txn: &mut heed::RwTxn<'_>) -> Result<()> {
        let value = postcard::to_allocvec(&StoredWork {
            id: self.id,
            peer: self.peer,
            selector: self.selector.clone(),
            window: self.window.clone(),
            kind: self.kind,
            payload: self.payload.clone(),
            rate_ratio: self.inputs.rate_ratio,
            streak: self.inputs.streak,
        })
        .map_err(|_| corrupt())?;
        vault.store.sync_queue.put(txn, &self.key(), &value)?;
        Ok(())
    }

    fn decode(value: &[u8]) -> Result<Self> {
        let row: StoredWork = postcard::from_bytes(value).map_err(|_| corrupt())?;
        if WindowKey::try_new(&row.window).is_none()
            || row.payload.len() > MAX_DECODED_PAYLOAD_BYTES
            || !row.rate_ratio.is_finite()
            || row.rate_ratio < 0.0
        {
            return Err(corrupt());
        }
        Ok(Self {
            id: row.id,
            peer: row.peer,
            selector: row.selector,
            window: row.window,
            kind: row.kind,
            payload: row.payload,
            inputs: NormalizedBurstInputs {
                rate_ratio: row.rate_ratio,
                streak: row.streak,
            },
        })
    }

    /// Delete only after durable import or successful direct-response enqueue.
    /// A crash before deletion safely replays the same deterministic CRDT ops.
    pub(in crate::sync) fn complete(&self, vault: &Vault, peer: &FederationPeer) -> Result<()> {
        peer.revalidate(vault)?;
        if self.peer != peer.digest() || self.selector != encode_sync_selector(&peer.selector)? {
            return Err(corrupt());
        }
        vault.with_write_txn(|txn| {
            vault.store.sync_queue.delete(txn, &self.key())?;
            // Keep a small, payload-free delivery witness. If the socket dies
            // after direct enqueue, the same authenticated ticket can fetch
            // again. A guessed hash with no witness cannot bypass observation.
            if self.kind == WorkKind::Selector {
                vault
                    .store
                    .sync_queue
                    .put(txn, &self.completion_key(), &self.id)?;
            }
            observations::outcome_in_txn(vault, txn, peer, false)
        })
    }

    pub(in crate::sync) fn next_update(
        vault: &Vault,
        peer: &FederationPeer,
    ) -> Result<Option<Self>> {
        peer.revalidate(vault)?;
        let txn = vault.store.env.read_txn()?;
        let prefix = prefix(peer)?;
        for row in vault.store.sync_queue.prefix_iter(&txn, &prefix)? {
            let (key, value) = row?;
            let work = Self::decode(&value)?;
            if work.key().as_slice() != key.as_ref() {
                return Err(corrupt());
            }
            let window = WindowKey::try_new(&work.window).ok_or_else(corrupt)?;
            let expected = Self::new(peer, &window, work.kind, &work.payload)?;
            if work.id != expected.id
                || work.selector != expected.selector
                || work.peer != expected.peer
            {
                return Err(corrupt());
            }
            if work.kind != WorkKind::Selector {
                return Ok(Some(work));
            }
        }
        Ok(None)
    }
}

/// One coalesced review projection for a peer's isolated pending payloads.
/// Review is advisory. The automatic replay doors never wait for a human.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationBurstReviewBundle {
    pub bundle_ref: String,
    pub request_refs: Vec<String>,
    pub quarantined: bool,
    pub replay_automatic: bool,
}
impl Vault {
    /// Pending payload bytes stay outside live entities and coalesce by peer.
    /// Completion removes requests from this projection, not from a human pause.
    pub fn federation_burst_review_bundles(&self) -> Result<Vec<FederationBurstReviewBundle>> {
        let txn = self.store.env.read_txn()?;
        let mut bundles = std::collections::BTreeMap::<[u8; 32], Vec<String>>::new();
        for row in self
            .store
            .sync_queue
            .prefix_iter(&txn, b"m:federation-deferred:v1:")?
        {
            let (key, value) = row?;
            let work = DeferredWork::decode(&value)?;
            if key.as_ref() != work.key() {
                return Err(corrupt());
            }
            bundles
                .entry(work.peer)
                .or_default()
                .push(blake3::Hash::from(work.id).to_hex().to_string());
        }
        Ok(bundles
            .into_iter()
            .map(|(peer, request_refs)| FederationBurstReviewBundle {
                bundle_ref: format!("federation-review:{}", blake3::Hash::from(peer).to_hex()),
                request_refs,
                quarantined: true,
                replay_automatic: true,
            })
            .collect())
    }
}
