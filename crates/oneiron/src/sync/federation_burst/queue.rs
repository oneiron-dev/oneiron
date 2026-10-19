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

/// The review evidence an isolated update keeps: each part its admission
/// lands as, the window that part imports into and its admitted bytes, in
/// import order (FIX 3662).
pub(super) type IsolatedParts = Vec<(String, Vec<u8>)>;

#[derive(Debug, Clone)]
pub(in crate::sync) struct DeferredWork {
    pub(in crate::sync) id: [u8; 32],
    pub(in crate::sync) authority_digest: [u8; 32],
    /// The window the original request names: its replay address.
    pub(in crate::sync) window: String,
    pub(in crate::sync) kind: WorkKind,
    pub(in crate::sync) payload: Vec<u8>,
    pub(super) inputs: NormalizedBurstInputs,
    pub(super) peer: [u8; 32],
    pub(super) isolated_update: Option<IsolatedParts>,
    pub(super) streak_ratio: f32,
    pub(super) selector: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct StoredWork {
    id: [u8; 32],
    authority_digest: [u8; 32],
    peer: [u8; 32],
    selector: Vec<u8>,
    window: String,
    kind: WorkKind,
    payload: Vec<u8>,
    rate_ratio: f32,
    streak: u32,
    streak_ratio: f32,
    isolated_update: Option<IsolatedParts>,
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
    pub(in crate::sync) fn new(
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
            authority_digest: [0; 32],
            peer: peer.digest(),
            selector,
            window: key.as_str().to_owned(),
            kind,
            payload: payload.to_vec(),
            isolated_update: None,
            streak_ratio: 0.0,
            inputs: NormalizedBurstInputs {
                rate_ratio: 0.0,
                streak: 0,
            },
        })
    }

    pub(in crate::sync) fn revalidate_authority_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        peer: &FederationPeer,
    ) -> Result<()> {
        if self.authority_digest != peer.authority_digest_in_txn(vault, txn)? {
            return Err(crate::Error::InvalidConfig("federation batch grant or pact scope changed; reject the retained batch and send a newly authorized delivery".into()));
        }
        Ok(())
    }

    pub(super) fn with_inputs(mut self, inputs: NormalizedBurstInputs) -> Self {
        self.inputs = inputs;
        self
    }

    pub(super) fn key(&self) -> Vec<u8> {
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
            authority_digest: self.authority_digest,
            peer: self.peer,
            selector: self.selector.clone(),
            window: self.window.clone(),
            kind: self.kind,
            payload: self.payload.clone(),
            rate_ratio: self.inputs.rate_ratio,
            streak: self.inputs.streak,
            streak_ratio: self.streak_ratio,
            isolated_update: self.isolated_update.clone(),
        })
        .map_err(|_| corrupt())?;
        // Storage capacity is distinct from the peer-relative burst verdict.
        // Keep accepted work durable; the sender can retry a capacity refusal.
        crate::store::check_queue_capacity(
            &vault.store.sync_queue,
            txn,
            b"m:federation-",
            &self.key(),
            value.len(),
            vault.config.map_size / 16,
        )?;
        let mut peer_prefix = b"m:federation-deferred:v1:".to_vec();
        peer_prefix.extend_from_slice(&self.peer);
        crate::store::check_queue_capacity(
            &vault.store.sync_queue,
            txn,
            &peer_prefix,
            &self.key(),
            value.len(),
            vault.config.map_size / 32,
        )?;
        vault.store.sync_queue.put(txn, &self.key(), &value)?;
        Ok(())
    }

    pub(super) fn decode(value: &[u8]) -> Result<Self> {
        let row: StoredWork = postcard::from_bytes(value).map_err(|_| corrupt())?;
        if WindowKey::try_new(&row.window).is_none()
            || row.payload.len() > MAX_DECODED_PAYLOAD_BYTES
            || !row.rate_ratio.is_finite()
            || row.rate_ratio < 0.0
            || !row.streak_ratio.is_finite()
            || row.streak_ratio < 0.0
            || (row.kind == WorkKind::Selector && row.isolated_update.is_some())
            || row.isolated_update.as_ref().is_some_and(|parts| {
                parts.is_empty()
                    || parts
                        .iter()
                        .any(|(window, _)| WindowKey::try_new(window).is_none())
            })
        {
            return Err(corrupt());
        }
        Ok(Self {
            id: row.id,
            authority_digest: row.authority_digest,
            peer: row.peer,
            selector: row.selector,
            window: row.window,
            kind: row.kind,
            payload: row.payload,
            isolated_update: row.isolated_update,
            streak_ratio: row.streak_ratio,
            inputs: NormalizedBurstInputs {
                rate_ratio: row.rate_ratio,
                streak: row.streak,
            },
        })
    }

    /// Delete only after durable import or successful direct-response enqueue.
    /// A crash before deletion safely replays the same deterministic CRDT ops.
    pub(in crate::sync) fn complete(&self, vault: &Vault, peer: &FederationPeer) -> Result<()> {
        self.settle(vault, peer, false)
    }

    /// Retires an update the admission door refused as the peer's own bytes
    /// when it was retried, recorded as a structural failure as a live refusal
    /// is, so the work behind it drains.
    pub(in crate::sync) fn reject(&self, vault: &Vault, peer: &FederationPeer) -> Result<()> {
        self.settle(vault, peer, true)
    }

    fn settle(&self, vault: &Vault, peer: &FederationPeer, structural_failure: bool) -> Result<()> {
        peer.revalidate(vault)?;
        if self.peer != peer.digest() || self.selector != encode_sync_selector(&peer.selector)? {
            return Err(corrupt());
        }
        vault.with_write_txn_grouped(|txn| {
            peer.revalidate_in_txn(vault, txn)?;
            vault.store.sync_queue.delete(txn, &self.key())?;
            super::ledger::settle(vault, txn, peer, self, structural_failure)?;
            // Keep a small, payload-free delivery witness. If the socket dies
            // after direct enqueue, the same authenticated ticket can fetch
            // again. A guessed hash with no witness cannot bypass observation.
            if self.kind == WorkKind::Selector {
                vault
                    .store
                    .sync_queue
                    .put(txn, &self.completion_key(), &self.id)?;
            }
            observations::outcome_in_txn(vault, txn, peer, structural_failure)
        })
    }

    pub(in crate::sync) fn next_update(
        vault: &Vault,
        peer: &FederationPeer,
    ) -> Result<Option<Self>> {
        Self::find_update(vault, peer, None)
    }

    pub(in crate::sync) fn update_by_id(
        vault: &Vault,
        peer: &FederationPeer,
        id: &[u8; 32],
    ) -> Result<Option<Self>> {
        Self::find_update(vault, peer, Some(id))
    }

    fn find_update(
        vault: &Vault,
        peer: &FederationPeer,
        id: Option<&[u8; 32]>,
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
            if id.is_some_and(|id| work.id != *id) {
                continue;
            }
            work.revalidate_authority_in_txn(vault, &txn, peer)?;
            if work.kind != WorkKind::Selector
                && (work.isolated_update.is_none()
                    || observations::replay_ready_in_txn(
                        vault,
                        &txn,
                        peer,
                        vault.now_recorded_at(),
                    )?)
            {
                return Ok(Some(work));
            }
        }
        Ok(None)
    }
}
