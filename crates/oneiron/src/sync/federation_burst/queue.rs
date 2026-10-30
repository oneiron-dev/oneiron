//! Actual deferred payloads and their identity-bound, idempotent completion.

use super::schedule::{self, RetainedWorkQueue, Waiting};
use super::{FederationBurstWorkState, FederationPeer, corrupt, erase, observations};
use crate::llm::NormalizedBurstInputs;
use crate::store::Store;
use crate::sync::transport::MAX_DECODED_PAYLOAD_BYTES;
use crate::sync::{WindowKey, encode_sync_selector};
use crate::{EntityId, Result, Vault};
use serde::{Deserialize, Serialize};

const DEFERRED_PREFIX: &[u8] = b"m:federation-deferred:v1:";

/// The schedule queue these rows wait in: its deadline index notes each one.
const QUEUE: RetainedWorkQueue = RetainedWorkQueue::FederationBurst;

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
    /// When the batch was retained: a store clock id, so the drain serves
    /// a caller's batches oldest first (FIX 7997).
    pub(super) arrival: [u8; 16],
    /// When its wait ends, in seconds; an identity never retained has none.
    pub(super) deadline: u64,
    /// The rows whose bytes the batch carries, which an erase of any of them
    /// scrubs (FIX 7998).
    pub(super) carried: Vec<EntityId>,
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
    arrival: [u8; 16],
    deadline: u64,
    carried: Vec<EntityId>,
}

fn prefix(peer: &FederationPeer) -> Result<Vec<u8>> {
    let mut prefix = DEFERRED_PREFIX.to_vec();
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
            arrival: [0; 16],
            deadline: 0,
            carried: Vec::new(),
        })
    }

    /// How this retained batch has ended at `now` without its turn, if it
    /// has: it was held under a grant or pact scope that has since changed
    /// (FIX 7999), or its wait is over (FIX 7997).
    pub(in crate::sync) fn ended_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        peer: &FederationPeer,
        now: u64,
    ) -> Result<Option<FederationBurstWorkState>> {
        if self.authority_digest != peer.authority_digest_in_txn(vault, txn)? {
            return Ok(Some(FederationBurstWorkState::StaleAuthority));
        }
        Ok((self.deadline != 0 && self.deadline <= now)
            .then_some(FederationBurstWorkState::Expired))
    }

    /// Starts this batch's wait in the admitting writer: its arrival, and its
    /// deadline from the owner's wait for retained federation work.
    pub(super) fn arrive_in_txn(
        &mut self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        now: u64,
    ) -> Result<()> {
        self.arrival = vault.store.clock.ulid()?;
        let wait = schedule::wait_secs_in(vault, txn, RetainedWorkQueue::FederationBurst)?;
        self.deadline = now.saturating_add(wait);
        Ok(())
    }

    pub(super) fn with_inputs(mut self, inputs: NormalizedBurstInputs) -> Self {
        self.inputs = inputs;
        self
    }

    pub(super) fn key(&self) -> Vec<u8> {
        let mut key = DEFERRED_PREFIX.to_vec();
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
            arrival: self.arrival,
            deadline: self.deadline,
            carried: self.carried.clone(),
        })
        .map_err(|_| corrupt())?;
        // Storage capacity is distinct from the peer-relative burst verdict.
        // Accepted work stays durable: the queue's byte totals are observed
        // against these thresholds, never refused (FIX 7996, 8852).
        crate::store::check_queue_capacity(
            &vault.store.sync_queue,
            txn,
            b"m:federation-",
            &self.key(),
            value.len(),
            vault.config.map_size / 16,
        )?;
        let mut peer_prefix = DEFERRED_PREFIX.to_vec();
        peer_prefix.extend_from_slice(&self.peer);
        crate::store::check_queue_capacity(
            &vault.store.sync_queue,
            txn,
            &peer_prefix,
            &self.key(),
            value.len(),
            vault.config.map_size / 32,
        )?;
        // A row put again under another deadline drops its old note.
        let replaced = vault
            .store
            .sync_queue
            .get(txn, &self.key())?
            .and_then(|saved| Self::decode(&saved).ok())
            .map(|saved| saved.deadline);
        if let Some(replaced) = replaced
            && replaced != self.deadline
        {
            schedule::drop_deadline_in_txn(&vault.store, txn, QUEUE, replaced, &self.key())?;
        }
        vault.store.sync_queue.put(txn, &self.key(), &value)?;
        schedule::note_deadline_in_txn(&vault.store, txn, QUEUE, self.deadline, &self.key())?;
        erase::register_in_txn(
            &vault.store,
            txn,
            &self.carried,
            &erase::CarriedBy::Burst(self.key()),
        )
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
            arrival: row.arrival,
            deadline: row.deadline,
            carried: row.carried,
        })
    }

    /// Removes the retained batch: its row, its review copies and its
    /// carrier rows. Its receipt is the caller's to settle.
    pub(super) fn remove_in_txn(&self, store: &Store, txn: &mut heed::RwTxn<'_>) -> Result<()> {
        store.sync_queue.delete(txn, &self.key())?;
        schedule::drop_deadline_in_txn(store, txn, QUEUE, self.deadline, &self.key())?;
        super::review_doors::scrub_in_txn(store, txn, &self.peer, &self.id)?;
        erase::forget_in_txn(
            store,
            txn,
            &self.carried,
            &erase::CarriedBy::Burst(self.key()),
        )
    }

    /// Ends the retained batch with `state`, keeping only its content-free
    /// receipt. Nothing is imported and no outcome is observed: an ended
    /// batch says nothing about the peer's structural health.
    pub(super) fn retire_in_txn(
        &self,
        store: &Store,
        txn: &mut heed::RwTxn<'_>,
        state: FederationBurstWorkState,
    ) -> Result<()> {
        self.remove_in_txn(store, txn)?;
        super::ledger::settle_in_txn(store, txn, &self.id, state)
    }

    /// [`Self::retire_in_txn`] in its own writer, when the batch is still
    /// retained and still ends as `state` there; the peer's other batches
    /// go on draining (FIX 7997, 7999).
    pub(in crate::sync) fn retire(
        &self,
        vault: &Vault,
        peer: &FederationPeer,
        state: FederationBurstWorkState,
    ) -> Result<()> {
        vault.with_write_txn_grouped(|txn| {
            let Some(saved) = self.load_in_txn(vault, txn)? else {
                return Ok(());
            };
            if saved.ended_in_txn(vault, txn, peer, vault.now_recorded_at())? == Some(state) {
                saved.retire_in_txn(&vault.store, txn, state)?;
            }
            Ok(())
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
            self.remove_in_txn(&vault.store, txn)?;
            let state = if structural_failure {
                FederationBurstWorkState::Rejected
            } else {
                FederationBurstWorkState::Imported
            };
            super::ledger::settle(vault, txn, peer, self, state)?;
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

    /// The oldest ready update this peer retained under its selector. A
    /// batch held under an older grant or pact scope, and one past its wait,
    /// ends alone with its typed receipt; the others still drain (FIX 7997,
    /// 7999). A selector read waits for its peer's replay, and an isolated
    /// update for the peer's rate to come back to its baseline.
    fn find_update(
        vault: &Vault,
        peer: &FederationPeer,
        id: Option<&[u8; 32]>,
    ) -> Result<Option<Self>> {
        peer.revalidate(vault)?;
        let now = vault.now_recorded_at();
        let prefix = prefix(peer)?;
        let (turns, stale) = {
            let txn = vault.store.env.read_txn()?;
            let current = peer.authority_digest_in_txn(vault, &txn)?;
            let rate_ready = observations::replay_ready_in_txn(vault, &txn, peer, now)?;
            let mut waiting = Vec::new();
            let mut stale = Vec::new();
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
                if work.authority_digest != current {
                    stale.push(work);
                    continue;
                }
                let ready = work.kind != WorkKind::Selector
                    && (work.isolated_update.is_none() || rate_ready);
                waiting.push(Waiting {
                    caller: prefix.clone(),
                    arrival: work.arrival,
                    deadline: work.deadline,
                    ready,
                    item: work,
                });
            }
            (schedule::turns(waiting, None, now), stale)
        };
        for work in stale {
            work.retire(vault, peer, FederationBurstWorkState::StaleAuthority)?;
        }
        for work in turns.expired {
            work.retire(vault, peer, FederationBurstWorkState::Expired)?;
        }
        Ok(turns.due.into_iter().next().map(|(_, work)| work))
    }
}

/// Scrubs the retained batch stored at `key` for an erase of a row it
/// carries: its bytes and review copies go, and its receipt says it was
/// erased (FIX 7998).
pub(super) fn erase_in_txn(store: &Store, txn: &mut heed::RwTxn<'_>, key: &[u8]) -> Result<()> {
    let work = match store.sync_queue.get(txn, key)? {
        Some(value) => DeferredWork::decode(&value)?,
        None => return Ok(()),
    };
    if work.key().as_slice() != key {
        return Err(corrupt());
    }
    work.retire_in_txn(store, txn, FederationBurstWorkState::Erased)
}

/// Ends every retained batch past its wait with its typed receipt, whoever
/// its peer is, so work a peer never comes back for does not wait for ever
/// (FIX 7997). Returns how many ended.
pub(crate) fn expire_retained_work(vault: &Vault) -> Result<u64> {
    let now = vault.now_recorded_at();
    // The deadline index names them, up to now alone.
    let expired = {
        let txn = vault.store.env.read_txn()?;
        schedule::deadlines_through_in(&vault.store, &txn, QUEUE, now)?
    };
    if expired.is_empty() {
        return Ok(0);
    }
    vault.with_write_txn_grouped(|txn| {
        let mut ended = 0;
        for (deadline, key) in &expired {
            let saved = vault
                .store
                .sync_queue
                .get(txn, key)?
                .map(|saved| DeferredWork::decode(&saved))
                .transpose()?;
            if let Some(work) = saved
                && work.key() == *key
                && work.deadline <= now
            {
                work.retire_in_txn(&vault.store, txn, FederationBurstWorkState::Expired)?;
                ended += 1;
            }
            // No note stays at a past deadline: a row still waiting is noted
            // at its own, and a note whose row is gone waits for nothing.
            schedule::drop_deadline_in_txn(&vault.store, txn, QUEUE, *deadline, key)?;
        }
        Ok(ended)
    })
}

/// The earliest deadline of the retained batches, or `None` when none is
/// retained: the same rows [`expire_retained_work`] ends (FIX 11183), read
/// from the first row of their deadline index.
pub(crate) fn earliest_retained_deadline(vault: &Vault) -> Result<Option<u64>> {
    let txn = vault.store.env.read_txn()?;
    schedule::earliest_deadline_in(&vault.store, &txn, QUEUE)
}
