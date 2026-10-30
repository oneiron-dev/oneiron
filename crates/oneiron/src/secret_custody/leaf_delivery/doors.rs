//! The `Vault` doors of live leaf delivery (FIX 7402): the asker's
//! pending asks, the holder's answer, the asker's accept and the failure
//! L03's frame reports; and the carrier key lookups the open paths share.

use std::sync::{MutexGuard, PoisonError};

use ed25519_dalek::Signer;

use super::super::carrier_custody::{
    CARRIER_REF_BYTES, CUSTODY_CARRIER_LEAF_WIRE, CarrierRef, carrier_release_admits,
};
use super::super::control::input::input_carrier_in_txn;
use super::super::control::permits;
use super::super::transition::transitions_awaiting_leaf_in_txn;
use super::{
    Asker, CustodyLeafSession, LEAF_KEY_REFUSED_BACKOFF_MS, LEAF_KEY_WIRE_VERSION, LeafKeyAnswer,
    LeafKeyFailureCause, LeafKeyRequest, LeafNeed, REFUSED_ASKER_KEY, REFUSED_EXPIRED,
    REFUSED_MALFORMED, REFUSED_NOT_ADMITTED, REFUSED_NOT_BOUND, REFUSED_NOT_HOLDER,
    REFUSED_REPLAYED, REFUSED_SIGNATURE, REFUSED_UNKNOWN_CARRIER, REFUSED_WIRE_OFF, machine_signed,
    open_leaf, seal_leaf,
};
use crate::Vault;
use crate::authority::{CustodyChange, OwnerWorkBody, PeerMachine, authority_refused};
use crate::error::Result;
use crate::store::{CredentialLeaf, CustodyKind};

impl Vault {
    /// This handle's live leaf delivery state, in memory only.
    pub(crate) fn custody_leaves(&self) -> MutexGuard<'_, CustodyLeafSession> {
        self.world_keys
            .custody_leaves
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The key of `carrier` this install holds, read in the caller's
    /// writer: one it was answered, in memory, else its own custody's, as
    /// the recorder or executor that minted it. `None` while it holds
    /// neither: what the carrier seals stays pending.
    pub(crate) fn carrier_leaf_in_writer(&self, carrier: &CarrierRef) -> Option<CredentialLeaf> {
        if let Some(leaf) = self.custody_leaves().leaf(carrier) {
            return Some(leaf);
        }
        self.store
            .read_carrier_leaf(carrier.kind, &carrier.credential, &carrier.instance)
            .ok()
    }

    /// [`Self::carrier_leaf_in_writer`] outside any transaction: the
    /// custody read guard is taken before custody is read.
    #[cfg(feature = "sync")]
    pub(crate) fn carrier_leaf_outside_txn(&self, carrier: &CarrierRef) -> Option<CredentialLeaf> {
        if let Some(leaf) = self.custody_leaves().leaf(carrier) {
            return Some(leaf);
        }
        let _custody = self.store.gate_custody_read_guard().ok()?;
        self.store
            .read_carrier_leaf(carrier.kind, &carrier.credential, &carrier.instance)
            .ok()
    }

    /// Each carrier key this install must ask for now (executor side, FIX
    /// 7402): one ask per custody input it executes and per transition sealed
    /// to it whose carrier key is neither in memory nor in its own custody,
    /// signed by its install key, standing `LEAF_KEY_REQUEST_TTL_MS` and
    /// naming its live encryption key. Called on every live client tick: an
    /// ask still out is returned again, same id and signature, until it is
    /// answered or expires, then a fresh one is minted; a carrier whose
    /// holder refused waits [`LEAF_KEY_REFUSED_BACKOFF_MS`]. A key no work
    /// here needs any more goes from memory. Empty while the carrier wire is
    /// off, and on an install with no machine identity, install key or
    /// importable encryption key.
    ///
    /// # Errors
    /// Storage faults.
    pub fn pending_leaf_key_requests(&self) -> Result<Vec<LeafKeyRequest>> {
        if !CUSTODY_CARRIER_LEAF_WIRE {
            return Ok(Vec::new());
        }
        let _ = self.load_install_signing_if_minted();
        let now = crate::unix_millis_now();
        let (needs, asker) = {
            let txn = self.store.env.read_txn()?;
            let Some(machine) = crate::identity::read_machine_id_in_txn(self, &txn)? else {
                return Ok(Vec::new());
            };
            let fold = self.authority_view_readonly_in_txn(&txn)?;
            let mut needs = Vec::new();
            for (hash, request) in fold.pending_owner_work_for(machine) {
                let OwnerWorkBody::Custody {
                    change,
                    input: Some(digest),
                    ..
                } = &request.work
                else {
                    continue;
                };
                if *change == CustodyChange::Revoke || fold.custody_revoked(&request.act.target) {
                    continue;
                }
                if let Some(carrier) = input_carrier_in_txn(&self.store, &txn, digest)?
                    && carrier.kind == CustodyKind::CustodyRequestInput
                    && carrier.credential == request.act.target
                {
                    needs.push(LeafNeed {
                        carrier,
                        work: hash,
                        holder: request.carrier,
                    });
                }
            }
            needs.extend(transitions_awaiting_leaf_in_txn(
                self, &txn, &fold, machine,
            )?);
            // A key this install minted is in its own custody: no ask.
            needs.retain(|need| need.holder != machine);
            let signing = crate::identity::read_machine_signing_key_in_txn(self, &txn)
                .ok()
                .flatten();
            let asker = match (
                fold.vault_id,
                signing,
                permits::candidate_for(&fold, machine),
            ) {
                (Some(vault_id), Some(signing), Some((_, key_suite, key))) => Some(Asker {
                    vault_id,
                    machine,
                    signing,
                    key_suite,
                    key,
                }),
                _ => None,
            };
            (needs, asker)
        };
        let mut session = self.custody_leaves();
        session.prune(&needs, now);
        if let Some(asker) = asker {
            for need in &needs {
                if !session.covered(need) {
                    let ask = asker.ask(need, now);
                    session.asks.insert(ask.request_id, ask);
                }
            }
        }
        Ok(session.asks.values().cloned().collect())
    }

    /// The holder's answer to `request` (FIX 7402): the carrier key it
    /// names, sealed to the asker's live encryption key under the ask's id,
    /// asker, expiry and carrier, signed by this install's key. The asker is
    /// whoever the ask's own signature proves, never `connection`'s peer: a
    /// relayed ask reaches this install on its client socket, whose peer is
    /// the home, and the asker may be the home's own install. The key goes
    /// only to the exact current request's executor, for its input, or one
    /// of its recipient permits, for its transition
    /// ([`carrier_release_admits`]). Nothing is written: the answer rides
    /// the frame and is gone.
    ///
    /// # Errors
    /// Each refusal names its branch as a typed `AuthorityRefused` reason
    /// ([`LeafKeyFailureCause::of_refusal`]), never a key: the wire off; a
    /// malformed ask; a passed expiry; another holder named; a signature
    /// that is not the asker's live one; a key that is not its live
    /// encryption key; the release rule refusing; no such key here.
    /// Storage faults otherwise.
    pub fn answer_leaf_key_request(
        &self,
        request: &LeafKeyRequest,
        connection: PeerMachine,
    ) -> Result<LeafKeyAnswer> {
        // The asker is the ask's signer alone; the socket names nobody.
        let _ = connection;
        if !CUSTODY_CARRIER_LEAF_WIRE {
            return Err(authority_refused(REFUSED_WIRE_OFF));
        }
        if request.version != LEAF_KEY_WIRE_VERSION {
            return Err(authority_refused(REFUSED_MALFORMED));
        }
        if request.expires_at_ms <= crate::unix_millis_now() {
            return Err(authority_refused(REFUSED_EXPIRED));
        }
        let carrier = request
            .carrier_ref()
            .ok_or_else(|| authority_refused(REFUSED_UNKNOWN_CARRIER))?;
        let _ = self.load_install_signing_if_minted();
        // The guard before the snapshot: no key goes between it and its read.
        let _custody = self.store.gate_custody_read_guard()?;
        let txn = self.store.env.read_txn()?;
        if crate::identity::read_machine_id_in_txn(self, &txn)? != Some(request.holder) {
            return Err(authority_refused(REFUSED_NOT_HOLDER));
        }
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let vault_id = fold
            .vault_id
            .ok_or_else(|| authority_refused(REFUSED_NOT_ADMITTED))?;
        if !machine_signed(
            &fold,
            request.executor,
            &request.transcript(&vault_id),
            &request.signature,
        ) {
            return Err(authority_refused(REFUSED_SIGNATURE));
        }
        let key =
            permits::live_encryption_key(&fold, request.executor, request.key_suite, &request.key)
                .ok_or_else(|| authority_refused(REFUSED_ASKER_KEY))?;
        if !carrier_release_admits(&fold, &carrier, &request.work, request.executor) {
            return Err(authority_refused(REFUSED_NOT_ADMITTED));
        }
        let leaf = self
            .store
            .read_carrier_leaf(carrier.kind, &carrier.credential, &carrier.instance)
            .map_err(|_| authority_refused(REFUSED_UNKNOWN_CARRIER))?;
        let signing = crate::identity::read_machine_signing_key_in_txn(self, &txn)?
            .ok_or_else(|| authority_refused(REFUSED_NOT_HOLDER))?;
        drop(txn);
        let mut answer = LeafKeyAnswer {
            version: LEAF_KEY_WIRE_VERSION,
            request_id: request.request_id,
            holder: request.holder,
            executor: request.executor,
            expires_at_ms: request.expires_at_ms,
            sealed: seal_leaf(&vault_id, request, &key, &leaf)?,
            signature: Vec::new(),
        };
        answer.signature = signing
            .sign(&answer.transcript(&vault_id, request))
            .to_bytes()
            .to_vec();
        Ok(answer)
    }

    /// Takes the holder's `answer` to this install's ask `request` (FIX
    /// 7402): it must answer exactly that ask, still out here and unexpired,
    /// be the named holder's live signature, and open with this install's
    /// machine secret. The key goes into memory alone, never a row or a log,
    /// keyed by its carrier, and the ask is done: a second answer for the
    /// same id is refused. The pending work opens on its next run (the
    /// owner work pickup, the custody pass).
    ///
    /// # Errors
    /// Typed `AuthorityRefused` reasons, never a key: the wire off; an
    /// answer bound to another ask, or one that does not open; no such ask
    /// out (answered, expired or never made); a passed expiry; a signature
    /// that is not the holder's live one. Keystore and storage faults.
    pub fn accept_leaf_key_answer(
        &self,
        request: &LeafKeyRequest,
        answer: &LeafKeyAnswer,
    ) -> Result<()> {
        if !CUSTODY_CARRIER_LEAF_WIRE {
            return Err(authority_refused(REFUSED_WIRE_OFF));
        }
        if !answer.answers(request) {
            return Err(authority_refused(REFUSED_NOT_BOUND));
        }
        let carrier = request
            .carrier_ref()
            .ok_or_else(|| authority_refused(REFUSED_UNKNOWN_CARRIER))?;
        {
            let mut session = self.custody_leaves();
            if session.asks.get(&request.request_id) != Some(request) {
                return Err(authority_refused(REFUSED_REPLAYED));
            }
            if request.expires_at_ms <= crate::unix_millis_now() {
                session.asks.remove(&request.request_id);
                return Err(authority_refused(REFUSED_EXPIRED));
            }
        }
        let secret = self.machine_secret_outside_txn()?;
        if secret.machine != request.executor {
            return Err(authority_refused(REFUSED_NOT_BOUND));
        }
        let vault_id = {
            let txn = self.store.env.read_txn()?;
            let fold = self.authority_view_readonly_in_txn(&txn)?;
            let vault_id = fold
                .vault_id
                .ok_or_else(|| authority_refused(REFUSED_NOT_BOUND))?;
            if !machine_signed(
                &fold,
                request.holder,
                &answer.transcript(&vault_id, request),
                &answer.signature,
            ) {
                return Err(authority_refused(REFUSED_SIGNATURE));
            }
            vault_id
        };
        let leaf = open_leaf(&vault_id, request, &answer.sealed, &secret)
            .ok_or_else(|| authority_refused(REFUSED_NOT_BOUND))?;
        let mut session = self.custody_leaves();
        if session.asks.remove(&request.request_id).is_none() {
            return Err(authority_refused(REFUSED_REPLAYED));
        }
        let carrier = carrier.encode();
        session.held_back.remove(&carrier);
        session.leaves.insert(carrier, leaf);
        Ok(())
    }

    /// What L03's failure frame says of this install's ask `request_id`
    /// (FIX 7402): an expired or replayed ask is dropped, and the next
    /// [`Self::pending_leaf_key_requests`] mints a fresh one; an offline
    /// socket keeps it pending, sent again on the next tick; a holder's
    /// refusal drops it and holds a new ask for its carrier back
    /// [`LEAF_KEY_REFUSED_BACKOFF_MS`]. An id no ask here has is nothing to
    /// do.
    ///
    /// # Errors
    /// None today; the signature leaves room for a durable cause.
    pub fn leaf_key_request_failed(
        &self,
        request_id: [u8; 32],
        cause: &LeafKeyFailureCause,
    ) -> Result<()> {
        let mut session = self.custody_leaves();
        match cause {
            LeafKeyFailureCause::HolderOffline | LeafKeyFailureCause::ExecutorOffline => {}
            LeafKeyFailureCause::Expired | LeafKeyFailureCause::Replayed => {
                session.asks.remove(&request_id);
            }
            LeafKeyFailureCause::HolderRefused(_) => {
                if let Some(ask) = session.asks.remove(&request_id)
                    && let Ok(carrier) = <[u8; CARRIER_REF_BYTES]>::try_from(ask.carrier.as_slice())
                {
                    let until =
                        crate::unix_millis_now().saturating_add(LEAF_KEY_REFUSED_BACKOFF_MS);
                    session.held_back.insert(carrier, until);
                }
            }
        }
        Ok(())
    }
}
