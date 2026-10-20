//! FIX 6679 (Engine 10-20 22:3x, pick B): a failure-signal batch the Gate
//! holds for its owner carries into the next pass. A pass stages its batch
//! here before the send leaves, so a hold the owner sees is never lost; the
//! next pass sends exactly that batch again, under its own batch id, send
//! ref, body and content ref, so the owner's approve-once press on its
//! digest is spent by the batch he saw, and signals recorded since wait for
//! the batch after it (CALLS `FIX 6679 held failure-signal batch carries
//! over`). The row is custody only, never approval authority: the Gate
//! decides every send, the carried one included, as it always does.
//!
//! What a pass does with a carried batch is read from durable facts: its
//! intent ledger row (absent, retryable on an owner's recorded press, or
//! settled), the Gate's newest decision on a send of it when none was
//! admitted (only a hold for the owner keeps it), and the owner's denial of
//! its digest in the Gate's decisions since it was staged. Its settlement
//! takes exactly the quantities and records it froze, once, in one writer
//! with the row's removal: the row still there is what says they are owed.
//! A denial, a change in what it may carry, or an actor erase retires it
//! with no ack of anything its ledger row has not settled, and nothing is
//! dropped: the next pass selects afresh (CALLS `FIX 6679 denied or
//! ineligible held batch retires without ack`).

use std::sync::{MutexGuard, PoisonError};

use serde::{Deserialize, Serialize};

use super::code_fix::{CodeFixShare, ack_code_fix_records_in_txn, code_fix_still_eligible_in};
use super::count_delivery::{CountShare, count_shares, subtract_counts_in_txn};
use super::delivery::batch_request;
use super::{
    CodeFixExport, FAILURE_SIGNAL_BATCH_VERSION, FailureSignalBatch, FailureSignalCounts,
    Tier1FailureCount,
};
use crate::consent::{CONSENT_CONTENT_KIND, CONSENT_REASON_DENIED};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::gate::GateOutcome;
use crate::outbound::{
    OutboundDispatchError, OutboundDispatchRequest, OutboundDispatchResult,
    outbound_approve_once_digest, outbound_dispatch_attempt_id,
};
use crate::outbound_intent_ledger::{
    IntentLedgerError, IntentLedgerRecord, IntentResolution, IntentState, RecordedOutboundOutcome,
    UnconfirmedDelivery, read_intent_for_attempt_in_txn,
};
use crate::side_table::{self, Named, SideTable};
use crate::store::{GateDecisionId, GateDecisionRecord};
use crate::{EntityId, Vault};

/// The vault's one carried batch (CALLS `FIX 6679 held batch custody
/// table`): one active publisher batch per vault, so the key is the unit.
const HELD: SideTable<(), HeldBatch, Named> =
    SideTable::new(&side_table::FAILURE_SIGNALS_HELD_BATCH);

/// One batch, as it was built and first sent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct HeldBatch {
    /// The batch JSON exactly as first serialized; never encoded again.
    pub(super) body: String,
    /// Lowercase hex BLAKE3 of `body`; the send's content ref names it.
    pub(super) digest: String,
    /// The publisher endpoint it was built for.
    pub(super) endpoint: String,
    /// Its random id.
    pub(super) batch_id: String,
    /// Whether the deployment let the publisher train on it when it was
    /// built.
    training_permitted: bool,
    /// The aggregate rows and quantities it froze.
    pub(super) counts: Vec<CountShare>,
    /// The code-fix records it carries, each with the worlds its failure
    /// touched.
    pub(super) code_fix: Vec<CodeFixShare>,
    /// A store id taken just before it was staged: every Gate decision on
    /// it, the owner's answer included, is recorded after this one.
    floor: [u8; 16],
    /// Seconds since the epoch.
    created_at: u64,
    stage: HeldStage,
}

/// Where a kept batch stood after its last send. A record: what a pass does
/// with a carried batch is read from durable facts, and this counts only
/// where the Gate's decisions on it are gone, to say the Gate held it once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum HeldStage {
    /// Written before its send.
    Staged,
    /// The Gate held it for the owner.
    Held,
    /// Admitted on the owner's press and failed definitely: it retries
    /// under its own ref on that recorded press (CALLS `FIX 6679 held batch
    /// retry proof`).
    Admitted,
}

/// One batch's send this pass: its custody, its request, and for a carried
/// batch the approve-once digest the owner's answer to it names.
pub(super) struct BatchSend {
    pub(super) held: HeldBatch,
    pub(super) request: OutboundDispatchRequest,
    pub(super) approval_digest: Option<String>,
}

impl HeldBatch {
    /// A fresh batch of `counts` and `code_fix` for `endpoint`, under a new
    /// random id, staged after the store id `floor`.
    pub(super) fn mint(
        endpoint: &str,
        training_permitted: bool,
        counts: Vec<Tier1FailureCount>,
        code_fix: Vec<(CodeFixExport, Vec<EntityId>)>,
        floor: [u8; 16],
        now: u64,
    ) -> Result<Self> {
        let mut id = [0u8; 16];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut id);
        let (code_fix, worlds): (Vec<_>, Vec<_>) = code_fix.into_iter().unzip();
        let batch = FailureSignalBatch {
            version: FAILURE_SIGNAL_BATCH_VERSION,
            batch_id: bytes_to_hex_lower(&id),
            training_permitted,
            counts,
            code_fix,
        };
        let body = serde_json::to_vec(&batch)
            .ok()
            .and_then(|body| String::from_utf8(body).ok())
            .ok_or(Error::InvariantViolation("failure signal batch encode"))?;
        Ok(Self {
            digest: blake3::hash(body.as_bytes()).to_hex().to_string(),
            body,
            endpoint: endpoint.to_owned(),
            counts: count_shares(&batch.counts)?,
            code_fix: batch
                .code_fix
                .iter()
                .map(|record| record.id().to_owned())
                .zip(worlds)
                .collect(),
            batch_id: batch.batch_id,
            training_permitted,
            floor,
            created_at: now,
            stage: HeldStage::Staged,
        })
    }

    /// The send ref every one of its sends carries.
    pub(super) fn send_ref(&self) -> String {
        format!("failure_signals:batch:{}", self.batch_id)
    }

    /// Its content ref: the digest of its body.
    pub(super) fn content_ref(&self) -> String {
        format!("failure_signals:digest:{}", self.digest)
    }

    /// Whether its body still hashes to its digest.
    fn body_intact(&self) -> bool {
        blake3::hash(self.body.as_bytes()).to_hex().as_str() == self.digest
    }

    /// It as an actor erase leaves a batch its ledger row has settled
    /// nothing of yet (FIX 6679): its body and digest gone, its frozen
    /// shares kept for whoever settles it. No check finds it live, so no
    /// pass sends it again.
    fn erased(mut self) -> Self {
        self.body.clear();
        self.digest.clear();
        self
    }

    /// Whether it may still leave, read in `txn`: the training permission
    /// it was built under, every record in it still queued and public, and
    /// no owner denial of `approval_digest` since it was staged.
    fn eligible_in(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        approval_digest: Option<&str>,
    ) -> Result<bool> {
        if self.training_permitted != vault.config.failure_signals.permits_training()
            || !code_fix_still_eligible_in(vault, txn, &self.code_fix)?
        {
            return Ok(false);
        }
        match approval_digest {
            Some(digest) => Ok(!owner_denied_in(vault, txn, self.floor, digest)?),
            None => Ok(true),
        }
    }

    /// [`Self::eligible_in`] with its custody still this batch, read in
    /// `txn`: an erase may have retired it, or kept only its frozen shares,
    /// since the pass read it.
    pub(super) fn may_still_leave_in(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        approval_digest: Option<&str>,
    ) -> Result<bool> {
        let live = HELD
            .get_lenient(&vault.store, txn, &())?
            .is_some_and(|kept| kept.batch_id == self.batch_id && kept.digest == self.digest);
        Ok(live && self.eligible_in(vault, txn, approval_digest)?)
    }
}

impl FailureSignalCounts {
    /// Held for one whole delivery pass. It guards nothing in memory, so a
    /// pass that panicked leaves it usable.
    pub(super) fn lock_delivery(&self) -> MutexGuard<'_, ()> {
        self.delivery.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Vault {
    /// The batch this pass carries, with its request and digest, if any. A
    /// row that does not decode, or whose body no longer hashes to its
    /// digest (an erase's frozen shares among them), is retired. A batch no
    /// send of which was admitted goes again only while the Gate's newest
    /// decision on it holds it for the owner and it may still leave to the
    /// same endpoint; a Gate Deny, any other decision on it, or none on one
    /// only ever staged retires it, and the pass selects afresh as it
    /// always did. One admitted and failed definitely retries under its own
    /// ref only when its admission spent the owner's press; one a grant
    /// admitted is retired. One whose ledger row is settled or unresolved
    /// is carried, so its replay resolves it with no wire before anything
    /// is selected anew.
    pub(super) fn carried_failure_signal_batch(
        &self,
        endpoint: &str,
        sender: EntityId,
        now: u64,
    ) -> std::result::Result<Option<BatchSend>, OutboundDispatchError> {
        let held = {
            let txn = self.store.env.read_txn().map_err(Error::from)?;
            HELD.get_bytes(&self.store, &txn, &())?.map(|bytes| {
                HELD.decode_value(&bytes)
                    .ok()
                    .filter(HeldBatch::body_intact)
            })
        };
        let held = match held {
            None => return Ok(None),
            Some(Some(held)) => held,
            Some(None) => {
                self.retire_failure_signal_batch()?;
                return Ok(None);
            }
        };
        let request = batch_request(sender, &held, now);
        let approval_digest =
            outbound_approve_once_digest(self, &request)?.map(|digest| digest.to_hex());
        let carry = {
            let _custody = self.store.gate_custody_read_guard()?;
            let txn = self.store.env.read_txn().map_err(Error::from)?;
            let attempt = outbound_dispatch_attempt_id(&held.send_ref())?;
            let may_leave = |pressed: bool| -> Result<bool> {
                Ok(pressed
                    && held.endpoint == endpoint
                    && held.eligible_in(self, &txn, approval_digest.as_deref())?)
            };
            match read_intent_for_attempt_in_txn(self, &txn, attempt, 0)? {
                None => may_leave(owner_held_in(self, &txn, &held, sender)?)?,
                Some(row) if retryable(&row) => may_leave(row.admitted_approval.is_some())?,
                Some(_) => true,
            }
        };
        if !carry {
            self.retire_failure_signal_batch()?;
            return Ok(None);
        }
        Ok(Some(BatchSend {
            held,
            request,
            approval_digest,
        }))
    }

    /// [`HeldBatch::may_still_leave_in`] on a snapshot of its own, just
    /// before the wire.
    pub(super) fn failure_signal_batch_may_leave(
        &self,
        held: &HeldBatch,
        approval_digest: Option<&str>,
    ) -> Result<bool> {
        let _custody = self.store.gate_custody_read_guard()?;
        let txn = self.store.env.read_txn()?;
        held.may_still_leave_in(self, &txn, approval_digest)
    }

    /// Stages `held` before its send leaves.
    pub(super) fn stage_failure_signal_batch(&self, held: &HeldBatch) -> Result<()> {
        self.with_write_txn_grouped(|txn| HELD.put(&self.store, txn, &(), held))
    }

    /// Records that `held` stands at `stage`, unless it was retired
    /// meanwhile.
    pub(super) fn keep_failure_signal_batch(
        &self,
        held: &HeldBatch,
        stage: HeldStage,
    ) -> Result<()> {
        if held.stage == stage {
            return Ok(());
        }
        self.with_write_txn_grouped(|txn| {
            let Some(mut kept) = HELD.get_lenient(&self.store, &*txn, &())? else {
                return Ok(());
            };
            if kept.batch_id != held.batch_id {
                return Ok(());
            }
            kept.stage = stage;
            HELD.put(&self.store, txn, &(), &kept)
        })
    }

    /// Retires the carried batch with no ack of anything its ledger row has
    /// not settled. What the row already settled (a delivered send's
    /// quantities and records, or the counts of a stopped send that may
    /// have landed) is acked first in the same writer, with no wire, so
    /// retiring never sends again what left. Every other signal stays
    /// queued. A pass, or the participation reconcile, calls this under the
    /// delivery lock, so no send of it is under way.
    pub(super) fn retire_failure_signal_batch(&self) -> Result<()> {
        let carried = {
            let txn = self.store.env.read_txn()?;
            HELD.get_bytes(&self.store, &txn, &())?.is_some()
        };
        if !carried {
            return Ok(());
        }
        self.with_write_txn_grouped(|txn| {
            if let Some(held) = HELD.get_lenient(&self.store, &*txn, &())?
                && let Some(delivered) = settled_in(self, &*txn, &held)?
            {
                settle_in_txn(self, txn, &held, delivered)?;
            }
            HELD.delete(&self.store, txn, &())?;
            Ok(())
        })
    }

    /// Settles `held` in one writer with its row's removal: its frozen
    /// quantities leave the aggregate, and, once it was `delivered`, its
    /// code-fix records leave the queue. An ambiguous send takes the counts
    /// only, since a record sent again carries its own id and the publisher
    /// keeps one. Counts and records that came since stay. Its row gone
    /// means an actor erase settled it first, so nothing is taken twice
    /// (FIX 6679).
    pub(super) fn settle_failure_signal_batch(
        &self,
        held: &HeldBatch,
        delivered: bool,
    ) -> Result<()> {
        self.with_write_txn_grouped(|txn| {
            let Some(bytes) = HELD.get_bytes(&self.store, &*txn, &())? else {
                return Ok(());
            };
            if HELD
                .decode_value(&bytes)
                .is_ok_and(|kept| kept.batch_id != held.batch_id)
            {
                return Ok(());
            }
            settle_in_txn(self, txn, held, delivered)?;
            HELD.delete(&self.store, txn, &())?;
            Ok(())
        })
    }

    /// Where a batch the dispatch neither delivered nor left ambiguous
    /// stands, `None` to discard it (CALLS `FIX 6679 held failure-signal
    /// batch carries over`). The Gate holding it for the owner (`pending`;
    /// a delivery window, budget or suppression hold the Gate allowed is
    /// not one) keeps it. So does an admitted send that failed definitely,
    /// its ledger row still Pending, when its admission spent the owner's
    /// press: it retries under its own ref on that press. A Gate Deny, and
    /// every other ending, discards it, as a fresh batch always was.
    pub(super) fn next_failure_signal_stage(
        &self,
        held: &HeldBatch,
        result: &OutboundDispatchResult,
    ) -> std::result::Result<Option<HeldStage>, OutboundDispatchError> {
        if result.gate_outcome == GateOutcome::Pending.as_str() {
            return Ok(Some(HeldStage::Held));
        }
        if result.gate_outcome == GateOutcome::Deny.as_str()
            || !matches!(result.resolution, Some(IntentResolution::Pending { .. }))
        {
            return Ok(None);
        }
        let txn = self.store.env.read_txn().map_err(Error::from)?;
        let attempt = outbound_dispatch_attempt_id(&held.send_ref())?;
        let pressed = read_intent_for_attempt_in_txn(self, &txn, attempt, 0)?
            .is_some_and(|row| retryable(&row) && row.admitted_approval.is_some());
        Ok(pressed.then_some(HeldStage::Admitted))
    }
}

/// A ledger row a definite failure left Pending and retryable.
fn retryable(row: &IntentLedgerRecord) -> bool {
    row.state == IntentState::Pending
        && row.recorded_outcome == Some(RecordedOutboundOutcome::DefiniteNonDelivery)
}

/// Takes `held`'s frozen quantities out of the aggregate in `txn`, and its
/// code-fix records out of the queue once it was `delivered`.
fn settle_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    held: &HeldBatch,
    delivered: bool,
) -> Result<()> {
    subtract_counts_in_txn(vault, txn, &held.counts)?;
    if delivered {
        let ids = held
            .code_fix
            .iter()
            .map(|(id, _)| id.as_str())
            .collect::<Vec<_>>();
        ack_code_fix_records_in_txn(vault, txn, &ids)?;
    }
    Ok(())
}

/// What `held`'s ledger row settled for good, read in `txn`: `Some(true)`
/// delivered, `Some(false)` stopped with its delivery unresolved, `None`
/// for no row, a row still Pending, one stopped undelivered, or one that
/// does not read.
fn settled_in(vault: &Vault, txn: &heed::RoTxn<'_>, held: &HeldBatch) -> Result<Option<bool>> {
    let Ok(attempt) = outbound_dispatch_attempt_id(&held.send_ref()) else {
        return Ok(None);
    };
    let row = match read_intent_for_attempt_in_txn(vault, txn, attempt, 0) {
        Ok(row) => row,
        Err(IntentLedgerError::Engine(error)) => return Err(error),
        Err(_) => return Ok(None),
    };
    Ok(match row.as_ref().map(IntentResolution::from_record) {
        Some(Ok(IntentResolution::Delivered)) => Some(true),
        Some(Ok(IntentResolution::Stopped {
            delivery: UnconfirmedDelivery::Unresolved,
            ..
        })) => Some(false),
        _ => None,
    })
}

/// Whether the owner denied `digest` after the store id `after`: a
/// `gate.consent.denied` receipt whose diff handle is that digest, every
/// decision since read exhaustively.
fn owner_denied_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    after: [u8; 16],
    digest: &str,
) -> Result<bool> {
    let found = vault.store.find_gate_decision_after_in_txn(
        txn,
        GateDecisionId::from_bytes(after),
        |record: &GateDecisionRecord| {
            record.content_kind == CONSENT_CONTENT_KIND
                && record.reason_codes.first().map(String::as_str) == Some(CONSENT_REASON_DENIED)
                && bytes_to_hex_lower(&record.diff_handle) == digest
        },
    )?;
    Ok(found.is_some())
}

/// The content kind of the Gate's decision on an outbound send
/// (`GateContentKind::ExternalEffect`).
const SEND_DECISION_KIND: &str = "external_effect";

/// Whether the Gate holds `held` for its owner, read in `txn`, for a batch
/// no send of which was admitted (FIX 6679). The newest of the Gate's
/// decisions on a send by `sender` since it was staged says so: one batch
/// per vault is in flight, and every pass sends it until it is settled or
/// retired, so each such decision since its floor is on it. A pending one
/// is the owner's hold; a Gate Deny, or any other decision, is none, and
/// no ledger row alone is no hold. Where no such decision is left, a batch
/// the Gate held on an earlier pass (its stage says so) still waits, and
/// one only ever staged was never shown.
fn owner_held_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    held: &HeldBatch,
    sender: EntityId,
) -> Result<bool> {
    let actor = sender.to_hex();
    let mut newest = None;
    vault.store.find_gate_decision_after_in_txn(
        txn,
        GateDecisionId::from_bytes(held.floor),
        |record: &GateDecisionRecord| {
            if record.content_kind == SEND_DECISION_KIND
                && record.actor_ref.as_deref() == Some(actor.as_str())
            {
                newest = Some(record.outcome == GateOutcome::Pending.as_str());
            }
            false
        },
    )?;
    Ok(newest.unwrap_or(held.stage != HeldStage::Staged))
}

/// An erase of `actor` retires the carried batch with no ack of anything
/// its ledger row has not settled (CALLS `FIX 6679 held batch custody
/// table`): its counts and records may come from that actor's failures, and
/// nothing in a frozen body is edited under its old ref. What the row
/// already settled (a delivered send's quantities and records, or the
/// counts of a stopped send that may have landed) is acked here first, with
/// no wire, and the custody goes with it, so a crash after the send's Done
/// never sends them again. A batch whose row has settled nothing yet keeps
/// only its frozen shares, its body and digest gone: no check finds it
/// live, so no pass sends it, and whoever settles it next (the pass still
/// sending it, or the next pass's retirement) takes them once, with the
/// row. The signals stay queued; the next pass selects afresh. An id whose
/// entity is no actor retires nothing; a row that does not decode goes by
/// its key all the same.
pub(crate) fn erase_held_batch_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if crate::learning_setting::names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let Some(held) = HELD.get_lenient(&vault.store, &*wtxn, &())? else {
        HELD.delete(&vault.store, wtxn, &())?;
        return Ok(());
    };
    match settled_in(vault, &*wtxn, &held)? {
        Some(delivered) => {
            settle_in_txn(vault, wtxn, &held, delivered)?;
            HELD.delete(&vault.store, wtxn, &())?;
        }
        None => HELD.put(&vault.store, wtxn, &(), &held.erased())?,
    }
    Ok(())
}
