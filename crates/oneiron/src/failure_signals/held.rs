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
//! What a pass keeps is decided by [`next_stage`]; its settlement takes
//! exactly the quantities and records the batch froze, in one writer with
//! the row's removal. The owner's denial of its digest, a change in what it
//! may carry, or an actor erase retires it with no ack, and nothing is
//! dropped: the next pass selects afresh (CALLS `FIX 6679 denied or
//! ineligible held batch retires without ack`).

use std::sync::{MutexGuard, PoisonError};

use serde::{Deserialize, Serialize};

use super::code_fix::{
    CodeFixShare, ack_code_fix_records_in_txn, code_fix_still_eligible_in, public_id_key,
};
use super::count_delivery::{CountShare, count_shares, subtract_counts_in_txn};
use super::{
    CodeFixExport, FAILURE_SIGNAL_BATCH_VERSION, FailureSignalBatch, FailureSignalCounts,
    Tier1FailureCount,
};
use crate::consent::{CONSENT_CONTENT_KIND, CONSENT_REASON_DENIED};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::gate::GateOutcome;
use crate::outbound::{
    OutboundDispatchError, OutboundDispatchResult, outbound_dispatch_attempt_id,
};
use crate::outbound_intent_ledger::{
    IntentResolution, IntentState, RecordedOutboundOutcome, read_intent_for_attempt_in_txn,
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
    pub(super) training_permitted: bool,
    /// The aggregate rows and quantities it froze.
    pub(super) counts: Vec<CountShare>,
    /// The code-fix records it carries, each with the worlds its failure
    /// touched.
    pub(super) code_fix: Vec<CodeFixShare>,
    /// Seconds since the epoch.
    pub(super) created_at: u64,
    pub(super) stage: HeldStage,
}

/// Where a kept batch stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum HeldStage {
    /// Written before its send; no owner hold seen.
    Staged,
    /// The Gate holds it for the owner.
    Held(OwnerHold),
    /// The owner held it, the Gate admitted it, and it failed definitely:
    /// it retries under its own ref on the press its admission recorded
    /// (CALLS `FIX 6679 held batch retry proof`).
    Admitted(OwnerHold),
}

/// How the Gate first held a batch for the owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct OwnerHold {
    /// The decision that first held it.
    decision: Option<[u8; 16]>,
    /// The approve-once digest his press names, when its family pins one.
    approval_digest: Option<String>,
}

impl HeldStage {
    fn owner_hold(&self) -> Option<&OwnerHold> {
        match self {
            Self::Held(hold) | Self::Admitted(hold) => Some(hold),
            Self::Staged => None,
        }
    }
}

impl HeldBatch {
    /// A fresh batch of `counts` and `code_fix` for `endpoint`, under a new
    /// random id, staged.
    pub(super) fn mint(
        endpoint: &str,
        training_permitted: bool,
        counts: Vec<Tier1FailureCount>,
        code_fix: Vec<(CodeFixExport, Vec<EntityId>)>,
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

    /// Whether `vault` may still send it now, read in `txn`: the same
    /// endpoint and training permission, every record still queued and
    /// public, and no owner denial of its digest since it was held.
    fn may_leave_in(&self, vault: &Vault, txn: &heed::RoTxn<'_>, endpoint: &str) -> Result<bool> {
        if self.endpoint != endpoint
            || self.training_permitted != vault.config.failure_signals.permits_training()
            || !code_fix_still_eligible_in(vault, txn, &self.code_fix)?
        {
            return Ok(false);
        }
        let Some(OwnerHold {
            decision,
            approval_digest: Some(digest),
        }) = self.stage.owner_hold()
        else {
            return Ok(true);
        };
        Ok(!owner_denied_in(vault, txn, *decision, digest)?)
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
    /// The batch this pass carries, if any. A row that does not decode, or
    /// whose body no longer hashes to its digest, is retired. A batch whose
    /// send could still leave (no ledger row, or one a definite failure left
    /// retryable) is retired when it may no longer leave; one whose row is
    /// settled or unresolved is carried, so its replay resolves it under its
    /// own ref with no wire before anything is selected anew.
    pub(super) fn carried_failure_signal_batch(
        &self,
        endpoint: &str,
    ) -> std::result::Result<Option<HeldBatch>, OutboundDispatchError> {
        let held = {
            let _custody = self.store.gate_custody_read_guard()?;
            let txn = self.store.env.read_txn().map_err(Error::from)?;
            let Some(bytes) = HELD.get_bytes(&self.store, &txn, &())? else {
                return Ok(None);
            };
            match HELD.decode_value(&bytes) {
                Ok(held) if held.body_intact() => {
                    let attempt = outbound_dispatch_attempt_id(&held.send_ref())?;
                    let may_wire = read_intent_for_attempt_in_txn(self, &txn, attempt, 0)?
                        .is_none_or(|row| {
                            row.state == IntentState::Pending
                                && row.recorded_outcome
                                    == Some(RecordedOutboundOutcome::DefiniteNonDelivery)
                        });
                    (!may_wire || held.may_leave_in(self, &txn, endpoint)?).then_some(held)
                }
                _ => None,
            }
        };
        if held.is_none() {
            self.retire_failure_signal_batch()?;
        }
        Ok(held)
    }

    /// Stages `held` before its send leaves.
    pub(super) fn stage_failure_signal_batch(&self, held: &HeldBatch) -> Result<()> {
        self.with_write_txn_grouped(|txn| HELD.put(&self.store, txn, &(), held))
    }

    /// Keeps `held` at `stage`, unless an erase retired it meanwhile.
    pub(super) fn keep_failure_signal_batch(
        &self,
        held: &HeldBatch,
        stage: HeldStage,
    ) -> Result<()> {
        if held.stage == stage {
            return Ok(());
        }
        self.with_write_txn_grouped(|txn| {
            let Some(mut kept) = HELD.get(&self.store, &*txn, &())? else {
                return Ok(());
            };
            if kept.batch_id != held.batch_id {
                return Ok(());
            }
            kept.stage = stage;
            HELD.put(&self.store, txn, &(), &kept)
        })
    }

    /// Retires the carried batch with no ack: its signals stay queued.
    pub(super) fn retire_failure_signal_batch(&self) -> Result<()> {
        let carried = {
            let txn = self.store.env.read_txn()?;
            HELD.get_bytes(&self.store, &txn, &())?.is_some()
        };
        if !carried {
            return Ok(());
        }
        self.with_write_txn_grouped(|txn| HELD.delete(&self.store, txn, &()).map(drop))
    }

    /// Settles `held` in one writer with its row's removal: its frozen
    /// quantities leave the aggregate, and, once it was `delivered`, its
    /// code-fix records leave the queue. An ambiguous send takes the counts
    /// only, since a record sent again carries its own id and the publisher
    /// keeps one. Counts and records that came since stay.
    pub(super) fn settle_failure_signal_batch(
        &self,
        held: &HeldBatch,
        delivered: bool,
    ) -> Result<()> {
        let ids = held
            .code_fix
            .iter()
            .map(|(id, _)| id.as_str())
            .collect::<Vec<_>>();
        self.with_write_txn_grouped(|txn| {
            subtract_counts_in_txn(self, txn, &held.counts)?;
            if delivered {
                ack_code_fix_records_in_txn(self, txn, &ids)?;
            }
            HELD.delete(&self.store, txn, &())?;
            Ok(())
        })
    }
}

/// The stage a batch the dispatch neither delivered nor left ambiguous
/// keeps, `None` to discard it (CALLS `FIX 6679 held failure-signal batch
/// carries over`). The Gate holding it for the owner (`pending`; a delivery
/// window, budget or suppression hold the Gate allowed is not one) keeps it
/// held, under the decision that first held it. A batch the owner held
/// stays when the Gate admitted it and it failed definitely (its ledger row
/// still Pending: it retries under its own ref on its recorded press), and
/// when the Gate allowed it without admitting it (a delivery window or seat
/// hold: its press is unspent). A Gate Deny, and every other ending of a
/// batch the owner never held, discards it, as a fresh batch always was.
pub(super) fn next_stage(held: &HeldBatch, result: &OutboundDispatchResult) -> Option<HeldStage> {
    let hold = held.stage.owner_hold().cloned();
    if result.gate_outcome == GateOutcome::Pending.as_str() {
        return Some(HeldStage::Held(hold.unwrap_or_else(|| {
            OwnerHold {
                decision: result
                    .gate_decision_id
                    .as_deref()
                    .and_then(|id| id.strip_prefix("gate:"))
                    .and_then(public_id_key),
                approval_digest: result.approval_digest.clone(),
            }
        })));
    }
    let hold = hold.filter(|_| result.gate_outcome != GateOutcome::Deny.as_str())?;
    match result.resolution {
        Some(IntentResolution::Pending { .. }) => Some(HeldStage::Admitted(hold)),
        None => Some(held.stage.clone()),
        Some(_) => None,
    }
}

/// Whether the owner denied `digest` after the decision `after` held it
/// (every decision since, read exhaustively; all of them when the hold named
/// none): a `gate.consent.denied` receipt whose diff handle is that digest.
fn owner_denied_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    after: Option<[u8; 16]>,
    digest: &str,
) -> Result<bool> {
    let denies = |record: &GateDecisionRecord| {
        record.content_kind == CONSENT_CONTENT_KIND
            && record.reason_codes.first().map(String::as_str) == Some(CONSENT_REASON_DENIED)
            && bytes_to_hex_lower(&record.diff_handle) == digest
    };
    let found = match after {
        Some(after) => vault.store.find_gate_decision_after_in_txn(
            txn,
            GateDecisionId::from_bytes(after),
            denies,
        )?,
        None => vault.store.find_gate_decision_id_in_txn(txn, denies)?,
    };
    Ok(found.is_some())
}

/// An erase of `actor` retires the carried batch whole, with no ack (CALLS
/// `FIX 6679 held batch custody table`): its counts and records may come
/// from that actor's failures, and nothing in a frozen body is edited under
/// its old ref. The signals stay queued; the next pass selects afresh. An id
/// whose entity is no actor retires nothing; a row that does not decode goes
/// by its key all the same.
pub(crate) fn erase_held_batch_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if crate::learning_setting::names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    HELD.delete(&vault.store, wtxn, &())?;
    Ok(())
}
