//! The owner's answer to a filed courtesy ask (OF-273, BIZ-LEGAL-0004 B2).
//!
//! One writer re-proves the owner, reads the ask and records the answer
//! (FIX 9784). A legal hold choice places its customer hold there, on this
//! pact's recipient copies the ask covers only (FIX 2927), and links it to
//! the answer and the ask (FIX 2924). A delete choice names each record once
//! (FIX 2925), is refused there before anything is deleted when a legal hold
//! keeps any of its records, and saves its operation with the answer (FIX
//! 2926). Its deletes then run one by one through the owner's own delete
//! rail, outside that writer, each one's observed state saved as it goes.

use std::collections::BTreeSet;

use super::types::{CooperativeDeleteOperation, CooperativeDeleteRecordState};
use super::{
    CooperativeDeletionAnswer, CooperativeDeletionDisposition, CooperativeDeletionDispositionKind,
    INCOMING, IncomingCooperativeDeletion, MAX_REASON_CODE_LEN, hex, invalid,
};
use crate::consent::AuthenticatedOwner;
use crate::deletion::{LegalHold, LegalHoldKind, LegalHoldTarget};
use crate::edge::EdgeActorClass;
use crate::memory::SafeDeleteReason;
use crate::store::legal_hold::{self as hold_store, HoldActor};
use crate::{EntityId, Error, Result, Vault};

/// A filed ask's key: its pact, then its nonce.
type AskKey = ([u8; 32], [u8; 16]);

impl Vault {
    /// Records the owner's choice on a filed ask, in one writer that
    /// re-proves the owner (FIX 9784). A legal hold choice places a customer
    /// hold on the records the owner named that are this pact's copies the
    /// ask covers, in that writer, so a refused hold leaves the old answer in
    /// place; a named record the ask does not cover is left out and recorded
    /// with the answer, and the rest of the answer goes on (FIX 2927). The
    /// hold is linked to the answer and the ask, and an earlier choice's hold
    /// stays linked and standing (FIX 2924). A delete choice names each
    /// record once, in the order first named; an empty one deletes nothing
    /// and is recorded (FIX 2925). A legal hold on any of its records, on a
    /// pad's world or on a redirect shell its erase takes refuses the whole
    /// choice in that writer, before anything is deleted, naming the held
    /// records; otherwise the choice and its operation are saved before the
    /// first delete runs (FIX 2926). The same delete choice again resumes the
    /// records still pending. Every choice but delete is recorded with its
    /// reason code and review date, and no choice but these two touches the
    /// data.
    pub fn answer_cooperative_deletion_as(
        &self,
        owner: &AuthenticatedOwner,
        pact_id: &[u8; 32],
        nonce: &[u8; 16],
        answer: &CooperativeDeletionAnswer,
        now: u64,
    ) -> Result<IncomingCooperativeDeletion> {
        check_answer(answer, now)?;
        let key = (*pact_id, *nonce);
        let delete = (answer.kind == CooperativeDeletionDispositionKind::Delete)
            .then(|| first_occurrences(&answer.delete));
        let operation_id = self.store.clock.entity_id()?;
        let written = self.with_write_txn_grouped(|txn| {
            let actor = owner.revalidate_in_txn(self, txn)?;
            let mut filed = INCOMING
                .get(&self.store, txn, &key)?
                .ok_or_else(|| invalid("no such ask"))?;
            let mut hold_ids = Vec::new();
            let mut excluded = Vec::new();
            if answer.kind == CooperativeDeletionDispositionKind::LegalHold {
                let (hold, left_out) =
                    hold_for_ask(self, txn, owner, pact_id, nonce, &filed, &answer.hold)?;
                hold_ids.extend(hold.map(|hold| hold.hold_id));
                excluded = left_out.iter().map(EntityId::to_hex).collect();
            }
            let delete_operation = match &delete {
                Some(records) => {
                    preflight_delete_in_txn(self, txn, actor, records)?;
                    let saved = filed
                        .disposition
                        .as_ref()
                        .and_then(|answer| answer.delete_operation.clone());
                    Some(match saved {
                        Some(operation) if operation.deletes(records) => operation,
                        _ => CooperativeDeleteOperation::new(operation_id, records),
                    })
                }
                None => None,
            };
            let deleted = delete_operation
                .as_ref()
                .map_or_else(Vec::new, CooperativeDeleteOperation::removed_hex);
            for id in &hold_ids {
                if !filed.courtesy_hold_ids.contains(id) {
                    filed.courtesy_hold_ids.push(*id);
                }
            }
            // A new choice replaces the old one but lifts no hold an earlier
            // legal hold answer placed. The owner lifts that only through
            // `confirm_lift_legal_hold_and_erase`.
            filed.disposition = Some(CooperativeDeletionDisposition {
                kind: answer.kind,
                reason_code: answer.reason_code.clone(),
                review_at: answer.review_at,
                deleted,
                recorded_at: now,
                hold_ids,
                excluded,
                delete_operation,
            });
            INCOMING.put(&self.store, txn, &key, &filed)?;
            Ok(filed)
        });
        let filed = match written {
            Ok(filed) => filed,
            Err(error) => {
                // A hold's refusal reaches its log once the writer has ended.
                self.flush_legal_hold_refusals_after_failure();
                return Err(error);
            }
        };
        match filed
            .disposition
            .as_ref()
            .and_then(|answer| answer.delete_operation.as_ref())
        {
            Some(operation) => self.run_courtesy_delete(owner, &key, operation.operation_id),
            None => Ok(filed),
        }
    }

    /// Runs a delete choice's saved operation, outside the answer's writer
    /// (FIX 2926): each record still pending goes through the owner's own
    /// delete rail, `owner`'s proof re-proved in its writes (FIX 9784), and
    /// its observed state is saved to the operation while it is still the
    /// answer's. One a run a crash cut short already removed reads removed
    /// by its hard-delete marker. A failed delete leaves its record pending
    /// and the rest go on, so the answer returned says what is removed and
    /// what is not; nothing removed is put back. A newer choice stops the run
    /// before its next record.
    fn run_courtesy_delete(
        &self,
        owner: &AuthenticatedOwner,
        key: &AskKey,
        operation_id: EntityId,
    ) -> Result<IncomingCooperativeDeletion> {
        let (actor, pending) = {
            let txn = self.store.env.read_txn()?;
            let actor = owner.revalidate_in_txn(self, &txn)?;
            let pending = running_operation_in(self, &txn, key, operation_id)?
                .map_or_else(Vec::new, |operation| operation.pending());
            (actor, pending)
        };
        let memory = self.memory(actor, EdgeActorClass::Human);
        let mut failed = false;
        for record in pending {
            let removed = {
                let txn = self.store.env.read_txn()?;
                if running_operation_in(self, &txn, key, operation_id)?.is_none() {
                    break;
                }
                self.local_hard_delete_marker_exists_in_txn(&txn, &record)?
            };
            let state = if removed {
                CooperativeDeleteRecordState::Removed
            } else {
                let hard = SafeDeleteReason::UserHardDelete;
                match memory.safe_delete_as_owner(owner, &record.to_hex(), hard) {
                    Ok(receipt) if receipt.existed => CooperativeDeleteRecordState::Removed,
                    Ok(_) => CooperativeDeleteRecordState::Missing,
                    Err(error) => {
                        failed = true;
                        tracing::warn!(
                            record = %record.to_hex(),
                            error = %error.message,
                            "a courtesy delete's record stays pending"
                        );
                        continue;
                    }
                }
            };
            self.settle_courtesy_record(key, operation_id, record, state)?;
        }
        if failed {
            self.flush_legal_hold_refusals_after_failure();
        }
        let txn = self.store.env.read_txn()?;
        INCOMING
            .get(&self.store, &txn, key)?
            .ok_or_else(|| invalid("no such ask"))
    }

    /// Saves what became of `record` to operation `operation_id`, while it
    /// is still the answer's.
    fn settle_courtesy_record(
        &self,
        key: &AskKey,
        operation_id: EntityId,
        record: EntityId,
        state: CooperativeDeleteRecordState,
    ) -> Result<()> {
        self.with_write_txn_grouped(|txn| {
            let Some(mut filed) = INCOMING.get(&self.store, txn, key)? else {
                return Ok(());
            };
            let Some(answer) = filed.disposition.as_mut() else {
                return Ok(());
            };
            let Some(operation) = answer
                .delete_operation
                .as_mut()
                .filter(|operation| operation.operation_id == operation_id)
            else {
                return Ok(());
            };
            if !operation.settle(record, state) {
                return Ok(());
            }
            let removed = operation.removed_hex();
            answer.deleted = removed;
            INCOMING.put(&self.store, txn, key, &filed)
        })
    }
}

/// The delete operation `operation_id` while it is still the answer's.
fn running_operation_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &AskKey,
    operation_id: EntityId,
) -> Result<Option<CooperativeDeleteOperation>> {
    Ok(INCOMING
        .get(&vault.store, txn, key)?
        .and_then(|filed| filed.disposition)
        .and_then(|answer| answer.delete_operation)
        .filter(|operation| operation.operation_id == operation_id))
}

/// `records` each once, in the order first named (FIX 2925).
fn first_occurrences(records: &[EntityId]) -> Vec<EntityId> {
    let mut seen = BTreeSet::new();
    records
        .iter()
        .copied()
        .filter(|record| seen.insert(*record))
        .collect()
}

/// The answer's own shape: a delete choice carries no reason code or review
/// date; every other choice has a short reason code and a future review
/// date and deletes nothing; a legal hold choice names the records it
/// holds, each once, and no other choice names any.
fn check_answer(answer: &CooperativeDeletionAnswer, now: u64) -> Result<()> {
    if answer.kind == CooperativeDeletionDispositionKind::Delete {
        if answer.reason_code.is_some() || answer.review_at.is_some() {
            return Err(invalid(
                "a delete choice carries no reason code or review date",
            ));
        }
    } else {
        let code = answer
            .reason_code
            .as_deref()
            .ok_or_else(|| invalid("this choice needs a reason code"))?;
        if code.is_empty()
            || code.len() > MAX_REASON_CODE_LEN
            || !code
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(invalid("a reason code is a short snake_case token"));
        }
        if answer.review_at.is_none_or(|at| at <= now) {
            return Err(invalid("this choice needs a future review date"));
        }
        if !answer.delete.is_empty() {
            return Err(invalid("only a delete choice deletes records"));
        }
    }
    check_hold_records(answer)
}

/// A legal hold choice names the records it holds, each once; every other
/// choice names none.
fn check_hold_records(answer: &CooperativeDeletionAnswer) -> Result<()> {
    if answer.kind != CooperativeDeletionDispositionKind::LegalHold {
        if !answer.hold.is_empty() {
            return Err(invalid("only a legal hold choice holds records"));
        }
        return Ok(());
    }
    if answer.hold.is_empty() {
        return Err(invalid("a legal hold choice names the records it holds"));
    }
    let mut seen = BTreeSet::new();
    if !answer.hold.iter().all(|id| seen.insert(*id)) {
        return Err(invalid("a legal hold choice names each record once"));
    }
    Ok(())
}

/// Every record of a delete choice, in the answer's writer, before any is
/// deleted (FIX 2926): a legal hold on it, on its world when it is a pad, or
/// on a redirect shell its hard erase takes with it refuses the whole
/// choice. The refusal is the hold's own, naming the held records; each is
/// logged once the writer ends. Each delete's own writers check again.
fn preflight_delete_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
    records: &[EntityId],
) -> Result<()> {
    let who = HoldActor::owner(actor);
    let mut held = Vec::new();
    let mut refusal = None;
    for id in records {
        let checked = vault
            .store
            .reject_legal_holds_in_txn(txn, &[*id], &who)
            .and_then(|()| {
                crate::world_keys::reject_held_pad_world_in_txn(&vault.store, txn, &[*id])
            })
            .and_then(|()| vault.reject_held_redirect_shells_in_txn(txn, id));
        if let Err(error) = checked {
            held.push(id.to_hex());
            refusal.get_or_insert(error);
        }
    }
    match refusal {
        None => Ok(()),
        Some(Error::InvalidConfig(message)) => Err(Error::InvalidConfig(format!(
            "{message}; held: {}",
            held.join(", ")
        ))),
        Some(error) => Err(error),
    }
}

/// The matter reference of the hold an ask's legal hold answer places:
/// `courtesy:`, the pact's 64 hex, `:`, the nonce's 32 hex. Its 106
/// characters fit the 128 an opaque reference allows.
fn courtesy_matter_ref(pact_id: &[u8; 32], nonce: &[u8; 16]) -> String {
    format!("courtesy:{}:{}", hex(pact_id), hex(nonce))
}

/// Holds `records` for one filed ask, in the answer's writer. Each must be a
/// record this vault stores. Only this pact's recipient copies the ask
/// covers are held (FIX 2927); the rest are left out and returned, for the
/// answer to record. A standing customer hold of this ask that already names
/// every one held is kept and nothing new is placed, so a retried answer
/// holds once. Other holds on the same records stand beside it. Returns the
/// hold, none when nothing is left to hold, and what was left out.
fn hold_for_ask(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    owner: &AuthenticatedOwner,
    pact_id: &[u8; 32],
    nonce: &[u8; 16],
    filed: &IncomingCooperativeDeletion,
    records: &[EntityId],
) -> Result<(Option<LegalHold>, Vec<EntityId>)> {
    for id in records {
        if !crate::ports::EntityStoreRead::port_entity_present(&vault.store, txn, id)? {
            return Err(invalid("a held record must exist in this vault"));
        }
    }
    // A named world that does not parse covers nothing (FIX 321).
    let worlds: Option<Vec<EntityId>> = filed
        .worlds
        .iter()
        .map(|world| EntityId::from_hex(world).ok())
        .collect();
    let (covered, excluded) = match worlds {
        Some(worlds) => crate::federation::courtesy_scope::split_recipient_copies_in_txn(
            vault,
            txn,
            pact_id,
            &worlds,
            filed.epoch_cutoff,
            records,
        )?,
        None => (Vec::new(), records.to_vec()),
    };
    if covered.is_empty() {
        return Ok((None, excluded));
    }
    let matter_ref = courtesy_matter_ref(pact_id, nonce);
    let targets: Vec<LegalHoldTarget> = covered
        .iter()
        .copied()
        .map(LegalHoldTarget::Record)
        .collect();
    let held = hold_store::holds_in_txn(&vault.store, txn)?
        .into_iter()
        .find(|hold| {
            hold.kind == LegalHoldKind::Customer
                && hold.stands()
                && hold.matter_ref.as_deref() == Some(matter_ref.as_str())
                && targets.iter().all(|target| hold.targets.contains(target))
        });
    let hold = match held {
        Some(hold) => hold,
        None => vault.place_legal_hold_in_txn(txn, owner, targets, Some(matter_ref))?,
    };
    Ok((Some(hold), excluded))
}
