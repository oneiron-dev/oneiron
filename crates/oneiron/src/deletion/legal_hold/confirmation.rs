//! The owner's one "Lift the hold and erase?" confirm, bound to what it
//! showed (OF-470, FIX 1462), and the claim-free partition it may name (FIX
//! 9782).
//!
//! The confirm carries a typed echo of what the owner was shown: the title
//! and prompt, the records, and every standing customer hold on them, whole.
//! Its writer reads the same state again before it links, logs or lifts
//! anything, and acts only on an exact match. Anything else changes nothing
//! and answers with what the confirm shows now, so the owner confirms again
//! in one step. No token, expiry or second press is kept, and no host order
//! is ever part of the echo: one under a secrecy order stays unseen (C2).
//!
//! In a shared vault with two or more Owners an explicit erase waits out the
//! vault's `erase` veto window first (ARCH-0043, FIX 9781): each record
//! starts its own `erase` act, and its erase runs from the legal-hold pass
//! once that act completes and nothing holds the record.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{
    ErasePendingReason, LIFT_AND_ERASE_PROMPT, LIFT_AND_ERASE_TITLE, LegalHold, LegalHoldEventKind,
    LegalHoldKind, LegalHoldReason, LegalHoldTarget, LiftAndEraseOutcome, LiftAndEraseStatus,
    erase_status, kept_status,
};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::deletion::DeleteReason;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::legal_hold::{self as hold_store, HoldActor, PendingErase, PendingEraseKind};

/// One standing customer hold as the confirm showed it, whole: a hold
/// widened since is not narrowed on an old confirm.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct ShownCustomerHold {
    pub hold_id: EntityId,
    /// Everything the hold names, not only the confirm's records.
    pub targets: Vec<LegalHoldTarget>,
    pub placed_by: Option<String>,
    pub placed_at: u64,
    pub matter_ref: Option<String>,
}

impl ShownCustomerHold {
    fn of(hold: &LegalHold) -> Self {
        let mut targets = hold.targets.clone();
        targets.sort_unstable();
        targets.dedup();
        Self {
            hold_id: hold.hold_id,
            targets,
            placed_by: hold.placed_by.clone(),
            placed_at: hold.placed_at,
            matter_ref: hold.matter_ref.clone(),
        }
    }
}

/// What the owner's one confirm showed: its title and prompt, the records
/// it names, whether it names the claim-free gate-decision partition, and
/// each standing customer hold on them. The engine compares it, in one
/// order, with what it reads in the confirm's writer (FIX 1462).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LiftAndEraseShownState {
    /// [`LIFT_AND_ERASE_TITLE`].
    pub title: String,
    /// [`LIFT_AND_ERASE_PROMPT`].
    pub prompt: String,
    pub records: Vec<EntityId>,
    /// The confirm also releases the claim-free partition (FIX 9782).
    #[serde(default)]
    pub claim_free_partition: bool,
    pub holds: Vec<ShownCustomerHold>,
}

impl LiftAndEraseShownState {
    /// What the confirm shows over `records`, and the claim-free partition
    /// with `claim_free_partition`, from hold rows the owner was shown, such
    /// as the hold list's: each standing customer hold naming one of them,
    /// whole. Host orders are left out, so a client builds the same echo
    /// from the list it displayed.
    #[must_use]
    pub fn from_holds(
        records: &[EntityId],
        claim_free_partition: bool,
        holds: &[LegalHold],
    ) -> Self {
        let records: BTreeSet<EntityId> = records.iter().copied().collect();
        let mut shown: Vec<ShownCustomerHold> = holds
            .iter()
            .filter(|hold| hold.kind == LegalHoldKind::Customer && hold.stands())
            .filter(|hold| {
                hold.targets.iter().any(|target| match target.id() {
                    Some(id) => records.contains(&id),
                    None => claim_free_partition,
                })
            })
            .map(ShownCustomerHold::of)
            .collect();
        shown.sort_unstable();
        shown.dedup();
        Self {
            title: LIFT_AND_ERASE_TITLE.to_owned(),
            prompt: LIFT_AND_ERASE_PROMPT.to_owned(),
            records: records.into_iter().collect(),
            claim_free_partition,
            holds: shown,
        }
    }

    /// The same state, every set in the one order the engine compares.
    fn canonical(&self) -> Self {
        let mut records = self.records.clone();
        records.sort_unstable();
        records.dedup();
        let mut holds: Vec<ShownCustomerHold> = self
            .holds
            .iter()
            .map(|hold| {
                let mut hold = hold.clone();
                hold.targets.sort_unstable();
                hold.targets.dedup();
                hold
            })
            .collect();
        holds.sort_unstable();
        holds.dedup();
        Self {
            title: self.title.clone(),
            prompt: self.prompt.clone(),
            records,
            claim_free_partition: self.claim_free_partition,
            holds,
        }
    }
}

/// The confirm's state in `txn`: the standing customer holds on `records`
/// and, with `claim_free_partition`, on the claim-free partition.
fn shown_state_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    records: &BTreeSet<EntityId>,
    claim_free_partition: bool,
) -> Result<LiftAndEraseShownState> {
    let mut holds = Vec::new();
    for record in records {
        let target = LegalHoldTarget::Record(*record);
        holds.extend(hold_store::holds_on_in_txn(&vault.store, txn, &target)?);
    }
    if claim_free_partition {
        let target = LegalHoldTarget::GatePartition(None);
        holds.extend(hold_store::holds_on_in_txn(&vault.store, txn, &target)?);
    }
    let records: Vec<EntityId> = records.iter().copied().collect();
    Ok(LiftAndEraseShownState::from_holds(
        &records,
        claim_free_partition,
        &holds,
    ))
}

/// What the confirm's writer settled.
struct Settled {
    actor: EntityId,
    /// Each record a host order keeps, with the orders the owner may see.
    kept: BTreeMap<EntityId, Vec<LegalHold>>,
    /// The customer holds lifted or narrowed.
    holds: Vec<EntityId>,
    /// The shared vault whose veto window the erase waits out (FIX 9781).
    veto_vault: Option<u64>,
    /// Each record's waiting erase, as stored.
    waiting: BTreeMap<EntityId, PendingErase>,
}

impl Vault {
    /// What the one confirm over `records` (and the claim-free partition,
    /// with `claim_free_partition`) shows now, read in one owner-checked
    /// snapshot (FIX 1462). A local caller shows it and confirms with it; a
    /// remote one builds the same from the hold list it showed
    /// ([`LiftAndEraseShownState::from_holds`]).
    ///
    /// # Errors
    /// The owner proof no longer holds.
    pub fn lift_and_erase_shown_state(
        &self,
        owner: &AuthenticatedOwner,
        records: &[EntityId],
        claim_free_partition: bool,
    ) -> Result<LiftAndEraseShownState> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let records: BTreeSet<EntityId> = records.iter().copied().collect();
        shown_state_in_txn(self, &txn, &records, claim_free_partition)
    }

    /// The owner's one confirm: [`LIFT_AND_ERASE_TITLE`], showing
    /// [`LIFT_AND_ERASE_PROMPT`], bound to `shown`, what it showed (FIX
    /// 1462). Lifts every customer hold on `records` (a hold naming more
    /// keeps the rest), and on the claim-free gate-decision partition with
    /// `claim_free_partition` (FIX 9782), and erases the records through the
    /// owner delete rail; the confirm, the lift and each scope change are
    /// logged first, in one transaction, so the choice is recorded whatever
    /// the erase does. When what the writer reads is not `shown`, nothing is
    /// linked, logged, lifted or erased, and the outcome's `changed` is what
    /// the confirm shows now.
    ///
    /// A host order is never lifted here: its records keep their bytes,
    /// read as retained for law with the order's bound, the erase waits,
    /// and it runs once Oneiron lifts the order. An erase that ran reads
    /// erased once its receipt is complete, and [`super::ERASE_COMPLETION_PENDING`]
    /// with its receipt while what it waits on is owed, wherever the bytes
    /// live; a record a secret order keeps reads that, and nothing more (C2,
    /// C4, WILL-PLAN L01 row 04). In a shared vault with two or more Owners
    /// nothing is erased at once: each record starts its own `erase` act and
    /// reads completion pending on the veto window, its erase run once the
    /// act completes and nothing holds it (FIX 9781).
    ///
    /// # Errors
    /// The owner proof no longer holds, or neither a record nor the
    /// claim-free partition is named. A record's own erase failure is its
    /// [`LiftAndEraseStatus::Failed`].
    pub fn confirm_lift_legal_hold_and_erase(
        &self,
        owner: &AuthenticatedOwner,
        records: &[EntityId],
        claim_free_partition: bool,
        shown: &LiftAndEraseShownState,
    ) -> Result<LiftAndEraseOutcome> {
        let records: BTreeSet<EntityId> = records.iter().copied().collect();
        if records.is_empty() && !claim_free_partition {
            return Err(Error::InvalidConfig(
                "lift and erase names the records or the claim-free partition".into(),
            ));
        }
        let shown = shown.canonical();
        let settled = self.with_write_txn_grouped(|txn| {
            let actor = owner.revalidate_in_txn(self, txn)?;
            let current = shown_state_in_txn(self, txn, &records, claim_free_partition)?;
            if current != shown {
                return Ok(Err(current));
            }
            self.lift_for_erase_in_txn(txn, actor, &records, claim_free_partition)
                .map(Ok)
        })?;
        let settled = match settled {
            Ok(settled) => settled,
            Err(current) => {
                return Ok(LiftAndEraseOutcome {
                    holds: Vec::new(),
                    records: Vec::new(),
                    changed: Some(current),
                });
            }
        };
        // The lifts committed: a delete they deferred asks again (FIX 1488),
        // and an erase they kept from completing completes (FIX 5844).
        self.note_backup_hold_recheck();
        self.finish_redaction_erases_logged();
        let memory = self.memory(settled.actor, EdgeActorClass::Human);
        let hard = crate::memory::SafeDeleteReason::UserHardDelete;
        let now = self.store.clock.now_recorded_at();
        let mut statuses = Vec::with_capacity(records.len());
        let mut failed = false;
        for record in records {
            let kept = settled.kept.get(&record);
            let status = match (settled.veto_vault, kept) {
                (Some(vault_id), _) => {
                    self.wait_out_veto(owner, vault_id, record, &settled.waiting, kept, now)
                }
                (None, Some(seen)) => kept_status(seen, now),
                (None, None) => match memory.owner_confirmed_erase(owner, record, hard) {
                    Ok(receipt) => erase_status(&memory, owner, receipt.receipt_ref),
                    Err(error) => {
                        failed = true;
                        LiftAndEraseStatus::Failed {
                            message: error.message,
                        }
                    }
                },
            };
            statuses.push((record, status));
        }
        if failed {
            self.flush_legal_hold_refusals_after_failure();
        }
        Ok(LiftAndEraseOutcome {
            holds: settled.holds,
            records: statuses,
            changed: None,
        })
    }

    /// The confirm's writer, once what it read matches what the owner was
    /// shown: links each record's coming erase to its holds, logs, lifts or
    /// narrows each customer hold, and records each erase that waits.
    fn lift_for_erase_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        actor: EntityId,
        records: &BTreeSet<EntityId>,
        claim_free_partition: bool,
    ) -> Result<Settled> {
        let who = HoldActor::owner(actor);
        let now = self.store.clock.now_recorded_at();
        // Each customer hold on these targets, with what leaves it.
        let mut lifting: BTreeMap<EntityId, (LegalHold, Vec<LegalHoldTarget>)> = BTreeMap::new();
        // Each kept record, with the host orders on it the owner may see.
        let mut kept: BTreeMap<EntityId, Vec<LegalHold>> = BTreeMap::new();
        for record in records {
            let target = LegalHoldTarget::Record(*record);
            for hold in hold_store::holds_on_in_txn(&self.store, txn, &target)? {
                hold_store::link_erase_in_txn(&self.store, txn, record, &hold)?;
                if hold.kind == LegalHoldKind::HostOrder {
                    hold_store::log_in_txn(
                        &self.store,
                        txn,
                        &hold,
                        LegalHoldEventKind::LiftAndEraseConfirmed,
                        LegalHoldReason::CompletionPending,
                        vec![target],
                        &who,
                        now,
                        None,
                    )?;
                    let seen = kept.entry(*record).or_default();
                    if hold.owner_may_see(now) {
                        seen.push(hold);
                    }
                    continue;
                }
                let leaving: Vec<LegalHoldTarget> = hold
                    .targets
                    .iter()
                    .filter(|named| hold_store::names_id(named, record))
                    .copied()
                    .collect();
                let (_, left) = lifting
                    .entry(hold.hold_id)
                    .or_insert_with(|| (hold, Vec::new()));
                left.extend(leaving);
            }
        }
        // The claim-free partition leaves its customer holds; a host order on
        // it stays (FIX 9782).
        if claim_free_partition {
            let target = LegalHoldTarget::GatePartition(None);
            for hold in hold_store::holds_on_in_txn(&self.store, txn, &target)? {
                if hold.kind == LegalHoldKind::Customer {
                    let (_, left) = lifting
                        .entry(hold.hold_id)
                        .or_insert_with(|| (hold, Vec::new()));
                    left.push(target);
                }
            }
        }
        for (mut hold, leaving) in lifting.values().cloned() {
            hold_store::log_in_txn(
                &self.store,
                txn,
                &hold,
                LegalHoldEventKind::LiftAndEraseConfirmed,
                LegalHoldReason::OwnerConfirmed,
                leaving.clone(),
                &who,
                now,
                None,
            )?;
            hold.targets.retain(|named| !leaving.contains(named));
            // A hold left naming nothing is lifted, keeping its last scope.
            let event = if hold.targets.is_empty() {
                hold.targets.clone_from(&leaving);
                hold.lifted_at = Some(now);
                LegalHoldEventKind::Lifted
            } else {
                LegalHoldEventKind::ScopeChanged
            };
            let reason = if hold.stands() {
                LegalHoldReason::ScopeNarrowedByErase
            } else {
                LegalHoldReason::OwnerConfirmed
            };
            hold_store::put_hold_in_txn(&self.store, txn, &hold)?;
            hold_store::log_in_txn(
                &self.store,
                txn,
                &hold,
                event,
                reason,
                leaving,
                &who,
                now,
                None,
            )?;
        }
        // An erase a host order keeps waits for it; in a shared vault with two
        // or more Owners every erase waits out the veto window (FIX 9781).
        let veto_vault = self.owner_erase_veto_vault_in_txn(txn)?;
        let mut waiting = BTreeMap::new();
        for record in records {
            if veto_vault.is_none() && !kept.contains_key(record) {
                continue;
            }
            let request = PendingErase {
                confirmed_by: Some(actor.to_hex()),
                confirmed_at: now,
                kind: PendingEraseKind::LiftAndErase,
                reason: DeleteReason::UserHardDelete,
                generation: self.store.clock.entity_id()?,
                veto_act: None,
            };
            let stored = hold_store::put_pending_erase_in_txn(&self.store, txn, record, request)?;
            waiting.insert(*record, stored);
        }
        // A birth these holds kept from an erased actor's scrub goes with
        // them (FIX 6280), and so does each Gate decision scrub they kept
        // (FIX 7993, 7994); a row another hold still names keeps its own.
        self.settle_held_scrubs_in_txn(txn)?;
        Ok(Settled {
            actor,
            kept,
            holds: lifting.into_keys().collect(),
            veto_vault,
            waiting,
        })
    }

    /// A record whose erase waits out shared vault `vault_id`'s veto window
    /// (FIX 9781): its own `erase` act, started under `owner`'s proof unless
    /// its waiting erase already names one. It reads as its host order keeps
    /// it, else completion pending on the window. A failed start drops the
    /// waiting erase and is the record's failure.
    fn wait_out_veto(
        &self,
        owner: &AuthenticatedOwner,
        vault_id: u64,
        record: EntityId,
        waiting: &BTreeMap<EntityId, PendingErase>,
        kept: Option<&Vec<LegalHold>>,
        now: u64,
    ) -> LiftAndEraseStatus {
        let Some(pending) = waiting.get(&record) else {
            return LiftAndEraseStatus::Failed {
                message: "no erase of this record waits".into(),
            };
        };
        let started = match pending.veto_act {
            Some(_) => Ok(()),
            None => self
                .start_record_erase_act(owner, vault_id, record)
                .and_then(|act| {
                    self.with_write_txn_grouped(|txn| {
                        hold_store::set_pending_veto_act_in_txn(
                            &self.store,
                            txn,
                            &record,
                            &pending.generation,
                            act.clone(),
                        )
                    })
                })
                .map(drop),
        };
        if let Err(error) = started {
            let generation = pending.generation;
            let dropped = self.with_write_txn_grouped(|txn| {
                hold_store::drop_pending_erase_in_txn(&self.store, txn, &record, &generation)
            });
            if let Err(drop_error) = dropped {
                tracing::warn!(
                    error = %drop_error,
                    "a waiting erase whose act did not start stays"
                );
            }
            return LiftAndEraseStatus::Failed {
                message: error.to_string(),
            };
        }
        match kept {
            Some(seen) => kept_status(seen, now),
            None => LiftAndEraseStatus::CompletionPending {
                receipt_ref: None,
                reason: Some(ErasePendingReason::VetoWindow),
            },
        }
    }

    /// Whether the waiting erase `pending` of `record` may run now, as far as
    /// the shared vault's veto window goes (FIX 9781). An explicit
    /// lift-and-erase in a vault that erases through it runs only once its
    /// own `erase` act completed, and claims that act in this writer, so the
    /// act authorizes one erase. Any other erase, and one whose act another
    /// door already executed, runs as it did.
    pub(super) fn erase_act_cleared(
        &self,
        record: &EntityId,
        pending: &PendingErase,
    ) -> Result<bool> {
        if pending.kind != PendingEraseKind::LiftAndErase {
            return Ok(true);
        }
        self.with_write_txn_grouped(|txn| {
            let Some(act_id) = &pending.veto_act else {
                return Ok(self.owner_erase_veto_vault_in_txn(txn)?.is_none());
            };
            let Some(act) = self.pending_authority_act_in_txn(txn, act_id)? else {
                tracing::warn!(record = %record.to_hex(), "a waiting erase's act is gone");
                return Ok(false);
            };
            if act.execution.is_some() {
                return Ok(true);
            }
            if !self.authority_act_completed_in_txn(txn, &act)? {
                return Ok(false);
            }
            self.claim_completed_authority_act_in_txn(
                txn,
                act_id,
                pending.generation.to_hex(),
                None,
            )?;
            Ok(true)
        })
    }
}
