//! Legal hold doors (OF-470, design B; owner ruling 2026-10-17: "B, and
//! that stuff is for cloud only + we mention in ToS").
//!
//! Every deployment: the owner places a customer hold naming records or
//! gate-decision partitions; every byte-destroying path refuses a held
//! record whoever acts ([`crate::store`]'s `reject_legal_holds_in_txn`); the
//! owner lifts the hold only through the one "Lift the hold and erase?"
//! confirm; every hold event is logged, ids only, for the hold's life plus
//! 24 months.
//!
//! Only where Oneiron hosts the bytes (posture `Hosted` or `Relay`): host
//! orders only Oneiron places and lifts, through host-only doors no owner,
//! member or agent surface may route to; a host-only log the owner reads
//! through one permitted view; silence under a secrecy order; refusals that
//! name the order's law bound and what self-hosting changes; a privacy erase
//! that keeps only the held part; and a use limit on what it keeps, for its
//! holds' purpose only, while any hold keeps it, customer or host order
//! (WILL-PLAN L01 rows 01-03, FIX 8849). Everywhere, "erase confirmed"
//! stands apart from "erase completed" (C4, row 04).

mod confirmation;
mod held_scrubs;
mod pending_delete;
mod types;

use std::collections::BTreeSet;

pub use confirmation::{LiftAndEraseShownState, ShownCustomerHold};
pub(in crate::deletion) use held_scrubs::held_scrubs_owed_in_txn;
pub use types::*;

use crate::consent::AuthenticatedOwner;
use crate::deletion::ConfirmedEraseOutcome;
use crate::entity_id::EntityId;
use crate::error::{Error, LegalHoldState, Result};
use crate::memory::Memory;
use crate::memory::erase_sweep::{RecordEraseSweep, RecordEraseSweepRequest};
use crate::recovery::checkpoint::CUSTODY_RETIREMENT_COMPLETE;
use crate::store::legal_hold::{self as hold_store, HoldActor};
use crate::{HostingPrivacyPosture, Vault};

/// An opaque reference: ids only, never free text (C3).
fn check_opaque(value: &str, what: &str) -> Result<()> {
    let opaque = !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-/".contains(&byte));
    if opaque {
        Ok(())
    } else {
        Err(Error::InvalidConfig(format!(
            "{what} must be an opaque id: 1 to 128 of A-Z a-z 0-9 . _ : - /"
        )))
    }
}

fn distinct(targets: Vec<LegalHoldTarget>) -> Result<Vec<LegalHoldTarget>> {
    let mut seen = BTreeSet::new();
    let targets: Vec<LegalHoldTarget> = targets
        .into_iter()
        .filter(|target| seen.insert(*target))
        .collect();
    if targets.is_empty() {
        return Err(Error::InvalidConfig("a legal hold names records".into()));
    }
    Ok(targets)
}

impl Vault {
    /// Oneiron hosts this vault's bytes: Cloud, or our relay copy of a
    /// self-hosted vault. The host-order additions apply only here.
    pub(crate) fn legal_hold_hosted(&self) -> bool {
        matches!(
            self.privacy_posture(),
            HostingPrivacyPosture::Hosted | HostingPrivacyPosture::Relay
        )
    }

    fn require_hosted_bytes(&self) -> Result<()> {
        if self.legal_hold_hosted() {
            Ok(())
        } else {
            Err(Error::InvalidConfig(
                "host-order holds exist only where Oneiron hosts the bytes".into(),
            ))
        }
    }

    /// A claim whose erase committed takes no hold until its key is gone.
    fn refuse_erased_targets_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        targets: &[LegalHoldTarget],
    ) -> Result<()> {
        for id in targets.iter().filter_map(LegalHoldTarget::id) {
            self.store
                .refuse_hold_on_erased_partition_in_txn(txn, id.as_bytes())?;
        }
        Ok(())
    }

    /// Places the owner's hold on `targets`: a customer hold, logged as
    /// placed. Deletes of what it names then fail for agents, timers,
    /// members and the owner alike, and every other verb keeps working, but
    /// on a record a hosted privacy erasure kept, which serves only the
    /// hold's purpose (C6, FIX 8849).
    ///
    /// # Errors
    /// The owner proof no longer holds, `matter_ref` is not an opaque id, or
    /// a named claim's erase has already committed.
    pub fn place_legal_hold(
        &self,
        owner: &AuthenticatedOwner,
        targets: Vec<LegalHoldTarget>,
        matter_ref: Option<String>,
    ) -> Result<LegalHold> {
        self.with_write_txn_grouped(|txn| {
            self.place_legal_hold_in_txn(txn, owner, targets, matter_ref)
        })
    }

    /// [`Self::place_legal_hold`] inside the caller's writer, so the hold
    /// commits or rolls back with what else that writer records. Fails as
    /// that door does.
    pub(crate) fn place_legal_hold_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        targets: Vec<LegalHoldTarget>,
        matter_ref: Option<String>,
    ) -> Result<LegalHold> {
        if let Some(matter) = &matter_ref {
            check_opaque(matter, "matter reference")?;
        }
        let targets = distinct(targets)?;
        let actor = owner.revalidate_in_txn(self, txn)?;
        self.refuse_erased_targets_in_txn(txn, &targets)?;
        let now = self.store.clock.now_recorded_at();
        let hold = LegalHold {
            hold_id: self.store.clock.entity_id()?,
            kind: LegalHoldKind::Customer,
            targets: targets.clone(),
            placed_by: Some(actor.to_hex()),
            placed_by_kind: LegalHoldActorKind::Owner,
            placed_at: now,
            ends_at: None,
            secret_until: None,
            matter_ref,
            legal_basis_ref: None,
            jurisdiction: None,
            issuing_authority_ref: None,
            lifted_at: None,
            owner_told: true,
            requires_non_use: false,
        };
        hold_store::put_hold_in_txn(&self.store, txn, &hold)?;
        hold_store::log_in_txn(
            &self.store,
            txn,
            &hold,
            LegalHoldEventKind::Placed,
            LegalHoldReason::OwnerPlaced,
            targets,
            &HoldActor::owner(actor),
            now,
            None,
        )?;
        Ok(hold)
    }

    /// Adds `targets` to the owner's standing hold `hold_id`, logged as a
    /// scope change. A hold narrows only through the owner's one confirm.
    ///
    /// # Errors
    /// No standing customer hold `hold_id`, or as [`Self::place_legal_hold`].
    pub fn widen_legal_hold(
        &self,
        owner: &AuthenticatedOwner,
        hold_id: EntityId,
        targets: Vec<LegalHoldTarget>,
    ) -> Result<LegalHold> {
        let targets = distinct(targets)?;
        self.with_write_txn_grouped(|txn| {
            let actor = owner.revalidate_in_txn(self, txn)?;
            let mut hold = hold_store::hold_in_txn(&self.store, txn, &hold_id)?
                .filter(|hold| hold.kind == LegalHoldKind::Customer && hold.stands())
                .ok_or(Error::EntityNotFound)?;
            let added: Vec<LegalHoldTarget> = targets
                .into_iter()
                .filter(|target| !hold.targets.contains(target))
                .collect();
            if added.is_empty() {
                return Ok(hold);
            }
            self.refuse_erased_targets_in_txn(txn, &added)?;
            hold.targets.extend(added.iter().copied());
            hold_store::put_hold_in_txn(&self.store, txn, &hold)?;
            hold_store::log_in_txn(
                &self.store,
                txn,
                &hold,
                LegalHoldEventKind::ScopeChanged,
                LegalHoldReason::ScopeWidened,
                added,
                &HoldActor::owner(actor),
                self.store.clock.now_recorded_at(),
                None,
            )?;
            Ok(hold)
        })
    }

    /// The holds the owner may see, whole, through the one permitted view
    /// ([`LegalHold::owner_may_see`]): every customer hold, and each host
    /// order with its order reference, operator and terms. A host order under
    /// a secrecy order is absent while its silence runs (C2, WILL-PLAN L01
    /// row 02).
    pub fn legal_holds(&self, owner: &AuthenticatedOwner) -> Result<Vec<LegalHold>> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let now = self.store.clock.now_recorded_at();
        Ok(hold_store::holds_in_txn(&self.store, &txn)?
            .into_iter()
            .filter(|hold| hold.owner_may_see(now))
            .collect())
    }

    /// The owner-visible hold log, oldest first: ids, times and reason
    /// codes (C3), each host order's through the one permitted view. Nothing
    /// of a host order while its silence runs (C2).
    pub fn legal_hold_log(&self, owner: &AuthenticatedOwner) -> Result<Vec<LegalHoldEvent>> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let now = self.store.clock.now_recorded_at();
        hold_store::owner_events_in_txn(&self.store, &txn, now)
    }

    /// Host-only door (C1): Oneiron holds records on an authority order.
    /// Only where Oneiron hosts the bytes. The order and its reference go to
    /// the host-only log; the owner is told a legal order keeps the data
    /// unless the order forbids it until `secret_until` (C2). No owner,
    /// member or agent surface may route here.
    ///
    /// A managed vault's host-order writes go through its supervisor, which
    /// holds them while the vault is frozen for a restore and applies them
    /// to the authoritative vault once the restore settles: never refused,
    /// never dropped (FIX 6825).
    ///
    /// # Errors
    /// Self-hosted, a reference or term that is not an opaque id, an order
    /// already ended, or a named claim whose erase has committed.
    pub fn place_host_order_hold(&self, order: HostOrderHold) -> Result<LegalHold> {
        self.require_hosted_bytes()?;
        check_opaque(&order.order_ref, "order reference")?;
        check_opaque(&order.placed_by, "host operator")?;
        let terms = [
            (&order.legal_basis_ref, "legal basis reference"),
            (&order.jurisdiction, "jurisdiction"),
            (&order.issuing_authority_ref, "issuing authority reference"),
        ];
        for (term, what) in terms {
            if let Some(term) = term {
                check_opaque(term, what)?;
            }
        }
        let targets = distinct(order.targets)?;
        self.with_write_txn_grouped(|txn| {
            let now = self.store.clock.now_recorded_at();
            if order.ends_at <= now {
                return Err(Error::InvalidConfig("the order has already ended".into()));
            }
            self.refuse_erased_targets_in_txn(txn, &targets)?;
            let hold = LegalHold {
                hold_id: self.store.clock.entity_id()?,
                kind: LegalHoldKind::HostOrder,
                targets: targets.clone(),
                placed_by: Some(order.placed_by.clone()),
                placed_by_kind: LegalHoldActorKind::Host,
                placed_at: now,
                ends_at: Some(order.ends_at),
                secret_until: order.secret_until,
                matter_ref: Some(order.order_ref.clone()),
                legal_basis_ref: order.legal_basis_ref.clone(),
                jurisdiction: order.jurisdiction.clone(),
                issuing_authority_ref: order.issuing_authority_ref.clone(),
                lifted_at: None,
                owner_told: order.secret_until.is_none_or(|until| now >= until),
                requires_non_use: order.requires_non_use,
            };
            hold_store::put_hold_in_txn(&self.store, txn, &hold)?;
            hold_store::log_in_txn(
                &self.store,
                txn,
                &hold,
                LegalHoldEventKind::Placed,
                LegalHoldReason::LegalOrder,
                targets.clone(),
                &HoldActor::host(&order.placed_by),
                now,
                None,
            )?;
            Ok(hold)
        })
    }

    /// Host-only door: lifts host order `hold_id` on the authority's release
    /// notice, then runs the owner erases it kept waiting.
    ///
    /// A managed vault's host-order writes go through its supervisor, which
    /// holds them while the vault is frozen for a restore and applies them
    /// to the authoritative vault once the restore settles: never refused,
    /// never dropped (FIX 6825).
    ///
    /// # Errors
    /// Self-hosted, an operator ref that is not an opaque id, or no standing
    /// host order `hold_id`.
    pub fn lift_host_order_hold(&self, hold_id: EntityId, lifted_by: &str) -> Result<LegalHold> {
        self.require_hosted_bytes()?;
        check_opaque(lifted_by, "host operator")?;
        let hold = self.with_write_txn_grouped(|txn| {
            let mut hold = standing_host_order_in_txn(self, txn, &hold_id)?;
            let now = self.store.clock.now_recorded_at();
            hold.lifted_at = Some(now);
            hold_store::put_hold_in_txn(&self.store, txn, &hold)?;
            hold_store::log_in_txn(
                &self.store,
                txn,
                &hold,
                LegalHoldEventKind::Lifted,
                LegalHoldReason::AuthorityReleased,
                hold.targets.clone(),
                &HoldActor::host(lifted_by),
                now,
                None,
            )?;
            Ok(hold)
        })?;
        // The release committed: a delete it deferred asks again (FIX 1488).
        self.note_backup_hold_recheck();
        self.run_due_legal_hold_erases()?;
        Ok(hold)
    }

    /// Host-only door: moves a host order's stored end, as on a renewal
    /// (§2703(f) 90 more days, an EU preservation order 30 more).
    ///
    /// A managed vault's host-order writes go through its supervisor, which
    /// holds them while the vault is frozen for a restore and applies them
    /// to the authoritative vault once the restore settles: never refused,
    /// never dropped (FIX 6825).
    ///
    /// # Errors
    /// Self-hosted, an operator ref that is not an opaque id, an end already
    /// past, or no standing host order `hold_id`.
    pub fn set_host_order_hold_end(
        &self,
        hold_id: EntityId,
        ends_at: u64,
        changed_by: &str,
    ) -> Result<LegalHold> {
        self.require_hosted_bytes()?;
        check_opaque(changed_by, "host operator")?;
        self.with_write_txn_grouped(|txn| {
            let mut hold = standing_host_order_in_txn(self, txn, &hold_id)?;
            let now = self.store.clock.now_recorded_at();
            if ends_at <= now {
                return Err(Error::InvalidConfig(
                    "a host order's end lies ahead; lift it instead".into(),
                ));
            }
            hold.ends_at = Some(ends_at);
            hold_store::put_hold_in_txn(&self.store, txn, &hold)?;
            hold_store::log_in_txn(
                &self.store,
                txn,
                &hold,
                LegalHoldEventKind::ScopeChanged,
                LegalHoldReason::EndDateChanged,
                hold.targets.clone(),
                &HoldActor::host(changed_by),
                now,
                None,
            )?;
            Ok(hold)
        })
    }

    /// Host-only door: every host order, standing or released, with its
    /// order reference.
    ///
    /// # Errors
    /// Self-hosted.
    pub fn host_order_holds(&self) -> Result<Vec<LegalHold>> {
        self.require_hosted_bytes()?;
        let txn = self.store.env.read_txn()?;
        Ok(hold_store::holds_in_txn(&self.store, &txn)?
            .into_iter()
            .filter(|hold| hold.kind == LegalHoldKind::HostOrder)
            .collect())
    }

    /// Host-only door: the host-only log, oldest first (C2).
    ///
    /// # Errors
    /// Self-hosted.
    pub fn host_legal_hold_log(&self) -> Result<Vec<LegalHoldEvent>> {
        self.require_hosted_bytes()?;
        let txn = self.store.env.read_txn()?;
        hold_store::host_events_in_txn(&self.store, &txn)
    }

    /// One legal-hold maintenance pass, for the host's housekeeping: lifts
    /// host orders whose stored end passed, tells the owner of orders whose
    /// silence ended, runs owner erases nothing holds any more, writes
    /// queued refusals, and drops log rows 24 months past their hold's
    /// release.
    pub fn maintain_legal_holds(&self) -> Result<LegalHoldMaintenance> {
        let lapsed = self.with_write_txn_grouped(|txn| {
            let now = self.store.clock.now_recorded_at();
            let mut lapsed = 0_u64;
            for mut hold in hold_store::holds_in_txn(&self.store, txn)? {
                if hold.kind != LegalHoldKind::HostOrder || !hold.stands() {
                    continue;
                }
                let (event, reason) = if hold.ends_at.is_some_and(|end| now >= end) {
                    hold.lifted_at = Some(now);
                    lapsed = lapsed.saturating_add(1);
                    (LegalHoldEventKind::Lifted, LegalHoldReason::OrderEnded)
                } else if !hold.owner_told && !hold.secret_at(now) {
                    hold.owner_told = true;
                    (LegalHoldEventKind::Placed, LegalHoldReason::SecrecyEnded)
                } else {
                    continue;
                };
                hold_store::put_hold_in_txn(&self.store, txn, &hold)?;
                hold_store::log_in_txn(
                    &self.store,
                    txn,
                    &hold,
                    event,
                    reason,
                    hold.targets.clone(),
                    &HoldActor::TIMER,
                    now,
                    None,
                )?;
            }
            Ok(lapsed)
        })?;
        // Each pass, once its lapses committed: a delete a lapsed order
        // deferred asks again (FIX 1488).
        self.note_backup_hold_recheck();
        Ok(LegalHoldMaintenance {
            lapsed,
            erased: self.run_due_legal_hold_erases()?,
            refusals: self.flush_legal_hold_refusals()?,
            expired: self.sweep_legal_hold_log()?,
        })
    }

    /// Runs each owner erase that waits whose record nothing holds now, as
    /// its request asked: an explicit lift-and-erase hard, an owner's plain
    /// delete under its own reason (FIX 1465), and in a shared vault with
    /// two or more Owners an explicit one only once its own `erase` act
    /// completed (FIX 9781). A failed one stays for the next pass. One
    /// whose request went or was replaced before its writer ran is
    /// cancelled: nothing erased, counted or dropped (FIX 6337). A released
    /// gate-decision partition runs it too.
    pub(crate) fn run_due_legal_hold_erases(&self) -> Result<u64> {
        // What a released hold kept from an erase's scrubs goes first,
        // whether or not an erase waits (FIX 6280, 6386, 7993, 7994): then
        // an erase it kept from completing completes (FIX 5844).
        let due = self.with_write_txn_grouped(|txn| {
            self.settle_held_scrubs_in_txn(txn)?;
            hold_store::due_erases_in_txn(&self.store, txn)
        })?;
        self.finish_redaction_erases_logged();
        let mut erased = 0_u64;
        for (record, pending) in due {
            match self.erase_act_cleared(&record, &pending) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        "a confirmed erase stays pending on its veto window"
                    );
                    continue;
                }
            }
            match self.due_confirmed_erase(&record, &pending) {
                Ok(ConfirmedEraseOutcome::Completed(_)) => {
                    self.with_write_txn_grouped(|txn| {
                        hold_store::drop_pending_erase_in_txn(
                            &self.store,
                            txn,
                            &record,
                            &pending.generation,
                        )
                    })?;
                    erased = erased.saturating_add(1);
                }
                // A row confirmed since stays for its own pass.
                Ok(ConfirmedEraseOutcome::Cancelled) => {
                    tracing::info!("a confirmed erase was cancelled: none waits any more");
                }
                Err(error) => tracing::warn!(
                    error = %error,
                    "a confirmed erase stays pending for the next legal hold pass"
                ),
            }
        }
        Ok(erased)
    }

    /// Writes the refusals still queued to the hold logs. Each refusing door
    /// logs its own before it returns, so this writes what a failed log write
    /// left. A refused privacy erasure keeps its record under a use limit
    /// where Oneiron hosts the bytes, while any hold keeps it (C6, FIX
    /// 8849). Returns how many were written.
    pub fn flush_legal_hold_refusals(&self) -> Result<u64> {
        self.store.flush_legal_hold_refusals_now()
    }

    /// After a failed delete: its refusal, if a hold refused it, reaches the
    /// log. Never masks the delete's own error.
    pub(crate) fn flush_legal_hold_refusals_after_failure(&self) {
        self.store.flush_legal_hold_refusals_settled();
    }

    /// Drops hold-log rows and released holds 24 calendar months past the
    /// release (C3). Returns the rows removed.
    pub fn sweep_legal_hold_log(&self) -> Result<u64> {
        self.with_write_txn_grouped(|txn| {
            hold_store::expire_in_txn(&self.store, txn, self.store.clock.now_recorded_at())
        })
    }

    /// The use limit on a record kept after a refused privacy erasure, while
    /// any standing hold, customer or host order, still names it: it serves
    /// only the legal reason that kept it, for that whole retention (C6, FIX
    /// 8849). Enforcing it on reads is the scope checks' (L02).
    pub fn legal_hold_use_limit(&self, record: &EntityId) -> Result<Option<LegalHoldUseLimit>> {
        let txn = self.store.env.read_txn()?;
        hold_store::use_limit_in_txn(&self.store, &txn, record)
    }
}

/// What a record a host order keeps reads as after the owner's confirm:
/// retained for law, naming the bound of an order the owner may see; else
/// completion pending and nothing more, since only a secret order keeps it
/// (C2, WILL-PLAN L01 rows 01 and 04).
fn kept_status(seen: &[LegalHold], now: u64) -> LiftAndEraseStatus {
    match hold_store::law_notice(seen, now, LegalHoldState::RetainedForLaw) {
        Some(notice) => LiftAndEraseStatus::RetainedForLaw(notice),
        None => LiftAndEraseStatus::CompletionPending {
            receipt_ref: None,
            reason: None,
        },
    }
}

/// What an owner erase that ran reads as (C4, WILL-PLAN L01 row 04), one
/// rule wherever the bytes live: erased once its receipt's signed final row
/// is appended (its hard purge, its historical sweep, every custody
/// retirement it bound and every scrub a hold kept finished, FIX 5844),
/// else completion pending with the receipt and what it still waits on: its
/// queued sweep, or its custody. A scrub a hold keeps owed names no reason.
/// No receipt: nothing was there to erase.
fn erase_status(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    receipt_ref: Option<String>,
) -> LiftAndEraseStatus {
    let Some(receipt_ref) = receipt_ref else {
        return LiftAndEraseStatus::Erased { receipt_ref: None };
    };
    let request = RecordEraseSweepRequest {
        receipt_ref: receipt_ref.clone(),
    };
    let reason = match memory.record_erase_sweep_as(owner, request) {
        Ok(Some(sweep)) if sweep.erase_complete_at.is_some() => {
            return LiftAndEraseStatus::Erased {
                receipt_ref: Some(receipt_ref),
            };
        }
        Ok(Some(sweep)) if sweep.sweep_queued_at.is_some() && sweep.sweep_complete_at.is_none() => {
            Some(ErasePendingReason::HistoricalSweep)
        }
        Ok(Some(sweep)) if custody_pending(&sweep) => Some(ErasePendingReason::CustodyRetirement),
        // Only a scrub a hold keeps owed is left (FIX 6386, 7993, 7994), or
        // the receipt did not read, which proves nothing complete.
        _ => None,
    };
    LiftAndEraseStatus::CompletionPending {
        receipt_ref: Some(receipt_ref),
        reason,
    }
}

/// Whether a custody retirement the erase `sweep` reads bound is still owed.
fn custody_pending(sweep: &RecordEraseSweep) -> bool {
    sweep
        .custody
        .as_ref()
        .is_some_and(|custody| custody.state != CUSTODY_RETIREMENT_COMPLETE)
}

fn standing_host_order_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    hold_id: &EntityId,
) -> Result<LegalHold> {
    hold_store::hold_in_txn(&vault.store, txn, hold_id)?
        .filter(|hold| hold.kind == LegalHoldKind::HostOrder && hold.stands())
        .ok_or(Error::EntityNotFound)
}
