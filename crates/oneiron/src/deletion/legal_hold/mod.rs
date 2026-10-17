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
//! member or agent surface may route to; a host-only log; silence under a
//! secrecy order; "erase confirmed" apart from "erase completed"; a privacy
//! erase that keeps only the held part; and a use limit on what it keeps.

mod types;

use std::collections::{BTreeMap, BTreeSet};

pub use types::*;

use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
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
    /// members and the owner alike, and every other verb keeps working.
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
        if let Some(matter) = &matter_ref {
            check_opaque(matter, "matter reference")?;
        }
        let targets = distinct(targets)?;
        self.with_write_txn_grouped(|txn| {
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
                matter_ref: matter_ref.clone(),
                lifted_at: None,
                owner_told: true,
            };
            hold_store::put_hold_in_txn(&self.store, txn, &hold)?;
            hold_store::log_in_txn(
                &self.store,
                txn,
                &hold,
                LegalHoldEventKind::Placed,
                LegalHoldReason::OwnerPlaced,
                targets.clone(),
                &HoldActor::owner(actor),
                now,
                None,
            )?;
            Ok(hold)
        })
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

    /// The holds the owner may see: every customer hold, and each host order
    /// the owner may be told of, without its order reference or operator.
    /// A host order under a secrecy order is absent (C2).
    pub fn legal_holds(&self, owner: &AuthenticatedOwner) -> Result<Vec<LegalHold>> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let now = self.store.clock.now_recorded_at();
        Ok(hold_store::holds_in_txn(&self.store, &txn)?
            .into_iter()
            .filter(|hold| {
                hold.kind == LegalHoldKind::Customer || (hold.owner_told && !hold.secret_at(now))
            })
            .map(|mut hold| {
                if hold.kind == LegalHoldKind::HostOrder {
                    hold.matter_ref = None;
                    hold.placed_by = None;
                }
                hold
            })
            .collect())
    }

    /// The owner-visible hold log, oldest first: ids, times and reason
    /// codes (C3). Nothing of a host order under a secrecy order (C2).
    pub fn legal_hold_log(&self, owner: &AuthenticatedOwner) -> Result<Vec<LegalHoldEvent>> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        hold_store::owner_events_in_txn(&self.store, &txn)
    }

    /// The owner's one confirm: [`LIFT_AND_ERASE_TITLE`], showing
    /// [`LIFT_AND_ERASE_PROMPT`]. Lifts every customer hold on `records`
    /// (a hold naming more keeps the rest) and erases them through the
    /// owner delete rail; the confirm, the lift and each scope change are
    /// logged first, in one transaction, so the choice is recorded whatever
    /// the erase does. A host order is never lifted here: its records keep
    /// their bytes, the erase waits, and it runs once Oneiron lifts the
    /// order. Where Oneiron hosts the bytes every erase reads
    /// [`ERASE_COMPLETION_PENDING`] until its receipt completes, so a secret
    /// order shows nothing more (C2, C4).
    ///
    /// # Errors
    /// The owner proof no longer holds, or no record is named. A record's
    /// own erase failure is its [`LiftAndEraseStatus::Failed`].
    pub fn confirm_lift_legal_hold_and_erase(
        &self,
        owner: &AuthenticatedOwner,
        records: &[EntityId],
    ) -> Result<LiftAndEraseOutcome> {
        let records: BTreeSet<EntityId> = records.iter().copied().collect();
        if records.is_empty() {
            return Err(Error::InvalidConfig(
                "lift and erase names the records".into(),
            ));
        }
        let (actor, kept, holds) = self.with_write_txn_grouped(|txn| {
            let actor = owner.revalidate_in_txn(self, txn)?;
            let who = HoldActor::owner(actor);
            let now = self.store.clock.now_recorded_at();
            // Each customer hold on these records, with what leaves it.
            let mut lifting: BTreeMap<EntityId, (LegalHold, Vec<LegalHoldTarget>)> =
                BTreeMap::new();
            // Each kept record, and whether its owner may be told why.
            let mut kept: BTreeMap<EntityId, bool> = BTreeMap::new();
            for record in &records {
                let target = LegalHoldTarget::Record(*record);
                for hold in hold_store::holds_on_in_txn(&self.store, txn, &target)? {
                    hold_store::link_erase_in_txn(&self.store, txn, record, &hold)?;
                    if hold.kind == LegalHoldKind::HostOrder {
                        let told = hold.owner_told && !hold.secret_at(now);
                        *kept.entry(*record).or_default() |= told;
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
            for record in kept.keys() {
                hold_store::put_pending_erase_in_txn(
                    &self.store,
                    txn,
                    record,
                    Some(actor.to_hex()),
                    now,
                )?;
            }
            Ok((actor, kept, lifting.into_keys().collect::<Vec<_>>()))
        })?;
        let hosted = self.legal_hold_hosted();
        let memory = self.memory(actor, EdgeActorClass::Human);
        let hard = crate::memory::SafeDeleteReason::UserHardDelete;
        let mut statuses = Vec::with_capacity(records.len());
        let mut failed = false;
        for record in records {
            let status = match kept.get(&record) {
                Some(true) => LiftAndEraseStatus::KeptByLegalOrder,
                Some(false) => LiftAndEraseStatus::CompletionPending,
                None => match memory.safe_delete(&record.to_hex(), hard) {
                    Ok(_) if hosted => LiftAndEraseStatus::CompletionPending,
                    Ok(receipt) => LiftAndEraseStatus::Erased {
                        receipt_ref: receipt.receipt_ref,
                    },
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
            holds,
            records: statuses,
        })
    }

    /// Host-only door (C1): Oneiron holds records on an authority order.
    /// Only where Oneiron hosts the bytes. The order and its reference go to
    /// the host-only log; the owner is told a legal order keeps the data
    /// unless the order forbids it until `secret_until` (C2). No owner,
    /// member or agent surface may route here.
    ///
    /// # Errors
    /// Self-hosted, a reference that is not an opaque id, an order already
    /// ended, or a named claim whose erase has committed.
    pub fn place_host_order_hold(&self, order: HostOrderHold) -> Result<LegalHold> {
        self.require_hosted_bytes()?;
        check_opaque(&order.order_ref, "order reference")?;
        check_opaque(&order.placed_by, "host operator")?;
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
                lifted_at: None,
                owner_told: order.secret_until.is_none_or(|until| now >= until),
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
        self.run_due_legal_hold_erases()?;
        Ok(hold)
    }

    /// Host-only door: moves a host order's stored end, as on a renewal
    /// (§2703(f) 90 more days, an EU preservation order 30 more).
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
        Ok(LegalHoldMaintenance {
            lapsed,
            erased: self.run_due_legal_hold_erases()?,
            refusals: self.flush_legal_hold_refusals()?,
            expired: self.sweep_legal_hold_log()?,
        })
    }

    /// Runs each owner-confirmed erase whose record nothing holds now.
    /// A failed one stays for the next pass.
    fn run_due_legal_hold_erases(&self) -> Result<u64> {
        let due = {
            let txn = self.store.env.read_txn()?;
            hold_store::due_erases_in_txn(&self.store, &txn)?
        };
        let mut erased = 0_u64;
        for record in due {
            match self.delete_entity_with_reason(&record, super::DeleteReason::UserHardDelete) {
                Ok(_) => {
                    self.with_write_txn_grouped(|txn| {
                        hold_store::drop_pending_erase_in_txn(&self.store, txn, &record)
                    })?;
                    erased = erased.saturating_add(1);
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
    /// where Oneiron hosts the bytes (C6). Returns how many were written.
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

    /// The use limit on a record kept after a refused privacy erasure: it
    /// serves only the legal reason that kept it (C6). Enforcing it on
    /// reads is the scope checks' (L02).
    pub fn legal_hold_use_limit(&self, record: &EntityId) -> Result<Option<LegalHoldUseLimit>> {
        let txn = self.store.env.read_txn()?;
        hold_store::use_limit_in_txn(&self.store, &txn, record)
    }
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
