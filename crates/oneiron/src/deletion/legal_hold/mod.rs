//! Legal hold doors (OF-470, design B; owner ruling 2026-10-17: "B, and
//! that stuff is for cloud only + we mention in ToS").
//!
//! Every deployment: the owner places a customer hold naming records or
//! gate-decision partitions, with a sealed copy of exactly its scope written
//! to the install's hold store outside the vault. A hold never refuses an
//! erase, a delete or a backup expiry (LEGAL-HOLD-USE = B, ARCH-0038
//! #legal-hold-clone-ruling): deletes and erases work fully, including the
//! ordinary backup and key-retirement paths, and the sealed copy outlives
//! them. GDPR Art. 17 does not erase the legal copy while its lawful hold
//! runs; it still erases the user's vault fully. Every hold event is logged,
//! ids only, for the hold's life plus 24 months. The owner lifts a hold
//! through `vault.legal_holds.lift`, which destroys its sealed copy, and
//! produces a standing hold through `vault.legal_holds.produce`, which
//! re-seals the copy to a recipient public key the owner names.
//!
//! Only where Oneiron hosts the bytes (posture `Hosted` or `Relay`): host
//! orders only Oneiron places and lifts, through host-only doors no owner,
//! member or agent surface may route to; a host-only log the owner reads
//! through one permitted view; silence under a secrecy order. A host order
//! keeps nothing in the vault: what it covers is preserved as its clone in
//! the host's separate legal-hold store (LEGAL-HOLD-USE = B as a clone, owner
//! 2026-11-05). Everywhere, "erase confirmed" stands apart from "erase
//! completed" (C4, row 04).

pub(super) mod clone;
mod held_scrubs;
pub(crate) mod prospective;
mod types;

use std::collections::BTreeSet;
use std::fs;

use oneiron_crypto::HybridPublicKey;

pub(in crate::deletion) use held_scrubs::held_scrubs_owed_in_txn;
pub use types::*;

use crate::consent::AuthenticatedOwner;
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
    /// placed, with a sealed copy of exactly its scope written to the
    /// install's hold store outside the vault. A hold never refuses an erase,
    /// a delete or a backup expiry (LEGAL-HOLD-USE = B, ARCH-0038
    /// #legal-hold-clone-ruling), and the sealed copy outlives them. With
    /// `future_messages`, each matching new MESSAGE joins the hold's copy
    /// until its end (Ruling L10-21-OWNER-FUTURE-MESSAGES = A, ARCH-0038
    /// :320-321); without it, nothing new joins.
    ///
    /// # Errors
    /// The owner proof no longer holds, `matter_ref` is not an opaque id,
    /// `future_messages.until` lies not ahead, a named claim's erase has
    /// already committed, or no legal hold store is set: the sealed copy
    /// has nowhere to go.
    pub fn place_legal_hold(
        &self,
        owner: &AuthenticatedOwner,
        targets: Vec<LegalHoldTarget>,
        matter_ref: Option<String>,
        future_messages: Option<LegalHoldFutureMessages>,
    ) -> Result<LegalHold> {
        // Fresh before the writer, so a failed write still names its hold
        // directory for cleanup: the clock hands no id twice, even across
        // an abort.
        let hold_id = self.store.clock.entity_id()?;
        let outcome = self.with_write_txn_grouped(|txn| {
            self.place_legal_hold_in_txn(txn, owner, targets, matter_ref, hold_id, future_messages)
        });
        if outcome.is_err() {
            self.remove_uncommitted_hold_copy(&hold_id);
        }
        outcome
    }

    /// [`Self::place_legal_hold`] inside the caller's writer, so the hold
    /// commits or rolls back with what else that writer records, under a
    /// hold id the caller minted before that writer. The sealed copy is
    /// written inside the writer, before the hold row, and the `Placed`
    /// event carries the first capture's fingerprint. Its files outlive a
    /// rollback, so a caller whose writer fails afterwards calls
    /// [`Self::remove_uncommitted_hold_copy`] with the same id. Fails as
    /// [`Self::place_legal_hold`] does.
    pub(crate) fn place_legal_hold_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        targets: Vec<LegalHoldTarget>,
        matter_ref: Option<String>,
        hold_id: EntityId,
        future_messages: Option<LegalHoldFutureMessages>,
    ) -> Result<LegalHold> {
        if let Some(matter) = &matter_ref {
            check_opaque(matter, "matter reference")?;
        }
        let targets = distinct(targets)?;
        let actor = owner.revalidate_in_txn(self, txn)?;
        self.refuse_erased_targets_in_txn(txn, &targets)?;
        let now = self.store.clock.now_recorded_at();
        if let Some(future) = &future_messages
            && future.until <= now
        {
            return Err(Error::InvalidConfig(
                "a hold's future-messages end must lie ahead".into(),
            ));
        }
        let placed = (|| -> Result<LegalHold> {
            let captures =
                clone::legal_hold_store::write_hold_clone_in_txn(self, txn, hold_id, &targets)?;
            if let Some(future) = future_messages {
                let selector = match future.selector {
                    MessageSelector::Vault => {
                        oneiron_vault_contract::host_legal::MessageSelector::Vault
                    }
                };
                let public = clone::legal_hold_store::hold_public_key(self, &hold_id)?;
                let (request, _) = clone::legal_hold_store::prospective_capture_request_for(
                    self,
                    &hold_id,
                    &public,
                    selector,
                    future.until,
                )?;
                let request_digest = request.digest()?;
                let dir = clone::legal_hold_store::configured(self)?
                    .hold_dir(self, &hold_id)
                    .to_string_lossy()
                    .into_owned();
                prospective::stand_in_txn(&self.store, txn, &request, request_digest, Some(dir))?;
            }
            let hold = LegalHold {
                hold_id,
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
                clone_captures: captures,
                future_messages,
            };
            let first = hold
                .clone_captures
                .first()
                .ok_or(Error::InvariantViolation(
                    "a legal hold wrote no sealed capture",
                ))?;
            hold_store::put_hold_in_txn(&self.store, txn, &hold)?;
            let row = LegalHoldEvent {
                clone_fingerprint: Some(first.fingerprint),
                ..hold_store::events::event_row(
                    &hold,
                    LegalHoldEventKind::Placed,
                    LegalHoldReason::OwnerPlaced,
                    targets,
                    &HoldActor::owner(actor),
                    now,
                    None,
                )
            };
            hold_store::events::append_event_in_txn(&self.store, txn, &hold, &row)?;
            Ok(hold)
        })();
        if placed.is_err() {
            self.remove_uncommitted_hold_copy(&hold_id);
        }
        placed
    }

    /// Removes the sealed files of hold `hold_id`, whose writer failed so
    /// no hold row names them, ignoring every failure (best effort).
    pub(crate) fn remove_uncommitted_hold_copy(&self, hold_id: &EntityId) {
        clone::legal_hold_store::remove_hold_dir_best_effort(self, hold_id);
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
        let outcome = self.with_write_txn_grouped(|txn| {
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
            let captures =
                clone::legal_hold_store::write_hold_clone_in_txn(self, txn, hold_id, &added)?;
            let widened = (|| -> Result<LegalHold> {
                let fingerprint = captures.first().map(|capture| capture.fingerprint).ok_or(
                    Error::InvariantViolation("a legal hold widening wrote no sealed capture"),
                )?;
                hold.clone_captures.extend(captures.iter().copied());
                hold.targets.extend(added.iter().copied());
                hold_store::put_hold_in_txn(&self.store, txn, &hold)?;
                let row = LegalHoldEvent {
                    clone_fingerprint: Some(fingerprint),
                    ..hold_store::events::event_row(
                        &hold,
                        LegalHoldEventKind::ScopeChanged,
                        LegalHoldReason::ScopeWidened,
                        added,
                        &HoldActor::owner(actor),
                        self.store.clock.now_recorded_at(),
                        None,
                    )
                };
                hold_store::events::append_event_in_txn(&self.store, txn, &hold, &row)?;
                Ok(hold)
            })();
            if widened.is_err() {
                clone::legal_hold_store::remove_captures_best_effort(self, &hold_id, &captures);
            }
            widened
        });
        if outcome.is_err() {
            // A commit that failed after its files were written leaves them
            // unreferenced; they go too.
            clone::legal_hold_store::remove_unreferenced_captures_best_effort(self, &hold_id);
        }
        outcome
    }

    /// Lifts the owner's customer hold `hold_id` and destroys its sealed
    /// copy (LEGAL-HOLD-USE = B, ARCH-0038 #legal-hold-clone-ruling: the
    /// copy is destroyed when the hold ends). Nothing in the vault is erased
    /// by it. A host order is lifted only by the host
    /// ([`Self::lift_host_order_hold`]).
    ///
    /// The lift commits first, then the copy goes: a crash between the two
    /// never leaves a standing hold without its copy; it leaves a lifted
    /// hold's files, and the repeat lift removes them. `CloneDestroyed` is
    /// logged once, after the files are gone, by the first lift that finds
    /// it unlogged, so a crash before that log is logged by the repeat. A
    /// hold whose row has no captures (written before the sealed copy) logs
    /// `Lifted` only. A repeat lift answers the first: the same `lifted_at`,
    /// no second `Lifted`.
    ///
    /// # Errors
    /// The owner proof no longer holds, no customer hold `hold_id`, or the
    /// store is unset or the copy's files cannot be removed: the hold then
    /// reads lifted, and a repeat lift finishes the removal.
    pub fn lift_legal_hold(
        &self,
        owner: &AuthenticatedOwner,
        hold_id: EntityId,
    ) -> Result<LegalHold> {
        let lifted = self.with_write_txn_grouped(|txn| {
            let actor = owner.revalidate_in_txn(self, txn)?;
            let Some(mut hold) = hold_store::hold_in_txn(&self.store, txn, &hold_id)?
                .filter(|hold| hold.kind == LegalHoldKind::Customer)
            else {
                return Err(Error::EntityNotFound);
            };
            if !hold.stands() {
                return Ok(hold);
            }
            // No message is sealed for a lifted hold (Ruling
            // L10-21-OWNER-FUTURE-MESSAGES = A): its standing ends with its
            // outbox, and never stands again. A hold without future
            // messages has none.
            if hold.future_messages.is_some() {
                prospective::end_in_txn(&self.store, txn, (*hold_id.as_bytes(), 0), true)?;
            }
            let now = self.store.clock.now_recorded_at();
            hold.lifted_at = Some(now);
            hold_store::put_hold_in_txn(&self.store, txn, &hold)?;
            let targets = hold.targets.clone();
            hold_store::log_in_txn(
                &self.store,
                txn,
                &hold,
                LegalHoldEventKind::Lifted,
                LegalHoldReason::OwnerLifted,
                targets,
                &HoldActor::owner(actor),
                now,
                None,
            )?;
            Ok(hold)
        })?;
        if !lifted.clone_captures.is_empty() {
            clone::legal_hold_store::destroy_hold_copy(self, &hold_id)?;
            self.with_write_txn_grouped(|txn| {
                let actor = owner.revalidate_in_txn(self, txn)?;
                let Some(hold) = hold_store::hold_in_txn(&self.store, txn, &hold_id)?
                    .filter(|hold| hold.kind == LegalHoldKind::Customer)
                else {
                    return Err(Error::EntityNotFound);
                };
                if hold_store::events::logged_in_txn(
                    &self.store,
                    txn,
                    &hold,
                    LegalHoldEventKind::CloneDestroyed,
                )? {
                    return Ok(());
                }
                let targets = hold.targets.clone();
                hold_store::log_in_txn(
                    &self.store,
                    txn,
                    &hold,
                    LegalHoldEventKind::CloneDestroyed,
                    LegalHoldReason::OwnerLifted,
                    targets,
                    &HoldActor::owner(actor),
                    self.store.clock.now_recorded_at(),
                    None,
                )?;
                Ok(())
            })?;
        }
        let txn = self.store.env.read_txn()?;
        hold_store::hold_in_txn(&self.store, &txn, &hold_id)?
            .filter(|hold| hold.kind == LegalHoldKind::Customer)
            .ok_or(Error::EntityNotFound)
    }

    /// Produces the standing customer hold `hold_id` to the recipient
    /// `recipient` names (PRODUCE = A): the package carries the hold's
    /// capture files byte for byte, plus the hold's 32-byte seed sealed to
    /// the recipient's public key, and the access is logged. Plaintext never
    /// leaves the engine, and nothing is re-encrypted.
    ///
    /// The package is returned only after its `CloneProduced` event commits:
    /// every access is logged.
    ///
    /// # Errors
    /// The owner proof no longer holds, no standing customer hold `hold_id`,
    /// the hold has no sealed copy, the store is unset, a capture file is
    /// missing or altered, or the hold key does not open.
    pub fn produce_legal_hold(
        &self,
        owner: &AuthenticatedOwner,
        hold_id: EntityId,
        recipient: &HybridPublicKey,
    ) -> Result<LegalHoldProduction> {
        let hold = {
            let txn = self.store.env.read_txn()?;
            owner.revalidate_in_txn(self, &txn)?;
            hold_store::hold_in_txn(&self.store, &txn, &hold_id)?
                .filter(|hold| hold.kind == LegalHoldKind::Customer && hold.stands())
                .ok_or(Error::EntityNotFound)?
        };
        if hold.clone_captures.is_empty() {
            return Err(Error::InvalidConfig("this hold has no sealed copy".into()));
        }
        let seed = clone::legal_hold_store::open_hold_seed(self, &hold_id)?;
        let store = clone::legal_hold_store::configured(self)?;
        let dir = store.hold_dir(self, &hold_id);
        let mut captures = Vec::with_capacity(hold.clone_captures.len());
        for named in &hold.clone_captures {
            let frames = fs::read(dir.join(format!("{}.clone", named.capture.to_hex())))?;
            clone::legal_hold_store::check_capture_fingerprint(&frames, &named.fingerprint)?;
            captures.push(ProducedHoldCapture {
                capture: named.capture,
                fingerprint: named.fingerprint,
                frames,
            });
        }
        let production_id = self.store.clock.entity_id()?;
        let vault_id = self.vault_id();
        let sealed_hold_key = clone::legal_hold_store::seal_production_key(
            vault_id.as_bytes(),
            &hold_id,
            &production_id,
            recipient,
            &seed,
        )?;
        let recipient_fingerprint = *blake3::hash(&recipient.to_bytes()).as_bytes();
        self.with_write_txn_grouped(|txn| {
            let actor = owner.revalidate_in_txn(self, txn)?;
            let Some(hold) = hold_store::hold_in_txn(&self.store, txn, &hold_id)?
                .filter(|hold| hold.kind == LegalHoldKind::Customer && hold.stands())
            else {
                return Err(Error::EntityNotFound);
            };
            let targets = hold.targets.clone();
            let row = LegalHoldEvent {
                recipient_fingerprint: Some(recipient_fingerprint),
                ..hold_store::events::event_row(
                    &hold,
                    LegalHoldEventKind::CloneProduced,
                    LegalHoldReason::OwnerProduced,
                    targets,
                    &HoldActor::owner(actor),
                    self.store.clock.now_recorded_at(),
                    None,
                )
            };
            hold_store::events::append_event_in_txn(&self.store, txn, &hold, &row)?;
            Ok(())
        })?;
        Ok(LegalHoldProduction {
            hold_id,
            production_id,
            recipient_fingerprint,
            sealed_hold_key,
            captures,
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
                clone_captures: Vec::new(),
                future_messages: None,
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
    /// notice, then settles the scrubs no cooperative restriction keeps.
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
        self.settle_held_scrubs()?;
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
    /// silence ended, settles the scrubs no cooperative restriction keeps,
    /// and drops log rows 24 months past their hold's release.
    pub fn maintain_legal_holds(&self) -> Result<LegalHoldMaintenance> {
        let lapsed = self.with_write_txn_grouped(|txn| {
            let now = self.store.clock.now_recorded_at();
            // An owner's pending outbox reaches its hold store before its
            // term ends it (Ruling L10-21-OWNER-FUTURE-MESSAGES = A).
            #[cfg(unix)]
            prospective::flush_owner_standings_in_txn(&self.store, txn)?;
            // A prospective capture order whose term passed ends with its
            // outbox, even with no live connection (FIX 13867).
            prospective::end_lapsed_in_txn(&self.store, txn, now)?;
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
        self.settle_held_scrubs()?;
        Ok(LegalHoldMaintenance {
            lapsed,
            expired: self.sweep_legal_hold_log()?,
        })
    }

    /// Settles the scrubs a cooperative restriction kept: the births and
    /// carriers, Gate decision scrubs and relayed ask rows no restriction
    /// keeps any more (FIX 6280, 6386, 7993, 7994). Runs after a host-order
    /// lift, a gate-partition release and each maintenance pass, whether or
    /// not an erase waits; an erase a restriction kept from completing then
    /// completes (FIX 5844).
    pub(crate) fn settle_held_scrubs(&self) -> Result<()> {
        let cancelled = self.with_write_txn_grouped(|txn| self.settle_held_scrubs_in_txn(txn))?;
        crate::attempt_queue::AttemptQueue::new(self)
            .erased_payload_cancellations_committed(&cancelled);
        self.finish_redaction_erases_logged();
        Ok(())
    }

    /// Drops hold-log rows and released holds 24 calendar months past the
    /// release (C3). Returns the rows removed.
    pub fn sweep_legal_hold_log(&self) -> Result<u64> {
        self.with_write_txn_grouped(|txn| {
            hold_store::expire_in_txn(&self.store, txn, self.store.clock.now_recorded_at())
        })
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
