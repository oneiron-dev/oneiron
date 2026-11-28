//! Owner checks for the ordinary booking publication claim write/read seam.

use super::support::{verify_actor_binding_in_txn, verify_owner_actor_binding_in_txn};
use super::{MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};
use crate::booking::lifecycle::{BookingHomeRefusal, publication_home_refusal_in_txn};
use crate::edge::EdgeActorClass;
use crate::side_table::{self, Raw, SideTable};
use crate::{EntityId, Vault};

/// Marks an id as inside the owner-authorized booking-publication write
/// transaction. Staged and removed inside that one transaction only, never
/// committed or accepted from replay. A home move's adopting transaction
/// stages it for each publication claim the old home carried, as that
/// node's owner write stored it ([`land_carried_publication_in_txn`]).
/// Key: id16; value: the literal marker `b"owner"` (presence is all any
/// reader checks). Generic byte and candidate
/// doors cannot mint a publication by copying write-envelope evidence:
/// `crate::booking::publication::write_index` checks this row's presence.
pub(crate) const STAGE: SideTable<EntityId, Vec<u8>, Raw> =
    SideTable::new(&side_table::BOOKING_PUBLICATION_WRITE_STAGE);

pub(super) fn stage_publication_write(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
) -> crate::Result<()> {
    STAGE.put(&vault.store, txn, &id, &b"owner".to_vec())?;
    Ok(())
}

pub(super) fn finish_publication_write(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
) -> crate::Result<()> {
    STAGE.delete(&vault.store, txn, &id)?;
    Ok(())
}

/// FIX [BK-HOME-MOVE-PUBLIC-PAGE-INDEX-NOT-CARRIED]: runs `put`, the landing
/// of publication claim `id` as a home move carried it from the old home,
/// inside the owner write's staging for that one id: the claim is the owner's
/// write as that node stored it, and the move lands it unchanged, never a new
/// one. No generic, candidate or replay door reaches this staging.
///
/// # Errors
///
/// Storage errors, and `put`'s own.
#[cfg(feature = "sync")]
pub(crate) fn land_carried_publication_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    put: impl FnOnce(&mut heed::RwTxn<'_>) -> crate::Result<()>,
) -> crate::Result<()> {
    stage_publication_write(vault, txn, id)?;
    put(txn)?;
    finish_publication_write(vault, txn, id)
}

pub(crate) fn verify_public_booking_owner_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    owner: EntityId,
) -> MemoryResult<()> {
    if !crate::vault::live_entity_row_in_txn(&vault.store, txn, &owner)?.is_live() {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "booking publication requires a live owner actor",
            &["Bind the live owner actor through the normal authority interface."],
        ));
    }
    verify_actor_binding_in_txn(vault, txn, owner, EdgeActorClass::Human)?;
    verify_owner_actor_binding_in_txn(vault, txn, owner)
}

impl Memory<'_> {
    /// Confirms a staged booking revision through the same deferred closure gate.
    /// The live owner is checked before either publication slot is writable.
    pub fn confirm_booking_publication(
        &self,
        claim_ref: &str,
        now: u64,
    ) -> MemoryResult<crate::inbox::InboxAmendedApproval> {
        let id = self.resolve_ref(claim_ref)?;
        // The writer's refusal as it was typed, not the flattened engine error that aborts
        // the transaction: a refusal off the booking home names its reason and the act.
        let refusal = std::cell::RefCell::new(None);
        let (approval, vad) = self
            .vault
            .with_write_txn_grouped(|txn| {
                if let Err(error) = self.verify_public_booking_writer_in_txn(txn) {
                    *refusal.borrow_mut() = Some(error);
                    return Err(crate::Error::InvalidClaimBody(
                        "booking publication owner authority refused",
                    ));
                }
                let body = self
                    .vault
                    .get_claim_in_txn(txn, &id)?
                    .ok_or(crate::Error::EntityNotFound)?;
                if body.predicate != crate::booking::BOOKING_PUBLIC_PAGE_PREDICATE {
                    return Err(crate::Error::InvalidClaimBody("not a booking publication"));
                }
                let Some(old) = self.vault.pending_claim_supersession_in_txn(txn, &id)? else {
                    // A proposed revision with no confirmation pending here is one a home
                    // move carried without it (the carry lands the indexed head alone):
                    // name the acts that publish the page on this booking home again.
                    if body.approval == crate::claim::ClaimApprovalStatus::Proposed {
                        *refusal.borrow_mut() = Some(revision_not_pending(claim_ref));
                        return Err(crate::Error::InvalidClaimBody(
                            "booking publication revision has no pending confirmation",
                        ));
                    }
                    return Err(crate::Error::EntityNotFound);
                };
                stage_publication_write(self.vault, txn, id)?;
                stage_publication_write(self.vault, txn, old)?;
                let result = self.vault.approve_inbox_member_with_edit_in_txn(
                    txn,
                    &id,
                    &crate::claim::encode_claim_body(&body)?,
                    now,
                    None,
                )?;
                finish_publication_write(self.vault, txn, id)?;
                finish_publication_write(self.vault, txn, old)?;
                Ok(result)
            })
            .map_err(|error| refusal.take().unwrap_or_else(|| MemoryError::from(error)))?;
        if let Some(id) = vad {
            self.vault
                .consolidate_claim_vad_now(&id, now)
                .map_err(MemoryError::from)?;
        }
        Ok(approval)
    }

    pub(super) fn verify_public_booking_writer_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> MemoryResult<()> {
        if self.actor_class != EdgeActorClass::Human {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "booking publication is an owner write",
                &["Use the owner-authorized memory claim write interface."],
            ));
        }
        verify_public_booking_owner_in_txn(self.vault, txn, self.actor)?;
        // FIX [BK-PUBLICATION-CLAIM-REFUSED-AT-SYNC-INGRESS] (BK-PUBLICATION-OFF-HOME-WRITE = B
        // with B1, lead 21 Nov 17:3x): the owner publishes, revises, confirms and retracts a
        // booking page on the booking home alone, the node whose public routes serve it. A
        // peer never admits the claim from sync (`guard_publication_put`), so a write here
        // would answer the owner with a page no visitor reaches.
        match publication_home_refusal_in_txn(self.vault, txn) {
            Ok(None) => Ok(()),
            Ok(Some(refusal)) => Err(publication_home_refused(refusal)),
            Err(error) => Err(super::booking::booking_error(error)),
        }
    }
}

/// Reason code of a booking publication write on a vault no election names a booking home for.
const REASON_NO_BOOKING_HOME: &str = "booking.publication.no_booking_home";
/// Reason code of a booking publication write on a node whose election names another home.
const REASON_NOT_BOOKING_HOME: &str = "booking.publication.not_booking_home";
/// Reason code of a booking publication write while a home move carries the booking rows.
const REASON_BOOKING_HOME_MOVING: &str = "booking.publication.booking_home_moving";
/// Reason code of a confirm of a staged revision whose confirmation this node does not hold.
const REASON_REVISION_NOT_PENDING: &str = "booking.publication.revision_not_pending";

/// The owner's typed refusal of a confirm of a staged booking page revision `claim_ref` whose
/// confirmation this booking home does not hold (review round 1 of #10332): a home move carries
/// the page's indexed head and not the staged revision's pending confirmation or the
/// publication it replaces, so the revision cannot be confirmed here. The page is dark, as it was
/// on the former home while the revision waited; the owner retracts the revision and publishes
/// the page again here.
fn revision_not_pending(claim_ref: &str) -> MemoryError {
    let mut error = MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        "this booking page revision was staged on a former booking home, and its confirmation \
         stayed there: this device cannot confirm it",
        &[],
    );
    error.suggestions = vec![format!(
        "Retract the revision {claim_ref}, then publish the booking page again on this device."
    )];
    error.reason_codes = vec![REASON_REVISION_NOT_PENDING.to_owned()];
    error
}

/// The owner's typed refusal of a booking publication write off the booking home: one reason
/// code, and the act that lets the write run (B1: with no home, or another home, the owner can
/// make this device the booking home with his home pick).
fn publication_home_refused(refusal: BookingHomeRefusal) -> MemoryError {
    let (reason, message, suggestions) = match refusal {
        BookingHomeRefusal::NoHome { node_id } => (
            REASON_NO_BOOKING_HOME,
            "no device is this vault's booking home, and a booking page is published only on \
             the booking home"
                .to_owned(),
            vec![make_this_device_the_booking_home(node_id)],
        ),
        BookingHomeRefusal::Elsewhere {
            home_node_id,
            node_id,
        } => (
            REASON_NOT_BOOKING_HOME,
            format!(
                "this device is not the booking home: node {home_node_id} publishes, revises, \
                 confirms and retracts this vault's booking pages"
            ),
            vec![
                format!("Publish on the booking home, node {home_node_id}."),
                make_this_device_the_booking_home(Some(node_id)),
            ],
        ),
        BookingHomeRefusal::Moving => (
            REASON_BOOKING_HOME_MOVING,
            "a booking home move is carrying the booking rows, so this device publishes no \
             booking page now"
                .to_owned(),
            vec!["Publish on the new booking home once the move lands.".to_owned()],
        ),
    };
    let mut error = MemoryError::new(MEMORY_CODE_INVALID_STATE, message, &[]);
    error.suggestions = suggestions;
    error.reason_codes = vec![reason.to_owned()];
    error
}

/// The one owner act a refusal off the booking home offers: the owner's home pick naming this
/// device, which re-elects the home over the vault's candidates.
fn make_this_device_the_booking_home(node_id: Option<u64>) -> String {
    let device = node_id.map_or_else(|| "this device".to_owned(), |node| format!("node {node}"));
    format!(
        "Make this device the booking home: pick {device} with vault.consolidation.home.pick, \
         then publish again."
    )
}
