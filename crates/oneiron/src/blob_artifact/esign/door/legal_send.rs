//! The check-in of a person's send for signature (ROLES-CHECKIN P2.5, row
//! 2k6a; ARCH-0082 #act-table "Legal: prepare and send for signature";
//! P25-SHAPE Q1 = A).
//!
//! `vault.esign.send_for_signature` is judged in a writer of its own after
//! the door's binding, lane and retry-key checks and before the dispatch, as
//! the delete doors are (2k5). Only a human caller is judged: an agent's
//! send keeps its principal's autonomy dial, and PR 3's act gate judges
//! agents.
//!
//! * The vault's Owner sends on their own proof, and the view records it.
//! * A shared-vault member is judged under their membership role. A
//!   Deputy's send goes on their own judgment (`sure`). An Admin's (canon:
//!   "propose"), a Steward's, a Member's and a Guest's wait: the door admits
//!   each of them, so where canon gives the role no power of its own the
//!   send asks. The door commits the pending check-in alone, dispatches
//!   nothing and answers `CHECK_IN_PENDING` naming it. Once it is approved,
//!   the call that names it as `check_in_ref` spends it in the judge's
//!   writer and dispatches, and a dispatch refused after leaves it spent.
//!   The same person's retry that names it again goes on the basis it gave:
//!   a document sends once, so a retry is the same send (a gate that held
//!   the first call releases it on its retry). A member's send whose
//!   `recipient_count` is not the document's is refused before any ask
//!   opens: the dispatch would refuse it, so an approved check-in spent on
//!   it would be lost.
//! * Any other person (one with no membership grant, or any person on a
//!   vault that is not shared) is not judged, as on main. A Delegate grant
//!   is no membership grant (the ladder climbs from membership grants, as at
//!   every door of 2i to 2k), so a Delegate's send is not judged either (FIX
//!   CHECK-IN-PERSON-DELEGATE-UNJUDGED).
//!
//! Drafting (`vault.esign.create`) is not judged: it sends nothing.

use crate::check_in::{
    self, ActClass, CheckInDecision, CheckInScope, DoorAct, DoorCheckIn, RolePreset,
};
use crate::memory::Memory;
use crate::{EntityId, Error, Result, Vault};
use oneiron_contracts::memory::{MemoryError, MemoryResult};

/// The saved verb this module judges.
const SEND_FOR_SIGNATURE_VERB: &str = "vault.esign.send_for_signature";

/// What the judge made of one send.
enum SendCheckIn {
    /// The Owner's own send, on their own proof.
    Own(CheckInDecision),
    /// A member's send that goes, on this decision.
    Go(CheckInDecision),
    /// A member's send that waits on this pending check-in.
    Waits(EntityId),
    /// A send no role judges here.
    Unjudged,
}

impl Memory<'_> {
    /// The check-in decision of this caller's send of `document`, whose
    /// recipients it counted as `recipient_count` (module docs).
    ///
    /// # Errors
    ///
    /// `BAD_REQUEST` for a `check_in_ref` that is no check-in id, or that a
    /// send no membership role judges names, and for a member's
    /// `recipient_count` that is not the document's; `CHECK_IN_PENDING`
    /// while the send waits; as [`check_in::person_door_check_in_in_txn`].
    pub(super) fn send_for_signature_check_in(
        &self,
        document: EntityId,
        recipient_count: usize,
        check_in_ref: Option<&str>,
    ) -> MemoryResult<Option<CheckInDecision>> {
        let check_in_ref = check_in_ref
            .map(|hex| {
                EntityId::from_hex(hex)
                    .map_err(|_| MemoryError::bad_request("check_in_ref is not a check-in id"))
            })
            .transpose()?;
        let (vault, actor) = (self.vault(), self.actor());
        let judged = if self.actor_class() == crate::edge::EdgeActorClass::Human {
            vault.try_with_write_txn_grouped(|txn| {
                send_check_in_in_txn(
                    vault,
                    txn,
                    actor,
                    document,
                    recipient_count,
                    check_in_ref.as_ref(),
                )
            })?
        } else {
            SendCheckIn::Unjudged
        };
        match judged {
            SendCheckIn::Own(_) | SendCheckIn::Unjudged if check_in_ref.is_some() => {
                Err(MemoryError::bad_request(
                    "check_in_ref names a member's waiting send; an Owner's, an agent's or an \
                     unjudged send waits on none",
                ))
            }
            SendCheckIn::Own(decision) | SendCheckIn::Go(decision) => Ok(Some(decision)),
            SendCheckIn::Waits(id) => Err(Error::CheckInPending(id.to_hex()).into()),
            SendCheckIn::Unjudged => Ok(None),
        }
    }
}

/// `actor`'s send of `document` judged in `txn`, the judge's writer: the
/// Owner on their own proof, a shared-vault member under their membership
/// role over the send's digest, with `check_in_ref` spent when it names an
/// approved ask, or taken again when it names this send's spent one.
fn send_check_in_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    document: EntityId,
    recipient_count: usize,
    check_in_ref: Option<&EntityId>,
) -> Result<SendCheckIn> {
    let at = crate::ports::job_recorded_at_in_txn(&vault.store, txn)?;
    let Some(person) = crate::workspace_roster::person_of_actor_in_txn(vault, txn, actor, at)?
    else {
        return Ok(SendCheckIn::Unjudged);
    };
    if crate::policy_model::owners_in_txn(vault, txn)?.contains(&person) {
        return Ok(SendCheckIn::Own(check_in::owner_own_proof_decision(
            ActClass::LegalSend,
        )));
    }
    let Some(creation) = vault.shared_vault_creation_in_txn(txn)? else {
        return Ok(SendCheckIn::Unjudged);
    };
    let Some((grant, role)) = vault.member_grant_in_txn(txn, creation.vault_id, person)? else {
        return Ok(SendCheckIn::Unjudged);
    };
    // A count the dispatch refuses opens no ask (module docs). A state the
    // judge cannot read is left to the dispatch, which refuses it in its own
    // writer, as on main.
    if let Ok(state) = super::super::ledger::state_in(vault, txn, document)
        && state.document.recipients.len() != recipient_count
    {
        return Err(super::super::model::invalid(
            "recipient_count is not the document's recipient count",
        ));
    }
    let act = DoorAct {
        person,
        role: RolePreset::of_grant_role(role),
        grant,
        verb: SEND_FOR_SIGNATURE_VERB,
        act: ActClass::LegalSend,
        scope: CheckInScope::default(),
        effect_digest: check_in::legal_send_effect_digest(&document, recipient_count),
    };
    if let Some(id) = check_in_ref
        && let Some(decision) = resent_check_in_in_txn(vault, txn, &act, id)?
    {
        return Ok(SendCheckIn::Go(decision));
    }
    let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    Ok(
        match check_in::person_door_check_in_in_txn(vault, txn, &act, check_in_ref, now)? {
            DoorCheckIn::Go(decision) => SendCheckIn::Go(decision),
            DoorCheckIn::Wait(id) => SendCheckIn::Waits(id),
        },
    )
}

/// The decision of a retry of `act` under `id`, a check-in this person
/// already spent on this same send: the basis it gave. `None` for any other
/// row, which the judge then spends or refuses.
fn resent_check_in_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    act: &DoorAct<'_>,
    id: &EntityId,
) -> Result<Option<CheckInDecision>> {
    let Some(row) = check_in::pending_check_in_in_txn(&vault.store, txn, id)? else {
        return Ok(None);
    };
    if row.consumed_at.is_none()
        || row.asker != act.person
        || row.verb != act.verb
        || row.act != act.act
        || row.scope != act.scope
        || row.effect_digest != act.effect_digest
    {
        return Ok(None);
    }
    Ok(row.eligible_basis().map(|basis| CheckInDecision {
        act_class: act.act.as_str().to_owned(),
        role: act.role.as_str().to_owned(),
        mode: Some(row.mode.as_str().to_owned()),
        basis: basis.as_str().to_owned(),
        check_in: Some(id.to_hex()),
        requester: None,
    }))
}
