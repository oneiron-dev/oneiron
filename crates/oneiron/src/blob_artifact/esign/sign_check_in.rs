//! The check-in of a sign act as the vault's principal (ROLES-CHECKIN P2.5,
//! row 2k6b; ARCH-0082 #act-table "Sign act (C)" and "Sign: anyone signs in
//! their own name. The row is binding the vault's principal."; P25-SHAPE
//! Q1 = A; Engine ruling ESIGN-CHECKIN Q2 and Q3 = A).
//!
//! Only `Complete` is judged, and only when a credentialed person
//! ([`SigningCaller::Person`] with a verified actor) completes a recipient
//! whose principal is the vault's own: a vault Owner, or a row of the
//! signing principal set. The judge runs in the act's own writer after every
//! gate of the ceremony and before the signature, so a spent check-in and
//! the signature commit together.
//!
//! * The Owner signs on their own proof.
//! * A shared-vault member is judged under their membership role on the
//!   catastrophe row, where every role but the Owner always asks. The act
//!   commits its pending check-in, signs nothing and answers
//!   `check_in_pending` naming it; once it is approved, the Complete that
//!   names it as `check_in_ref` spends it and signs.
//! * A person completing a recipient whose principal is their own person
//!   signs in their own name and is not judged. Nor is a person no
//!   membership role judges (a Delegate grant is no membership grant: FIX
//!   CHECK-IN-PERSON-DELEGATE-UNJUDGED), a recipient with no principal or
//!   another's, a bearer's call or an agent's, which keep the natural-person
//!   refusal and the D6 dial.
//!
//! The signature's evidence records the decision.
//!
//! Known limit: the capability is the authority (ARCH-0064), so whoever
//! holds a vault principal's signing link can complete it as a bearer,
//! unjudged.

use super::SigningCaller;
use super::model::{EsignCheckInDecision, EsignRecipient, invalid};
use crate::check_in::{
    self, ActClass, CheckInDecision, CheckInScope, DoorAct, DoorCheckIn, RolePreset,
};
use crate::{EntityId, Result, Vault};

/// The saved verb this module judges.
const SIGN_VERB: &str = "vault.esign.signing.act";

/// One Complete the ceremony is about to sign.
pub(super) struct SignAct<'a> {
    pub(super) caller: SigningCaller,
    pub(super) verified_actor: Option<EntityId>,
    pub(super) document: EntityId,
    pub(super) recipient: &'a EsignRecipient,
    /// The check-in the Complete names, 32 hex.
    pub(super) check_in_ref: Option<&'a str>,
}

/// What the ceremony does with a Complete.
pub(super) enum SignCheckIn {
    /// It signs, and its evidence records nothing.
    Unjudged,
    /// It signs, and its evidence records this decision.
    Go(EsignCheckInDecision),
    /// It waits on this pending check-in and signs nothing.
    Waits(EntityId),
}

/// What the judge made of a Complete.
enum Judged {
    Own(CheckInDecision),
    Go(CheckInDecision),
    Waits(EntityId),
    Unjudged,
}

/// Judges `act` in `txn`, the act's writer (module docs).
///
/// # Errors
///
/// A `check_in_ref` that is no check-in id, or that a Complete not judged
/// under a membership role names; as
/// [`check_in::person_door_check_in_in_txn`]; storage errors.
pub(super) fn sign_check_in_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    act: &SignAct<'_>,
) -> Result<SignCheckIn> {
    let check_in_ref = act
        .check_in_ref
        .map(|hex| EntityId::from_hex(hex).map_err(|_| invalid("check_in_ref is no check-in id")))
        .transpose()?;
    match judge_in_txn(vault, txn, act, check_in_ref.as_ref())? {
        Judged::Own(_) | Judged::Unjudged if check_in_ref.is_some() => Err(invalid(
            "check_in_ref names a member's waiting sign act; this one waits on none",
        )),
        Judged::Own(decision) | Judged::Go(decision) => {
            Ok(SignCheckIn::Go(evidence_decision(decision)))
        }
        Judged::Waits(id) => Ok(SignCheckIn::Waits(id)),
        Judged::Unjudged => Ok(SignCheckIn::Unjudged),
    }
}

fn judge_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    act: &SignAct<'_>,
    check_in_ref: Option<&EntityId>,
) -> Result<Judged> {
    let (SigningCaller::Person, Some(actor)) = (act.caller, act.verified_actor) else {
        return Ok(Judged::Unjudged);
    };
    let Some(principal) = act.recipient.principal_ref.as_deref() else {
        return Ok(Judged::Unjudged);
    };
    let heads = vault.resolve_entity_in_txn(txn, &EntityId::from_hex(principal)?)?;
    let [principal] = heads.as_slice() else {
        return Ok(Judged::Unjudged);
    };
    let principal = *principal;
    let at = crate::ports::job_recorded_at_in_txn(&vault.store, txn)?;
    let Some(person) = crate::workspace_roster::person_of_actor_in_txn(vault, txn, actor, at)?
    else {
        return Ok(Judged::Unjudged);
    };
    let owners = crate::policy_model::owners_in_txn(vault, txn)?;
    let mut vaults_principal = super::principals::signing_principal_in(vault, txn, principal)?;
    for owner in &owners {
        vaults_principal = vaults_principal || resolves_to(vault, txn, owner, principal)?;
    }
    if !vaults_principal {
        return Ok(Judged::Unjudged);
    }
    if owners.contains(&person) {
        return Ok(Judged::Own(check_in::owner_own_proof_decision(
            ActClass::Sign,
        )));
    }
    if resolves_to(vault, txn, &person, principal)? {
        return Ok(Judged::Unjudged);
    }
    let Some(creation) = vault.shared_vault_creation_in_txn(txn)? else {
        return Ok(Judged::Unjudged);
    };
    let Some((grant, role)) = vault.member_grant_in_txn(txn, creation.vault_id, person)? else {
        return Ok(Judged::Unjudged);
    };
    let door = DoorAct {
        person,
        role: RolePreset::of_grant_role(role),
        grant,
        verb: SIGN_VERB,
        act: ActClass::Sign,
        scope: CheckInScope::default(),
        effect_digest: check_in::sign_effect_digest(&act.document, &act.recipient.id),
    };
    let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    Ok(
        match check_in::person_door_check_in_in_txn(vault, txn, &door, check_in_ref, now)? {
            DoorCheckIn::Go(decision) => Judged::Go(decision),
            DoorCheckIn::Wait(id) => Judged::Waits(id),
        },
    )
}

/// Whether `id` resolves to the one entity `canonical`.
fn resolves_to(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    canonical: EntityId,
) -> Result<bool> {
    Ok(vault.resolve_entity_in_txn(txn, id)? == vec![canonical])
}

/// `decision` as the signature's evidence stores it.
fn evidence_decision(decision: CheckInDecision) -> EsignCheckInDecision {
    let CheckInDecision {
        act_class,
        role,
        mode,
        basis,
        check_in,
        requester,
    } = decision;
    EsignCheckInDecision {
        act_class,
        role,
        mode,
        basis,
        check_in,
        requester,
    }
}
