//! The check-in of a caller's widen of who reaches an item (ROLES-CHECKIN
//! P2.5, row 2k8f; ARCH-0082 #act-table "Widen another's grant"; Engine
//! rulings P25-SHAPE Q1 = A, 14 Nov 13:39, and MEMBER-SHARE-OWN = B, 19:33).
//!
//! A door that widens who reaches an item (act class `grant_widen`: a mail
//! thread's share, a room's pins opened to every member, a share's view
//! link) judges its caller in its own writer, after every check that
//! refuses the call and before the write:
//!
//! * The vault's Owner widens on their own proof, and the answer records it.
//! * A shared-vault member who wrote or owns the item widens it at once
//!   under the door's other gates, with basis `own_item`: the door's own
//!   predicate names whose the item is.
//! * A member who widens someone else's item is judged under their
//!   membership role ([`person_door_check_in_in_txn`]): a Deputy goes on
//!   their own judgment (`sure`) and an Admin at once (`never_ask`); a
//!   Steward's and a Member's widen waits (canon's "propose": the door admits
//!   them, so they hold the power, and the act asks). The door commits the
//!   pending check-in alone, widens nothing and answers `CHECK_IN_PENDING`
//!   naming it; once it is approved, the call that names it as
//!   `check_in_ref` widens and spends it in the same writer.
//! * Any other caller is not judged, as on main: an agent (PR 3's act gate
//!   judges agents), a person with no membership grant (a Delegate grant is
//!   none), and any person but the Owner on a vault that is not shared.
//!
//! Only a member's widen of another's item waits, so a `check_in_ref` on any
//! other widen is refused before the door writes.

use super::act_class::ActClass;
use super::effect::{
    CheckInDecision, DoorAct, DoorCheckIn, owner_own_proof_decision, person_door_check_in_in_txn,
};
use super::mode::CheckInMode;
use super::policy::CheckInScope;
use super::role_preset::RolePreset;
use super::waits::refuse;
use crate::Vault;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Result;

/// One widen a door runs for its caller, as check-in judges it.
pub(crate) struct WidenAct<'a> {
    /// The caller, as the door's writer verified it.
    pub(crate) actor: EntityId,
    /// The caller's class: only a human is judged.
    pub(crate) class: EdgeActorClass,
    /// Whether the caller wrote or owns the item, by the door's predicate,
    /// read in the same writer.
    pub(crate) owns_item: bool,
    /// The saved verb the door is.
    pub(crate) verb: &'a str,
    /// The digest of the exact widen.
    pub(crate) effect_digest: [u8; 32],
}

/// What a door does with its widen.
pub(crate) enum WidenCheckIn {
    /// The widen runs; its answer records this decision, or none for a
    /// widen no role judges.
    Go(Option<CheckInDecision>),
    /// The widen waits on this pending check-in, opened or found in the
    /// door's writer: the door commits, widens nothing and answers
    /// `CHECK_IN_PENDING`.
    Wait(EntityId),
}

/// Judges `widen` in the door's writer `txn`, spending `check_in_ref` when
/// it names this member's approved ask (module docs).
///
/// # Errors
///
/// A `check_in_ref` that a widen which waits on none names; as
/// [`person_door_check_in_in_txn`].
pub(crate) fn person_widen_check_in_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    widen: &WidenAct<'_>,
    check_in_ref: Option<&EntityId>,
) -> Result<WidenCheckIn> {
    let decision = match widen_role_in_txn(vault, txn, widen)? {
        WidenRole::Unjudged => None,
        WidenRole::Owner => Some(owner_own_proof_decision(ActClass::GrantWiden)),
        WidenRole::Member { role, .. } if widen.owns_item => Some(CheckInDecision {
            act_class: ActClass::GrantWiden.as_str().to_owned(),
            role: role.as_str().to_owned(),
            mode: Some(CheckInMode::NeverAsk.as_str().to_owned()),
            basis: "own_item".to_owned(),
            check_in: None,
            requester: None,
        }),
        WidenRole::Member {
            person,
            grant,
            role,
        } => {
            let act = DoorAct {
                person,
                role,
                grant,
                verb: widen.verb,
                act: ActClass::GrantWiden,
                scope: CheckInScope::default(),
                effect_digest: widen.effect_digest,
            };
            let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
            return Ok(
                match person_door_check_in_in_txn(vault, txn, &act, check_in_ref, now)? {
                    DoorCheckIn::Go(decision) => WidenCheckIn::Go(Some(decision)),
                    DoorCheckIn::Wait(id) => WidenCheckIn::Wait(id),
                },
            );
        }
    };
    if check_in_ref.is_some() {
        return Err(refuse(
            "check_in_ref names a member's waiting widen of another's item; this widen waits on \
             none",
        ));
    }
    Ok(WidenCheckIn::Go(decision))
}

/// Whom check-in judges a widen as.
enum WidenRole {
    /// An agent, a person with no membership grant, or a person other than
    /// the Owner on a vault that is not shared.
    Unjudged,
    /// The vault's Owner.
    Owner,
    /// A shared-vault member, by their live membership grant.
    Member {
        person: EntityId,
        grant: EntityId,
        role: RolePreset,
    },
}

/// The caller of `widen` as check-in judges it, read in `txn`.
fn widen_role_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    widen: &WidenAct<'_>,
) -> Result<WidenRole> {
    if widen.class != EdgeActorClass::Human {
        return Ok(WidenRole::Unjudged);
    }
    let at = crate::ports::job_recorded_at_in_txn(&vault.store, txn)?;
    let Some(person) =
        crate::workspace_roster::person_of_actor_in_txn(vault, txn, widen.actor, at)?
    else {
        return Ok(WidenRole::Unjudged);
    };
    if crate::policy_model::owners_in_txn(vault, txn)?.contains(&person) {
        return Ok(WidenRole::Owner);
    }
    let Some(creation) = vault.shared_vault_creation_in_txn(txn)? else {
        return Ok(WidenRole::Unjudged);
    };
    let Some((grant, role)) = vault.member_grant_in_txn(txn, creation.vault_id, person)? else {
        return Ok(WidenRole::Unjudged);
    };
    Ok(WidenRole::Member {
        person,
        grant,
        role: RolePreset::of_grant_role(role),
    })
}
