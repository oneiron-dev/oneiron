//! A door's own check-in for a person's act (ARCH-0082 #composing;
//! ROLES-CHECKIN P2.4b, piece 2i; Engine ruling P24-SHAPE Q3, Q4, Q6 and Q9
//! = A).
//!
//! A door that runs a typed effect for a person judges the act in its own
//! writer, before the effect: the act class the door names for its typed
//! effect (a verb row may be `unstated` because its door runs several
//! classes, Q6), the person's membership role, and the power the door has
//! already checked. A person's act is their own judgment, as a person
//! holder's answer is (`chain`), so the unsure test and the model check,
//! which bound a model, do not apply: an act asked when unsure goes, and an
//! act that always asks waits (Q3). Then:
//!
//! * go: the door runs the effect, and its family receipt records the
//!   decision ([`CheckInDecision`], Q9; never a pending row);
//! * wait, with no `check_in_ref`: the pending check-in for this exact
//!   effect is opened in the door's writer, or the open one found; the door
//!   commits it, runs nothing and answers `CHECK_IN_PENDING` naming it (Q4);
//! * wait, with `check_in_ref`: the row must be this person's ask for this
//!   verb, act class, scope and effect digest, settled eligible. It is spent
//!   in the door's writer, so the commit that runs the effect is the one
//!   that marks it used, and an abort leaves it eligible.
//!
//! No explicit mode row and no standing row is read (the change path is PR
//! 3). An agent reaches these acts through `vault.check_in.open`; PR 3's act
//! gate admits agents at these doors.

use serde::{Deserialize, Serialize};

use super::act_class::ActClass;
use super::chain::{NoAgentVerdict, VerifiedChain};
use super::mode::CheckInMode;
use super::pending::{
    OpenPendingCheckIn, consume_pending_check_in_in_txn, open_keyed_pending_check_in_in_txn,
    pending_check_in_in_txn,
};
use super::policy::CheckInScope;
use super::resolve::{CheckInRequest, ResolvedMode, WaitReason, resolve_mode};
use super::role_preset::RolePreset;
use super::waits::refuse;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::federation::FederationGrantRole;

/// One act a door runs for a person, as check-in judges it.
pub(crate) struct DoorAct<'a> {
    /// The person, revalidated by the door.
    pub(crate) person: EntityId,
    /// Their role on the vault link.
    pub(crate) role: RolePreset,
    /// Their live membership grant on the vault: the grant a pending ask
    /// climbs the ladder from.
    pub(crate) grant: EntityId,
    /// The saved verb the door is.
    pub(crate) verb: &'a str,
    /// The act class of the door's typed effect.
    pub(crate) act: ActClass,
    /// Where the effect sits.
    pub(crate) scope: CheckInScope,
    /// The digest of the exact effect.
    pub(crate) effect_digest: [u8; 32],
}

/// The check-in decision an act's family receipt records (P24-SHAPE Q9 =
/// A): the act class, the role it was judged under, the mode and why it
/// went.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckInDecision {
    /// The act class's token.
    pub act_class: String,
    /// The role's token.
    pub role: String,
    /// The mode's wire token; none when the role acts on its own proof.
    pub mode: Option<String>,
    /// Why the act went: `never_ask`, `sure` (the person's own judgment),
    /// `own_proof`, or the basis the spent check-in gave (`approved`,
    /// `proceed_with_undo` or `window_passed`).
    pub basis: String,
    /// The check-in the act spent, 32 hex.
    pub check_in: Option<String>,
    /// Who asked for the act, PERSON or agent id hex, when an Owner applied
    /// another asker's approved check-in on their own proof (P24-SHAPE Q7 =
    /// A); none for an act its own actor asked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester: Option<String>,
}

/// What a door does with its act.
pub(crate) enum DoorCheckIn {
    /// The effect runs; its family receipt records this decision.
    Go(CheckInDecision),
    /// The act waits on this pending check-in, opened or found in the door's
    /// writer: the door commits, runs nothing and answers `CHECK_IN_PENDING`.
    Wait(EntityId),
}

/// Judges `act` in the door's writer `txn` at `now`; with `check_in_ref`,
/// spends that settled ask when the act waits.
///
/// # Errors
///
/// A role that does not hold the power; a `check_in_ref` that names no row,
/// another person's ask or another act, another effect, or an ask that is
/// not eligible or already spent; a refused open; storage errors.
pub(crate) fn person_door_check_in_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    act: &DoorAct<'_>,
    check_in_ref: Option<&EntityId>,
    now: u64,
) -> Result<DoorCheckIn> {
    let request = CheckInRequest {
        act: act.act,
        role: act.role,
        holds_power: true,
        explicit_mode: None,
        standing_row: None,
    };
    let mode = match resolve_mode(&request) {
        ResolvedMode::OwnProof => {
            return Ok(DoorCheckIn::Go(decision(act, None, "own_proof", None)));
        }
        ResolvedMode::Propose | ResolvedMode::Absent => {
            return Err(refuse(
                "the person's role does not hold the power for this act",
            ));
        }
        ResolvedMode::Mode {
            mode: mode @ CheckInMode::NeverAsk,
            ..
        } => {
            return Ok(DoorCheckIn::Go(decision(
                act,
                Some(mode),
                "never_ask",
                None,
            )));
        }
        // The person's own act is their judgment: they are sure.
        ResolvedMode::Mode {
            mode: mode @ CheckInMode::AskWhenUnsure,
            ..
        } => return Ok(DoorCheckIn::Go(decision(act, Some(mode), "sure", None))),
        ResolvedMode::Mode {
            mode: mode @ CheckInMode::AlwaysAsk,
            ..
        } => mode,
    };
    match check_in_ref {
        Some(id) => spend_in_txn(vault, txn, act, mode, id, now),
        None => {
            let (row, _) = open_keyed_pending_check_in_in_txn(
                vault,
                txn,
                OpenPendingCheckIn {
                    asker: act.person,
                    grant_ref: act.grant.to_hex(),
                    verb: act.verb.to_owned(),
                    act: act.act,
                    scope: act.scope.clone(),
                    effect_digest: act.effect_digest,
                    mode,
                    reason: WaitReason::AlwaysAsk,
                    asker_wait_secs: None,
                    until: None,
                    undo_plan: None,
                    delay_window: None,
                },
                None,
                &VerifiedChain::new(&NoAgentVerdict),
                now,
            )?;
            Ok(DoorCheckIn::Wait(row.id))
        }
    }
}

/// Spends the settled ask `id` for `act`, in the door's writer.
fn spend_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    act: &DoorAct<'_>,
    mode: CheckInMode,
    id: &EntityId,
    now: u64,
) -> Result<DoorCheckIn> {
    let row = pending_check_in_in_txn(&vault.store, txn, id)?.ok_or(Error::EntityNotFound)?;
    if row.asker != act.person
        || row.verb != act.verb
        || row.act != act.act
        || row.scope != act.scope
    {
        return Err(refuse("the check-in is not this person's ask for this act"));
    }
    let basis = consume_pending_check_in_in_txn(vault, txn, id, &act.effect_digest, now)?;
    Ok(DoorCheckIn::Go(decision(
        act,
        Some(mode),
        basis.as_str(),
        Some(*id),
    )))
}

fn decision(
    act: &DoorAct<'_>,
    mode: Option<CheckInMode>,
    basis: &str,
    check_in: Option<EntityId>,
) -> CheckInDecision {
    CheckInDecision {
        act_class: act.act.as_str().to_owned(),
        role: act.role.as_str().to_owned(),
        mode: mode.map(|mode| mode.as_str().to_owned()),
        basis: basis.to_owned(),
        check_in: check_in.as_ref().map(EntityId::to_hex),
        requester: None,
    }
}

/// The digest of deleting shared vault `vault_id`: the effect an asker's
/// `vault.check_in.open` names for `vault.shared.propose_delete`, and the
/// one an Owner's start of the `delete_vault` act spends (2j; P24-SHAPE Q7 =
/// A). BLAKE3, key derived from `oneiron check_in vault delete v1`, over the
/// vault id as eight big-endian bytes.
#[must_use]
pub fn vault_delete_effect_digest(vault_id: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron check_in vault delete v1");
    hasher.update(&vault_id.to_be_bytes());
    *hasher.finalize().as_bytes()
}

/// The digest of erasing `record`, with or without every other record
/// holding its bytes: the effect an asker's `vault.check_in.open` names for
/// `vault.records.erase_confirm`, and the one an Owner's confirm spends (2j;
/// P24-SHAPE Q7 = A). BLAKE3, key derived from `oneiron check_in record erase
/// v1`, over the record's 16 id bytes and one byte, 1 when the erase takes
/// the same bytes too.
#[must_use]
pub fn record_erase_effect_digest(record: &EntityId, also_same_bytes: bool) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron check_in record erase v1");
    hasher.update(record.as_bytes());
    hasher.update(&[u8::from(also_same_bytes)]);
    *hasher.finalize().as_bytes()
}

/// The digest of `from` handing their ownership of shared vault `vault_id`
/// to `to`, keeping `from_keeps` or leaving when it is `None`: the effect an
/// asker's `vault.check_in.open` names for `vault.shared.propose_transfer`,
/// and the one the start of `from`'s `transfer_ownership` act spends (2k1;
/// P25-SHAPE Q1 = A). Only `from` applies it: the act moves the starter's
/// own ownership. BLAKE3, key derived from `oneiron check_in ownership
/// transfer v1`, over the vault id as eight big-endian bytes, the 16 id
/// bytes of `from` and of `to`, and the kept role.
#[must_use]
pub fn ownership_transfer_effect_digest(
    vault_id: u64,
    from: &EntityId,
    to: &EntityId,
    from_keeps: Option<FederationGrantRole>,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron check_in ownership transfer v1");
    hasher.update(&vault_id.to_be_bytes());
    hasher.update(from.as_bytes());
    hasher.update(to.as_bytes());
    update_kept_role(&mut hasher, from_keeps);
    *hasher.finalize().as_bytes()
}

/// The digest of making `owner` an Owner of shared vault `vault_id`: the
/// effect an asker's `vault.check_in.open` names for
/// `vault.shared.propose_add_owner`, and the one an Owner's start of the
/// `add_owner` act spends (2k1; P25-SHAPE Q1 = A). BLAKE3, key derived from
/// `oneiron check_in owner add v1`, over the vault id as eight big-endian
/// bytes and the 16 id bytes of `owner`.
#[must_use]
pub fn owner_add_effect_digest(vault_id: u64, owner: &EntityId) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron check_in owner add v1");
    hasher.update(&vault_id.to_be_bytes());
    hasher.update(owner.as_bytes());
    *hasher.finalize().as_bytes()
}

/// The digest of removing Owner `target` of shared vault `vault_id`, with
/// its `successor`, the role `target_keeps` and the export-first answer: the
/// effect an asker's `vault.check_in.open` names for
/// `vault.shared.propose_remove_owner`, and the one an Owner's start of the
/// `remove_owner` act spends (2k1; P25-SHAPE Q1 = A). BLAKE3, key derived
/// from `oneiron check_in owner remove v1`, over the vault id as eight
/// big-endian bytes, the 16 id bytes of `target`, one byte 1 and the
/// successor's 16 id bytes or one byte 0, the kept role, and one byte, 1
/// when the target exports first.
#[must_use]
pub fn owner_remove_effect_digest(
    vault_id: u64,
    target: &EntityId,
    successor: Option<&EntityId>,
    target_keeps: Option<FederationGrantRole>,
    export_first: bool,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron check_in owner remove v1");
    hasher.update(&vault_id.to_be_bytes());
    hasher.update(target.as_bytes());
    match successor {
        Some(successor) => hasher.update(&[1]).update(successor.as_bytes()),
        None => hasher.update(&[0]),
    };
    update_kept_role(&mut hasher, target_keeps);
    hasher.update(&[u8::from(export_first)]);
    *hasher.finalize().as_bytes()
}

/// One byte 0 for no kept role; else one byte 1, the role name's length as
/// one byte and its bytes.
fn update_kept_role(hasher: &mut blake3::Hasher, role: Option<FederationGrantRole>) {
    match role {
        Some(role) => {
            let name = role.as_str().as_bytes();
            hasher
                .update(&[1, u8::try_from(name.len()).unwrap_or(u8::MAX)])
                .update(name);
        }
        None => {
            hasher.update(&[0]);
        }
    }
}

/// The decision of an Owner's own act on a catastrophe row: the Owner acts
/// on their own proof (P24-SHAPE Q9 = A), where the act's door asks for it.
pub(crate) fn owner_own_proof_decision(act: ActClass) -> CheckInDecision {
    CheckInDecision {
        act_class: act.as_str().to_owned(),
        role: RolePreset::Owner.as_str().to_owned(),
        mode: None,
        basis: "own_proof".to_owned(),
        check_in: None,
        requester: None,
    }
}

/// Spends `id`, another asker's settled check-in for `verb`'s `act` over
/// `effect_digest`, in the writer of the Owner who applies the act on their
/// own proof (2j; P24-SHAPE Q7 = A). The answer is no proof of its own: the
/// Owner's proof runs the act, and every gate of the act's door still
/// holds. Returns the asker, the act's requester.
///
/// # Errors
///
/// No such row; another verb's or act class's ask; another effect; an ask
/// that is not eligible or already spent; storage errors.
pub(crate) fn spend_applied_check_in_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    verb: &str,
    act: ActClass,
    effect_digest: &[u8; 32],
    now: u64,
) -> Result<EntityId> {
    let row = pending_check_in_in_txn(&vault.store, txn, id)?.ok_or(Error::EntityNotFound)?;
    if row.verb != verb || row.act != act {
        return Err(refuse("the check-in is another act's ask"));
    }
    consume_pending_check_in_in_txn(vault, txn, id, effect_digest, now)?;
    Ok(row.asker)
}
