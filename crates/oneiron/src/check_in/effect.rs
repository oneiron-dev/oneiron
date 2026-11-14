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

use super::act_class::ActClass;
use super::chain::{NoAgentVerdict, VerifiedChain};
use super::mode::CheckInMode;
use super::pending::{
    OpenPendingCheckIn, consume_pending_check_in_in_txn, open_keyed_pending_check_in_in_txn,
    pending_check_in_in_txn, spendable_basis,
};
use super::policy::CheckInScope;
use super::resolve::{CheckInRequest, ResolvedMode, WaitReason, resolve_mode};
use super::role_preset::RolePreset;
use super::waits::refuse;
use crate::Vault;
use crate::authority::{RootChange, StepUpFactor};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::federation::FederationGrantRole;
use crate::gate::PolicyRowChange;
use crate::store::custody_protocol::{TargetScope, TargetSpec};

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

#[doc(hidden)]
pub use oneiron_verb_wire::check_in::effect::CheckInDecision;

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

/// Refuses `applied` in a read of its own, as the act's writer would refuse
/// to spend it: no such row, another act's ask, another effect, an ask that
/// is not eligible or already spent. It writes nothing. A door that writes
/// before the act's own writer checks the check-in first: a hub import
/// admits its publisher in a writer of its own, so a refused check-in
/// leaves no publisher admitted (2k8d review). The act's writer spends it
/// under the same checks.
///
/// # Errors
///
/// As [`spend_applied_check_in_in_txn`].
pub(crate) fn require_spendable_check_in(
    vault: &Vault,
    act: ActClass,
    applied: &AppliedCheckIn<'_>,
) -> Result<()> {
    let txn = vault.store.env.read_txn()?;
    let row =
        pending_check_in_in_txn(&vault.store, &txn, &applied.id)?.ok_or(Error::EntityNotFound)?;
    if row.verb != applied.verb || row.act != act {
        return Err(refuse("the check-in is another act's ask"));
    }
    spendable_basis(&row, &applied.effect_digest)?;
    Ok(())
}

/// Another asker's approved check-in an Owner applies to their own act on a
/// catastrophe row (2j apply shape; P25-SHAPE Q1 = A): its id, the verb and
/// the exact effect it was asked for.
pub(crate) struct AppliedCheckIn<'a> {
    pub(crate) id: EntityId,
    pub(crate) verb: &'a str,
    pub(crate) effect_digest: [u8; 32],
}

/// The decision an Owner's own act on a catastrophe row runs on, in `txn`,
/// the act's own writer: the Owner on their own proof, and with `applied`
/// the asker's approved check-in, spent here and named with its requester
/// (2k2; P25-SHAPE Q1 = A). The answer is no proof of its own: every gate
/// of the act's door still holds.
///
/// # Errors
///
/// As [`spend_applied_check_in_in_txn`].
pub(crate) fn owner_act_decision_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    act: ActClass,
    applied: Option<&AppliedCheckIn<'_>>,
) -> Result<CheckInDecision> {
    let mut decision = owner_own_proof_decision(act);
    if let Some(applied) = applied {
        let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        let requester = spend_applied_check_in_in_txn(
            vault,
            txn,
            &applied.id,
            applied.verb,
            act,
            &applied.effect_digest,
            now,
        )?;
        decision.check_in = Some(applied.id.to_hex());
        decision.requester = Some(requester.to_hex());
    }
    Ok(decision)
}

/// The digest of the Owner's one "Lift the hold and erase?" confirm over
/// `records`, and the claim-free gate-decision partition with
/// `claim_free_partition`: the effect an asker's `vault.check_in.open` names
/// for `vault.legal_holds.lift_and_erase`, and the one the confirm spends
/// (2k2; P25-SHAPE Q1 = A). The order of `records` and a repeat do not
/// change it. BLAKE3, key derived from `oneiron check_in legal hold erase
/// v1`, over the count of distinct records as eight big-endian bytes, their
/// 16 id bytes each in id order, and one byte, 1 when the confirm releases
/// the claim-free partition.
#[must_use]
pub fn legal_hold_erase_effect_digest(
    records: &[EntityId],
    claim_free_partition: bool,
) -> [u8; 32] {
    let records: std::collections::BTreeSet<&EntityId> = records.iter().collect();
    let mut hasher = blake3::Hasher::new_derive_key("oneiron check_in legal hold erase v1");
    hasher.update(
        &u64::try_from(records.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for record in records {
        hasher.update(record.as_bytes());
    }
    hasher.update(&[u8::from(claim_free_partition)]);
    *hasher.finalize().as_bytes()
}

/// The digest of erasing `entity`'s text history through `through`, or
/// through the engine's own boundary when `None` (a NOTE's oldest pin, as
/// `vault.notes.history_purge` always asks): the effect an asker's
/// `vault.check_in.open` names for `vault.notes.history_purge`, and the one
/// the Owner's erase spends (2k2; P25-SHAPE Q1 = A). BLAKE3, key derived
/// from `oneiron check_in text history erase v1`, over the entity's 16 id
/// bytes, then one byte 0, or one byte 1, the frontier's length as eight
/// big-endian bytes and its bytes.
#[must_use]
pub fn text_history_erase_effect_digest(entity: &EntityId, through: Option<&[u8]>) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron check_in text history erase v1");
    hasher.update(entity.as_bytes());
    match through {
        Some(frontier) => {
            let len = u64::try_from(frontier.len()).unwrap_or(u64::MAX);
            hasher
                .update(&[1])
                .update(&len.to_be_bytes())
                .update(frontier)
        }
        None => hasher.update(&[0]),
    };
    *hasher.finalize().as_bytes()
}

/// The digest of erasing the frozen request of outbound call `call_seq` of
/// attempt `attempt`: the effect an asker's `vault.check_in.open` names for
/// `vault.outbound_calls.request.erase`, and the one the Owner's erase
/// spends (2k2; P25-SHAPE Q1 = A). BLAKE3, key derived from `oneiron
/// check_in outbound call request erase v1`, over the attempt's 16 id bytes
/// and the call's sequence as eight big-endian bytes.
#[must_use]
pub fn outbound_call_request_erase_effect_digest(attempt: &EntityId, call_seq: u64) -> [u8; 32] {
    let mut hasher =
        blake3::Hasher::new_derive_key("oneiron check_in outbound call request erase v1");
    hasher.update(attempt.as_bytes());
    hasher.update(&call_seq.to_be_bytes());
    *hasher.finalize().as_bytes()
}

/// The digest of the Owner's root `change` for install `target`: the effect
/// an asker's `vault.check_in.open` names for `vault.roots.requests.create`,
/// and the one the recorded request spends (2k3; P25-SHAPE Q1 = A). BLAKE3,
/// key derived from `oneiron check_in root request v1`, over the target's 16
/// id bytes, the change's wire tag's length as one byte and its bytes, one
/// byte 1 and the root's 32 bytes or one byte 0, and one byte 1 and the
/// anchored machine's 16 id bytes or one byte 0.
#[must_use]
pub fn root_request_effect_digest(target: &EntityId, change: RootChange) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron check_in root request v1");
    hasher.update(target.as_bytes());
    let tag = change.as_str().as_bytes();
    hasher
        .update(&[u8::try_from(tag.len()).unwrap_or(u8::MAX)])
        .update(tag);
    match change.root() {
        Some(root) => hasher.update(&[1]).update(&root.0),
        None => hasher.update(&[0]),
    };
    match change {
        RootChange::Anchor { machine, .. } => hasher.update(&[1]).update(machine.as_bytes()),
        RootChange::Pin { .. } | RootChange::Activate | RootChange::Restore { .. } => {
            hasher.update(&[0])
        }
    };
    *hasher.finalize().as_bytes()
}

/// The digest of the Owner's reset of every `factor` step-up factor `person`
/// enrolled: the effect an asker's `vault.check_in.open` names for
/// `vault.step_up.passkeys.reset` (passkeys) and `vault.step_up.totp.reset`
/// (authenticator apps), and the one the reset spends (2k3; P25-SHAPE Q1 =
/// A). BLAKE3, key derived from `oneiron check_in step up reset v1`, over
/// the person's 16 id bytes and one byte, 0 for passkeys and 1 for
/// authenticator apps.
#[must_use]
pub fn step_up_reset_effect_digest(person: &EntityId, factor: StepUpFactor) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron check_in step up reset v1");
    hasher.update(person.as_bytes());
    hasher.update(&[match factor {
        StepUpFactor::Passkey => 0,
        StepUpFactor::Totp => 1,
    }]);
    *hasher.finalize().as_bytes()
}

/// The decision an Owner's own act on a catastrophe row runs on when its
/// effect lands outside the vault's writer (a custody journal; 2k3,
/// P25-SHAPE Q1 = A): the Owner on their own proof, and with `applied` the
/// asker's approved check-in, spent in a writer of its own on the Owner's
/// live proof before the act runs, as the NOTE history purge spends it
/// (2k2). A refusal after it leaves the approval spent.
///
/// # Errors
///
/// The Owner's proof no longer holds; as [`spend_applied_check_in_in_txn`].
pub(crate) fn owner_act_decision_in_own_writer(
    vault: &Vault,
    owner: &crate::consent::AuthenticatedOwner,
    act: ActClass,
    applied: Option<&AppliedCheckIn<'_>>,
) -> Result<CheckInDecision> {
    match applied {
        Some(applied) => vault.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(vault, txn)?;
            owner_act_decision_in_txn(vault, txn, act, Some(applied))
        }),
        None => Ok(owner_own_proof_decision(act)),
    }
}

/// The digest of draining custody member `target_id` out of the required
/// set: the effect an asker's `vault.check_in.open` names for
/// `vault.custody.members.drain.begin`, `.drain.commit` (the ack's member)
/// and `.drain.folder`, and the one that door spends (2k3; P25-SHAPE Q1 =
/// A). BLAKE3, key derived from `oneiron check_in custody drain v1`, over
/// the id's length as one byte and its bytes.
#[must_use]
pub fn custody_drain_effect_digest(target_id: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron check_in custody drain v1");
    update_short_text(&mut hasher, target_id);
    *hasher.finalize().as_bytes()
}

/// The digest of re-enrolling `spec`, a drained custody member: the effect
/// an asker's `vault.check_in.open` names for
/// `vault.custody.members.reenrol`, and the one the re-enrolment spends
/// (2k3; P25-SHAPE Q1 = A). BLAKE3, key derived from `oneiron check_in
/// custody reenrol v1`, over the member's id and its kind's name, each as
/// its length in one byte and its bytes, and one byte, 0 when it holds heads
/// and the log, 1 for the log alone.
#[must_use]
pub fn custody_reenrol_effect_digest(spec: &TargetSpec) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron check_in custody reenrol v1");
    update_short_text(&mut hasher, spec.id().as_str());
    update_short_text(&mut hasher, spec.kind().name());
    hasher.update(&[match spec.scope {
        TargetScope::HeadAndLog => 0,
        TargetScope::LogOnly => 1,
    }]);
    *hasher.finalize().as_bytes()
}

/// The digest of an Owner policy row change: the effect an asker's
/// `vault.check_in.open` names for `vault.policy.owner.row.change`, and the
/// one the Owner's change spends (2k4; P25-SHAPE Q1 = A). BLAKE3, key
/// derived from `oneiron check_in policy row change v1`, over the change's
/// MessagePack encoding with field names, as the change ledger keeps it.
///
/// # Errors
///
/// The change does not encode.
pub fn policy_row_change_effect_digest(change: &PolicyRowChange) -> Result<[u8; 32]> {
    let encoded = rmp_serde::to_vec_named(change)
        .map_err(|_| Error::InvariantViolation("policy row change encode"))?;
    let mut hasher = blake3::Hasher::new_derive_key("oneiron check_in policy row change v1");
    hasher.update(&encoded);
    Ok(*hasher.finalize().as_bytes())
}

/// The reason code of an agent's act refused at a person's door, naming the
/// route it takes instead: it asks through `vault.check_in.open`, and the
/// vault's Owner applies the approved ask (Engine ruling PEN-COMPLIANCE-SET
/// = A; P25-SHAPE Q1: no agent path into an Owner's door before PR 4).
pub const CHECK_IN_OPEN_ROUTE_REASON: &str = "check_in.route:vault.check_in.open";

/// The digest of turning org compliance search on or off (`enabled`) for
/// `purpose`: the effect `vault.mail.compliance.set` judges, and the one an
/// approved check-in for it spends (2k4; P25-SHAPE Q1 = A). BLAKE3, key
/// derived from `oneiron check_in mail compliance set v1`, over one byte, 1
/// to turn it on, the purpose's length as eight big-endian bytes and its
/// bytes.
#[must_use]
pub fn mail_compliance_set_effect_digest(enabled: bool, purpose: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron check_in mail compliance set v1");
    hasher
        .update(&[u8::from(enabled)])
        .update(
            &u64::try_from(purpose.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        )
        .update(purpose.as_bytes());
    *hasher.finalize().as_bytes()
}

/// `text`'s length as one byte (at most 255; custody ids are at most 128)
/// and its bytes.
fn update_short_text(hasher: &mut blake3::Hasher, text: &str) {
    hasher
        .update(&[u8::try_from(text.len()).unwrap_or(u8::MAX)])
        .update(text.as_bytes());
}

/// The digest of deleting `record` for `reason`: the effect a person's
/// `vault.delete` judges, and the one an approved check-in for it spends
/// (2k5; P25-SHAPE Q1 = A). BLAKE3, key derived from `oneiron check_in
/// record delete v1`, over the record's 16 id bytes and the reason's wire
/// token, as its length in one byte and its bytes.
#[must_use]
pub fn record_delete_effect_digest(
    record: &EntityId,
    reason: crate::deletion::DeleteReason,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron check_in record delete v1");
    hasher.update(record.as_bytes());
    update_short_text(&mut hasher, reason.as_str());
    *hasher.finalize().as_bytes()
}

/// The digest of deleting stored embedding space probe `probe`: the effect
/// an asker's `vault.check_in.open` names for
/// `vault.embedding_spaces.probes.delete`, and the one the Owner's delete
/// spends (2k5; P25-SHAPE Q1 = A). BLAKE3, key derived from `oneiron
/// check_in embedding space probe delete v1`, over the probe's 16 id bytes.
#[must_use]
pub fn embedding_space_probe_delete_effect_digest(probe: &[u8; 16]) -> [u8; 32] {
    let mut hasher =
        blake3::Hasher::new_derive_key("oneiron check_in embedding space probe delete v1");
    hasher.update(probe);
    *hasher.finalize().as_bytes()
}

/// The digest of deleting the cleanup-archived completed attempt `attempt`:
/// the effect an Admin's or a Deputy's `vault.archive.attempt.delete.confirm`
/// is judged over (2k5e; P25-SHAPE Q1 = A). The confirm's own expectation
/// binds the exact queue bytes in the same writer. BLAKE3, key derived from
/// `oneiron check_in attempt archive delete v1`, over the attempt's 16 id
/// bytes.
#[must_use]
pub fn attempt_archive_delete_effect_digest(attempt: &[u8; 16]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron check_in attempt archive delete v1");
    hasher.update(attempt);
    *hasher.finalize().as_bytes()
}

/// The digest of sending signing document `document`, whose recipients the
/// caller counted as `recipient_count`, for signature: the effect a person's
/// `vault.esign.send_for_signature` is judged over (2k6a; P25-SHAPE Q1 = A).
/// Only the create door drafts a document, on an artifact no draft holds
/// yet, so the id binds the draft the asker sent, and a document sends once.
/// BLAKE3, key derived from `oneiron check_in esign legal send v1`, over the
/// document's 16 id bytes and the count as eight big-endian bytes.
#[must_use]
pub fn legal_send_effect_digest(document: &EntityId, recipient_count: usize) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron check_in esign legal send v1");
    hasher.update(document.as_bytes());
    hasher.update(&(recipient_count as u64).to_be_bytes());
    *hasher.finalize().as_bytes()
}

/// The digest of completing recipient `recipient`'s signature on signing
/// document `document` as the vault's principal: the effect a member's
/// `vault.esign.signing.act` Complete is judged over (2k6b; P25-SHAPE Q1 =
/// A). BLAKE3, key derived from `oneiron check_in esign sign v1`, over the
/// document's 16 id bytes, then the recipient id's length as eight
/// big-endian bytes and its UTF-8 bytes.
#[must_use]
pub fn sign_effect_digest(document: &EntityId, recipient: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron check_in esign sign v1");
    hasher.update(document.as_bytes());
    hasher.update(&(recipient.len() as u64).to_be_bytes());
    hasher.update(recipient.as_bytes());
    *hasher.finalize().as_bytes()
}

/// The digest of converting slip `slip` into its holder's default read
/// Grants: the effect an asker's `vault.check_in.open` names for
/// `vault.agents.grants.from_slip`, and the one the Owner's conversion
/// spends (2k7; P25-SHAPE Q1 = A). The Grants minted are the holder's live
/// slips' Scopes as the Owner's writer reads them. BLAKE3, key derived from
/// `oneiron check_in agent grant from slip v1`, over the slip's 32 id
/// bytes.
#[must_use]
pub fn agent_grant_from_slip_effect_digest(slip: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron check_in agent grant from slip v1");
    hasher.update(slip);
    *hasher.finalize().as_bytes()
}

/// The digest of giving base agent `agent` its default grant back: the
/// effect an asker's `vault.check_in.open` names for
/// `vault.agents.grants.restore`, and the one the Owner's grant back spends
/// (2k7; P25-SHAPE Q1 = A). BLAKE3, key derived from `oneiron check_in
/// agent grant restore v1`, over the agent principal's 16 id bytes.
#[must_use]
pub fn agent_grant_restore_effect_digest(agent: &EntityId) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron check_in agent grant restore v1");
    hasher.update(agent.as_bytes());
    *hasher.finalize().as_bytes()
}

/// The digest of minting the standing consent grant over `bound`: the
/// effect an asker's `vault.check_in.open` names for
/// `vault.consent.create_standing_grant` or for an auto answer to
/// `vault.consent.graduation.answer`, and the one the Owner's mint spends
/// (2k8; P25-SHAPE Q1 = A). BLAKE3, key derived from `oneiron check_in
/// standing grant v1`, over the bound's own digest, the grant ref its
/// receipt names: two requests that normalize to one bound are one effect.
#[must_use]
pub fn standing_grant_effect_digest(bound: &crate::consent::GrantBound) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron check_in standing grant v1");
    hasher.update(bound.digest().as_bytes());
    *hasher.finalize().as_bytes()
}

/// The decision of a person's `act` at a door no role that reaches it waits
/// at, judged in the door's writer `txn` at `now` (2k8e3; P25-SHAPE Q1 =
/// A): the Owner's act goes on their own proof, and every other role's by
/// [`person_door_check_in_in_txn`] under the role it holds. The door takes
/// no `check_in_ref`, so a judge that would wait opens nothing: the pending
/// check-in it opened is refused with the writer.
///
/// # Errors
///
/// A role that does not hold the power, or one that would wait; storage
/// errors.
pub(crate) fn person_door_go_decision_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    act: &DoorAct<'_>,
    now: u64,
) -> Result<CheckInDecision> {
    if act.role == RolePreset::Owner {
        return Ok(owner_own_proof_decision(act.act));
    }
    match person_door_check_in_in_txn(vault, txn, act, None, now)? {
        DoorCheckIn::Go(decision) => Ok(decision),
        DoorCheckIn::Wait(_) => Err(refuse(
            "the act would wait, and its door applies no check-in",
        )),
    }
}

/// The digest of a one-hop Delegate grant from admin grant `parent_grant`
/// to `member_ref`, narrowed to `authority_scope` (`None`: the ceiling the
/// parent and the vault's Delegate default meet at), expiring at
/// `expires_at`: the effect a holder's `vault.members.delegate` is judged
/// over (2k8e3; P25-SHAPE Q1 = A). BLAKE3, key derived from `oneiron
/// check_in members delegate v1`, over the parent's and the member's 16 id
/// bytes, the expiry as eight big-endian bytes, then one byte, 1 when a
/// scope is named, and the scope's MessagePack encoding with field names.
///
/// # Errors
///
/// The scope does not encode.
pub fn members_delegate_effect_digest(
    parent_grant: &EntityId,
    member_ref: &EntityId,
    authority_scope: Option<&crate::federation::Scope>,
    expires_at: u64,
) -> Result<[u8; 32]> {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron check_in members delegate v1");
    hasher
        .update(parent_grant.as_bytes())
        .update(member_ref.as_bytes())
        .update(&expires_at.to_be_bytes())
        .update(&[u8::from(authority_scope.is_some())]);
    if let Some(scope) = authority_scope {
        let encoded = rmp_serde::to_vec_named(scope)
            .map_err(|_| Error::InvariantViolation("delegate scope encode"))?;
        hasher.update(&encoded);
    }
    Ok(*hasher.finalize().as_bytes())
}

/// The digest of proposing `policy` for shared act `act` of shared vault
/// `vault_id` (`None` removes the vault's own row), against the rows whose
/// digest is `expected_policy_hash`: the effect an editor's
/// `vault.shared.policy.propose` is judged over (2k8e3; P25-SHAPE Q1 = A).
/// BLAKE3, key derived from `oneiron check_in shared policy propose v1`,
/// over the vault id as eight big-endian bytes, the act's and then the
/// hash's length as eight big-endian bytes and its UTF-8 bytes, then one
/// byte, 1 when a row is named, and the row's MessagePack encoding with
/// field names.
///
/// # Errors
///
/// The row does not encode.
pub fn shared_policy_propose_effect_digest(
    vault_id: u64,
    act: &str,
    policy: Option<&crate::federation::SharedActPolicy>,
    expected_policy_hash: &str,
) -> Result<[u8; 32]> {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron check_in shared policy propose v1");
    hasher.update(&vault_id.to_be_bytes());
    for text in [act, expected_policy_hash] {
        hasher.update(&(text.len() as u64).to_be_bytes());
        hasher.update(text.as_bytes());
    }
    hasher.update(&[u8::from(policy.is_some())]);
    if let Some(row) = policy {
        let encoded = rmp_serde::to_vec_named(row)
            .map_err(|_| Error::InvariantViolation("shared policy row encode"))?;
        hasher.update(&encoded);
    }
    Ok(*hasher.finalize().as_bytes())
}

/// The digest of sharing mail thread `thread`, the thread audience policy
/// the share's `record_ref` resolves to in its writer, with PERSON `person`:
/// the effect a member's `vault.mail.threads.share` of another's thread is
/// judged over (2k8f2; P25-SHAPE Q1 = A). Every row of a thread names one
/// share. BLAKE3, key derived from `oneiron check_in mail thread share v1`,
/// over the thread policy's and the person's 16 id bytes.
#[must_use]
pub fn mail_thread_share_effect_digest(thread: &EntityId, person: &EntityId) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron check_in mail thread share v1");
    hasher.update(thread.as_bytes()).update(person.as_bytes());
    *hasher.finalize().as_bytes()
}

/// The digest of opening ordinary room `room`'s shared pins to every
/// current member: the effect a member's `vault.rooms.pins.policy.set` to
/// `members` on a room another created is judged over (2k8f; P25-SHAPE Q1
/// = A). BLAKE3, key derived from `oneiron check_in room pins open v1`,
/// over the room's 16 id bytes.
#[must_use]
pub fn room_pins_open_effect_digest(room: &EntityId) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron check_in room pins open v1");
    hasher.update(room.as_bytes());
    *hasher.finalize().as_bytes()
}
