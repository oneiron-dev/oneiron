//! An act on a vault setting and an owner's whole-vault export in the audit
//! (FIX 4624, FIX 5660). A setting act's subject is its target (the
//! setting's reserved target, or the agent a free-time policy is for) and
//! its detail the setting and whether it set or cleared it; an agent's act
//! names its agent as holder and its Grant. An export's subject is the owner
//! whose copy it was and its detail the format. Never a setting's value nor
//! a byte of the copy: the record keeps only their digests.
//!
//! Every op that records an owner act names that act's author on its row
//! (Engine RULING L6-03-CARRY-AUDIT-AUTHOR, 14 Nov 08:35): one of the vault's
//! owners, a person in their own right, or an agent and its Grant.

use std::collections::BTreeSet;

use super::{AuthorityAuditActAuthor, AuthorityAuditEventKind, OpFields};
use crate::EntityId;
use oneiron_authority::authority::{
    ActBy, AuthorityOp, ExportActRecord, OwnerAct, PolicySettingSet,
};

/// Who decided the owner act `op` records, if it records one. `owners` is
/// the vault's recorded Owner census in the page's snapshot
/// (`policy_model::recorded_owners_in_txn`).
pub(super) fn op_act_author(
    op: &AuthorityOp,
    owners: &BTreeSet<EntityId>,
) -> Option<AuthorityAuditActAuthor> {
    carried_owner_act(op).map(|act| act_author(op, act, owners))
}

/// The owner act `op` records, if it records one. No wildcard arm: a new op
/// says here whether its row names an author.
fn carried_owner_act(op: &AuthorityOp) -> Option<&OwnerAct> {
    match op {
        AuthorityOp::MachineProfile(profile) => profile.act.as_ref(),
        AuthorityOp::WorldPrivacy(edit) => Some(&edit.act),
        AuthorityOp::GrantTravelSet(set) => Some(&set.act),
        AuthorityOp::OwnerWorkRequest(request) => Some(&request.act),
        AuthorityOp::OwnerWorkCancel(cancel) => Some(&cancel.act),
        AuthorityOp::ExportSupplementImported(mark) => Some(&mark.act),
        AuthorityOp::CheckpointPolicySet(set) => Some(&set.act),
        AuthorityOp::HomeNodePick(pick) => Some(&pick.act),
        AuthorityOp::ConversationTrainingSet(set) => Some(&set.act),
        AuthorityOp::ConversationTrainingVaultSet(set) => Some(&set.act),
        AuthorityOp::AgentGrantAct(record) => Some(&record.act),
        AuthorityOp::PolicySettingSet(set) => Some(&set.act),
        AuthorityOp::ExportAct(record) => Some(&record.act),
        AuthorityOp::OwnerKeyEnroll(enroll) => Some(&enroll.act),
        AuthorityOp::OriginCut(cut) => Some(&cut.act),
        AuthorityOp::DeviceSuccession(succession) => Some(&succession.act),
        AuthorityOp::SlipMint(_)
        | AuthorityOp::SlipRevoke { .. }
        | AuthorityOp::SlipConsume { .. }
        | AuthorityOp::SlipGrantRevoke { .. }
        | AuthorityOp::RemovalArchiveConsume { .. }
        | AuthorityOp::Genesis { .. }
        | AuthorityOp::EnrollDevice { .. }
        | AuthorityOp::RevokeDevice { .. }
        | AuthorityOp::RotateKey { .. }
        | AuthorityOp::ReRoot { .. }
        | AuthorityOp::FederationConfirm(_)
        | AuthorityOp::CriticalWriteConfirm(_)
        | AuthorityOp::FederationLifecycle(_)
        | AuthorityOp::BindActor { .. }
        | AuthorityOp::RebindActor { .. }
        | AuthorityOp::RevokeActor { .. }
        | AuthorityOp::OwnerRoot(_)
        | AuthorityOp::WorldKeyWraps(_)
        | AuthorityOp::OwnerHandover(_)
        | AuthorityOp::ResidenceDirective(_)
        | AuthorityOp::ResidenceResult(_)
        | AuthorityOp::OwnerWorkResult(_)
        | AuthorityOp::CustodyPermitPiece(_)
        | AuthorityOp::HomeCandidacy(_)
        | AuthorityOp::FrontierJoin(_)
        | AuthorityOp::MembershipExecution(_) => None,
    }
}

/// Who decided `act`, which `op` records: an owner, a person in their own
/// right, never relabelled as an owner, or an agent under its Grant.
///
/// `by: Owner` also has the holder meaning (`OwnerActKind`): a person who
/// acted with a vault-wide power they hold, owning no vault (an Admin's
/// training setting, a policy holder's world edit, the key work it derives
/// or the inference defaults), or for themselves alone. So it reads as an
/// owner's act only while its person is one of `owners`, and never on a
/// person's own training opt-out, which is no owner act whoever makes it.
fn act_author(
    op: &AuthorityOp,
    act: &OwnerAct,
    owners: &BTreeSet<EntityId>,
) -> AuthorityAuditActAuthor {
    match act.by {
        ActBy::Owner
            if owners.contains(&act.owner)
                && !matches!(op, AuthorityOp::ConversationTrainingSet(_)) =>
        {
            AuthorityAuditActAuthor::Owner {
                owner: act.owner.to_hex(),
            }
        }
        ActBy::Owner | ActBy::Person => AuthorityAuditActAuthor::Person {
            person: act.owner.to_hex(),
        },
        ActBy::Agent { agent, grant } => AuthorityAuditActAuthor::Agent {
            owner: act.owner.to_hex(),
            agent: agent.to_hex(),
            grant: grant.to_hex(),
        },
    }
}

/// The class, op name and fields of one setting act.
pub(super) fn classify_policy_setting(
    set: &PolicySettingSet,
) -> (AuthorityAuditEventKind, &'static str, OpFields) {
    let (holder_ref, grant_ref) = match set.act.by {
        ActBy::Owner => (None, None),
        ActBy::Agent { agent, grant } => (Some(agent.to_hex()), Some(grant.to_hex())),
        // No setting takes a person's own act (`OwnerAct::validate_carried`);
        // were one stored, its row names the person who acted.
        ActBy::Person => (Some(set.act.owner.to_hex()), None),
    };
    let change = if set.value.is_some() { "set" } else { "clear" };
    (
        AuthorityAuditEventKind::Other,
        "policy_setting",
        OpFields {
            detail: Some(format!("{} {change}", set.setting.wire())),
            subject_ref: Some(set.act.target.to_hex()),
            grant_ref,
            holder_ref,
            ..OpFields::default()
        },
    )
}

/// The class, op name and fields of one export act.
pub(super) fn classify_export(
    record: &ExportActRecord,
) -> (AuthorityAuditEventKind, &'static str, OpFields) {
    (
        AuthorityAuditEventKind::Other,
        "export_act",
        OpFields {
            detail: Some(record.format.clone()),
            subject_ref: Some(record.act.owner.to_hex()),
            ..OpFields::default()
        },
    )
}
