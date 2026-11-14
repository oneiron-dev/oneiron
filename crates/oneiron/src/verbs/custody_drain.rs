//! The owner's custody member drain as typed rows (FIX 11274; the doors
//! ruled 10-20, FIX 5843): `vault.custody.members.drain.begin`,
//! `vault.custody.members.drain.commit`, `vault.custody.members.drain.folder`
//! and `vault.custody.members.reenrol`. Each runs the engine door of the
//! same name under the owner's proof, which the door checks again in its
//! own read. A member leaves the required set only by its own deletion ack,
//! never by a forced unpin, and comes back only by the owner's re-enrolment.
//!
//! The begun drain's ticket carries the drain's generation token: the key
//! the member MACs its ack with, for the member's own adapter on its own
//! authenticated channel. `Debug` never prints it, and it is wiped when the
//! reply drops.
//!
//! Each door takes `check_in_ref` and answers the check-in decision it ran
//! on (2k3; P25-SHAPE Q1 = A): the Owner on their own proof, and with
//! `check_in_ref` an asker's approved check-in for that door's effect,
//! which the Owner applies. The custody journal is no vault writer, so the
//! check-in is spent in a writer of its own before the door acts.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::check_in::{
    ActClass, AppliedCheckIn, CheckInDecision, custody_drain_effect_digest,
    custody_reenrol_effect_digest, owner_act_decision_in_own_writer,
};
use crate::consent::AuthenticatedOwner;
use crate::memory::{MemoryError, MemoryResult};
use crate::store::custody_protocol::{AckPosition, TargetId, TargetKind, TargetSpec};
use crate::{EntityId, Vault};

/// The prefix of a residence member's id: `residence:<machine hex>`.
const RESIDENCE_PREFIX: &str = "residence:";

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::custody_drain::{
    CustodyDrainCommitRequest, CustodyMemberReenrolRequest, CustodyMemberRef,
};

/// A begun drain: what the member's ack must name, and the token it MACs
/// the ack with. A retry before the set changes returns the same ticket.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyDrainTicketView {
    /// The member being drained.
    pub target_id: String,
    /// The set revision it is drained out of.
    pub set_revision: u64,
    /// The local log position the drain began at.
    pub position: AckPosition,
    /// The drain's operation id, 64 hex.
    pub operation_id: String,
    /// The drain's generation token, 64 hex: for the member's own adapter.
    pub token: String,
    /// The check-in decision the begin ran on (2k3): the Owner on their own
    /// proof, and the approved check-in of another asker it applied, with
    /// its requester.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_in: Option<CheckInDecision>,
}

impl Drop for CustodyDrainTicketView {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

impl std::fmt::Debug for CustodyDrainTicketView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustodyDrainTicketView")
            .field("target_id", &self.target_id)
            .field("set_revision", &self.set_revision)
            .field("position", &self.position)
            .field("operation_id", &self.operation_id)
            .field("check_in", &self.check_in)
            .finish_non_exhaustive()
    }
}

/// The required set's revision after the owner's change, and the check-in
/// decision the change ran on (2k3): the Owner on their own proof, and the
/// approved check-in of another asker it applied, with its requester.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodySetRevision {
    pub revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_in: Option<CheckInDecision>,
}

fn target_id(id: &str) -> MemoryResult<TargetId> {
    TargetId::new(id).map_err(|_| {
        MemoryError::bad_request("target_id is `<kind>:<name>`, lowercase, at most 128 bytes")
    })
}

/// The check-in decision door `verb` runs on: the Owner on their own proof,
/// and with `check_in_ref` an asker's approved check-in for `verb` over
/// `effect_digest`, spent in a writer of its own before the door acts.
fn key_recovery_decision(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    verb: &'static str,
    check_in_ref: Option<&str>,
    effect_digest: [u8; 32],
) -> MemoryResult<CheckInDecision> {
    let applied = super::shared::check_in_ref(check_in_ref)?.map(|id| AppliedCheckIn {
        id,
        verb,
        effect_digest,
    });
    Ok(owner_act_decision_in_own_writer(
        vault,
        owner,
        ActClass::KeyRecovery,
        applied.as_ref(),
    )?)
}

/// `vault.custody.members.drain.begin`: fences the member at once and
/// returns the ticket its ack must name.
///
/// # Errors
/// Every refusal of [`Vault::begin_custody_member_drain_as`]; a
/// `check_in_ref` that is no check-in id, or names no approved, unspent
/// check-in for this door's effect.
pub fn custody_member_drain_begin_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: CustodyMemberRef,
) -> MemoryResult<CustodyDrainTicketView> {
    let target = target_id(&input.target_id)?;
    let check_in = key_recovery_decision(
        vault,
        owner,
        "vault.custody.members.drain.begin",
        input.check_in_ref.as_deref(),
        custody_drain_effect_digest(target.as_str()),
    )?;
    let ticket = vault.begin_custody_member_drain_as(owner, &target)?;
    Ok(CustodyDrainTicketView {
        target_id: ticket.target_id.as_str().to_owned(),
        set_revision: ticket.set_revision,
        position: AckPosition::of(&ticket.position),
        operation_id: hex(&ticket.operation_id),
        token: hex(ticket.token.expose()),
        check_in: Some(check_in),
    })
}

/// `vault.custody.members.drain.commit`: takes the member out of the set at
/// the next revision once its ack names exactly its begun drain.
///
/// # Errors
/// Every refusal of [`Vault::commit_custody_member_drain_as`]; a
/// `check_in_ref` that is no check-in id, or names no approved, unspent
/// check-in for this door's effect.
pub fn custody_member_drain_commit_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: CustodyDrainCommitRequest,
) -> MemoryResult<CustodySetRevision> {
    let check_in = key_recovery_decision(
        vault,
        owner,
        "vault.custody.members.drain.commit",
        input.check_in_ref.as_deref(),
        custody_drain_effect_digest(&input.ack.target_id),
    )?;
    let revision = vault.commit_custody_member_drain_as(owner, &input.ack)?;
    Ok(CustodySetRevision {
        revision,
        check_in: Some(check_in),
    })
}

/// `vault.custody.members.drain.folder`: drains a folder member here, this
/// install being its adapter.
///
/// # Errors
/// Every refusal of [`Vault::drain_custody_folder_member_as`]; a
/// `check_in_ref` that is no check-in id, or names no approved, unspent
/// check-in for this door's effect.
pub fn custody_folder_member_drain_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: CustodyMemberRef,
) -> MemoryResult<CustodySetRevision> {
    let target = target_id(&input.target_id)?;
    let check_in = key_recovery_decision(
        vault,
        owner,
        "vault.custody.members.drain.folder",
        input.check_in_ref.as_deref(),
        custody_drain_effect_digest(target.as_str()),
    )?;
    let revision = vault.drain_custody_folder_member_as(owner, &target)?;
    Ok(CustodySetRevision {
        revision,
        check_in: Some(check_in),
    })
}

/// `vault.custody.members.reenrol`: adds a member the owner drained back
/// at the next revision; a member already in the set keeps its revision.
///
/// # Errors
/// An input that names no member, or both an id and a folder; every refusal
/// of [`Vault::reenrol_custody_member_as`]; a `check_in_ref` that is no
/// check-in id, or names no approved, unspent check-in for this re-enrolment.
pub fn custody_member_reenrol_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: CustodyMemberReenrolRequest,
) -> MemoryResult<CustodySetRevision> {
    let spec = reenrolled_spec(&input)?;
    let check_in = key_recovery_decision(
        vault,
        owner,
        "vault.custody.members.reenrol",
        input.check_in_ref.as_deref(),
        custody_reenrol_effect_digest(&spec),
    )?;
    let revision = vault.reenrol_custody_member_as(owner, &spec)?;
    Ok(CustodySetRevision {
        revision,
        check_in: Some(check_in),
    })
}

/// The member `input` names.
fn reenrolled_spec(input: &CustodyMemberReenrolRequest) -> MemoryResult<TargetSpec> {
    match (input.target_id.as_deref(), input.folder.as_deref()) {
        (None, Some(folder)) => {
            let folder = PathBuf::from(folder);
            if !folder.is_absolute() {
                return Err(MemoryError::bad_request(
                    "folder is the member's absolute folder on this install",
                ));
            }
            Ok(TargetSpec::of_folder(folder))
        }
        (Some(id), None) => match id.strip_prefix(RESIDENCE_PREFIX) {
            Some(home) => {
                target_id(id)?;
                let home = EntityId::from_hex(home).map_err(|_| {
                    MemoryError::bad_request("a residence member is `residence:<machine hex>`")
                })?;
                Ok(TargetSpec::residence(home))
            }
            None => {
                let spec = TargetSpec::declared(id)
                    .map_err(|error| MemoryError::bad_request(format!("target_id: {error}")))?;
                Ok(match (spec.kind(), input.scope) {
                    (TargetKind::Hosted(kind), Some(scope)) => {
                        TargetSpec::hosted(spec.id().clone(), kind, scope)
                    }
                    _ => spec,
                })
            }
        },
        _ => Err(MemoryError::bad_request(
            "name the member by target_id, or a folder member by folder",
        )),
    }
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
