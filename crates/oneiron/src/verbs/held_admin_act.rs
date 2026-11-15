//! The org two-admin rule's verbs (UNBUILT-06 PR 2; Engine RULING
//! UNBUILT06-SHAPE Q2 = A): every admin verb that fronts a held power act
//! keeps its call as written ([`HeldVerbCall`]), and when the gate holds the
//! act, stores it and answers `ADMIN_ACT_HELD` naming it. A second, distinct
//! live admin approves it (`vault.members.held.approve`), which re-runs the
//! same verb with the same input under the approver's own proof; the first
//! admin may withdraw it (`vault.members.held.withdraw`); the admins list
//! them (`vault.members.held`). An admin act no verb here fronts (a
//! Memory-tier verb such as `vault.members.reset_project_access` or
//! `vault.workspace.work_companion.set`, or a REST door) refuses with the
//! hold's own reason, `two_admin_hold`: it must be made by an Owner.
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::authority::HostSlipIssuer;
use crate::consent::AuthenticatedOwner;
use crate::federation::HeldAdminAct;
use crate::memory::{
    ADMIN_ACT_HELD_REASON_PREFIX, MEMORY_CODE_ADMIN_ACT_HELD, MemoryError, MemoryResult,
    TWO_ADMIN_HOLD_REASON_CODE,
};

/// `vault.members.held.approve`'s and `vault.members.held.withdraw`'s input:
/// the shared vault and the held act.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HeldAdminActRequest {
    #[serde(with = "crate::federation::vault_id_decimal")]
    #[schemars(with = "String")]
    pub vault_id: u64,
    /// The held act's id, 32 hex: the `admin_act:` reason code names it.
    pub held: String,
}

/// `vault.members.held.approve`'s answer: the act, now landed, and its
/// verb's own answer to the approver's re-run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeldAdminActApproved {
    pub act: HeldAdminAct,
    pub output: serde_json::Value,
}

/// One call of an admin verb as written, kept until its answer.
pub(crate) struct HeldVerbCall {
    verb: &'static str,
    input: serde_json::Value,
}

impl HeldVerbCall {
    pub(crate) fn new(verb: &'static str, input: &impl Serialize) -> MemoryResult<Self> {
        let input = serde_json::to_value(input)
            .map_err(|_| MemoryError::bad_request("the input does not encode"))?;
        Ok(Self { verb, input })
    }

    /// The call's answer. A refusal by the org two-admin rule holds the act:
    /// it is stored as written under `caller`, its first admin, and the call
    /// answers `ADMIN_ACT_HELD` naming it. An approved re-run's refusal is
    /// answered as it is, so an approve never holds a second act.
    pub(crate) fn answer<T>(
        self,
        vault: &Vault,
        caller: &AuthenticatedOwner,
        answer: MemoryResult<T>,
    ) -> MemoryResult<T> {
        match answer {
            Err(err)
                if err
                    .reason_codes
                    .iter()
                    .any(|code| code == TWO_ADMIN_HOLD_REASON_CODE)
                    && crate::federation::current_held_admin_approval().is_none() =>
            {
                let first_admin = caller.revalidate_person(vault)?;
                let act = vault.hold_admin_act(first_admin, self.verb, self.input)?;
                Err(held(&act))
            }
            answer => answer,
        }
    }
}

/// The `ADMIN_ACT_HELD` answer naming `act`.
fn held(act: &HeldAdminAct) -> MemoryError {
    MemoryError {
        reason_codes: vec![format!("{ADMIN_ACT_HELD_REASON_PREFIX}{}", act.id)],
        ..MemoryError::new(
            MEMORY_CODE_ADMIN_ACT_HELD,
            format!(
                "{} waits for a second admin: this shared vault's two-admin rule is on, and \
                 nothing ran",
                act.verb
            ),
            &[
                "Do not call again: another live Owner, Admin or Deputy approves the held act its reason code names, which runs it.",
                "Withdraw it with vault.members.held.withdraw while it waits.",
            ],
        )
    }
}

fn decode<T: DeserializeOwned>(input: serde_json::Value) -> MemoryResult<T> {
    serde_json::from_value(input)
        .map_err(|_| MemoryError::bad_request("the held act's input no longer decodes"))
}

fn encode<T: Serialize>(output: T) -> MemoryResult<serde_json::Value> {
    serde_json::to_value(output)
        .map_err(|_| MemoryError::bad_request("the held act's answer does not encode"))
}

/// The held verb `verb` again, with `input`, under `approver`'s own proof.
fn rerun(
    vault: &Vault,
    approver: &AuthenticatedOwner,
    slips: Option<&HostSlipIssuer>,
    verb: &str,
    input: serde_json::Value,
) -> MemoryResult<serde_json::Value> {
    match verb {
        "vault.members.add" => encode(super::add_shared_member_as(
            vault,
            approver,
            decode(input)?,
        )?),
        "vault.members.change" => encode(super::change_shared_member_as(
            vault,
            approver,
            slips,
            decode(input)?,
        )?),
        "vault.members.remove" => encode(super::remove_shared_member_as(
            vault,
            approver,
            slips,
            decode(input)?,
        )?),
        "vault.members.withdraw_invitation" => encode(super::withdraw_shared_invitation_as(
            vault,
            approver,
            decode(input)?,
        )?),
        "vault.members.asks.apply" => encode(super::apply_shared_member_ask_as(
            vault,
            approver,
            slips,
            decode(input)?,
        )?),
        "vault.members.delegate" => encode(super::create_federation_delegate_as(
            vault,
            approver,
            decode(input)?,
        )?),
        "vault.workspace.establish" => encode(super::establish_workspace_as(
            vault,
            approver,
            decode(input)?,
        )?),
        "vault.workspace.members.onboard" => encode(super::onboard_workspace_member_as(
            vault,
            approver,
            decode(input)?,
        )?),
        _ => Err(MemoryError::bad_request("not a held admin verb")),
    }
}

/// `vault.members.held.approve`: a second, distinct live Owner, Admin or
/// Deputy approves an open held act before it lapses. Its verb runs again,
/// with its stored input, under the approver's own proof and the host's
/// slip issuer: every check of that verb's door holds, and its receipt
/// names the approver as `actor` and the first admin as `proposer`. A
/// refused re-run leaves the act open.
pub fn approve_held_admin_act_as(
    vault: &Vault,
    approver: &AuthenticatedOwner,
    slips: Option<&HostSlipIssuer>,
    input: HeldAdminActRequest,
) -> MemoryResult<HeldAdminActApproved> {
    let (act, approval) = vault.claim_held_admin_act(approver, input.vault_id, &input.held)?;
    let output = crate::federation::run_approved_admin_act(approval, || {
        rerun(vault, approver, slips, &act.verb, act.input.clone())
    });
    let act = vault.settle_held_admin_act(approval, output.is_ok())?;
    Ok(HeldAdminActApproved {
        act,
        output: output?,
    })
}

/// `vault.members.held.withdraw`: the first admin takes an open held act
/// back; it lands no more.
pub fn withdraw_held_admin_act_as(
    vault: &Vault,
    first_admin: &AuthenticatedOwner,
    input: HeldAdminActRequest,
) -> MemoryResult<HeldAdminAct> {
    Ok(vault.withdraw_held_admin_act(first_admin, input.vault_id, &input.held)?)
}

/// `vault.members.held`: every held act of a shared vault, for a live
/// Owner, Admin or Deputy there.
pub fn read_held_admin_acts(
    vault: &Vault,
    reader: &AuthenticatedOwner,
    input: super::SharedVaultRequest,
) -> MemoryResult<Vec<HeldAdminAct>> {
    Ok(vault.held_admin_acts(reader, input.vault_id)?)
}
