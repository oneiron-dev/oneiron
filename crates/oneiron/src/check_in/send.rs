//! The send grant at the Gate (ARCH-0046 #send-grant and
//! #check-in-roles-20261110; PLAN L3-35 PR 1 and PR 2).
//!
//! The vault's grant for act class `outbound_send` is a `mode` row of the
//! `check_in` policy row ([`super::CheckInPolicy`]). Each agent send the Gate
//! judges checks in here once, under the vault's rows (an outbound send names
//! no world or project yet):
//! * `full-access` (`NeverAsk`) releases the send with no press;
//! * `manual` (`AlwaysAsk`) and `auto` (`AskWhenUnsure`, whose unsure test is
//!   [`AlwaysUnsure`] until a decision model judges agent acts) release
//!   nothing, so the Gate's other coverage or the press per send decides;
//! * with no row naming the class, the sender's role decides, by its column
//!   of ARCH-0082 #role-defaults (Engine ruling L3-35-ROLE: the role column
//!   in PR 2): an agent holding Owner sends with no press, a Deputy's send is
//!   `AskWhenUnsure`, every other role asks. The role is the agent's
//!   membership on this vault's shared vault, a house link's among them;
//!   Member when it records none, as in a vault that is not shared;
//! * an unreadable policy counts as `AlwaysAsk`.
//!
//! The grant also sets how the holder presses (PLAN L3-35 D5; Engine ruling
//! L3-35-BATCH = A): one press may approve a reviewed batch of several sends
//! only when the rows compose `manual` with `ask_per: batch`
//! ([`send_grant_presses_batch_in_txn`], read by the batch door
//! `Vault::approve_outbound_batch`); in every other case one press covers one
//! send.
//!
//! The Gate's decision record names the rows that decided and the answer, in
//! its receipt vocabulary (`check_in_row_<ref>`, `check_in_go_never_ask`).
//!
//! The row does not reach these sends; the Gate gives them no check-in:
//! * a person's own send: "a send from the actor's own identity is go"
//!   (ARCH-0082 #role-defaults); only the `agent` actor class checks in, so a
//!   mail-pack reply, which goes as its mailbox's person, keeps that person's
//!   press;
//! * a send from a member mailbox, a delegated identity: that mailbox is its
//!   person's (ARCH-0082 #data-owner-consent; Engine ruling L3-35-PRINCIPAL =
//!   A), and the engine records no principal on it, so its press per send
//!   stays;
//! * a native-mail cold send, or a recipient of a message that takes one: it
//!   keeps its own graduation (OF-399), as it keeps it from an envelope slot;
//! * a campaign leg: it names its pinned sender only as its actor (FIX 11641
//!   leaves its channel identity unset), so the Gate cannot tell a member
//!   mailbox or a cold recipient from it; the leg is judged as before the row.

use super::act_class::ActClass;
use super::asker::AlwaysUnsure;
use super::mode::CheckInMode;
use super::policy::{AskPer, CheckInPolicyRead, CheckInScope};
use super::resolve::{
    CheckInAnswer, CheckInRequest, GoReason, WaitReason, check_in, check_in_with_mode,
};
use super::role_preset::RolePreset;
use crate::EntityId;
use crate::error::Result;
use crate::gate::{ApprovalTarget, ExternalEffectGateInput};
use crate::store::Store;

/// The prefix of the covering ref a send row gives.
const SEND_ROW_REF_PREFIX: &str = "check_in:row:";

/// The prefix of the covering ref a role's default gives.
const SEND_ROLE_REF_PREFIX: &str = "check_in:role:";

/// The prefix of the receipt reason that names a send row (the decision
/// ledger's `check_in_row_` family; the row decoder bounds the ref to fit).
const SEND_ROW_REASON_PREFIX: &str = "check_in_row_";

/// The prefix of the receipt reason that names the sender's role when its
/// default decided (the decision ledger's `check_in_` family).
const SEND_ROLE_REASON_PREFIX: &str = "check_in_role_";

/// Where an agent send's mode came from.
#[derive(Clone, Debug, Eq, PartialEq)]
enum SendModeSource {
    /// The `mode` rows that set it, in manifest order.
    Rows(Vec<String>),
    /// No row names `outbound_send`: the sender's role's shipped default.
    RoleDefault(RolePreset),
    /// The resolved policy failed closed: `AlwaysAsk`.
    Unreadable,
}

/// The check-in's answer for one send.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SendAnswer {
    /// `NeverAsk`: the row releases the send.
    NeverAsk,
    /// The row releases nothing; the Gate's other coverage or the press
    /// decides.
    Wait(WaitReason),
}

/// One agent send's check-in at the Gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SendCheckIn {
    source: SendModeSource,
    answer: SendAnswer,
}

impl SendCheckIn {
    /// Whether the row releases the send.
    pub(crate) const fn releases(&self) -> bool {
        matches!(self.answer, SendAnswer::NeverAsk)
    }

    /// The covering ref of a send the check-in releases: `check_in:row:<ref>`
    /// of the first row that set its mode, or `check_in:role:<role>` when the
    /// sender's role's default did. The Gate puts it in the standing-grant
    /// slot, as it puts an envelope slot's consent grant ref there; nothing
    /// resolves it as an outbound grant id.
    pub(crate) fn release_grant_ref(&self) -> Option<String> {
        match (&self.source, self.answer) {
            (SendModeSource::Rows(row_refs), SendAnswer::NeverAsk) => row_refs
                .first()
                .map(|row_ref| format!("{SEND_ROW_REF_PREFIX}{row_ref}")),
            (SendModeSource::RoleDefault(role), SendAnswer::NeverAsk) => {
                Some(format!("{SEND_ROLE_REF_PREFIX}{}", role.as_str()))
            }
            _ => None,
        }
    }

    /// The Gate decision record's reasons, in the decision ledger's
    /// `check_in_` family: `check_in_row_<ref>` for each row that set the mode
    /// (or `check_in_shipped_default` and `check_in_role_<role>`, or
    /// `check_in_unreadable`), then the answer: `check_in_go_never_ask` or
    /// `check_in_wait_<reason>`.
    pub(crate) fn receipt_reasons(&self) -> Vec<String> {
        let mut reasons = match &self.source {
            SendModeSource::Rows(row_refs) => row_refs
                .iter()
                .map(|row_ref| format!("{SEND_ROW_REASON_PREFIX}{row_ref}"))
                .collect(),
            SendModeSource::RoleDefault(role) => vec![
                "check_in_shipped_default".to_owned(),
                format!("{SEND_ROLE_REASON_PREFIX}{}", role.as_str()),
            ],
            SendModeSource::Unreadable => vec!["check_in_unreadable".to_owned()],
        };
        reasons.push(match self.answer {
            SendAnswer::NeverAsk => "check_in_go_never_ask".to_owned(),
            SendAnswer::Wait(reason) => format!("check_in_wait_{}", reason.as_str()),
        });
        reasons
    }
}

/// The check-in of `effect` under `read`, when it is an agent's send the row
/// reaches; `None` for every other effect (module doc). `delegated_or_cold`:
/// the Gate found the send from a member mailbox, or a native-mail cold send,
/// or a recipient of a message that takes one. With no row naming the class,
/// the sender's role is read in the Gate's `txn` ([`sender_role_in_txn`]).
///
/// # Errors
///
/// The store's, reading the sender's membership and the vault's authority
/// fold.
pub(crate) fn send_check_in_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    read: CheckInPolicyRead<'_>,
    effect: &ExternalEffectGateInput,
    delegated_or_cold: bool,
) -> Result<Option<SendCheckIn>> {
    if effect.actor.actor_class != "agent"
        || effect.verb != "send"
        || delegated_or_cold
        || matches!(
            effect.provenance.approval_target,
            Some(ApprovalTarget::Campaign(_))
        )
    {
        return Ok(None);
    }
    let explicit = match read {
        CheckInPolicyRead::Unreadable => Some((CheckInMode::AlwaysAsk, SendModeSource::Unreadable)),
        CheckInPolicyRead::NoRow => None,
        CheckInPolicyRead::Row(policy) => policy
            .explicit_mode(ActClass::OutboundSend, &CheckInScope::default())
            .map(|explicit| (explicit.mode, SendModeSource::Rows(explicit.row_refs))),
    };
    let (source, answer) = match explicit {
        Some((mode, source)) => (
            source,
            check_in_with_mode(ActClass::OutboundSend, mode, None, &AlwaysUnsure),
        ),
        None => {
            let role = sender_role_in_txn(store, txn, effect.provenance.actor_entity_ref)?;
            // The power is the Gate's own check (`has_permission`): a send
            // that lacks it is refused there whatever its check-in says.
            let request = CheckInRequest {
                act: ActClass::OutboundSend,
                role,
                holds_power: true,
                explicit_mode: None,
                standing_row: None,
            };
            (
                SendModeSource::RoleDefault(role),
                check_in(&request, &AlwaysUnsure),
            )
        }
    };
    let answer = match answer {
        CheckInAnswer::Go(GoReason::NeverAsk) => SendAnswer::NeverAsk,
        CheckInAnswer::Wait(reason) => SendAnswer::Wait(reason),
        // No standing row is passed, the unsure test is never sure, and no
        // role acts on its own proof for a send, so nothing else goes; any
        // other answer asks.
        CheckInAnswer::Go(_) | CheckInAnswer::Propose | CheckInAnswer::Absent => {
            SendAnswer::Wait(WaitReason::AlwaysAsk)
        }
    };
    Ok(Some(SendCheckIn { source, answer }))
}

/// The role `actor` sends in (ARCH-0082 #role-defaults; ruling L3-35-ROLE =
/// B, so an agent holding Owner sends with no press): its own standing
/// membership role on this vault's shared vault, a house link's among them
/// (`federation::shared_vault_member_role_for_store_in_txn`); Member when it
/// holds none there, or the send names no actor entity.
fn sender_role_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    actor: Option<EntityId>,
) -> Result<RolePreset> {
    let Some(actor) = actor else {
        return Ok(RolePreset::Member);
    };
    Ok(
        crate::federation::shared_vault_member_role_for_store_in_txn(store, txn, actor)?
            .map_or(RolePreset::Member, RolePreset::of_grant_role),
    )
}

/// Whether the vault's send grant, as the policy `txn` resolves it, lets one
/// press approve a reviewed batch of more than one send (ARCH-0046
/// #send-grant; Engine ruling L3-35-BATCH = A): its `mode` rows naming
/// `outbound_send` compose `manual` with `ask_per: batch`. With no such row
/// (the shipped defaults ask per send), `ask_per: send`, another mode or an
/// unreadable policy, one press covers one send.
///
/// # Errors
///
/// The store's, resolving the policy manifest.
pub(crate) fn send_grant_presses_batch_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<bool> {
    let resolution = crate::gate::resolve_policy_manifest(store, txn)?;
    let CheckInPolicyRead::Row(policy) = resolution.check_in_policy() else {
        return Ok(false);
    };
    Ok(policy
        .explicit_mode(ActClass::OutboundSend, &CheckInScope::default())
        .is_some_and(|explicit| {
            explicit.mode == CheckInMode::AlwaysAsk && explicit.ask_per == AskPer::Batch
        }))
}
