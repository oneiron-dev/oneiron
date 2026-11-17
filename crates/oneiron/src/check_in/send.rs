//! The send grant at the Gate (ARCH-0046 #send-grant and
//! #check-in-roles-20261110; PLAN L3-35 PR 1).
//!
//! The vault's grant for act class `outbound_send` is a `mode` row of the
//! `check_in` policy row ([`super::CheckInPolicy`]). Each agent send the Gate
//! judges checks in here once, under the vault's rows (an outbound send names
//! no world or project yet):
//! * `full-access` (`NeverAsk`) releases the send with no press;
//! * `manual` (`AlwaysAsk`) and `auto` (`AskWhenUnsure`, whose unsure test is
//!   [`AlwaysUnsure`] until a decision model judges agent acts) release
//!   nothing, so the Gate's other coverage or the press per send decides;
//! * with no row naming the class, the press-per-send floor decides (Engine
//!   ruling L3-35-ROLE = A; the role column of ARCH-0082 #role-defaults joins
//!   with PR 2's role resolver); an unreadable policy counts as `AlwaysAsk`.
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
use super::policy::{CheckInPolicyRead, CheckInScope};
use super::resolve::{CheckInAnswer, GoReason, WaitReason, check_in_with_mode};
use crate::gate::{ApprovalTarget, ExternalEffectGateInput};

/// The prefix of the covering ref a send row gives.
const SEND_ROW_REF_PREFIX: &str = "check_in:row:";

/// The prefix of the receipt reason that names a send row (the decision
/// ledger's `check_in_row_` family; the row decoder bounds the ref to fit).
const SEND_ROW_REASON_PREFIX: &str = "check_in_row_";

/// Where an agent send's mode came from.
#[derive(Clone, Debug, Eq, PartialEq)]
enum SendModeSource {
    /// The `mode` rows that set it, in manifest order.
    Rows(Vec<String>),
    /// No row names `outbound_send`: the press-per-send floor.
    ShippedDefault,
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

    /// The covering ref of a send the row releases: `check_in:row:<ref>` of
    /// the first row that set its mode. The Gate puts it in the
    /// standing-grant slot, as it puts an envelope slot's consent grant ref
    /// there; nothing resolves it as an outbound grant id.
    pub(crate) fn release_grant_ref(&self) -> Option<String> {
        match (&self.source, self.answer) {
            (SendModeSource::Rows(row_refs), SendAnswer::NeverAsk) => row_refs
                .first()
                .map(|row_ref| format!("{SEND_ROW_REF_PREFIX}{row_ref}")),
            _ => None,
        }
    }

    /// The Gate decision record's reasons, in the decision ledger's
    /// `check_in_` family: `check_in_row_<ref>` for each row that set the mode
    /// (or `check_in_shipped_default`, or `check_in_unreadable`), then the
    /// answer: `check_in_go_never_ask` or `check_in_wait_<reason>`.
    pub(crate) fn receipt_reasons(&self) -> Vec<String> {
        let mut reasons = match &self.source {
            SendModeSource::Rows(row_refs) => row_refs
                .iter()
                .map(|row_ref| format!("{SEND_ROW_REASON_PREFIX}{row_ref}"))
                .collect(),
            SendModeSource::ShippedDefault => vec!["check_in_shipped_default".to_owned()],
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
/// or a recipient of a message that takes one.
pub(crate) fn send_check_in(
    read: CheckInPolicyRead<'_>,
    effect: &ExternalEffectGateInput,
    delegated_or_cold: bool,
) -> Option<SendCheckIn> {
    if effect.actor.actor_class != "agent"
        || effect.verb != "send"
        || delegated_or_cold
        || matches!(
            effect.provenance.approval_target,
            Some(ApprovalTarget::Campaign(_))
        )
    {
        return None;
    }
    let (mode, source) = match read {
        CheckInPolicyRead::Unreadable => (CheckInMode::AlwaysAsk, SendModeSource::Unreadable),
        CheckInPolicyRead::NoRow => (CheckInMode::AlwaysAsk, SendModeSource::ShippedDefault),
        CheckInPolicyRead::Row(policy) => {
            match policy.explicit_mode(ActClass::OutboundSend, &CheckInScope::default()) {
                Some(explicit) => (explicit.mode, SendModeSource::Rows(explicit.row_refs)),
                None => (CheckInMode::AlwaysAsk, SendModeSource::ShippedDefault),
            }
        }
    };
    let answer = match check_in_with_mode(ActClass::OutboundSend, mode, None, &AlwaysUnsure) {
        CheckInAnswer::Go(GoReason::NeverAsk) => SendAnswer::NeverAsk,
        CheckInAnswer::Wait(reason) => SendAnswer::Wait(reason),
        // No standing row is passed and the unsure test is never sure, so
        // nothing else goes; any other answer asks.
        CheckInAnswer::Go(_) | CheckInAnswer::Propose | CheckInAnswer::Absent => {
            SendAnswer::Wait(WaitReason::AlwaysAsk)
        }
    };
    Some(SendCheckIn { source, answer })
}
