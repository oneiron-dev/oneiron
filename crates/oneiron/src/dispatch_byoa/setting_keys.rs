//! The runner dispatcher's owner Setting keys (DESIGN 15-setting-primitive): rows the setting
//! catalogue reads from this file.

use crate::Vault;
use crate::agent_dispatch::AgentDispatcher;
use crate::check_in::ActClass;
use crate::error::Result;
use crate::setting::{ItemDomain, Kind, ScopeKind, SettingScope, lower_is_tighter};

/// Off: only the owner manages runner seats.
fn owner_manages() -> bool {
    false
}

/// The runner-seat acts the key admits, one per owner door.
fn runner_seat_act(item: &str) -> bool {
    matches!(item, "quotas" | "resume" | "top_up")
}

/// The confirm sheet's line for letting an agent top up a seat's spent credit (`top_up`, or
/// every act, on a row that names none): the spend cap in force over the row's scope, every
/// open root for the vault row and the roots over that agent's open attempts for an agent's row,
/// as `models.quota.agent_may_answer` states it (RESTRICTION-WAVE-11-CAP-NOTE; CAP-SCOPE = B).
/// Reading quotas and resuming parked work state no line.
fn runner_seat_loosening_note(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    scope: &SettingScope,
    item: Option<&str>,
) -> Result<Option<String>> {
    match item {
        None | Some("top_up") => {
            let agent = match scope {
                SettingScope::Agent(agent) => Some(*agent),
                _ => None,
            };
            AgentDispatcher::new(vault)
                .spend_cap_in_force_line_in_txn(txn, agent)
                .map(Some)
        }
        Some(_) => Ok(None),
    }
}

crate::setting::setting_keys! {
    /// Let this agent do this runner-seat act. Off by default for every act: reading the
    /// seats' quotas (`quotas`), resuming parked runner work (`resume`) and topping up a seat's
    /// spent credit (`top_up`) take the owner, as before. One item per act. `top_up` puts a
    /// spent seat back to work, and its work spends on the seat's account, so the key is
    /// declared with the billing act class: turning any act on is a payment loosening
    /// (RESTRICTION-WAVE-11-OWNER-ROWS Q1 = A; ARCH-0082 #payment). The engine never pays. An
    /// agent's row names one agent; the vault row opens every agent, and an agent's own row wins
    /// over it. Only the owner turns it on; an agent's change waits on the owner's answer
    /// (restriction wave 11, census C51). The confirm sheet for turning on `top_up` states the
    /// spend cap in force, or "no cap", first.
    pub(crate) DISPATCH_BYOA_RUNNER_SEATS_AGENT_MAY_MANAGE: bool = "dispatch_byoa.runner_seats.agent_may_manage" {
        kind: Kind::new(owner_manages)
            .strictest(owner_manages)
            .tighter(lower_is_tighter::<bool>),
        scopes: &[ScopeKind::Vault, ScopeKind::Agent],
        item: Some(ItemDomain { name: "runner seat acts", admits: runner_seat_act }),
        act: ActClass::Billing,
        loosening_note: Some(runner_seat_loosening_note),
    };
}
