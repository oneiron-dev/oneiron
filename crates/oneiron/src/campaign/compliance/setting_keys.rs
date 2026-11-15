//! The compliance pack's owner Setting keys (DESIGN 15-setting-primitive): rows the setting
//! catalogue reads from this file.

use crate::check_in::ActClass;
use crate::setting::{Kind, ScopeKind, lower_is_tighter};

/// Off: only the owner installs or rejects.
fn owner_decides() -> bool {
    false
}

crate::setting::setting_keys! {
    /// Let this agent install compliance rows and reject a pending proposal. Off by default:
    /// install and reject take the authenticated owner, as before. On for an agent, it installs
    /// cited rows through the amendment path (a loosening among them still waits for the
    /// owner's exact-hash approval) and rejects a pending proposal (no active restriction
    /// changes). Approve and verify stay the owner's stamp whatever this key says: "Tighten =
    /// auto-apply + notice; loosen = owner-stamped" (ARCH-0059 r7; RESTRICTION-WAVE-11-OWNER-ROWS
    /// Q2 = B). An agent's row names one agent; the vault row opens every agent, and an agent's
    /// own row wins over it. On is the looser value, so only the owner turns it on; an agent's
    /// change waits on the owner's answer (restriction wave 11, census C60).
    pub(crate) CAMPAIGN_COMPLIANCE_AGENT_MAY_DECIDE: bool = "campaign.compliance.agent_may_decide" {
        kind: Kind::new(owner_decides)
            .strictest(owner_decides)
            .tighter(lower_is_tighter::<bool>),
        scopes: &[ScopeKind::Vault, ScopeKind::Agent],
        act: ActClass::GrantWiden,
    };
}
