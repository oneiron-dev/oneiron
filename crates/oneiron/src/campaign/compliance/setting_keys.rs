//! The campaign compliance leg's pack Setting key (owner ruling PACK-SETTINGS-ALL = B; Engine
//! RULING 23:46 15 Nov, C09): whether a campaign may contact a person who has no recorded
//! objection, or only a person with a recorded consent. The default is today's opt-out
//! behaviour: every campaign mail carries the STOP opt-out line (`campaign::sender`), and a
//! recorded objection stops later sends. The owner changes the value; an agent's change waits on
//! the owner's approval.
//!
//! Direction: false is tighter (fewer people are contacted), so turning it back on is a
//! loosening. A row that does not decode reads as false: the gate then asks for a recorded
//! consent, and fails closed.
//!
//! The agent key `campaign.compliance.agent_may_decide` (restriction wave 11, census C60) is the
//! last row: whether an agent may install compliance rows and reject a pending proposal.

use crate::error::Result;
use crate::setting::Kind;
use crate::store::Store;

const fn contact_without_recorded_objection() -> bool {
    true
}

const fn recorded_consent_required() -> bool {
    false
}

crate::setting::setting_keys! {
    /// Contact people with no recorded objection (default true: a 1:1 campaign send needs no
    /// recorded consent, carries the STOP opt-out line, and a recorded objection stops later
    /// sends). false: the campaign gate holds every send to a person a campaign governs until
    /// that person has a recorded consent that opts in on the send's channel, from its sender,
    /// whatever the compliance pack allows. false is tighter. An unreadable row reads as false.
    pub(crate) CAMPAIGN_CONTACT_WITHOUT_RECORDED_OBJECTION: bool =
        "campaign.contact_without_recorded_objection" {
        kind: Kind::new(contact_without_recorded_objection)
            .strictest(recorded_consent_required)
            .lower(),
    };
}

/// Whether the owner requires a recorded consent before any governed campaign send, in `txn`,
/// at the vault scope: the key's value, negated.
///
/// # Errors
///
/// Storage errors.
pub(super) fn recorded_consent_required_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<bool> {
    Ok(!CAMPAIGN_CONTACT_WITHOUT_RECORDED_OBJECTION
        .read_in_dbs_txn(store, txn, &[], None)?
        .value)
}

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
            .lower(),
        scopes: &[crate::setting::ScopeKind::Vault, crate::setting::ScopeKind::Agent],
        act: crate::check_in::ActClass::GrantWiden,
    };
}
