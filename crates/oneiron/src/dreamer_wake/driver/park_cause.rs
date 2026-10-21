//! What a non-deadline executor error parks as (FIX 7272). An error only an
//! owner act clears keeps its private ExecutorError park and ends the pass,
//! as before; any other parks as a Retry a later pass resumes after its
//! retry delay (Engine 10-21).

use crate::dreamer_runner::DreamerParkCause;
use crate::error::ErrorKind;

/// Whether an executor error of `kind` waits on an owner act: an authority,
/// grant, consent, approval or hold that nothing but the owner (or the
/// person a consent names) changes. Retrying such an attempt each pass
/// would only meet the same refusal.
pub(super) const fn waits_on_owner_act(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::AuthorityRefused
            | ErrorKind::ActorLacksClaimAuthority
            | ErrorKind::FamilyRequiresAutoGrant
            | ErrorKind::SourceNotTrustedForAuto
            | ErrorKind::GateWriteRejected
            | ErrorKind::GateConsentStale
            | ErrorKind::ConsentOwnerNotAuthenticated
            | ErrorKind::ConsentUnauthenticatedActor
            | ErrorKind::ConsentGuestNotRecorded
            | ErrorKind::ConsentGrantNotFound
            | ErrorKind::ConsentGrantRevoked
            | ErrorKind::ConsentApproveOnceSpent
            | ErrorKind::PersonaSnapshotConsentStale
            | ErrorKind::SettleNotAuthorized
            | ErrorKind::ConnectorCharterMissing
            | ErrorKind::ConnectorCharterApprovalMismatch
            | ErrorKind::WorkspaceMailboxAutonomyNotReady
            | ErrorKind::WorkCompanionRequired
            | ErrorKind::HostActionRequiresSupportGrant
            | ErrorKind::GitPushCapabilityRequired
            | ErrorKind::SecretBindingDenied
            | ErrorKind::SecretTierDenied
            | ErrorKind::SecretDoorPolicyRefused
            | ErrorKind::SecretGrantStale
            | ErrorKind::SecretGrantSpent
            | ErrorKind::AgentDefinitionDisabled
            | ErrorKind::KillSwitchDisabled
            | ErrorKind::IdentityUnsettled
            | ErrorKind::ProjectHistoryOverBudget
            | ErrorKind::LegalHold
    )
}

/// The cause a non-deadline executor error of `kind` parks under.
pub(super) const fn executor_error_park_cause(kind: ErrorKind) -> DreamerParkCause {
    if waits_on_owner_act(kind) {
        DreamerParkCause::ExecutorError
    } else {
        DreamerParkCause::Retry
    }
}
