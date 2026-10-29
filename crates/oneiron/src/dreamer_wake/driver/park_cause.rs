//! What a non-deadline executor error parks as (FIX 7272). An error only an
//! owner act clears keeps its private ExecutorError park and ends the pass,
//! as before; any other parks as a Retry a later pass resumes after its
//! retry delay (Engine 10-21).

use crate::dreamer_runner::DreamerParkCause;
use crate::error::ErrorKind;
use crate::llm::{FatalLlmError, LlmError, RetryableLlmError, SpentKind};

/// Whether an executor error of `kind` waits on an owner act: an authority,
/// grant, consent, approval or hold that nothing but the owner (or the
/// person a consent names) changes. Retrying such an attempt each pass
/// would only meet the same refusal.
pub(crate) const fn waits_on_owner_act(kind: ErrorKind) -> bool {
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

/// Whether a failed model call waits on an owner act (FIX 7382): a budget
/// denial, spent prepaid credit (the owner tops up), a world kept on the
/// device (world privacy), a failed login, a capability the routed model
/// lacks (the owner routes a capable one), or an answer an erase took
/// (terminal by its own contract). A rate limit, a spent usage window, a
/// provider outage and a refused or unreadable reply do not. Exhaustive, so
/// a new variant is classified here.
pub(crate) const fn llm_waits_on_owner_act(error: &LlmError) -> bool {
    match error {
        LlmError::BudgetDenied(_) => true,
        LlmError::Retryable(retryable) => match retryable {
            RetryableLlmError::QuotaSpent {
                kind: SpentKind::Credit,
                ..
            }
            | RetryableLlmError::KeptOnDevice { .. } => true,
            RetryableLlmError::QuotaSpent {
                kind: SpentKind::Window,
                ..
            }
            | RetryableLlmError::RateLimited { .. }
            | RetryableLlmError::ServerError
            | RetryableLlmError::Timeout
            | RetryableLlmError::StreamCut => false,
        },
        LlmError::Fatal(fatal) => match fatal {
            FatalLlmError::Auth | FatalLlmError::Unsupported(_) | FatalLlmError::ResponseErased => {
                true
            }
            FatalLlmError::InvalidRequest
            | FatalLlmError::InvalidRequestDetail { .. }
            | FatalLlmError::ContentFiltered
            | FatalLlmError::EmptyResponse
            | FatalLlmError::LabelRead(_) => false,
        },
    }
}

/// The cause a non-deadline executor error of `kind` parks under.
pub(super) const fn executor_error_park_cause(kind: ErrorKind) -> DreamerParkCause {
    if waits_on_owner_act(kind) {
        DreamerParkCause::ExecutorError
    } else {
        DreamerParkCause::Retry
    }
}
