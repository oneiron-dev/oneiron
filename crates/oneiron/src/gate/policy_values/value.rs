//! Typed policy values and their composition; see the parent module for row selection.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::gate) enum PolicyPrecedence {
    NestedNarrowing,
    MostSpecific,
}
impl PolicyPrecedence {
    pub(super) fn parse(value: &str) -> Option<Self> {
        match value {
            "nested_narrowing" => Some(Self::NestedNarrowing),
            "most_specific" => Some(Self::MostSpecific),
            _ => None,
        }
    }
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::NestedNarrowing => "nested_narrowing",
            Self::MostSpecific => "most_specific",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::gate) enum PolicyValue {
    ArtifactAnswerQuietSeconds(u64),
    CalendarOutcomeGraceSeconds(u64),
    CommOptOutPosture(crate::gate::resolution::CommOptOutPosture),
    DreamerRetryParkSeconds(u64),
    EsignRateDocumentThreshold(u64),
    EsignRateRecipientThreshold(u64),
    EscalationStandingRulings(u64),
    MinerRecurrenceReceipts(u64),
    MinerRejectionWaitSeconds(u64),
    ProposalCheckThreshold(u64),
    ProviderCooldownDefaultSeconds(u64),
    ProviderCooldownMaxSeconds(u64),
    ProviderCooldownMaxWaitSeconds(u64),
    ResidentRunMaxTries(u64),
    ScopePrecedence(PolicyPrecedence),
    SessionIdleFloorSeconds(u64),
    SessionLifetimeCeilingSeconds(u64),
    WorkflowStepMaxTries(u64),
}
impl PolicyValue {
    pub(super) fn restrict(self, other: Self) -> Self {
        match (self, other) {
            // A longer quiet never wakes a proposer sooner than any trusted
            // row asks.
            (Self::ArtifactAnswerQuietSeconds(a), Self::ArtifactAnswerQuietSeconds(b)) => {
                Self::ArtifactAnswerQuietSeconds(a.max(b))
            }
            // A longer grace never asks about a meeting sooner than any
            // trusted row asks.
            (Self::CalendarOutcomeGraceSeconds(a), Self::CalendarOutcomeGraceSeconds(b)) => {
                Self::CalendarOutcomeGraceSeconds(a.max(b))
            }
            (Self::CommOptOutPosture(a), Self::CommOptOutPosture(b)) => {
                Self::CommOptOutPosture(a.restrict(b))
            }
            // A longer pause never resumes a Retry park sooner than any
            // trusted row asks.
            (Self::DreamerRetryParkSeconds(a), Self::DreamerRetryParkSeconds(b)) => {
                Self::DreamerRetryParkSeconds(a.max(b))
            }
            (Self::EsignRateDocumentThreshold(a), Self::EsignRateDocumentThreshold(b)) => {
                Self::EsignRateDocumentThreshold(a.min(b))
            }
            (Self::EsignRateRecipientThreshold(a), Self::EsignRateRecipientThreshold(b)) => {
                Self::EsignRateRecipientThreshold(a.min(b))
            }
            // More agreeing rulings or recurring receipts, or a longer quiet
            // after a rejection, never proposes sooner than any trusted row
            // asks.
            (Self::EscalationStandingRulings(a), Self::EscalationStandingRulings(b)) => {
                Self::EscalationStandingRulings(a.max(b))
            }
            (Self::MinerRecurrenceReceipts(a), Self::MinerRecurrenceReceipts(b)) => {
                Self::MinerRecurrenceReceipts(a.max(b))
            }
            (Self::MinerRejectionWaitSeconds(a), Self::MinerRejectionWaitSeconds(b)) => {
                Self::MinerRejectionWaitSeconds(a.max(b))
            }
            (Self::ProposalCheckThreshold(a), Self::ProposalCheckThreshold(b)) => {
                Self::ProposalCheckThreshold(a.min(b))
            }
            // A longer rest never sends a call to a refusing provider sooner
            // than any trusted row asks.
            (Self::ProviderCooldownDefaultSeconds(a), Self::ProviderCooldownDefaultSeconds(b)) => {
                Self::ProviderCooldownDefaultSeconds(a.max(b))
            }
            (Self::ProviderCooldownMaxSeconds(a), Self::ProviderCooldownMaxSeconds(b)) => {
                Self::ProviderCooldownMaxSeconds(a.max(b))
            }
            // A call waits for a cooling chain no longer than every trusted
            // row allows.
            (Self::ProviderCooldownMaxWaitSeconds(a), Self::ProviderCooldownMaxWaitSeconds(b)) => {
                Self::ProviderCooldownMaxWaitSeconds(a.min(b))
            }
            // A shorter idle floor or lifetime ceiling never keeps a sitting
            // open longer than any trusted row allows.
            (Self::SessionIdleFloorSeconds(a), Self::SessionIdleFloorSeconds(b)) => {
                Self::SessionIdleFloorSeconds(a.min(b))
            }
            (Self::SessionLifetimeCeilingSeconds(a), Self::SessionLifetimeCeilingSeconds(b)) => {
                Self::SessionLifetimeCeilingSeconds(a.min(b))
            }
            // A lower cap never retries past what any trusted row allows.
            (Self::ResidentRunMaxTries(a), Self::ResidentRunMaxTries(b)) => {
                Self::ResidentRunMaxTries(a.min(b))
            }
            (Self::WorkflowStepMaxTries(a), Self::WorkflowStepMaxTries(b)) => {
                Self::WorkflowStepMaxTries(a.min(b))
            }
            _ => unreachable!("policy values for different keys never compose"),
        }
    }

    pub(in crate::gate) fn as_str(self) -> String {
        match self {
            Self::CommOptOutPosture(value) => value.as_str().to_owned(),
            Self::ArtifactAnswerQuietSeconds(value)
            | Self::CalendarOutcomeGraceSeconds(value)
            | Self::DreamerRetryParkSeconds(value)
            | Self::EsignRateDocumentThreshold(value)
            | Self::EsignRateRecipientThreshold(value)
            | Self::EscalationStandingRulings(value)
            | Self::MinerRecurrenceReceipts(value)
            | Self::MinerRejectionWaitSeconds(value)
            | Self::ProposalCheckThreshold(value)
            | Self::ProviderCooldownDefaultSeconds(value)
            | Self::ProviderCooldownMaxSeconds(value)
            | Self::ProviderCooldownMaxWaitSeconds(value)
            | Self::ResidentRunMaxTries(value)
            | Self::SessionIdleFloorSeconds(value)
            | Self::SessionLifetimeCeilingSeconds(value)
            | Self::WorkflowStepMaxTries(value) => value.to_string(),
            Self::ScopePrecedence(value) => value.as_str().to_owned(),
        }
    }
}
