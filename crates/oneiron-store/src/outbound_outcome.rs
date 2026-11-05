//! Stable outcome vocabulary for outbound dispatch observations.

/// Coarse pipeline outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum OutboundDispatchOutcome {
    DeliveredToChannel,
    Held,
    Degraded,
    Suppressed,
    LetGo,
    Failed,
    Ambiguous,
    /// The provider accepted the send as a remote task (FIX 7960).
    Deferred,
}

impl OutboundDispatchOutcome {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeliveredToChannel => "delivered_to_channel",
            Self::Held => "held",
            Self::Degraded => "degraded",
            Self::Suppressed => "suppressed",
            Self::LetGo => "let_go",
            Self::Failed => "failed",
            Self::Ambiguous => "ambiguous",
            Self::Deferred => "deferred",
        }
    }
}
