//! The class of a parked Dreamer attempt's typed wait: what resumes it.

/// What a parked attempt's typed wait blocks on. The wait itself lives on the
/// parked row in core; this class is what the park resume table reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DreamerParkWaitClass {
    /// A spend scope's top-up: the scope's own refill wakes the park's trap.
    Budget,
    /// A held effect's consent answer or an outbound call's settled reply delivered on the wait.
    Consent,
    /// A peer's or child's result delivered on the wait: a TASK, child, reader, summary or hook ask group.
    Peer,
    /// A person's answer delivered on the wait.
    Human,
}

impl DreamerParkWaitClass {
    /// Stable string stored in the private parked row's wait map.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Budget => "budget",
            Self::Consent => "consent",
            Self::Peer => "peer",
            Self::Human => "human",
        }
    }

    /// Parses the pinned wait-class string form.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "budget" => Some(Self::Budget),
            "consent" => Some(Self::Consent),
            "peer" => Some(Self::Peer),
            "human" => Some(Self::Human),
            _ => None,
        }
    }
}
