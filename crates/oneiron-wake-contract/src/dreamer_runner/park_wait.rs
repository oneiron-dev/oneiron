//! The class of a parked Dreamer attempt's typed wait: what resumes it.

/// What a parked attempt's typed wait blocks on. The wait itself lives on the
/// parked row in core; this class is what the park resume table reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DreamerParkWaitClass {
    /// A spend scope's top-up: the scope's own refill wakes the park's trap.
    Budget,
}

impl DreamerParkWaitClass {
    /// Stable string stored in the private parked row's wait map.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Budget => "budget",
        }
    }

    /// Parses the pinned wait-class string form.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "budget" => Some(Self::Budget),
            _ => None,
        }
    }
}
