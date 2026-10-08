//! Edge vocabulary the write path shares. The edge kinds, layouts and codec stay in
//! `oneiron::edge`, which re-exports [`EdgeActorClass`].

/// Hot actor-class flag cached on a 26-byte semantic-provenanced edge.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeActorClass {
    Human = 0,
    Agent = 1,
    System = 2,
}

impl EdgeActorClass {
    /// Decodes the stored actor-class byte; `None` for any byte outside the three classes.
    /// Public so `oneiron`'s edge, share, task and document codecs decode the byte the
    /// same way across the crate line.
    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Human),
            1 => Some(Self::Agent),
            2 => Some(Self::System),
            _ => None,
        }
    }

    /// Actor-class key used by Gate `actor_ceilings` policy rows.
    #[must_use]
    pub const fn gate_actor_class(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Agent => "agent",
            Self::System => "system",
        }
    }
}
