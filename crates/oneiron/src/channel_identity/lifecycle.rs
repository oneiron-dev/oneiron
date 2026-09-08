//! ChannelIdentity lifecycle states and transition edge tables.

/// ChannelIdentity lifecycle state (OF-347 R3/R5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ChannelIdentityState {
    Requested,
    PendingFulfillment,
    Active,
    Rotating,
    Released,
    Quarantine,
    Tombstone,
}

impl ChannelIdentityState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::PendingFulfillment => "pending_fulfillment",
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Released => "released",
            Self::Quarantine => "quarantine",
            Self::Tombstone => "tombstone",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "requested" => Some(Self::Requested),
            "pending_fulfillment" => Some(Self::PendingFulfillment),
            "active" => Some(Self::Active),
            "rotating" => Some(Self::Rotating),
            "released" => Some(Self::Released),
            "quarantine" => Some(Self::Quarantine),
            "tombstone" => Some(Self::Tombstone),
            _ => None,
        }
    }

    /// The SELF-HELD edge table: an account the product minted and can rotate,
    /// release, and hold out of recycling for its quarantine window.
    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Requested, Self::PendingFulfillment)
                | (Self::PendingFulfillment, Self::Active)
                | (Self::Active, Self::Rotating)
                | (Self::Rotating, Self::Active)
                | (Self::Active, Self::Released)
                | (Self::Rotating, Self::Released)
                | (Self::Released, Self::Quarantine)
                | (Self::Quarantine, Self::Tombstone)
        )
    }

    /// The DELEGATED edge table, for a mailbox the product never minted.
    ///
    /// Two states of the self-held table are absent, and their absence is the
    /// enforcement rather than a predicate somewhere else: ROTATING (re-minting
    /// an account we never owned) and QUARANTINE (taking a never-recycle hold
    /// on someone else's mailbox). Retirement is `Active -> Released ->
    /// Tombstone`, and both retirement stops free the assignment key, because
    /// the mailbox was never ours to hold back — closing the row out must never
    /// be the act that locks a member out of re-consenting.
    #[must_use]
    pub const fn can_transition_to_delegated(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Requested, Self::PendingFulfillment)
                | (Self::PendingFulfillment, Self::Active)
                | (Self::Active, Self::Released)
                | (Self::Released, Self::Tombstone)
        )
    }

    /// Whether a `delegated_grant` row in this state asserts a LIVE grant over
    /// the member's mailbox.
    ///
    /// True for every state that claims we can still read it, false once the
    /// row is retiring — which is exactly when custody may no longer be
    /// provable, and must not be required to be.
    #[must_use]
    pub const fn asserts_delegated_custody(self) -> bool {
        matches!(
            self,
            Self::Requested | Self::PendingFulfillment | Self::Active
        )
    }
}
