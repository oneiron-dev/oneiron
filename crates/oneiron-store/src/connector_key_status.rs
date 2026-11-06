//! Connector-key lifecycle status and its pinned wire strings.

/// ConnectorKeyRecord lifecycle status.
///
/// Catalogued keys and per-grant scoped keys start Pending; only the
/// qualification suite can activate them, and a protocol-revision change
/// returns them to Pending. Legacy catalog-free budget keys retain their
/// Active registration door.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectorKeyStatus {
    Pending,
    Active,
    Suspended,
    Revoked,
}

impl ConnectorKeyStatus {
    /// Returns the pinned on-disk status string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Revoked => "revoked",
        }
    }

    /// Parses a pinned on-disk status string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "active" => Some(Self::Active),
            "suspended" => Some(Self::Suspended),
            "revoked" => Some(Self::Revoked),
            _ => None,
        }
    }
}
