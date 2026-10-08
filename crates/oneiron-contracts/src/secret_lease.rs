//! Secret lease status. `oneiron::secret_lease` re-exports it next to the lease rows.

/// Lifecycle status of an `oneiron::secret_lease::SecretLease`. Wire bytes mirror the
/// device-lease registry precedent (`sync::lease`): `0x01` active, `0x02`
/// expired, `0x03` revoked. Only `Active` admits use; `Revoked` is terminal
/// for the lease (a fresh materialization mints a fresh lease id).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SecretLeaseStatus {
    /// Live and usable within its tier.
    Active = 0x01,
    /// Past `expires_at` (lazy check at use, or the maintenance sweep).
    Expired = 0x02,
    /// Terminal. The only door-rejecting status besides `Expired`.
    Revoked = 0x03,
}

impl SecretLeaseStatus {
    /// The wire byte.
    #[must_use]
    pub const fn as_wire_byte(self) -> u8 {
        self as u8
    }

    /// Parses the wire byte.
    #[must_use]
    pub fn from_wire_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::Active),
            0x02 => Some(Self::Expired),
            0x03 => Some(Self::Revoked),
            _ => None,
        }
    }
}
