//! What a provider's own record says became of one call (FIX 8814
//! follow-up): the read-back a transport can give for a send the ledger
//! holds uncertain.

/// A provider's answer about one call, read back from the provider.
///
/// `Delivered` and `NotDelivered` are claims the provider's own record
/// proves; a transport that cannot tell answers `Unknown`, and the ledger
/// keeps the call uncertain as before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryReadBack {
    /// The provider holds no record that decides the call.
    Unknown,
    /// The provider holds the call as accepted for delivery.
    Delivered,
    /// The provider's record proves the call was never accepted.
    NotDelivered,
}
