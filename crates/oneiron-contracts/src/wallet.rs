//! The host wallet an owner's agent Grant names (FIX 7766, ARCH-0011
//! billing): the host owns the money, a Grant names one wallet, and the
//! tasks and project budget leases the Grant funds draw on it.
//!
//! A [`WalletRef`] is an opaque reference the host issued: the namespace
//! that issued it and the wallet's id there, both compared byte for byte.
//! It holds no balance, credential or price, and the engine never derives
//! one from a PERSON or bills anything through it: the host resolves it to
//! the allocation it funds. Caps stay inherited spend parameters, never a
//! permission axis.

use serde::{Deserialize, Serialize};

/// One host wallet: `id` in the namespace `issuer`. Both are nonempty and
/// case-sensitive.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct WalletRef {
    /// The host namespace that issued the wallet.
    pub issuer: String,
    /// The wallet's id within `issuer`.
    pub id: String,
}

impl WalletRef {
    /// Whether both parts are nonempty.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.issuer.is_empty() && !self.id.is_empty()
    }
}
