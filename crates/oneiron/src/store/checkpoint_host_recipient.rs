//! Host recipient and sealing policy for checkpoint legal-hold members.

use crate::{Error, Result};
use oneiron_crypto::HybridPublicKey;
use oneiron_crypto::backup::host_holds_recipient_id;
use std::num::NonZeroU64;

/// The host recipient a hosted vault seals its checkpoints' host-order
/// family to: the public bundle its supervisor pinned and delivered (a
/// hybrid public key's wire form), its id (SHA-256 of the bundle's bytes)
/// and its nonzero epoch. Never read from the owner's settings.
#[derive(Clone, PartialEq)]
pub struct HostHoldsRecipient {
    pub(crate) public: HybridPublicKey,
    pub(crate) id: [u8; 32],
    pub(crate) epoch: NonZeroU64,
}

impl std::fmt::Debug for HostHoldsRecipient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HostHoldsRecipient(..)")
    }
}

impl HostHoldsRecipient {
    /// The recipient whose public bundle is `bundle`, at `epoch`.
    ///
    /// # Errors
    ///
    /// A bundle that is not a hybrid public key, or a zero epoch.
    pub fn new(bundle: &[u8], epoch: u64) -> Result<Self> {
        let public = HybridPublicKey::from_bytes(bundle).map_err(|_| {
            Error::InvalidConfig("the host-holds recipient is not a hybrid public key".into())
        })?;
        let epoch = NonZeroU64::new(epoch).ok_or_else(|| {
            Error::InvalidConfig("the host-holds recipient's epoch is zero".into())
        })?;
        Ok(Self {
            public,
            id: host_holds_recipient_id(bundle),
            epoch,
        })
    }

    /// Its id: SHA-256 of its bundle's bytes.
    #[must_use]
    pub fn id(&self) -> [u8; 32] {
        self.id
    }

    /// Its epoch.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch.get()
    }
}

/// Whether a vault's checkpoints carry its host-order family, as its host
/// configured it (`VaultConfig::checkpoint_host_holds`).
#[derive(Clone, Debug, Default, PartialEq)]
pub enum HostHoldsSealing {
    /// No host carries the vault: a self-hosted vault seals none.
    #[default]
    NotHosted,
    /// Sealed to this recipient.
    To(Box<HostHoldsRecipient>),
    /// A host carries the vault and gave no usable recipient: each receipt
    /// says the member is unavailable. Never a refused start.
    RecipientMissing,
}
