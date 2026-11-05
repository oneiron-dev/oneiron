//! Host recipient and sealing policy for checkpoint legal-hold members.

use oneiron_contracts::error::{Error, Result};
use oneiron_crypto::HybridPublicKey;
use oneiron_crypto::backup::host_holds_recipient_id;
use std::num::NonZeroU64;

/// The host recipient a hosted vault seals its checkpoints' host-order
/// family to: the 1616-byte ONHB frame its supervisor pinned and delivered
/// (`b"ONHB" || u16_be(1) || u16_be(0x0101) || u64_be(epoch) || 1600 bare
/// hybrid public key bytes`), its id (SHA-256 of the full bundle's bytes)
/// and its nonzero epoch. Never read from the owner's settings.
#[derive(Clone, PartialEq)]
pub struct HostHoldsRecipient {
    pub public: HybridPublicKey,
    pub id: [u8; 32],
    pub epoch: NonZeroU64,
}

impl std::fmt::Debug for HostHoldsRecipient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HostHoldsRecipient(..)")
    }
}

impl HostHoldsRecipient {
    /// The recipient whose public bundle is the 1616-byte ONHB frame `bundle`,
    /// at `epoch`.
    ///
    /// The frame epoch must equal `epoch`; the id is SHA-256 of the full
    /// bundle's bytes.
    ///
    /// # Errors
    ///
    /// A bundle that is not an ONHB public bundle, a zero epoch, or a bundle
    /// epoch that does not equal `epoch`.
    pub fn new(bundle: &[u8], epoch: u64) -> Result<Self> {
        if bundle.len() != 1616
            || !bundle.starts_with(b"ONHB")
            || u16::from_be_bytes([bundle[4], bundle[5]]) != 1
            || u16::from_be_bytes([bundle[6], bundle[7]]) != 0x0101
            || u64::from_be_bytes([
                bundle[8], bundle[9], bundle[10], bundle[11], bundle[12], bundle[13], bundle[14],
                bundle[15],
            ]) == 0
        {
            return Err(Error::InvalidConfig(
                "the host-holds recipient is not a hybrid public key".into(),
            ));
        }
        let frame_epoch = u64::from_be_bytes([
            bundle[8], bundle[9], bundle[10], bundle[11], bundle[12], bundle[13], bundle[14],
            bundle[15],
        ]);
        let epoch = NonZeroU64::new(epoch).ok_or_else(|| {
            Error::InvalidConfig("the host-holds recipient's epoch is zero".into())
        })?;
        if frame_epoch != epoch.get() {
            return Err(Error::InvalidConfig(
                "the host-holds recipient's epoch does not match its bundle".into(),
            ));
        }
        let public = HybridPublicKey::from_bytes(&bundle[16..]).map_err(|_| {
            Error::InvalidConfig("the host-holds recipient is not a hybrid public key".into())
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
