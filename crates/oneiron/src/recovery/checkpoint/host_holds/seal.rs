//! A hosted vault's host-order family in its own checkpoints (FIX 6598,
//! FIX 6817; LEGAL-HOLD = B): a hold must not depend on the node surviving.
//!
//! Where its host names a recipient (the node's CUSTODY-1 hybrid key, never
//! the owner's, the data key or a signing key), each snapshot reads the
//! complete host-order family in its own read transaction and seals it, after
//! the transaction, into the image's optional host-private member
//! (`oneiron_crypto::backup::seal_host_holds`), bound to the vault, the
//! artifact's snapshot id, the recipient and its epoch. The family stays out
//! of the canonical rows and the owner's payload: the owner's key opens the
//! image, never the member. A self-hosted vault seals none. A family that
//! does not read or seal leaves the member out, said in the receipt
//! ([`HostHoldsAvailability::Unavailable`]) and warned without content,
//! never a failed backup, an empty family or a wrap to another key.
//!
//! The engine never opens a member. At a cold restore the host's worker
//! opens it with the recipient's secret and hands the family back on the
//! input pipe, tagged with the member it came from
//! ([`ArtifactHostOrderHolds`]). The restore takes that family only when the
//! tag names the member the artifact it opened carries, the same snapshot,
//! recipient, epoch and member BLAKE3, and passes it to `finish`; any other,
//! or none, is unknown, warned and never a refusal.

use std::num::NonZeroU64;

use getrandom::SysRng;
use oneiron_crypto::HybridPublicKey;
use oneiron_crypto::backup::{
    HostHoldsBinding, SealedHostHolds, host_holds_recipient_id, seal_host_holds,
};
use serde::{Deserialize, Serialize};

use super::HostOrderHolds;
use crate::recovery::checkpoint::{CheckpointImage, CheckpointKey};
use crate::{Error, Result};

/// The host recipient a hosted vault seals its checkpoints' host-order
/// family to: the public bundle its supervisor pinned and delivered (a
/// hybrid public key's wire form), its id (SHA-256 of the bundle's bytes)
/// and its nonzero epoch. Never read from the owner's settings.
#[derive(Clone, PartialEq)]
pub struct HostHoldsRecipient {
    public: HybridPublicKey,
    id: [u8; 32],
    epoch: NonZeroU64,
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

/// Why a hosted vault's checkpoint carries no host-order family. Content
/// free.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostHoldsUnavailable {
    /// The host gave no usable recipient.
    RecipientMissing,
    /// The family did not read in the snapshot's transaction.
    ExportFailed,
    /// The family did not serialize or seal.
    SealFailed,
}

/// What a checkpoint carries of its vault's host-order family, for its host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostHoldsAvailability {
    /// No host carries the vault: none is sealed, and none is owed.
    NotHosted,
    /// The complete family, sealed to this recipient at this epoch; its
    /// member's BLAKE3, which a restore's tag names.
    Sealed {
        recipient_id: [u8; 32],
        recipient_epoch: u64,
        member_blake3: [u8; 32],
    },
    /// None is sealed, and why.
    Unavailable(HostHoldsUnavailable),
}

/// A sealed member as an image carries it: opaque bytes, MessagePack binary.
#[derive(Clone, PartialEq, Eq)]
pub(in crate::recovery::checkpoint) struct HostHoldsMember(Vec<u8>);

impl std::fmt::Debug for HostHoldsMember {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HostHoldsMember({} bytes)", self.0.len())
    }
}

impl Serialize for HostHoldsMember {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for HostHoldsMember {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = HostHoldsMember;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a sealed host-holds member")
            }

            fn visit_bytes<E: serde::de::Error>(
                self,
                bytes: &[u8],
            ) -> std::result::Result<HostHoldsMember, E> {
                Ok(HostHoldsMember(bytes.to_vec()))
            }

            fn visit_byte_buf<E: serde::de::Error>(
                self,
                bytes: Vec<u8>,
            ) -> std::result::Result<HostHoldsMember, E> {
                Ok(HostHoldsMember(bytes))
            }
        }
        deserializer.deserialize_bytes(Visitor)
    }
}

impl HostHoldsMember {
    /// BLAKE3 of the member's bytes: what a restore's tag names.
    fn digest(&self) -> [u8; 32] {
        *blake3::hash(&self.0).as_bytes()
    }
}

/// The family a vault's snapshot read, or why it did not.
pub(in crate::recovery::checkpoint) type ExportedHostHolds =
    std::result::Result<HostOrderHolds, HostHoldsUnavailable>;

/// Reads the complete family in the snapshot's own transaction `txn`, where
/// the vault's host seals one; `None` where it seals none.
pub(in crate::recovery::checkpoint) fn export_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
) -> Option<ExportedHostHolds> {
    match &vault.config.checkpoint_host_holds {
        HostHoldsSealing::NotHosted => None,
        HostHoldsSealing::RecipientMissing => Some(Err(HostHoldsUnavailable::RecipientMissing)),
        HostHoldsSealing::To(_) => Some(HostOrderHolds::read_in_txn(vault, txn).map_err(|error| {
            tracing::warn!(
                kind = ?error.kind(),
                "the host-order legal holds did not read for this checkpoint"
            );
            HostHoldsUnavailable::ExportFailed
        })),
    }
}

/// Seals `exported`, read by [`export_in_txn`], for the artifact of
/// `snapshot`: the image's member and what the receipt says of it. A
/// failure leaves the member out and is warned, content free, for the host
/// to alert on; the checkpoint goes on.
pub(in crate::recovery::checkpoint) fn seal_member(
    vault: &crate::Vault,
    vault_id: [u8; 32],
    snapshot: [u8; 32],
    exported: Option<ExportedHostHolds>,
) -> (Option<HostHoldsMember>, HostHoldsAvailability) {
    let recipient = match &vault.config.checkpoint_host_holds {
        HostHoldsSealing::NotHosted => return (None, HostHoldsAvailability::NotHosted),
        HostHoldsSealing::RecipientMissing => {
            return unavailable(HostHoldsUnavailable::RecipientMissing);
        }
        HostHoldsSealing::To(recipient) => recipient,
    };
    let family = match exported {
        Some(Ok(family)) => family,
        Some(Err(reason)) => return unavailable(reason),
        None => return unavailable(HostHoldsUnavailable::ExportFailed),
    };
    let binding = HostHoldsBinding {
        engine_vault_id: vault_id,
        snapshot,
        recipient_id: recipient.id,
        recipient_epoch: recipient.epoch.get(),
    };
    let sealed = serde_json::to_vec(&family)
        .map(zeroize::Zeroizing::new)
        .ok()
        .and_then(|bytes| seal_host_holds(&binding, &recipient.public, &bytes, &mut SysRng).ok());
    let Some(sealed) = sealed else {
        return unavailable(HostHoldsUnavailable::SealFailed);
    };
    let member = HostHoldsMember(sealed.to_bytes());
    let availability = HostHoldsAvailability::Sealed {
        recipient_id: binding.recipient_id,
        recipient_epoch: binding.recipient_epoch,
        member_blake3: member.digest(),
    };
    (Some(member), availability)
}

fn unavailable(reason: HostHoldsUnavailable) -> (Option<HostHoldsMember>, HostHoldsAvailability) {
    tracing::warn!(
        reason = "host_holds_unavailable",
        cause = ?reason,
        "this checkpoint carries no host-order legal holds; it is written without them"
    );
    (None, HostHoldsAvailability::Unavailable(reason))
}

/// A host-order family the host's worker opened from a checkpoint's member
/// and handed back for a cold restore (FIX 6817), with the tag naming that
/// member: the artifact's snapshot id, the recipient and its epoch, and the
/// member's BLAKE3. Its `Debug` names only how many rows it holds.
#[derive(Clone)]
pub struct ArtifactHostOrderHolds {
    family: HostOrderHolds,
    snapshot_id: [u8; 32],
    recipient_id: [u8; 32],
    recipient_epoch: u64,
    member_blake3: [u8; 32],
}

impl std::fmt::Debug for ArtifactHostOrderHolds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ArtifactHostOrderHolds({:?})", self.family)
    }
}

impl ArtifactHostOrderHolds {
    /// `family`, opened from the member the tag names.
    #[must_use]
    pub fn new(
        family: HostOrderHolds,
        snapshot_id: [u8; 32],
        recipient_id: [u8; 32],
        recipient_epoch: u64,
        member_blake3: [u8; 32],
    ) -> Self {
        Self {
            family,
            snapshot_id,
            recipient_id,
            recipient_epoch,
            member_blake3,
        }
    }

    /// Whether the tag names `member`, the one the artifact of `vault_id`
    /// and `snapshot` carries, and the member's own binding agrees.
    fn names(&self, vault_id: &[u8; 32], snapshot: &[u8; 32], member: &HostHoldsMember) -> bool {
        let Ok(sealed) = SealedHostHolds::from_bytes(&member.0) else {
            return false;
        };
        let binding = sealed.binding();
        binding.engine_vault_id == *vault_id
            && binding.snapshot == *snapshot
            && self.snapshot_id == *snapshot
            && binding.recipient_id == self.recipient_id
            && binding.recipient_epoch == self.recipient_epoch
            && member.digest() == self.member_blake3
    }
}

impl CheckpointKey {
    /// This key, carrying the family the host's worker opened from the
    /// artifact's host-private member, for a cold restore whose source could
    /// not answer (FIX 6817). The restore passes it to `finish` only when
    /// its tag names the member the artifact it opens carries.
    #[must_use]
    pub fn with_artifact_host_holds(mut self, holds: ArtifactHostOrderHolds) -> Self {
        self.artifact_host_holds = Some(Box::new(holds));
        self
    }

    /// The host-private member the artifact at `path` carries, its bytes
    /// as the image holds them, once the artifact opened and checked whole
    /// with this key: what a host's worker opens and catalogs. `None` where
    /// it carries none. The member stays sealed to the host's recipient.
    ///
    /// # Errors
    ///
    /// The artifact does not open with this key.
    pub fn host_holds_member(&self, path: &std::path::Path) -> Result<Option<Vec<u8>>> {
        let (image, _, _) = crate::recovery::checkpoint::read_image(path, self)?;
        Ok(image.host_holds.map(|member| member.0))
    }
}

/// Takes the member out of `image` before the image is consumed, and the
/// family `key` carries when its tag names that member: what `finish`
/// installs from the artifact. With no family on the key, `None` and no
/// word; with one that names no member here, `None`, warned: unknown,
/// never a refusal.
pub(in crate::recovery::checkpoint) fn artifact_host_holds(
    image: &mut CheckpointImage,
    key: &CheckpointKey,
) -> Option<HostOrderHolds> {
    let member = image.host_holds.take();
    let holds = key.artifact_host_holds.as_deref()?;
    let named = match (member.as_ref(), image.snapshot.as_ref()) {
        (Some(member), Some(snapshot)) => holds.names(&key.vault_id, snapshot, member),
        _ => false,
    };
    if !named {
        tracing::warn!(
            reason = "host_holds_unknown",
            "the host-order legal holds handed for this restore name no member its artifact \
             carries; they are not installed from it"
        );
        return None;
    }
    Some(holds.family.clone())
}
