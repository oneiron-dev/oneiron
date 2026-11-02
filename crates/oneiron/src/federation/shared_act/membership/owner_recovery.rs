//! Who authorized a proof-of-control owner recovery (ARCH-0043, OF-163; FIX
//! 1812). The recovery's writer takes one of these in place of the bare
//! digest of a proof note, and judges it again in its own transaction, so
//! an operator's word alone never makes an Owner.
//!
//! - A managed vault's account owner, whom his supervisor attested for the
//!   one request: the hosting account is the organization's control, and
//!   his say-so is the recovery (FIX 5255).
//! - A self-hosted vault's own host, on its live root credential: there the
//!   host acts as the vault's owner (FIX 2222), held to that root in the
//!   writer.
//! - A stopped self-hosted vault, opened by its own host with the key its
//!   config holds.
//!
//! A hosted operator's root is none of these: its host action is the typed
//! support-grant refusal, so it recovers no Owner. Each kind keeps the
//! BLAKE3 of the note its author gave, never the note.

use crate::authority::HostActionAuthority;
use crate::error::{Error, Result};
use crate::{EntityId, HostingPrivacyPosture, Vault};

/// The authenticated authorization of one owner recovery (FIX 1812).
#[derive(Debug, Clone)]
pub enum OwnerRecoveryAuthorization {
    /// A managed vault's account owner, his supervisor's attestation for
    /// this one request verified at managed ingress.
    AccountOwner { holder: EntityId, note: [u8; 32] },
    /// A self-hosted vault's host root, as the owner its host action names.
    SelfHostRoot {
        action: HostActionAuthority,
        note: [u8; 32],
    },
    /// A stopped self-hosted vault, opened by its own host.
    StoppedSelfHost { note: [u8; 32] },
}

impl OwnerRecoveryAuthorization {
    /// The BLAKE3 of the note its author gave, which the signed handover
    /// keeps.
    #[must_use]
    pub const fn note(&self) -> [u8; 32] {
        match self {
            Self::AccountOwner { note, .. }
            | Self::SelfHostRoot { note, .. }
            | Self::StoppedSelfHost { note } => *note,
        }
    }

    /// The person the signed handover names as its authorizer (FIX 5401):
    /// the attested account owner; `None` for a host's own authorization,
    /// which names no person.
    #[must_use]
    pub const fn authorizer(&self) -> Option<EntityId> {
        match self {
            Self::AccountOwner { holder, .. } => Some(*holder),
            Self::SelfHostRoot { .. } | Self::StoppedSelfHost { .. } => None,
        }
    }

    /// Whether this authorization still holds in the recovering writer: a
    /// host root's action still holds on a self-hosted vault, and a stopped
    /// host's vault is self-hosted. An account owner's attestation was
    /// verified at ingress for this one request.
    pub(crate) fn holds_in(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<()> {
        match self {
            Self::AccountOwner { .. } => Ok(()),
            Self::SelfHostRoot { action, .. } => action.guard().holds_in(vault, txn),
            Self::StoppedSelfHost { .. } => {
                if vault.privacy_posture() == HostingPrivacyPosture::SelfHostLocal {
                    Ok(())
                } else {
                    Err(Error::HostActionRequiresSupportGrant)
                }
            }
        }
    }
}
