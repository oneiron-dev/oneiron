//! What one bundle relay moved ([`SealedBundleRelay`]), with what the
//! generation it took or published leaves for a kit restore (FIX-LIST 11944):
//! the worlds whose capsule this machine's upload could not seal fresh (FIX
//! 4497), and the worlds a kit restore of that generation still awaits a
//! reader for (FIX 4496), as the CLI's kit restore names them.

use crate::authority::Destination;
use crate::sync::residence::{SealedBundleTake, sealed_bundle_awaiting_reader};
use crate::world_keys::{SealedBundleGeneration, SealedVaultBundle};
use crate::{EntityId, Vault};

/// What one bundle relay moved.
#[derive(Debug, Clone, Default)]
pub struct SealedBundleRelay {
    /// The newest generation taken in this slot, and what its take moved,
    /// with what the world capsules it opened imported (`authority`).
    pub taken: Option<(SealedBundleGeneration, SealedBundleTake)>,
    /// The generation this machine published for the slot.
    pub published: Option<SealedBundleGeneration>,
    /// Each world whose capsule the published generation does not seal fresh,
    /// because the history held here, merged with the capsule it replaces, is
    /// incomplete (FIX 4497): the latest generation's capsule rides on
    /// unchanged, or none. Empty when nothing was published.
    pub incomplete_authority: Vec<EntityId>,
    /// The worlds whose authority capsule the generation this relay took or
    /// published last files sealed to no recovery root pinned here now (FIX
    /// 4496): a kit restore of it restores each world's keys only once a
    /// machine that reads it publishes again. Empty when no root is pinned or
    /// the relay took and published nothing.
    pub awaiting_reader: Vec<EntityId>,
    /// Erased worlds and hard-erased keys stripped from every pad object the
    /// home keeps.
    pub erased: usize,
    /// Grants of a kept pad object's key this machine sealed for a machine
    /// admitted since its generation, and the home took (FIX 4271).
    pub offered: usize,
    /// Kept pad objects that open with no key here yet: their access is
    /// pending with the home. Never a swept erase.
    pub pending_pad_access: usize,
    /// Erased worlds and keys held back, unswept, while a kept pad object
    /// opens with no key here.
    pub pending_erases: usize,
    /// The relay reached the home; one that did not counted nothing (FIX 4953).
    pub reached: bool,
    /// Erase's sweep ran, so the two pending counts were counted (FIX 4953).
    pub swept: bool,
}

impl SealedBundleRelay {
    /// Whether this relay took or published a generation, so its
    /// `awaiting_reader` was read.
    pub(super) fn moved_generation(&self) -> bool {
        self.taken.is_some() || self.published.is_some()
    }
}

/// The worlds a kit restore of `bundle`, this machine's own upload for
/// `holder`, awaits a reader for: it opens with this machine's capsule. One
/// that does not open here names none, and the relay goes on.
pub(super) fn published_awaiting_reader(
    vault: &Vault,
    bundle: &SealedVaultBundle,
    holder: Destination,
) -> Vec<EntityId> {
    let awaiting = vault
        .open_vault_bundle(bundle, holder)
        .and_then(|opened| sealed_bundle_awaiting_reader(vault, &opened));
    awaiting.unwrap_or_else(|error| {
        tracing::warn!(
            kind = ?error.kind(),
            "the published generation's awaiting readers stay unread"
        );
        Vec::new()
    })
}
