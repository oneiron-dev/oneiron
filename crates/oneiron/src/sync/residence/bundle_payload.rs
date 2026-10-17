//! What the vault's sealed cloud bundle carries (FIX 922 PR 2): the base section
//! and each cloud-bound world's section a publisher seals, and how a reader takes
//! a bundle back in. The carrier is `world_keys::bundle`; the holder and the wire
//! are `residence::bundle` and the residence client's.

use crate::error::Result;
use crate::sync::WindowManager;
use crate::world_keys::{SealedKeyPads, SealedVaultBundle, SealedVaultUpload};

/// What one take moved.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SealedBundleTake {
    /// World sections this machine opened.
    pub sections: usize,
    /// Windows merged and materialized here.
    pub merged: usize,
    /// Windows kept in their mirror only, on an opened-item machine.
    pub mirrored: usize,
    /// Sections or windows that did not open or merge here.
    pub skipped: usize,
}

impl WindowManager {
    /// Seals this machine's upload for UTC slot `slot`: the base section, a
    /// fresh section of every cloud-bound world this machine reads, and every
    /// other section of `latest` (the holder's newest generation and its pad
    /// object) unchanged, minus the sections of worlds this machine reads that no
    /// longer go to the cloud. Refused on an opened-item machine.
    pub fn assemble_sealed_bundle(
        &self,
        slot: u64,
        latest: Option<(&SealedVaultBundle, &SealedKeyPads)>,
    ) -> Result<SealedVaultUpload> {
        let _ = (slot, latest);
        todo!("FIX 922 PR 2: payload assembly")
    }

    /// Takes `bundle` and its pad object in: opens every section this machine
    /// may read and merges each window into its mirror. A full machine
    /// materializes the rows; an `opened`-item machine keeps them in the mirror
    /// until a promotion materializes it.
    pub fn take_sealed_bundle(
        &self,
        bundle: &SealedVaultBundle,
        pads: &SealedKeyPads,
        opened: bool,
    ) -> Result<SealedBundleTake> {
        let _ = (bundle, pads, opened);
        todo!("FIX 922 PR 2: take")
    }
}
