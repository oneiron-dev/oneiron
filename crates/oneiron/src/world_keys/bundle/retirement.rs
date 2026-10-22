//! Bundle generation identity, upload cadence and retirement selection.
//! The entry point is `retired_bundle_generations`.
//! `super` owns generation minting and forwards these public definitions.

use super::*;

/// The bundle's size step: every bundle is a positive multiple of it.
pub const SEALED_BUNDLE_PAD_STEP_BYTES: usize = 64 * 1024 * 1024;
/// One upload per vault in each fixed UTC slot of this length, changed or not.
pub const SEALED_BUNDLE_UPLOAD_INTERVAL_SECS: u64 = 24 * 60 * 60;
/// The generations a holder keeps: 90 daily ones (ARCH-0038: backups keep a
/// deleted thing up to 90 days).
pub const SEALED_BUNDLE_KEEP: usize = 90;

/// The UTC upload slot `unix_secs` falls in.
#[must_use]
pub fn sealed_bundle_slot(unix_secs: u64) -> u64 {
    unix_secs / SEALED_BUNDLE_UPLOAD_INTERVAL_SECS
}

/// The generations a holder retires from `kept` in slot `now_slot`: every one
/// past the newest [`SEALED_BUNDLE_KEEP`], and every older one that many slots
/// old, so nothing but the last copy outlives 90 days when uploads stop. The
/// newest is never retired by age (owner ruling: spare the last copy). A retired
/// generation's pad object goes with it.
#[must_use]
pub fn retired_bundle_generations(
    now_slot: u64,
    kept: &[SealedBundleGeneration],
) -> Vec<SealedBundleGeneration> {
    let mut newest_first = kept.to_vec();
    newest_first.sort_unstable();
    newest_first.dedup();
    newest_first.reverse();
    newest_first
        .into_iter()
        .enumerate()
        .filter(|(rank, generation)| {
            *rank >= SEALED_BUNDLE_KEEP
                || (*rank > 0 && generation.slot.saturating_add(KEEP_SLOTS) <= now_slot)
        })
        .map(|(_, generation)| generation)
        .collect()
}

/// One generation's id: the UTC slot it was sealed for and 16 fresh random
/// bytes. Its bundle and its pad object carry the same id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SealedBundleGeneration {
    pub slot: u64,
    pub nonce: [u8; 16],
}

impl SealedBundleGeneration {
    /// `slot (8, big-endian) ‖ nonce (16)`.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; GENERATION_LEN] {
        let mut out = [0u8; GENERATION_LEN];
        out[..8].copy_from_slice(&self.slot.to_be_bytes());
        out[8..].copy_from_slice(&self.nonce);
        out
    }

    /// Parses [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != GENERATION_LEN {
            return Err(refused("a bundle generation is 24 bytes"));
        }
        let mut slot = [0u8; 8];
        let mut nonce = [0u8; 16];
        slot.copy_from_slice(&bytes[..8]);
        nonce.copy_from_slice(&bytes[8..]);
        Ok(Self {
            slot: u64::from_be_bytes(slot),
            nonce,
        })
    }
}
