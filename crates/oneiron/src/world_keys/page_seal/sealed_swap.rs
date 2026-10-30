//! A restore over a sealed vault (OF-570 maximum tier), kept recoverable
//! across its swap: the mirrors beside the live vault and its replacement
//! (moved out of `page_seal` whole).

use std::fs;
use std::path::Path;
use std::sync::PoisonError;

use super::{
    MIRROR_VERSION, MIRRORING, Mirror, custody_root, page_seal_custody_path, write_mirror,
};
use crate::Vault;
use crate::error::Result;
use crate::world_keys::{CarriedVaultKey, refused};

impl Vault {
    /// Step 1 of a restore over this vault ([`SealedSwap`]), before the
    /// exchange: the mirror beside this vault and the one beside
    /// `replacement`, restored for its place under a fresh incarnation of its
    /// seal, each name both incarnations, with the replacement's wraps. `None`
    /// for a plain vault and a plain replacement; a replacement of another
    /// tier, vault or key, or under this vault's own incarnation, is refused.
    pub fn stage_sealed_swap(&self, replacement: &Vault) -> Result<Option<SealedSwap>> {
        let (live, next) = match (self.sealed_page_seal()?, replacement.sealed_page_seal()?) {
            (None, None) => return Ok(None),
            (Some(live), Some(next)) => (live, next),
            _ => return Err(refused("a restore over a vault keeps its tier")),
        };
        let commitment = live.data_key.commitment(&live.vault_id);
        if live.vault_id != next.vault_id || commitment != next.data_key.commitment(&next.vault_id)
        {
            return Err(refused(
                "the replacement is sealed under another vault's data key",
            ));
        }
        if live.incarnation == next.incarnation {
            return Err(refused(
                "the replacement is sealed under the live vault's own incarnation",
            ));
        }
        let carried = replacement
            .resting_vault_key()?
            .ok_or_else(|| refused("the replacement's vault key has no wrap"))?;
        let swap = SealedSwap {
            vault_id: live.vault_id,
            live: live.incarnation,
            replacement: next.incarnation,
            carried,
        };
        let _mirroring = MIRRORING.lock().unwrap_or_else(PoisonError::into_inner);
        write_mirror(
            self.store.env.path(),
            &swap.mirror(vec![swap.live, swap.replacement]),
        )?;
        write_mirror(
            replacement.store.env.path(),
            &swap.mirror(vec![swap.replacement, swap.live]),
        )?;
        Ok(Some(swap))
    }
}

/// A restore over a sealed vault, kept recoverable across its swap. The live
/// vault and its replacement trade places in one exchange, but the mirror of
/// each sits beside its directory, outside it, and does not move:
/// 1. [`Vault::stage_sealed_swap`], before the exchange: the mirrors beside
///    both name both incarnations.
/// 2. The exchange.
/// 3. [`Self::mirror_archive`], before the previous vault takes its archive
///    name: the mirror beside that name names the previous vault's
///    incarnation.
/// 4. [`Self::confirm`], once the swap is durable: the mirror at the vault's
///    path names the replacement's alone.
///
/// A crash between any two steps leaves each environment beside a mirror that
/// names its incarnation. An open takes the one whose page key opens it, and
/// its next mirror rewrite names that one alone.
pub struct SealedSwap {
    vault_id: [u8; 32],
    live: [u8; 32],
    replacement: [u8; 32],
    carried: CarriedVaultKey,
}

impl std::fmt::Debug for SealedSwap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SealedSwap(..)")
    }
}

impl SealedSwap {
    fn mirror(&self, incarnations: Vec<[u8; 32]>) -> Mirror {
        Mirror {
            version: MIRROR_VERSION,
            vault_id: self.vault_id,
            incarnations,
            carried: self.carried.clone(),
        }
    }

    /// Step 3: the mirror beside `archive`, the name the previous vault is
    /// about to take, names its incarnation, so it opens there.
    pub fn mirror_archive(&self, archive: &Path) -> Result<()> {
        let root = custody_root(archive)?;
        let _mirroring = MIRRORING.lock().unwrap_or_else(PoisonError::into_inner);
        write_mirror(&root, &self.mirror(vec![self.live]))
    }

    /// Removes the mirror [`Self::mirror_archive`] wrote beside `archive`,
    /// when the previous vault did not take that name after all.
    pub fn discard_archive_mirror(&self, archive: &Path) {
        if let Ok(path) = page_seal_custody_path(archive) {
            let _ = fs::remove_file(path);
        }
    }

    /// Step 4, once the swap is durable: the mirror beside the vault at
    /// `home` names the replacement's incarnation alone.
    pub fn confirm(&self, home: &Path) -> Result<()> {
        let root = custody_root(home)?;
        let _mirroring = MIRRORING.lock().unwrap_or_else(PoisonError::into_inner);
        write_mirror(&root, &self.mirror(vec![self.replacement]))
    }
}
