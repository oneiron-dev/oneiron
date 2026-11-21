//! The recovery authority key's live generation, found from the kit's seed.
//!
//! Old kits read as generation 0 by construction: the kit carries no
//! generation, and generation 0 derives today's bytes exactly
//! ([`crate::world_keys::RecoveryAuthoritySigner::authority_seed`]). Each
//! rotation enrols the next generation and revokes the old one, gapless, so
//! deriving generations `0..=n` (where `n` is the count of
//! [`EnrolledOwnerKeyKind::RecoveryAuthority`] rows) covers every enrolled
//! generation; an over-count from adopted or branched rows only derives extra
//! keys that match nothing. The finder returns the one live match and the
//! highest enrolled match (live or revoked); the next generation is the
//! highest enrolled plus one.

use super::owner_key_enrollment_door::EnrolledOwnerKeyKind;
use crate::Vault;
use crate::authority::AuthorityVaultId;
use crate::error::Result;
use crate::world_keys::{RecoveryAuthoritySigner, RecoveryRootSeed};

/// What the kit's seed holds on the roster: the live generation, if any, and
/// the highest enrolled generation (live or revoked), if any. Each match is
/// its generation and its signer, derived from the kit's seed.
pub(crate) struct RecoveryAuthorityGenerations {
    /// The live match, if the roster holds one of this seed's generations
    /// live. At most one is live by construction; if several ever matched,
    /// this is the highest.
    pub(crate) live: Option<(u32, RecoveryAuthoritySigner)>,
    /// The highest enrolled match (live or revoked), if any of this seed's
    /// generations was ever enrolled. The next generation is this plus one.
    pub(crate) enrolled: Option<(u32, RecoveryAuthoritySigner)>,
}

impl Vault {
    /// Finds `seed`'s generations on the roster in the caller's transaction
    /// (a read or a write): derives generations `0..=n`, where `n` is the
    /// count of [`EnrolledOwnerKeyKind::RecoveryAuthority`] rows in
    /// [`Self::enrolled_owner_keys_in_txn`] (live or revoked), and compares
    /// each derived public key against those rows. Returns the live match and
    /// the highest enrolled match. No store or keystore write.
    pub(crate) fn recovery_authority_generations_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        seed: &RecoveryRootSeed,
        vault_id: &AuthorityVaultId,
    ) -> Result<RecoveryAuthorityGenerations> {
        let enrolled = self.enrolled_owner_keys_in_txn(txn)?;
        let authority: Vec<(&[u8; 32], bool)> = enrolled
            .iter()
            .filter(|key| key.kind == EnrolledOwnerKeyKind::RecoveryAuthority)
            .map(|key| (&key.public_key, key.live))
            .collect();
        let count = authority.len() as u32;
        let mut live_generation: Option<u32> = None;
        let mut highest_generation: Option<u32> = None;
        for generation in 0..=count {
            let public =
                RecoveryAuthoritySigner::from_seed(seed, vault_id, generation)?.public_key();
            let Some(matched) = authority
                .iter()
                .find(|(key, _)| **key == public)
                .map(|(_, live)| *live)
            else {
                continue;
            };
            highest_generation = Some(generation);
            if matched {
                live_generation = Some(generation);
            }
        }
        let live = match live_generation {
            Some(generation) => Some((
                generation,
                RecoveryAuthoritySigner::from_seed(seed, vault_id, generation)?,
            )),
            None => None,
        };
        let enrolled = match highest_generation {
            Some(generation) => Some((
                generation,
                RecoveryAuthoritySigner::from_seed(seed, vault_id, generation)?,
            )),
            None => None,
        };
        Ok(RecoveryAuthorityGenerations { live, enrolled })
    }

    /// Whether the roster holds any live recovery authority key at all, from
    /// any seed, in the caller's transaction. The kitless preset doors refuse
    /// on it; the kit doors refuse `KIT_NOT_THIS_VAULTS` when it holds but
    /// the kit's own seed holds none live.
    pub(crate) fn any_live_recovery_authority_in_txn(&self, txn: &heed::RoTxn<'_>) -> Result<bool> {
        Ok(self
            .enrolled_owner_keys_in_txn(txn)?
            .iter()
            .any(|key| key.kind == EnrolledOwnerKeyKind::RecoveryAuthority && key.live))
    }
}
