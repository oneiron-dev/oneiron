//! The training link key's custody client (TRAINING-LINK = C, TL-2): K, the
//! one key the vault's publisher training codes are made under
//! (`feedback::conversation_training::link`).
//!
//! K is one subject per vault: kind `TrainingLink`, an empty item. Its
//! custody generation is the training state's link generation: 0 for the
//! first K, one more each time a restore that brought no K left its slot
//! missing and the vault's next training writer minted a fresh one (FIX
//! 5892). A K is minted in the writer that needs it, which pins the custody
//! binding in the same transaction, and read strictly after. It sits in the
//! custody head's host-readable compartment, wrapped to the recovery root
//! when one is pinned and to the vault data key's custody subkey, so a
//! restore with either brings it back; a side restore carries every live
//! generation. It retires only by an erase's durable intent, through the
//! current generation, staged in the writer that applies the last purge
//! control's `removed` receipt and finished after that commit, under its
//! client's own readiness rule. A retired or unreadable K is never minted
//! again.

use heed::{RoTxn, RwTxn};
use zeroize::Zeroizing;

use crate::key_custody::files::EntryState;
use crate::key_custody::identity::CustodyBinding;
use crate::key_custody::identity::CustodyKind;
use crate::key_custody::identity::CustodySubject;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_base::error::StoreError;

/// Where K's custody slot at one generation stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrainingLinkSlot {
    /// Published and not retired.
    Live,
    /// Retired: the erase purge finished.
    Retired,
    /// Neither: never minted in this custody, or lost with a restore that
    /// brought no custody head.
    Missing,
}

/// K's subject in `binding`'s custody: a singleton, its item empty.
pub fn link_subject(binding: &CustodyBinding) -> Result<CustodySubject> {
    binding.subject(CustodyKind::TrainingLink, &[])
}

/// K's bytes, copied out of a custody secret: exactly 32.
pub fn copy_key(secret: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0; 32]);
    if secret.len() != key.len() {
        return Err(CustodyKind::TrainingLink.corrupt());
    }
    key.copy_from_slice(secret);
    Ok(key)
}
