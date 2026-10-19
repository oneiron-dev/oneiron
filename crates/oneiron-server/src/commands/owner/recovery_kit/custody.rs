//! The kit's side of a custody head (KS-4A1, FIX 5685). A world kit's
//! recovery root, rebuilt from its pieces for `oneiron restore --unlock kit`,
//! opens every compartment of the head published beside the backup, the
//! owner-only ones too. The restore reads that head through the same source
//! and validator an archive restore does; only the opener differs. The kit
//! keeps its seed alone: nothing here stores it or a key it opens.

use oneiron::world_keys::{HybridSecretKey, WORLD_KIT_ESCROW};

use super::super::vault_key::HostUnlock;

/// The recovery root `unlock` holds, when it is a world kit's.
pub(in crate::commands::owner) fn kit_custody_root(
    unlock: &HostUnlock,
) -> Option<&HybridSecretKey> {
    match unlock {
        HostUnlock::Escrow { label, secret } if label == WORLD_KIT_ESCROW => Some(secret),
        _ => None,
    }
}
