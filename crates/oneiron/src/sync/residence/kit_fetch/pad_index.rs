//! The kit's read of the home's current index (FIX 7106): the generations a
//! publisher named the kit's root for, newest committed first, with the
//! revision of the one read that named them. A request is signed as a part
//! fetch is ([`super::KitBundleFetch`]), under its own domain and path, so
//! neither stands for the other, and the home takes each nonce once, beside
//! the part fetches' own. The answer names no world and no other root's
//! generation.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use super::super::bundle::{SealedBundleEntry, denied, entries_in, index_in, served_index};
use super::{KIT_BUNDLE_FETCH_MAX_AGE_SECS, KIT_BUNDLE_FETCH_NONCE_BYTES, take_nonce};
use crate::Vault;
use crate::error::Result;
use crate::sync::residence::SealedBundleIndex;
use crate::world_keys::RecoveryRootId;

/// The kit index door's path on the home.
pub const KIT_PAD_INDEX_FETCH_PATH: &str = "/v1/recovery/sealed-bundle/index";
/// What every kit index fetch's signed bytes start with.
const KIT_PAD_INDEX_FETCH_DOMAIN: &[u8] = b"oneiron/kit-pad-index-fetch/v1\0";

/// One kit index fetch: what its signature covers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KitPadIndexFetch {
    pub vault_id: [u8; 32],
    /// The kit's recovery root.
    pub root: RecoveryRootId,
    /// The home's address as the request names it, as a part fetch names it
    /// (`kit_bundle_fetch_origin`).
    pub origin: String,
    /// The signer's wall clock, in seconds.
    pub timestamp: u64,
    pub nonce: [u8; KIT_BUNDLE_FETCH_NONCE_BYTES],
}

impl KitPadIndexFetch {
    /// The bytes the root's anchor signs.
    #[must_use]
    pub fn transcript(&self) -> Vec<u8> {
        let mut out = KIT_PAD_INDEX_FETCH_DOMAIN.to_vec();
        out.extend_from_slice(&self.vault_id);
        out.extend_from_slice(&self.root.0);
        for field in [
            self.origin.as_bytes(),
            b"POST",
            KIT_PAD_INDEX_FETCH_PATH.as_bytes(),
        ] {
            out.extend_from_slice(&(field.len() as u64).to_be_bytes());
            out.extend_from_slice(field);
        }
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.nonce);
        out
    }

    /// Signs the request with the kit's owner anchor.
    #[must_use]
    pub fn sign(&self, anchor: &SigningKey) -> [u8; 64] {
        anchor.sign(&self.transcript()).to_bytes()
    }
}

/// The generations the home keeps named for `fetch`'s root, newest committed
/// first, with the revision of the one read that named them. `signature` is
/// that root's anchor, as the newest generation named for it records it,
/// over [`KitPadIndexFetch::transcript`].
///
/// # Errors
///
/// Another vault; no kept generation named for the root; a bad signature; a
/// request signed outside `KIT_BUNDLE_FETCH_MAX_AGE_SECS` of the home's
/// clock, or with a nonce the home took; storage errors.
pub fn kit_sealed_bundle_index(
    vault: &Vault,
    fetch: &KitPadIndexFetch,
    signature: &[u8; 64],
) -> Result<SealedBundleIndex> {
    let now = vault.store.clock.wall_now();
    if now.abs_diff(fetch.timestamp) > KIT_BUNDLE_FETCH_MAX_AGE_SECS {
        return Err(denied());
    }
    let kit = {
        let txn = vault.store.env.read_txn()?;
        if vault.authority_view_readonly_in_txn(&txn)?.vault_id != Some(fetch.vault_id) {
            return Err(denied());
        }
        entries_in(vault, &txn)?
            .into_iter()
            .rev()
            .find_map(|entry| entry.kit.filter(|kit| kit.root == fetch.root))
            .ok_or_else(denied)?
    };
    VerifyingKey::from_bytes(&kit.anchor_key)
        .and_then(|key| key.verify_strict(&fetch.transcript(), &Signature::from_bytes(signature)))
        .map_err(|_| denied())?;
    take_nonce(vault, fetch.timestamp, &fetch.nonce, now)?;
    let txn = vault.store.env.read_txn()?;
    Ok(served_index(
        index_in(vault, &txn)?,
        |entry: &SealedBundleEntry| entry.kit == Some(kit),
    ))
}
