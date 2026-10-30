//! The kit's read of the key custody the residence home holds (FIX 5846): a
//! restore on a new host that holds the kit and no machine of the vault's
//! reads the sealed head and log frames of its custody lineage from the home,
//! in place of the folder beside the backup. A request is signed as a part
//! fetch is ([`super::KitBundleFetch`]), under its own domain and path, and
//! the home checks it against the root this home pins for the vault, never a
//! root the request names alone: a caller who only names a lineage learns
//! nothing of its positions or sizes. The home takes each nonce once, beside
//! the part fetches' own.
//!
//! The custody comes in pages read only under the lineage's lock: the head
//! in slices, then the frames after the cursor's sequence number through the
//! head's, each page at most `KIT_CUSTODY_PAGE_BYTES` of both, or one frame
//! alone where it is larger. A page that is not the last names its cursor:
//! the head offset and the last sequence number it reached. Every answer
//! stays within the residence RPC result bound once base64 is added
//! ([`KIT_CUSTODY_REPLY_MAX`]). Sealed bytes only: the home opens nothing.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use super::super::bundle::denied;
use super::{KIT_BUNDLE_FETCH_MAX_AGE_SECS, KIT_BUNDLE_FETCH_NONCE_BYTES, take_nonce};
use crate::Vault;
use crate::error::Result;
use crate::store::custody_protocol::{CustodyHomePage, Lineage};
use crate::world_keys::RecoveryRootId;

/// The kit custody door's path on the home.
pub const KIT_CUSTODY_FETCH_PATH: &str = "/v1/recovery/custody/page";
/// What every kit custody fetch's signed bytes start with.
const KIT_CUSTODY_FETCH_DOMAIN: &[u8] = b"oneiron/kit-custody-fetch/v1\0";
/// The most bytes one custody page's answer may hold: the residence RPC
/// result bound (32 MiB once base64 is added), which every reply stays under.
pub const KIT_CUSTODY_REPLY_MAX: usize = 32 * 1024 * 1024;
/// The head and frame bytes one page holds at most, as a checkpoint part
/// does: base64 and each frame's sequence number, keys and punctuation keep
/// it under [`KIT_CUSTODY_REPLY_MAX`], and so does one frame larger than it
/// (a sealed frame's plaintext is at most 16 MiB).
const KIT_CUSTODY_PAGE_BYTES: usize = 16 * 1024 * 1024;

/// One kit custody fetch: what its signature covers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KitCustodyFetch {
    pub vault_id: [u8; 32],
    /// The kit's recovery root.
    pub root: RecoveryRootId,
    /// The home's address as the request names it, as a part fetch names it
    /// (`kit_bundle_fetch_origin`).
    pub origin: String,
    /// The custody lineage asked for: the vault and namespace the backup's
    /// custody names.
    pub lineage: Lineage,
    /// The head's bytes the page starts at.
    pub head_offset: u64,
    /// The page holds the frames after this log sequence number.
    pub after_seq: u64,
    /// The signer's wall clock, in seconds.
    pub timestamp: u64,
    pub nonce: [u8; KIT_BUNDLE_FETCH_NONCE_BYTES],
}

impl KitCustodyFetch {
    /// The bytes the root's anchor signs.
    #[must_use]
    pub fn transcript(&self) -> Vec<u8> {
        let mut out = KIT_CUSTODY_FETCH_DOMAIN.to_vec();
        out.extend_from_slice(&self.vault_id);
        out.extend_from_slice(&self.root.0);
        for field in [
            self.origin.as_bytes(),
            b"POST",
            KIT_CUSTODY_FETCH_PATH.as_bytes(),
        ] {
            out.extend_from_slice(&(field.len() as u64).to_be_bytes());
            out.extend_from_slice(field);
        }
        out.extend_from_slice(self.lineage.vault.as_bytes());
        out.extend_from_slice(self.lineage.namespace.as_bytes());
        out.extend_from_slice(&self.head_offset.to_be_bytes());
        out.extend_from_slice(&self.after_seq.to_be_bytes());
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

/// One page of the custody this home holds of `fetch`'s lineage, from
/// `fetch`'s cursor (FIX 5846). `signature` is the anchor of the recovery
/// root this home pins for the vault, over [`KitCustodyFetch::transcript`];
/// a request for another root is refused before any custody is read.
///
/// # Errors
///
/// Another vault; no pinned root, or another one than `fetch` names; a bad
/// signature; a request signed outside `KIT_BUNDLE_FETCH_MAX_AGE_SECS` of the
/// home's clock, or with a nonce the home took; no head of the lineage here,
/// or an offset past its end; storage errors.
pub fn kit_custody_page(
    vault: &Vault,
    fetch: &KitCustodyFetch,
    signature: &[u8; 64],
) -> Result<CustodyHomePage> {
    let now = vault.store.clock.wall_now();
    if now.abs_diff(fetch.timestamp) > KIT_BUNDLE_FETCH_MAX_AGE_SECS {
        return Err(denied());
    }
    let pin = {
        let txn = vault.store.env.read_txn()?;
        let view = vault.authority_view_readonly_in_txn(&txn)?;
        if view.vault_id != Some(fetch.vault_id) {
            return Err(denied());
        }
        view.pinned_root
            .filter(|pin| pin.id == fetch.root)
            .ok_or_else(denied)?
    };
    VerifyingKey::from_bytes(&pin.anchor_key)
        .and_then(|key| key.verify_strict(&fetch.transcript(), &Signature::from_bytes(signature)))
        .map_err(|_| denied())?;
    take_nonce(vault, fetch.timestamp, &fetch.nonce, now)?;
    vault
        .store
        .residence_custody_page(
            fetch.lineage,
            fetch.head_offset,
            fetch.after_seq,
            KIT_CUSTODY_PAGE_BYTES,
        )?
        .ok_or_else(denied)
}
