//! The kit's read of the home's current index (FIX 7106): the generations a
//! publisher named the kit's root for, newest committed first, with the
//! revision of the one read that named them. A request is signed as a part
//! fetch is ([`super::KitBundleFetch`]), under its own domain and path, so
//! neither stands for the other, and the home takes each nonce once, beside
//! the part fetches' own. The answer names no world and no other root's
//! generation.
//!
//! The index comes in pages (FIX 9364), so a big kit is never turned away:
//! each page is cut from one read, the root's generations first, newest
//! committed first, and fills up to [`KIT_PAD_INDEX_REPLY_MAX`]. A page that
//! is not the last names its cursor: the read's revision and the commit order
//! its last entry holds, never an offset. The next request signs that cursor
//! with a fresh nonce. A cursor whose revision the home no longer reads
//! starts from the newest again, under the revision it reads now.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use super::super::bundle::{SealedBundleEntry, denied, entries_in, index_in, served_index};
use super::{KIT_BUNDLE_FETCH_MAX_AGE_SECS, KIT_BUNDLE_FETCH_NONCE_BYTES, take_nonce};
use crate::Vault;
use crate::error::Result;
use crate::sync::residence::SealedBundleIndex;
use crate::world_keys::RecoveryRootId;

/// The kit index door's path on the home.
pub const KIT_PAD_INDEX_FETCH_PATH: &str = "/v1/recovery/sealed-bundle/index";
/// What every kit index fetch's signed bytes start with. A cursor joined the
/// signed bytes in v2 (FIX 9364).
const KIT_PAD_INDEX_FETCH_DOMAIN: &[u8] = b"oneiron/kit-pad-index-fetch/v2\0";
/// The most bytes one index answer may hold, now one page's (CALLS:
/// KIT_PAD_INDEX_REPLY_MAX, 1 MiB, FIX 9364): the kit's memory floor for one
/// answer, and what the home fills a page up to. It is the one default; a
/// bigger index comes in more pages, never refused.
pub const KIT_PAD_INDEX_REPLY_MAX: usize = 1024 * 1024;
/// The most bytes one entry takes in an index answer, its comma included:
/// 48-hex generation, two 64-hex digests, three 20-digit `u64`s, keys and
/// punctuation.
const KIT_PAD_INDEX_ENTRY_MAX: usize = 333;
/// The most bytes an index answer takes around its entries: its revision,
/// its list and its cursor, with room to spare.
const KIT_PAD_INDEX_PAGE_AROUND: usize = 512;
/// The entries one page holds, so its answer stays within
/// [`KIT_PAD_INDEX_REPLY_MAX`].
const KIT_PAD_INDEX_PAGE_ENTRIES: usize =
    (KIT_PAD_INDEX_REPLY_MAX - KIT_PAD_INDEX_PAGE_AROUND) / KIT_PAD_INDEX_ENTRY_MAX;

/// One kit index fetch: what its signature covers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KitPadIndexFetch {
    pub vault_id: [u8; 32],
    /// The kit's recovery root.
    pub root: RecoveryRootId,
    /// The home's address as the request names it, as a part fetch names it
    /// (`kit_bundle_fetch_origin`).
    pub origin: String,
    /// The revision an earlier page of the scan was read at: the cursor's,
    /// with [`Self::before_commit_order`]. `None` for the first page.
    pub retained_revision: Option<[u8; 32]>,
    /// The commit order the earlier page's last entry holds: this page holds
    /// the entries committed before it. `None` for the first page.
    pub before_commit_order: Option<u64>,
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
        match &self.retained_revision {
            Some(revision) => {
                out.push(1);
                out.extend_from_slice(revision);
            }
            None => out.push(0),
        }
        match self.before_commit_order {
            Some(order) => {
                out.push(1);
                out.extend_from_slice(&order.to_be_bytes());
            }
            None => out.push(0),
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

/// One page of the kit's index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KitPadIndexPage {
    /// The page's generations, newest committed first, and the revision of
    /// the one read that named them.
    pub index: SealedBundleIndex,
    /// Where the next page starts, under the same revision, when more
    /// follow: the commit order this page's last entry holds.
    pub next_before_commit_order: Option<u64>,
}

/// One page of the generations the home keeps named for `fetch`'s root,
/// newest committed first, with the revision of the one read that named
/// them: from the newest, or below `fetch`'s cursor while the home reads the
/// cursor's revision. `signature` is that root's anchor, as the newest
/// generation named for it records it, over [`KitPadIndexFetch::transcript`].
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
) -> Result<KitPadIndexPage> {
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
    let mut index = served_index(index_in(vault, &txn)?, |entry: &SealedBundleEntry| {
        entry.kit == Some(kit)
    });
    // A cursor of another read starts the scan over from the newest.
    let before = fetch
        .before_commit_order
        .filter(|_| fetch.retained_revision == Some(index.retained_revision));
    let mut rest = index
        .entries
        .into_iter()
        .filter(|entry| before.is_none_or(|before| entry.commit_order < before));
    index.entries = rest.by_ref().take(KIT_PAD_INDEX_PAGE_ENTRIES).collect();
    let next_before_commit_order = if rest.next().is_some() {
        index.entries.last().map(|entry| entry.commit_order)
    } else {
        None
    };
    Ok(KitPadIndexPage {
        index,
        next_before_commit_order,
    })
}
