//! The kit door to the home's sealed cloud bundle (FIX 922; owner ruling
//! 10-18: the recovery kit alone must restore). An install that holds the kit
//! and no machine of the vault's reads a kept generation in slices, as a
//! machine reads it (`bundle`), with no session or credential: each request is
//! signed with the owner anchor the kit's seed expands to.
//!
//! A publisher names the recovery root it pins when it commits a generation,
//! and the home serves that generation to that root's anchor alone. The newest
//! is the newest generation named for the root, so a replaced kit reads only
//! the generations still kept for it. A pad object is always the current one:
//! erase's rewrite replaces it for the kit too.
//!
//! Each request signs the vault, the root, the home's address as the request
//! names it, the door, the slice it asks for, its time and a fresh nonce. The
//! home takes a request signed within [`KIT_BUNDLE_FETCH_MAX_AGE_SECS`] of its
//! clock, and each nonce once.
//!
//! The door asks no device class (FIX 3349; CALLS: KIT_BUNDLE_PHONE_POLICY,
//! allow): a kit restore installs the vault from a generation and keeps no
//! sealed copy, so a phone that holds the kit may restore from it.
//!
//! The kit reads the home's current index of the generations named for its
//! root the same way, through its own signed door (`pad_index`, FIX 7106), a
//! page at a time (FIX 9364).

mod pad_index;

pub use self::pad_index::{
    KIT_PAD_INDEX_FETCH_PATH, KIT_PAD_INDEX_REPLY_MAX, KitPadIndexFetch, KitPadIndexPage,
    kit_sealed_bundle_index,
};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use super::bundle::{
    BundlePartRead, SealedBundleEntry, SealedBundleObject, denied, entries_in, entry_in, hex,
    read_part_in,
};
use crate::Vault;
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::world_keys::{RecoveryRootId, SealedBundleGeneration};

/// The kit door's path on the home.
pub const KIT_BUNDLE_FETCH_PATH: &str = "/v1/recovery/sealed-bundle/part";
/// What every kit fetch's signed bytes start with.
const KIT_BUNDLE_FETCH_DOMAIN: &[u8] = b"oneiron/kit-bundle-fetch/v1\0";
/// How far, either way, a request's signed time may sit from the home's clock.
pub const KIT_BUNDLE_FETCH_MAX_AGE_SECS: u64 = 300;
/// A request's nonce: fresh random bytes, taken once.
pub const KIT_BUNDLE_FETCH_NONCE_BYTES: usize = 32;
/// A taken nonce is kept until the home's clock is a day past its signed time,
/// so a host clock set back within a day reopens no request.
const KIT_BUNDLE_FETCH_NONCE_RETAIN_SECS: u64 = 24 * 60 * 60;

/// Each nonce the kit door took.
const NONCES: SideTable<String, (), Raw> =
    SideTable::new(&side_table::SYNC_RESIDENCE_BUNDLE_FETCH_NONCE);

/// One kit fetch: what its signature covers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KitBundleFetch {
    pub vault_id: [u8; 32],
    /// The kit's recovery root.
    pub root: RecoveryRootId,
    /// The home's address as the request names it: its host, and its port when
    /// the address names one, in lower case.
    pub origin: String,
    /// The generation asked for, or `None` for the newest named for the root.
    pub generation: Option<SealedBundleGeneration>,
    pub object: SealedBundleObject,
    pub offset: u64,
    /// The signer's wall clock, in seconds.
    pub timestamp: u64,
    pub nonce: [u8; KIT_BUNDLE_FETCH_NONCE_BYTES],
}

impl KitBundleFetch {
    /// The bytes the root's anchor signs.
    #[must_use]
    pub fn transcript(&self) -> Vec<u8> {
        let mut out = KIT_BUNDLE_FETCH_DOMAIN.to_vec();
        out.extend_from_slice(&self.vault_id);
        out.extend_from_slice(&self.root.0);
        for field in [
            self.origin.as_bytes(),
            b"POST",
            KIT_BUNDLE_FETCH_PATH.as_bytes(),
            self.object.name().as_bytes(),
        ] {
            out.extend_from_slice(&(field.len() as u64).to_be_bytes());
            out.extend_from_slice(field);
        }
        match &self.generation {
            Some(generation) => {
                out.push(1);
                out.extend_from_slice(&generation.to_bytes());
            }
            None => out.push(0),
        }
        out.extend_from_slice(&self.offset.to_be_bytes());
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

/// The home's address a kit fetch to `url` signs: its host, and its port when
/// `url` names one other than its scheme's, in lower case. The kit and the
/// door both take it from here.
#[must_use]
pub fn kit_bundle_fetch_origin(url: &reqwest::Url) -> Option<String> {
    let host = url.host_str()?;
    let origin = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    };
    Some(origin.to_ascii_lowercase())
}

/// The kept generation `fetch` asks for, when its publisher named the root
/// `fetch` signs for.
fn named_entry_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fetch: &KitBundleFetch,
) -> Result<Option<SealedBundleEntry>> {
    let named = |entry: &SealedBundleEntry| entry.kit.is_some_and(|kit| kit.root == fetch.root);
    Ok(match fetch.generation {
        Some(generation) => entry_in(vault, txn, &generation)?.filter(named),
        None => entries_in(vault, txn)?.into_iter().rev().find(named),
    })
}

/// Takes a request's `nonce` signed at `timestamp`, once: a nonce taken
/// before refuses. Nonces signed a day before `now` go in the same
/// transaction.
fn take_nonce(
    vault: &Vault,
    timestamp: u64,
    nonce: &[u8; KIT_BUNDLE_FETCH_NONCE_BYTES],
    now: u64,
) -> Result<()> {
    let key = format!("{timestamp:016x}:{}", hex(nonce));
    let floor = format!(
        "{:016x}",
        now.saturating_sub(KIT_BUNDLE_FETCH_NONCE_RETAIN_SECS)
    );
    vault.with_write_txn_grouped(|wtxn| {
        if NONCES.contains(&vault.store, wtxn, &key)? {
            return Err(denied());
        }
        let mut expired = Vec::new();
        for row in NONCES.iter_raw_from(&vault.store, wtxn, &[])? {
            let (row_key, _) = row?;
            if row_key.as_slice() >= floor.as_bytes() {
                break;
            }
            expired.push(String::from_utf8(row_key).map_err(|_| Error::InvalidKey)?);
        }
        for row_key in &expired {
            NONCES.delete(&vault.store, wtxn, row_key)?;
        }
        NONCES.put(&vault.store, wtxn, &key, &())
    })
}

/// One slice of a kept generation's object for the kit door, at most
/// `SEALED_BUNDLE_READ_PART_MAX` bytes from `fetch`'s offset, with the
/// generation's entry: a generation whose publisher named `fetch`'s root, and
/// the newest such when `fetch` names none. `signature` is that root's anchor
/// over [`KitBundleFetch::transcript`]. `None` for a generation retired since
/// the request was checked; the read says when the offset is at or past the
/// object's end, and when a kept pad object's bytes there are missing.
///
/// # Errors
///
/// Another vault; no kept generation named for the root; a bad signature; a
/// request signed outside [`KIT_BUNDLE_FETCH_MAX_AGE_SECS`] of the home's
/// clock, or with a nonce the home took; storage errors.
pub fn kit_sealed_bundle_part(
    vault: &Vault,
    fetch: &KitBundleFetch,
    signature: &[u8; 64],
) -> Result<Option<(SealedBundleEntry, BundlePartRead)>> {
    let now = vault.store.clock.wall_now();
    if now.abs_diff(fetch.timestamp) > KIT_BUNDLE_FETCH_MAX_AGE_SECS {
        return Err(denied());
    }
    let (generation, kit) = {
        let txn = vault.store.env.read_txn()?;
        if vault.authority_view_readonly_in_txn(&txn)?.vault_id != Some(fetch.vault_id) {
            return Err(denied());
        }
        let entry = named_entry_in(vault, &txn, fetch)?.ok_or_else(denied)?;
        (entry.generation, entry.kit.ok_or_else(denied)?)
    };
    VerifyingKey::from_bytes(&kit.anchor_key)
        .and_then(|key| key.verify_strict(&fetch.transcript(), &Signature::from_bytes(signature)))
        .map_err(|_| denied())?;
    take_nonce(vault, fetch.timestamp, &fetch.nonce, now)?;
    let txn = vault.store.env.read_txn()?;
    let Some(entry) = entry_in(vault, &txn, &generation)?.filter(|entry| entry.kit == Some(kit))
    else {
        return Ok(None);
    };
    let read = read_part_in(vault, &txn, &entry, fetch.object, fetch.offset)?;
    Ok(Some((entry, read)))
}
