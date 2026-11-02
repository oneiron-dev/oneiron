//! A restore's read of the sealed cloud bundle from the home with the kit
//! alone (FIX 922): no session, slip or machine of the vault's, only the kit's
//! rebuilt seed. Each slice request is signed with the seed's owner anchor
//! ([`KitBundleFetch`]), and the home's kit door serves the generations a
//! publisher named the kit's root for. The bytes are checked as a machine's
//! read checks them (`bundle::fetch_generation`). The kit reads the home's
//! current index of those generations the same way (FIX 7106), every page of
//! it (FIX 9364): one revision, strictly newer to older, each generation
//! once, started over when the revision changes, and nothing named until the
//! last page came.

mod custody;

pub use self::custody::fetch_custody_with_kit;

use std::collections::BTreeSet;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use serde::Deserialize;
use serde_json::{Value, json};

use super::bundle::{PartSource, fetch_generation};
use crate::sync::residence::{
    KIT_BUNDLE_FETCH_NONCE_BYTES, KIT_BUNDLE_FETCH_PATH, KIT_PAD_INDEX_FETCH_PATH,
    KIT_PAD_INDEX_REPLY_MAX, KitBundleFetch, KitPadIndexFetch, SEALED_BUNDLE_READ_PART_MAX,
    SealedBundleEntry, SealedBundleIndex, SealedBundleKitRoot, SealedBundleObject,
    kit_bundle_fetch_origin, sealed_digest_from_hex, sealed_digest_hex, sealed_generation_from_hex,
    sealed_generation_hex,
};
use crate::sync::transport::TransportError;
use crate::world_keys::{
    RecoveryRootId, RecoveryRootSeed, SealedBundleGeneration, SealedKeyPads, SealedVaultBundle,
};

/// How long a restore waits to reach the home's kit door.
const KIT_BUNDLE_CONNECT_TIMEOUT_SECS: u64 = 12;
/// How long one slice request may take, its answer's body included, before
/// the restore gives up on a home that stopped answering.
const KIT_BUNDLE_PART_TIMEOUT_SECS: u64 = 300;
/// The most bytes one slice's answer may hold (FIX 5953; CALLS:
/// KIT_BUNDLE_PART_REPLY_MAX = 349,769): the largest read part in base64,
/// `4 * SEALED_BUNDLE_READ_PART_MAX.div_ceil(3)` = 349,528, plus the 241 bytes
/// the home's compact `KitBundlePartResponse` adds around it (48-hex
/// generation, `bundle`, two 20-digit `u64`s, 64-hex digest, `false`, keys
/// and punctuation).
const KIT_BUNDLE_PART_REPLY_MAX: usize = 4 * SEALED_BUNDLE_READ_PART_MAX.div_ceil(3) + 241;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KitPadIndexReply {
    retained_revision: String,
    generations: Vec<KitPadIndexEntry>,
    #[serde(default)]
    next_cursor: Option<KitPadIndexCursor>,
}

/// Where the next page of the index starts (FIX 9364).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KitPadIndexCursor {
    retained_revision: String,
    before_commit_order: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KitPadIndexEntry {
    generation: String,
    commit_order: u64,
    bundle_length: u64,
    bundle_digest: String,
    pads_length: u64,
    pads_digest: String,
}

/// The home's kit door, and what each request to it is signed with.
pub(super) struct KitHome {
    client: reqwest::Client,
    url: reqwest::Url,
    /// The home's address as the requests name it.
    origin: String,
    vault_id: [u8; 32],
    root: RecoveryRootId,
    anchor: SigningKey,
}

impl KitHome {
    /// One slice of a kept object from `offset`, as the home sends it:
    /// `generation` names one, `None` the newest named for the kit's root,
    /// and a kept pad object whose bytes the home lacks its typed answer
    /// (FIX 7106). A refused or missing slice is `InvalidPayload`; a body that
    /// fails to arrive is `Storage`; a body past [`KIT_BUNDLE_PART_REPLY_MAX`]
    /// is `FrameTooLarge`.
    pub(super) async fn part(
        &self,
        generation: Option<SealedBundleGeneration>,
        object: SealedBundleObject,
        offset: u64,
    ) -> Result<Value, TransportError> {
        let mut nonce = [0u8; KIT_BUNDLE_FETCH_NONCE_BYTES];
        crate::world_keys::os_fill(&mut nonce)
            .map_err(|error| TransportError::Storage(error.to_string()))?;
        let fetch = KitBundleFetch {
            vault_id: self.vault_id,
            root: self.root,
            origin: self.origin.clone(),
            generation,
            object,
            offset,
            timestamp: crate::unix_seconds_now(),
            nonce,
        };
        let signature: String = fetch
            .sign(&self.anchor)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let response = self
            .client
            .post(self.url.clone())
            .json(&json!({
                "vaultId": sealed_digest_hex(&fetch.vault_id),
                "root": sealed_digest_hex(&fetch.root.0),
                "generation": generation.as_ref().map(sealed_generation_hex),
                "object": object.name(),
                "offset": offset,
                "timestamp": fetch.timestamp,
                "nonce": sealed_digest_hex(&fetch.nonce),
                "signature": signature,
            }))
            .send()
            .await
            .map_err(|e| TransportError::Storage(format!("kit fetch request failed: {e}")))?;
        // A kept pad object whose bytes the home lacks answers 409, typed.
        if !response.status().is_success() && response.status() != reqwest::StatusCode::CONFLICT {
            return Err(TransportError::InvalidPayload(
                "the home refused the kit fetch",
            ));
        }
        answer(response, KIT_BUNDLE_PART_REPLY_MAX).await
    }

    /// One page of the home's current index of the generations named for
    /// the kit's root (FIX 7106): from the newest, or from `cursor`, the
    /// revision and commit order a page before named (FIX 9364). A refused
    /// fetch is `InvalidPayload`; a body past [`KIT_PAD_INDEX_REPLY_MAX`] is
    /// `FrameTooLarge`.
    async fn index(&self, cursor: Option<([u8; 32], u64)>) -> Result<Value, TransportError> {
        let mut nonce = [0u8; KIT_BUNDLE_FETCH_NONCE_BYTES];
        crate::world_keys::os_fill(&mut nonce)
            .map_err(|error| TransportError::Storage(error.to_string()))?;
        let fetch = KitPadIndexFetch {
            vault_id: self.vault_id,
            root: self.root,
            origin: self.origin.clone(),
            retained_revision: cursor.map(|(revision, _)| revision),
            before_commit_order: cursor.map(|(_, before)| before),
            timestamp: crate::unix_seconds_now(),
            nonce,
        };
        let signature: String = fetch
            .sign(&self.anchor)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let mut url = self.url.clone();
        url.set_path(KIT_PAD_INDEX_FETCH_PATH);
        let response = self
            .client
            .post(url)
            .json(&json!({
                "vaultId": sealed_digest_hex(&fetch.vault_id),
                "root": sealed_digest_hex(&fetch.root.0),
                "retainedRevision": fetch.retained_revision.as_ref().map(sealed_digest_hex),
                "beforeCommitOrder": fetch.before_commit_order,
                "timestamp": fetch.timestamp,
                "nonce": sealed_digest_hex(&fetch.nonce),
                "signature": signature,
            }))
            .send()
            .await
            .map_err(|e| TransportError::Storage(format!("kit fetch request failed: {e}")))?;
        if !response.status().is_success() {
            return Err(TransportError::InvalidPayload(
                "the home refused the kit fetch",
            ));
        }
        answer(response, KIT_PAD_INDEX_REPLY_MAX).await
    }
}

/// A kit door's answer, `max` bytes at most.
async fn answer(mut response: reqwest::Response, max: usize) -> Result<Value, TransportError> {
    // A slice whose body fails to arrive, past the deadline or on a dropped
    // connection, is a failed transport, not a missing slice (FIX 4297;
    // CALLS: KIT_BUNDLE_BODY_READ_FAILURE, TransportError). A body that
    // arrived and does not decode stays `InvalidPayload`.
    // The body is counted as it arrives and refused once it passes the
    // largest answer a slice has (FIX 5953); a stated length may refuse it
    // sooner but never stands in for the count.
    if let Some(size) = response.content_length()
        && size > max as u64
    {
        return Err(TransportError::FrameTooLarge {
            size: usize::try_from(size).unwrap_or(usize::MAX),
            max,
        });
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| TransportError::Storage(format!("kit fetch request failed: {e}")))?
    {
        let size = body.len().checked_add(chunk.len()).unwrap_or(usize::MAX);
        if size > max {
            return Err(TransportError::FrameTooLarge { size, max });
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body)
        .map_err(|_| TransportError::InvalidPayload("the kit fetch answer does not decode"))
}

/// The kit door of the home at `home`, its requests signed with `seed`, the
/// kit's, rebuilt for the vault `vault_id`. `home` is the home's address, as
/// `https`, `http`, `wss` or `ws`.
fn kit_home(
    home: &str,
    vault_id: &[u8; 32],
    seed: &RecoveryRootSeed,
) -> Result<KitHome, TransportError> {
    let http = if let Some(rest) = home.strip_prefix("wss://") {
        format!("https://{rest}")
    } else if let Some(rest) = home.strip_prefix("ws://") {
        format!("http://{rest}")
    } else {
        home.to_owned()
    };
    let mut url = reqwest::Url::parse(&http)
        .map_err(|_| TransportError::InvalidPayload("the home's address does not parse"))?;
    let origin = kit_bundle_fetch_origin(&url).ok_or(TransportError::InvalidPayload(
        "the home's address names no host",
    ))?;
    url.set_path(KIT_BUNDLE_FETCH_PATH);
    url.set_query(None);
    let root = seed
        .public(vault_id)
        .map_err(|error| TransportError::Storage(error.to_string()))?
        .id;
    // Each slice is bounded, body included, so a home that stops answering
    // fails the restore instead of hanging it.
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(KIT_BUNDLE_CONNECT_TIMEOUT_SECS))
        .timeout(Duration::from_secs(KIT_BUNDLE_PART_TIMEOUT_SECS))
        .build()
        .map_err(|e| TransportError::Storage(format!("kit fetch client failed: {e}")))?;
    Ok(KitHome {
        client,
        url,
        origin,
        vault_id: *vault_id,
        root,
        anchor: seed.anchor(),
    })
}

/// One generation's bundle and pad object as the home at `home` keeps them,
/// read with the kit alone, for a restore on an install that is no machine of
/// the vault's: `seed` is the kit's, rebuilt for the vault `vault_id`.
/// `generation` names one, `None` the newest the home keeps for the kit's root.
/// `None` when the home keeps no such generation for the root, or refused the
/// kit. `home` is the home's address, as `https`, `http`, `wss` or `ws`.
pub async fn fetch_sealed_bundle_with_kit(
    home: &str,
    vault_id: &[u8; 32],
    seed: &RecoveryRootSeed,
    generation: Option<SealedBundleGeneration>,
) -> Result<Option<(SealedVaultBundle, SealedKeyPads)>, TransportError> {
    let home = kit_home(home, vault_id, seed)?;
    fetch_generation(&mut PartSource::Kit(&home), generation).await
}

/// The generations the home at `home` keeps named for the kit's root, newest
/// committed first, with the revision of the home's one read that named them,
/// read with the kit alone (FIX 7106): `seed` is the kit's, rebuilt for the
/// vault `vault_id`. Every page is read (FIX 9364), each under the revision
/// the first named, strictly older than the last and each generation once;
/// a revision that changed under the scan starts it over, and nothing is
/// named until the last page came. `None` when the home keeps none for the
/// root, or refused the kit. Each entry names the kit's root and anchor, the
/// ones its signature was checked against.
pub async fn fetch_sealed_bundle_index_with_kit(
    home: &str,
    vault_id: &[u8; 32],
    seed: &RecoveryRootSeed,
) -> Result<Option<SealedBundleIndex>, TransportError> {
    let home = kit_home(home, vault_id, seed)?;
    let refused = || TransportError::InvalidPayload("the kit index answer does not decode");
    let kit = SealedBundleKitRoot {
        root: home.root,
        anchor_key: home.anchor.verifying_key().to_bytes(),
    };
    let mut revision: Option<[u8; 32]> = None;
    let mut entries: Vec<SealedBundleEntry> = Vec::new();
    let mut seen = BTreeSet::new();
    let mut cursor = None;
    loop {
        let reply = match home.index(cursor).await {
            Ok(reply) => reply,
            Err(TransportError::InvalidPayload(_)) => return Ok(None),
            Err(error) => return Err(error),
        };
        let reply: KitPadIndexReply = serde_json::from_value(reply).map_err(|_| refused())?;
        let read = sealed_digest_from_hex(&reply.retained_revision).ok_or_else(refused)?;
        // The home answers a cursor of a read it no longer holds with the
        // first page of the one it holds now: the scan starts over on it.
        if revision.is_some_and(|held| held != read) {
            entries.clear();
            seen.clear();
        }
        revision = Some(read);
        for entry in &reply.generations {
            let entry = SealedBundleEntry {
                generation: sealed_generation_from_hex(&entry.generation).ok_or_else(refused)?,
                commit_order: entry.commit_order,
                bundle_len: entry.bundle_length,
                bundle_digest: sealed_digest_from_hex(&entry.bundle_digest).ok_or_else(refused)?,
                pads_len: entry.pads_length,
                pads_digest: sealed_digest_from_hex(&entry.pads_digest).ok_or_else(refused)?,
                kit: Some(kit),
            };
            if entries
                .last()
                .is_some_and(|last| last.commit_order <= entry.commit_order)
                || !seen.insert(entry.generation)
            {
                return Err(refused());
            }
            entries.push(entry);
        }
        let Some(next) = reply.next_cursor else {
            break;
        };
        // A cursor binds the page's read and its last entry.
        let next_revision = sealed_digest_from_hex(&next.retained_revision).ok_or_else(refused)?;
        if next_revision != read
            || reply.generations.is_empty()
            || entries.last().map(|last| last.commit_order) != Some(next.before_commit_order)
        {
            return Err(refused());
        }
        cursor = Some((read, next.before_commit_order));
    }
    Ok(Some(SealedBundleIndex {
        retained_revision: revision.ok_or_else(refused)?,
        entries,
    }))
}
