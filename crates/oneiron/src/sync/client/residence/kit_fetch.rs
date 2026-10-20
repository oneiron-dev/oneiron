//! A restore's read of the sealed cloud bundle from the home with the kit
//! alone (FIX 922): no session, slip or machine of the vault's, only the kit's
//! rebuilt seed. Each slice request is signed with the seed's owner anchor
//! ([`KitBundleFetch`]), and the home's kit door serves the generations a
//! publisher named the kit's root for. The bytes are checked as a machine's
//! read checks them (`bundle::fetch_generation`).

use std::time::Duration;

use ed25519_dalek::SigningKey;
use serde_json::{Value, json};

use super::bundle::{PartSource, fetch_generation};
use crate::sync::residence::{
    KIT_BUNDLE_FETCH_NONCE_BYTES, KIT_BUNDLE_FETCH_PATH, KitBundleFetch,
    SEALED_BUNDLE_READ_PART_MAX, SealedBundleObject, kit_bundle_fetch_origin, sealed_digest_hex,
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
    /// `generation` names one, `None` the newest named for the kit's root. A
    /// refused or missing slice is `InvalidPayload`; a body that fails to
    /// arrive is `Storage`; a body past [`KIT_BUNDLE_PART_REPLY_MAX`] is
    /// `FrameTooLarge`.
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
        let mut response = self
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
        if !response.status().is_success() {
            return Err(TransportError::InvalidPayload(
                "the home refused the kit fetch",
            ));
        }
        // A slice whose body fails to arrive, past the deadline or on a dropped
        // connection, is a failed transport, not a missing slice (FIX 4297;
        // CALLS: KIT_BUNDLE_BODY_READ_FAILURE, TransportError). A body that
        // arrived and does not decode stays `InvalidPayload`.
        // The body is counted as it arrives and refused once it passes the
        // largest answer a slice has (FIX 5953); a stated length may refuse it
        // sooner but never stands in for the count.
        if let Some(size) = response.content_length()
            && size > KIT_BUNDLE_PART_REPLY_MAX as u64
        {
            return Err(TransportError::FrameTooLarge {
                size: usize::try_from(size).unwrap_or(usize::MAX),
                max: KIT_BUNDLE_PART_REPLY_MAX,
            });
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| TransportError::Storage(format!("kit fetch request failed: {e}")))?
        {
            let size = body.len().checked_add(chunk.len()).unwrap_or(usize::MAX);
            if size > KIT_BUNDLE_PART_REPLY_MAX {
                return Err(TransportError::FrameTooLarge {
                    size,
                    max: KIT_BUNDLE_PART_REPLY_MAX,
                });
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body)
            .map_err(|_| TransportError::InvalidPayload("the kit fetch answer does not decode"))
    }
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
    let home = KitHome {
        client,
        url,
        origin,
        vault_id: *vault_id,
        root,
        anchor: seed.anchor(),
    };
    fetch_generation(&mut PartSource::Kit(&home), generation).await
}
