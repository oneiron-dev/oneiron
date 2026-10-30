//! A restore's read of its key custody from the residence home with the kit
//! alone (FIX 5846): no session, slip or machine of the vault's, only the
//! kit's rebuilt seed. Each page request is signed with the seed's owner
//! anchor ([`KitCustodyFetch`]), and the home's kit custody door serves the
//! lineage only to the root it pins for the vault. The sealed head comes in
//! slices, then every log frame the home holds in order: through the head's
//! sequence number and on past it, to the first frame the home lacks (FIX
//! 12020), each page continuing the one before it; a head the home switched
//! under the scan starts it over. The bytes are checked here only for their
//! order and lengths and the head's digest: the restore opens and chains
//! them.

use std::collections::BTreeMap;

use base64::Engine;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{KitHome, answer, kit_home};
use crate::store::custody_protocol::{FetchedCustodySource, Lineage};
use crate::sync::residence::{
    KIT_BUNDLE_FETCH_NONCE_BYTES, KIT_CUSTODY_FETCH_PATH, KIT_CUSTODY_REPLY_MAX, KitCustodyFetch,
    sealed_digest_from_hex, sealed_digest_hex,
};
use crate::sync::transport::TransportError;
use crate::world_keys::RecoveryRootSeed;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KitCustodyPageReply {
    head_object_id: String,
    head_length: u64,
    head_seq: u64,
    head_offset: u64,
    head_part: String,
    frames: Vec<KitCustodyFrame>,
    next_cursor: Option<KitCustodyCursor>,
}

#[derive(Deserialize)]
struct KitCustodyFrame {
    seq: u64,
    frame: String,
}

/// Where the next page of the home's custody starts.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KitCustodyCursor {
    head_offset: u64,
    after_seq: u64,
}

impl KitHome {
    /// One page of the home's custody of `lineage`, from the head offset and
    /// the last log sequence number a page before reached (FIX 5846). A
    /// refused or missing page is `InvalidPayload`; a body past
    /// [`KIT_CUSTODY_REPLY_MAX`] is `FrameTooLarge`.
    async fn custody_page(
        &self,
        lineage: Lineage,
        (head_offset, after_seq): (u64, u64),
    ) -> Result<Value, TransportError> {
        let mut nonce = [0u8; KIT_BUNDLE_FETCH_NONCE_BYTES];
        crate::world_keys::os_fill(&mut nonce)
            .map_err(|error| TransportError::Storage(error.to_string()))?;
        let fetch = KitCustodyFetch {
            vault_id: self.vault_id,
            root: self.root,
            origin: self.origin.clone(),
            lineage,
            head_offset,
            after_seq,
            timestamp: crate::unix_seconds_now(),
            nonce,
        };
        let signature: String = fetch
            .sign(&self.anchor)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let (custody_vault, custody_namespace) = lineage.to_hex();
        let mut url = self.url.clone();
        url.set_path(KIT_CUSTODY_FETCH_PATH);
        let response = self
            .client
            .post(url)
            .json(&json!({
                "vaultId": sealed_digest_hex(&fetch.vault_id),
                "root": sealed_digest_hex(&fetch.root.0),
                "custodyVault": custody_vault,
                "custodyNamespace": custody_namespace,
                "headOffset": head_offset,
                "afterSeq": after_seq,
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
        answer(response, KIT_CUSTODY_REPLY_MAX).await
    }
}

/// The custody lineage `lineage` as the residence home at `home` holds it,
/// read with the kit alone, for a restore on an install that is no machine
/// of the vault's (FIX 5846): `seed` is the kit's, rebuilt for the vault
/// `vault_id`. The whole sealed head and every log frame from the first, as
/// far as the home holds them in order: through the head's sequence number,
/// and past it, where a head older than its anchor chains to the anchor (FIX
/// 12020). `None` when the home holds no head of the lineage, or refused the
/// kit. `home` is the home's address, as `https`, `http`, `wss` or `ws`.
pub async fn fetch_custody_with_kit(
    home: &str,
    vault_id: &[u8; 32],
    seed: &RecoveryRootSeed,
    lineage: Lineage,
) -> Result<Option<FetchedCustodySource>, TransportError> {
    let home = kit_home(home, vault_id, seed)?;
    let refused = || TransportError::InvalidPayload("the kit custody answer does not decode");
    let decode = |text: &str| {
        base64::engine::general_purpose::STANDARD
            .decode(text)
            .map_err(|_| refused())
    };
    // The head the scan reads: its digest, length and sequence number.
    let mut held: Option<([u8; 32], u64, u64)> = None;
    let mut head = Vec::new();
    let mut frames = BTreeMap::new();
    let mut cursor = (0_u64, 0_u64);
    loop {
        let reply = match home.custody_page(lineage, cursor).await {
            Ok(reply) => reply,
            Err(TransportError::InvalidPayload(_)) => return Ok(None),
            Err(error) => return Err(error),
        };
        let page: KitCustodyPageReply = serde_json::from_value(reply).map_err(|_| refused())?;
        let read = (
            sealed_digest_from_hex(&page.head_object_id).ok_or_else(refused)?,
            page.head_length,
            page.head_seq,
        );
        // The home switched its head since the scan began: it starts over.
        if held.is_some_and(|held| held != read) {
            held = None;
            head.clear();
            frames.clear();
            cursor = (0, 0);
            continue;
        }
        held = Some(read);
        let (_, head_len, _) = read;
        // Each page continues where the one before it ended, the frames
        // only once the head is whole and without a gap: those past the
        // head's sequence number are the home's log after its head (FIX
        // 12020).
        let part = decode(&page.head_part)?;
        if page.head_offset != head.len() as u64
            || head.len().saturating_add(part.len()) as u64 > head_len
        {
            return Err(refused());
        }
        head.extend_from_slice(&part);
        let mut reached = cursor.1;
        for frame in &page.frames {
            if reached.checked_add(1) != Some(frame.seq) || (head.len() as u64) < head_len {
                return Err(refused());
            }
            frames.insert(frame.seq, decode(&frame.frame)?);
            reached = frame.seq;
        }
        let Some(next) = page.next_cursor else {
            break;
        };
        // A cursor names where the page ended, past the one it answered.
        let next = (next.head_offset, next.after_seq);
        if next != (head.len() as u64, reached) || next == cursor {
            return Err(refused());
        }
        cursor = next;
    }
    let (digest, head_len, _) = held.ok_or_else(refused)?;
    if head.len() as u64 != head_len || *blake3::hash(&head).as_bytes() != digest {
        return Err(refused());
    }
    Ok(Some(FetchedCustodySource::new(lineage, head, frames)))
}
