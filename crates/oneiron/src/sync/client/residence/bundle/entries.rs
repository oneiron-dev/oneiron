//! The home's list of the generations it keeps, newest first by the order it
//! committed them in (FIX 8885). A slot may hold more than one generation and
//! a generation's id is its slot and a random nonce, so the list's commit
//! order, never the id, says which is newer. The list names the revision of
//! the home's one read that made it (FIX 7106).

use std::collections::BTreeSet;

use serde::Deserialize;
use serde_json::json;

use super::{ResidenceRpc, refused};
use crate::authority::AuthorityEntryHash;
use crate::sync::residence::{
    sealed_digest_from_hex, sealed_digest_hex, sealed_generation_from_hex,
};
use crate::sync::transport::TransportError;
use crate::world_keys::{SEALED_BUNDLE_KEEP, SealedBundleGeneration};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BundleListReply {
    generations: Vec<BundleListEntry>,
    retained_revision: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BundleListEntry {
    generation: String,
    commit_order: u64,
    pads_digest: String,
}

/// One generation the home keeps, as its list names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ListedGeneration {
    pub(super) generation: SealedBundleGeneration,
    pub(super) commit_order: u64,
    /// BLAKE3 of its pad object as the home keeps it now.
    pub(super) pads_digest: [u8; 32],
}

/// The home's list as one read of it names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ListedIndex {
    /// The revision of the home's read (FIX 7106): opaque, never an order.
    pub(super) retained_revision: [u8; 32],
    /// Newest first.
    pub(super) generations: Vec<ListedGeneration>,
}

/// The generations the home keeps, newest first, naming the owner's
/// `request` this install is asked to publish for, when it is. Refused
/// unless each commit order falls below the one before it and no generation
/// comes twice.
pub(super) async fn list_entries(
    rpc: &mut ResidenceRpc,
    request: Option<AuthorityEntryHash>,
) -> Result<Vec<ListedGeneration>, TransportError> {
    Ok(list_index(rpc, request).await?.generations)
}

/// [`list_entries`], with the revision of the home's read that named them.
pub(super) async fn list_index(
    rpc: &mut ResidenceRpc,
    request: Option<AuthorityEntryHash>,
) -> Result<ListedIndex, TransportError> {
    let mut params = json!({});
    if let Some(request) = request {
        params["request"] = json!(sealed_digest_hex(&request));
    }
    let reply = rpc.request("residence.bundle.list", params).await?;
    let list: BundleListReply = serde_json::from_value(reply).map_err(|_| refused())?;
    if list.generations.len() > SEALED_BUNDLE_KEEP {
        return Err(refused());
    }
    let listed = list
        .generations
        .iter()
        .map(|entry| {
            Ok(ListedGeneration {
                generation: sealed_generation_from_hex(&entry.generation).ok_or_else(refused)?,
                commit_order: entry.commit_order,
                pads_digest: sealed_digest_from_hex(&entry.pads_digest).ok_or_else(refused)?,
            })
        })
        .collect::<Result<Vec<_>, TransportError>>()?;
    let distinct: BTreeSet<_> = listed.iter().map(|entry| entry.generation).collect();
    if distinct.len() != listed.len()
        || !listed
            .windows(2)
            .all(|pair| pair[0].commit_order > pair[1].commit_order)
    {
        return Err(refused());
    }
    Ok(ListedIndex {
        retained_revision: sealed_digest_from_hex(&list.retained_revision).ok_or_else(refused)?,
        generations: listed,
    })
}

/// Whether `newest`, the home's newest generation, is newer than `taken`, the
/// one this machine last took: another generation, committed after `taken`
/// while the home keeps `taken` (`listed`, newest first), and once it keeps
/// it no more, one of its slot or a later one.
pub(super) fn newer_than_taken(
    newest: &SealedBundleGeneration,
    taken: SealedBundleGeneration,
    listed: &[SealedBundleGeneration],
) -> bool {
    *newest != taken && (listed.contains(&taken) || newest.slot >= taken.slot)
}
