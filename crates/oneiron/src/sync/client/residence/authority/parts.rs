//! An authority entry past one RPC frame, either way (FIX 8087, 8246). A page
//! the home sends names such an entry by reference, and this machine reads it
//! a part at a time (`residence.authority.entry`), checks it against its hash
//! and puts it back in its place before the page imports. An entry this
//! machine appends past one request frame goes alone, a part at a time
//! (`residence.authority.append.part`); the home joins and checks it before
//! its door imports it.

use base64::Engine;
use serde::Deserialize;
use serde_json::json;

use super::{AuthorityAppendReply, ResidenceRpc, refused};
use crate::authority::{AuthorityEntryHash, authority_entry_hash, decode_authority_log_entry_body};
use crate::sync::residence::AUTHORITY_ENTRY_PART_MAX;
use crate::sync::transport::TransportError;

/// An entry a page names by reference: its place in the page, its hash in
/// base64 and its length.
#[derive(Deserialize)]
pub(super) struct AuthorityEntryRefReply {
    place: usize,
    hash: String,
    total: u64,
}

/// One part of an entry the home holds.
#[derive(Deserialize)]
struct AuthorityEntryPartReply {
    total: u64,
    part: String,
}

/// The page `inline` and `parted` carry, in order: each entry named by
/// reference read from the home and put in its place.
pub(super) async fn join_page(
    rpc: &mut ResidenceRpc,
    inline: Vec<Vec<u8>>,
    parted: Vec<AuthorityEntryRefReply>,
) -> Result<Vec<Vec<u8>>, TransportError> {
    let mut page = Vec::with_capacity(inline.len() + parted.len());
    let mut inline = inline.into_iter();
    for named in parted {
        if named.place < page.len() {
            return Err(refused());
        }
        while page.len() < named.place {
            page.push(inline.next().ok_or_else(refused)?);
        }
        let hash = base64::engine::general_purpose::STANDARD
            .decode(&named.hash)
            .ok()
            .and_then(|raw| <[u8; 32]>::try_from(raw).ok())
            .ok_or_else(refused)?;
        page.push(fetch_authority_entry(rpc, &hash, named.total).await?);
    }
    page.extend(inline);
    Ok(page)
}

/// The entry `hash` names, `total` bytes long, read from the home a part at
/// a time and checked against its hash.
async fn fetch_authority_entry(
    rpc: &mut ResidenceRpc,
    hash: &AuthorityEntryHash,
    total: u64,
) -> Result<Vec<u8>, TransportError> {
    let mut entry = Vec::new();
    while (entry.len() as u64) < total {
        let reply: AuthorityEntryPartReply = serde_json::from_value(
            rpc.request(
                "residence.authority.entry",
                json!({
                    "hash": base64::engine::general_purpose::STANDARD.encode(hash),
                    "offset": entry.len(),
                }),
            )
            .await?,
        )
        .map_err(|_| refused())?;
        let part = base64::engine::general_purpose::STANDARD
            .decode(reply.part)
            .map_err(|_| refused())?;
        if reply.total != total
            || part.is_empty()
            || part.len() > AUTHORITY_ENTRY_PART_MAX
            || (entry.len() + part.len()) as u64 > total
        {
            return Err(refused());
        }
        entry.extend_from_slice(&part);
    }
    let body = decode_authority_log_entry_body(&entry).map_err(|_| refused())?;
    if authority_entry_hash(&body).map_err(|_| refused())? != *hash {
        return Err(refused());
    }
    Ok(entry)
}

/// Appends `entry`, one signed entry past one request frame, to the home a
/// part at a time; the last part's answer is the append's.
pub(super) async fn append_authority_parts(
    rpc: &mut ResidenceRpc,
    entry: &[u8],
) -> Result<AuthorityAppendReply, TransportError> {
    let body = decode_authority_log_entry_body(entry).map_err(|_| refused())?;
    let hash = authority_entry_hash(&body).map_err(|_| refused())?;
    let mut offset = 0;
    for part in entry.chunks(AUTHORITY_ENTRY_PART_MAX) {
        let reply = rpc
            .request(
                "residence.authority.append.part",
                json!({
                    "hash": base64::engine::general_purpose::STANDARD.encode(hash),
                    "total": entry.len(),
                    "offset": offset,
                    "part": base64::engine::general_purpose::STANDARD.encode(part),
                }),
            )
            .await?;
        offset += part.len();
        if offset == entry.len() {
            return serde_json::from_value(reply).map_err(|_| refused());
        }
    }
    Err(refused())
}
