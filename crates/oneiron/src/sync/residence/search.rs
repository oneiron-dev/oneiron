//! A residence search served in pages (FIX 8865). A search for more hits
//! than one page carries is answered a page at a time from one final ranked
//! list, read at one second; each page names the revision of that whole
//! list, so no page mixes two lists and none is cut short as complete. A
//! search one page holds keeps its single call.

use serde::{Deserialize, Serialize};

use super::{ResolvedRecallSelection, recall_scope_transcript, residence_window_for_blob};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncProtocolValidation};
use crate::sync::types::WindowKey;

/// The most entry bytes one residence page reply carries (CALLS:
/// RESIDENCE_PAGE_REPLY_BYTES): half the 32 MiB a machine assembles of one
/// reply, so a page with its framing always fits. Only a page that would
/// pass it is cut short, and its cursor carries the rest.
pub const RESIDENCE_PAGE_REPLY_BYTES: usize = 16 * 1024 * 1024;

/// Where a paged residence search goes on: the offset into its final ranked
/// list, that list's revision, and the second its time words and recency
/// were read at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResidenceSearchCursor {
    pub offset: u64,
    pub revision: String,
    pub as_of: u64,
}

/// The forwarded `residence.search` a device signs and its home verifies, as
/// [`super::with_forwarded_search`] builds it, with a later page's cursor
/// bound too: its offset and `as_of` as big-endian `u64`s and its revision.
/// A first page signs the same bytes as a search of one call.
pub fn with_forwarded_search_page<R>(
    query: &str,
    limit: usize,
    selector_wire: &[u8],
    scope: Option<&ResolvedRecallSelection>,
    page: Option<&ResidenceSearchCursor>,
    with: impl FnOnce(&crate::authority::ForwardedRequest<'_>) -> R,
) -> R {
    let limit = (limit as u64).to_be_bytes();
    let scope = recall_scope_transcript(scope);
    let offset = page.map(|page| page.offset.to_be_bytes());
    let as_of = page.map(|page| page.as_of.to_be_bytes());
    let mut fields: Vec<&[u8]> = Vec::with_capacity(7);
    fields.extend([
        query.as_bytes(),
        limit.as_slice(),
        selector_wire,
        scope.as_slice(),
    ]);
    if let (Some(page), Some(offset), Some(as_of)) = (page, &offset, &as_of) {
        fields.extend([
            offset.as_slice(),
            page.revision.as_bytes(),
            as_of.as_slice(),
        ]);
    }
    with(&crate::authority::ForwardedRequest {
        method: "residence.search",
        fields: &fields,
    })
}

/// The actor-readable lexical candidates of a paged search, ranked `window`
/// deep at `as_of` (unix seconds) past the read lane's candidate window, and
/// how many rows the ranking held: fewer than `window` only once the matches
/// ran out. Admission and `scope` are those of [`super::home_search_candidates`].
pub fn home_search_page_candidates(
    vault: &Vault,
    proof: &crate::authority::VerifiedSlip,
    query: &str,
    window: usize,
    scope: Option<&ResolvedRecallSelection>,
    as_of: u64,
) -> Result<(Vec<(EntityId, f32, WindowKey)>, usize)> {
    let actor = vault
        .credential_read_key(proof)?
        .ok_or(Error::sync_protocol(
            SyncProtocolValidation::DocumentAdmissionDenied,
        ))?;
    let (found, ranked) = vault
        .scoped_read(actor)
        .residence_search_page(query, window, scope, as_of)?;
    let mut results = Vec::new();
    for hit in found {
        let Some(raw) = vault.get_raw(&hit.id)? else {
            continue;
        };
        results.push((hit.id, hit.score, residence_window_for_blob(&raw)?));
    }
    Ok((results, ranked))
}

/// The revision of a paged search's final list: its request and each hit's
/// id and window, in rank order. Scores are left out, so a list whose order
/// holds keeps its revision.
#[must_use]
pub fn residence_search_revision(
    query: &str,
    limit: usize,
    selector_wire: &[u8],
    scope: Option<&ResolvedRecallSelection>,
    as_of: u64,
    hits: &[(EntityId, WindowKey)],
) -> String {
    let limit = (limit as u64).to_be_bytes();
    let scope = recall_scope_transcript(scope);
    let as_of = as_of.to_be_bytes();
    let fields: [&[u8]; 5] = [query.as_bytes(), &limit, selector_wire, &scope, &as_of];
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron.residence.search.page.v1");
    for field in fields {
        hasher.update(&(field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    for (id, window) in hits {
        hasher.update(id.as_bytes());
        hasher.update(&(window.as_str().len() as u64).to_be_bytes());
        hasher.update(window.as_str().as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}
