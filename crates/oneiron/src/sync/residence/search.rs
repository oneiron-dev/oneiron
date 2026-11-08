//! A residence search served in pages (FIX 8865, FIX 196), from one final
//! grant-selected ranked list read at one second. Each page names the
//! revision of that whole list, so no page mixes two lists and none is cut
//! short as complete. A search one page holds keeps its single call.

use serde::{Deserialize, Serialize};

use super::{ResolvedRecallSelection, recall_scope_transcript, residence_window_for_blob};
use crate::Vault;
use crate::claim::{CallerLocality, ScopedReadActorKey};
use crate::entity_id::EntityId;
use crate::error::Result;
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

/// The tag that opens a caller filter's signed and hashed field (FIX 3977).
const READ_FILTER_FIELD_TAG: &[u8] = b"oneiron.residence.search.read_filter.v1";

/// A caller's retrieval filter as the one field a residence search signs and
/// hashes (FIX 3977): its tag, then each field in order, a presence byte
/// before each value: the entity types as a big-endian `u64` count and their
/// bytes, the band and staleness as one byte each, and the minima as their
/// big-endian `f32` bits. A search without a filter has no such field, so
/// its bytes are the ones it always had.
fn read_filter_transcript(filter: &crate::memory::ReadFilterInput) -> Vec<u8> {
    let mut field = READ_FILTER_FIELD_TAG.to_vec();
    match &filter.entity_types {
        Some(types) => {
            field.push(1);
            field.extend((types.len() as u64).to_be_bytes());
            field.extend(types.iter().copied());
        }
        None => field.push(0),
    }
    for byte in [
        filter.max_sensitivity_band,
        filter.include_stale.map(u8::from),
    ] {
        match byte {
            Some(byte) => field.extend([1, byte]),
            None => field.push(0),
        }
    }
    for minimum in [filter.min_confidence, filter.min_salience] {
        match minimum {
            Some(minimum) => {
                field.push(1);
                field.extend(minimum.to_bits().to_be_bytes());
            }
            None => field.push(0),
        }
    }
    field
}

/// A forwarded search's caller locality as its signed field (FIX 3550): one
/// byte, 0 for a caller on the forwarding device and 1 for one off it.
pub(super) const fn caller_locality_field(locality: CallerLocality) -> [u8; 1] {
    match locality {
        CallerLocality::OnDevice => [0],
        CallerLocality::OffDevice => [1],
    }
}

/// The forwarded `residence.search` a device signs and its home verifies, as
/// [`super::with_forwarded_search`] builds it, its caller's locality
/// included, with a later page's cursor bound too: its offset and `as_of` as
/// big-endian `u64`s and its revision. A recall's explicit clock pin adds
/// its own big-endian field before the cursor; an unpinned search is unchanged.
/// A caller's retrieval filter adds its transcript after the pin
/// (`read_filter_transcript`, FIX 3977); an unfiltered search is unchanged.
#[expect(
    clippy::too_many_arguments,
    reason = "one signed transcript names every field the search request carries"
)]
pub fn with_forwarded_search_page<R>(
    query: &str,
    limit: usize,
    selector_wire: &[u8],
    scope: Option<&ResolvedRecallSelection>,
    recall_as_of: Option<u64>,
    filter: Option<&crate::memory::ReadFilterInput>,
    locality: CallerLocality,
    page: Option<&ResidenceSearchCursor>,
    with: impl FnOnce(&crate::authority::ForwardedRequest<'_>) -> R,
) -> R {
    let limit = (limit as u64).to_be_bytes();
    let scope = recall_scope_transcript(scope);
    let recall_as_of = recall_as_of.map(u64::to_be_bytes);
    let filter = filter.map(read_filter_transcript);
    let locality = caller_locality_field(locality);
    let offset = page.map(|page| page.offset.to_be_bytes());
    let as_of = page.map(|page| page.as_of.to_be_bytes());
    let mut fields: Vec<&[u8]> = Vec::with_capacity(10);
    fields.extend([
        query.as_bytes(),
        limit.as_slice(),
        selector_wire,
        scope.as_slice(),
        locality.as_slice(),
    ]);
    if let Some(recall_as_of) = &recall_as_of {
        fields.push(recall_as_of.as_slice());
    }
    if let Some(filter) = &filter {
        fields.push(filter.as_slice());
    }
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
/// whether its lexical scan exhausted the matches without a window cut.
/// The read key and `scope` are those of
/// [`super::home_search_candidates`]; `filter`, the caller's own retrieval
/// filter, binds the read lane before its candidate cut (FIX 3977).
#[expect(
    clippy::too_many_arguments,
    reason = "a paged search's candidates take every field its request carries"
)]
pub fn home_search_page_candidates(
    vault: &Vault,
    actor: ScopedReadActorKey,
    query: &str,
    window: usize,
    scope: Option<&ResolvedRecallSelection>,
    as_of: u64,
    recall_as_of: Option<u64>,
    filter: Option<&crate::memory::ReadFilterInput>,
) -> Result<(Vec<(EntityId, f32, WindowKey)>, bool)> {
    let request = filter.map(crate::memory::ReadFilterInput::to_filter);
    let (found, exhausted) = vault
        .scoped_read(actor)
        .with_judged_at(recall_as_of)
        .with_read_filter(request.as_ref())
        .residence_search_page(query, window, scope, as_of)?;
    let mut results = Vec::new();
    for hit in found {
        let Some(raw) = vault.get_raw(&hit.id)? else {
            continue;
        };
        results.push((hit.id, hit.score, residence_window_for_blob(&raw)?));
    }
    Ok((results, exhausted))
}

/// The revision of a paged search's final list: its request and each hit's
/// id and window, in rank order. Scores are left out, so a list whose order
/// holds keeps its revision. A caller's retrieval filter adds its transcript
/// after `as_of` (FIX 3977); an unfiltered list keeps the revision it had.
#[must_use]
pub fn residence_search_revision(
    query: &str,
    limit: usize,
    selector_wire: &[u8],
    scope: Option<&ResolvedRecallSelection>,
    as_of: u64,
    filter: Option<&crate::memory::ReadFilterInput>,
    hits: &[(EntityId, WindowKey)],
) -> String {
    let limit = (limit as u64).to_be_bytes();
    let scope = recall_scope_transcript(scope);
    let as_of = as_of.to_be_bytes();
    let filter = filter.map(read_filter_transcript);
    let mut fields: Vec<&[u8]> = Vec::with_capacity(6);
    fields.extend([
        query.as_bytes(),
        limit.as_slice(),
        selector_wire,
        scope.as_slice(),
        as_of.as_slice(),
    ]);
    if let Some(filter) = &filter {
        fields.push(filter.as_slice());
    }
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
