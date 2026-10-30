//! A home search for more hits than one page carries (FIX 8865): the device
//! keeps the caller's whole count and asks the home page after page, each
//! page a slice of one ranked list the home names by its revision, until it
//! holds that many hits or the list ends. A list that changed between pages
//! starts the search over, so the answer never mixes two lists and is never
//! complete while the home holds more of it.

use base64::Engine;
use serde::Deserialize;
use serde_json::json;

use super::{
    ResidenceHit, ResidenceRpc, ResidenceSearch, SearchHit, SearchSource, WindowKey, refused,
};
use crate::claim::CallerLocality;
use crate::sync::residence::{ResidenceSearchCursor, ResolvedRecallSelection};
use crate::sync::transport::TransportError;

/// One page of a search served in pages.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SearchPageReply {
    hits: Vec<SearchHit>,
    source: String,
    complete: bool,
    revision: String,
    #[serde(default)]
    next_cursor: Option<ResidenceSearchCursor>,
}

/// Asks the home for `limit` hits a page at a time over `rpc`, as the caller
/// a forwarded search names, at its locality, within `scope`.
pub(super) async fn search_pages(
    vault: &crate::Vault,
    rpc: &mut ResidenceRpc,
    query: &str,
    limit: usize,
    selector_wire: &[u8],
    scope: Option<&ResolvedRecallSelection>,
    caller: Option<(&crate::authority::ForwardedCallerProof, CallerLocality)>,
) -> Result<ResidenceSearch, TransportError> {
    let selector = base64::engine::general_purpose::STANDARD.encode(selector_wire);
    let mut hits: Vec<ResidenceHit> = Vec::new();
    let mut page: Option<ResidenceSearchCursor> = None;
    loop {
        let mut params = json!({"query": query, "limit": limit, "selector": selector});
        if let Some(scope) = scope {
            params["scope"] = serde_json::to_value(scope).map_err(|_| refused())?;
        }
        if let Some(page) = &page {
            params["page"] = serde_json::to_value(page).map_err(|_| refused())?;
        }
        if let Some((caller, locality)) = caller {
            // Each page's request is signed whole, its cursor and the
            // caller's locality too (FIX 3550).
            let machine = crate::sync::residence::with_forwarded_search_page(
                query,
                limit,
                selector_wire,
                scope,
                locality,
                page.as_ref(),
                |request| vault.forwarding_machine_proof(request, caller),
            )
            .map_err(|e| TransportError::Storage(e.to_string()))?
            .ok_or_else(refused)?;
            params["forwarded"] = serde_json::to_value(caller).map_err(|_| refused())?;
            params["machine_proof"] = serde_json::to_value(machine).map_err(|_| refused())?;
            params["caller_locality"] = serde_json::to_value(locality).map_err(|_| refused())?;
        }
        let reply = match rpc.call("residence.search", params).await? {
            Ok(reply) => reply,
            // The list changed since its first page: the search starts over.
            Err(refusal) if refusal.code.as_deref() == Some("SEARCH_REVISION_CHANGED") => {
                hits.clear();
                page = None;
                continue;
            }
            Err(_) => return Err(TransportError::InvalidPayload("home refused residence RPC")),
        };
        let reply: SearchPageReply = serde_json::from_value(reply).map_err(|_| refused())?;
        let end = hits.len().saturating_add(reply.hits.len());
        if reply.source != "home"
            || reply.complete != reply.next_cursor.is_none()
            || end > limit
            || page
                .as_ref()
                .is_some_and(|page| page.revision != reply.revision)
            || reply.next_cursor.as_ref().is_some_and(|next| {
                reply.hits.is_empty()
                    || next.offset != end as u64
                    || next.revision != reply.revision
                    || page.as_ref().is_some_and(|page| page.as_of != next.as_of)
            })
        {
            return Err(refused());
        }
        for hit in reply.hits {
            let window = WindowKey::try_new(&hit.window).ok_or_else(refused)?;
            hits.push(ResidenceHit {
                entity_id: hit.entity_id,
                score: hit.score,
                window,
            });
        }
        match reply.next_cursor {
            Some(next) => page = Some(next),
            None => {
                return Ok(ResidenceSearch {
                    hits,
                    source: SearchSource::Home,
                    complete: true,
                });
            }
        }
    }
}
