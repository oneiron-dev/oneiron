//! Home search orchestration.
//! The entry point is `search_resident`.
//! Paging runs through `super::search::search_pages`.

use std::collections::HashSet;

use base64::Engine;
use serde::Deserialize;
use serde_json::json;

use super::super::base::SyncClient;
use super::super::types::{SyncClientConfig, SyncResidenceMode};
use super::{ResidenceHit, ResidenceSearch, SearchHit, SearchSource};
use crate::EntityId;
use crate::sync::selector::encode_sync_selector;
use crate::sync::transport::TransportError;
use crate::sync::types::WindowKey;

use super::rpc::{ResidenceRpc, refused, residence_budgets};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SearchReply {
    hits: Vec<SearchHit>,
    source: String,
    complete: bool,
}

impl SyncClient {
    /// Home results when reachable; offline results are explicitly local-only.
    pub async fn search_resident(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<ResidenceSearch, TransportError> {
        search_resident(&self.vault, &self.config, query, limit, None, None).await
    }
}

/// Home results when reachable; offline results are explicitly local-only.
/// On the vault and a client config alone, like [`super::relay_sealed_bundle`], so
/// a query door asks the home without a sync client.
///
/// With `caller`, the search is that caller's (FIX 2907): its own holder
/// proof goes to the home unchanged, with where the caller sits relative to
/// this device (FIX 3550) and this install's forwarding proof over both and
/// the request, and the home answers within the caller's reach, at that
/// locality, and this device's selector. A forwarded search never falls
/// back to this device's own scan: no home is no hits.
///
/// With `scope`, the search is a recall's (FIX 2905): the home narrows it by
/// the scope the device's recall resolved before its candidate cut, and a
/// forwarded caller's proof binds the scope too. A scoped search never
/// falls back to this device's own scan either: its recall already read it.
pub(crate) async fn search_resident(
    vault: &crate::Vault,
    config: &SyncClientConfig,
    query: &str,
    limit: usize,
    scope: Option<&crate::sync::residence::ResolvedRecallSelection>,
    caller: Option<(
        &crate::authority::ForwardedCallerProof,
        crate::claim::CallerLocality,
    )>,
) -> Result<ResidenceSearch, TransportError> {
    if config.residence_mode != SyncResidenceMode::Opened {
        return Err(refused());
    }
    let budgets = residence_budgets(vault)?;
    if query.trim().is_empty() || query.len() > budgets.search_query_max_bytes || limit == 0 {
        return Err(refused());
    }
    let selector = config.residence_selector.as_ref().ok_or_else(refused)?;
    let selector_wire = encode_sync_selector(selector).map_err(|_| refused())?;
    let mut params = json!({
        "query": query,
        "limit": limit,
        "selector": base64::engine::general_purpose::STANDARD.encode(&selector_wire),
    });
    if let Some(scope) = scope {
        params["scope"] = serde_json::to_value(scope).map_err(|_| refused())?;
    }
    if let Some((caller, locality)) = caller {
        let machine = crate::sync::residence::with_forwarded_search(
            query,
            limit,
            &selector_wire,
            scope,
            locality,
            |request| vault.forwarding_machine_proof(request, caller),
        )
        .map_err(|e| TransportError::Storage(e.to_string()))?
        .ok_or_else(refused)?;
        params["forwarded"] = serde_json::to_value(caller).map_err(|_| refused())?;
        params["machine_proof"] = serde_json::to_value(machine).map_err(|_| refused())?;
        params["caller_locality"] = serde_json::to_value(locality).map_err(|_| refused())?;
    }
    match ResidenceRpc::connect(vault, config, budgets).await? {
        // More hits than one page carries come a page at a time (FIX 8865).
        Some(mut rpc) if limit > budgets.search_limit => {
            super::search::search_pages(vault, &mut rpc, query, limit, &selector_wire, scope, caller).await
        }
        Some(mut rpc) => {
            let reply: SearchReply =
                serde_json::from_value(rpc.request("residence.search", params).await?)
                    .map_err(|_| refused())?;
            if reply.source != "home" || !reply.complete || reply.hits.len() > limit {
                return Err(refused());
            }
            let hits = reply
                .hits
                .into_iter()
                .map(|hit| {
                    WindowKey::try_new(&hit.window)
                        .map(|window| ResidenceHit {
                            entity_id: hit.entity_id,
                            score: hit.score,
                            window,
                        })
                        .ok_or_else(refused)
                })
                .collect::<Result<_, _>>()?;
            Ok(ResidenceSearch {
                hits,
                source: SearchSource::Home,
                complete: true,
            })
        }
        None if caller.is_some() || scope.is_some() => Err(refused()),
        None => {
            let opened: HashSet<_> = vault
                .sync_state_keys_with_prefix("ro:e:")
                .map_err(|e| TransportError::Storage(e.to_string()))?
                .into_iter()
                .filter_map(|key| {
                    key.strip_prefix("ro:e:")
                        .and_then(|id| EntityId::from_hex(id).ok())
                })
                .collect();
            let promoted: HashSet<_> = vault
                .sync_state_keys_with_prefix("rp:w:")
                .map_err(|e| TransportError::Storage(e.to_string()))?
                .into_iter()
                .filter_map(|key| key.strip_prefix("rp:w:").map(str::to_owned))
                .collect();
            let needle = query.to_lowercase();
            let mut hits = Vec::new();
            for id in &opened {
                let Some(item) = super::items::read_thin_item(vault, *id)? else {
                    continue;
                };
                let raw = String::from_utf8_lossy(&item.raw).to_lowercase();
                let text = String::from_utf8_lossy(&item.document).to_lowercase();
                if raw.contains(&needle) || text.contains(&needle) {
                    hits.push(ResidenceHit {
                        entity_id: id.to_hex(),
                        score: 1.0,
                        window: item.window.clone(),
                    });
                }
            }
            for hit in vault
                .search_text(
                    query,
                    budgets
                        .search_limit
                        .saturating_mul(budgets.offline_candidate_multiplier),
                )
                .map_err(|e| TransportError::Storage(e.to_string()))?
            {
                let Some(raw) = vault
                    .get_raw(&hit.id)
                    .map_err(|e| TransportError::Storage(e.to_string()))?
                else {
                    continue;
                };
                let Ok(window) = crate::sync::residence::residence_window_for_blob(&raw) else {
                    continue;
                };
                if promoted.contains(window.as_str())
                    && !hits
                        .iter()
                        .any(|existing| existing.entity_id == hit.id.to_hex())
                {
                    hits.push(ResidenceHit {
                        entity_id: hit.id.to_hex(),
                        score: hit.score,
                        window,
                    });
                }
            }
            hits.truncate(limit);
            Ok(ResidenceSearch {
                hits,
                source: SearchSource::LocalOnly,
                complete: false,
            })
        }
    }
}
