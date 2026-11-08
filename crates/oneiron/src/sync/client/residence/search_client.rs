//! Home search orchestration.
//! The entry points are `search_resident` and, one page at a time,
//! `search_resident_page`. Paging runs through `super::search`.

use std::collections::HashSet;

use super::super::base::SyncClient;
use super::super::types::{SyncClientConfig, SyncResidenceMode};
use super::search::ResidenceSearchPage;
use super::{ResidenceHit, ResidenceSearch, SearchSource};
use crate::EntityId;
use crate::sync::residence::ResidenceSearchCursor;
use crate::sync::residence_operation_budgets::ResidenceOperationBudgets;
use crate::sync::selector::encode_sync_selector;
use crate::sync::transport::TransportError;

use super::rpc::{ResidenceRpc, refused, residence_budgets};

impl SyncClient {
    /// Home results when reachable; offline results are explicitly local-only.
    pub async fn search_resident(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<ResidenceSearch, TransportError> {
        search_resident(
            &self.vault,
            &self.config,
            query,
            limit,
            None,
            None,
            None,
            None,
        )
        .await
    }

    /// One page of a home search of at most `limit` hits in all (FIX 9258):
    /// the first page with no `cursor`, else the page the cursor of the page
    /// before names. A host shows each page as it comes and asks for the next
    /// with its `next`. A list that changed since the cursor's page comes
    /// back from its first page, marked `restarted`. With no home reachable
    /// a first page is this device's partial offline scan, as
    /// [`Self::search_resident`] gives; a later page is refused, since only
    /// the home goes on with its list.
    ///
    /// # Errors
    ///
    /// A device not on opened items, an empty or oversized query, a zero
    /// limit, a refused or malformed home reply, or a later page with no
    /// home.
    pub async fn search_resident_page(
        &self,
        query: &str,
        limit: usize,
        cursor: Option<&ResidenceSearchCursor>,
    ) -> Result<ResidenceSearchPage, TransportError> {
        search_resident_page(&self.vault, &self.config, query, limit, cursor).await
    }
}

/// [`SyncClient::search_resident_page`] on the vault and a client config
/// alone, as [`search_resident`] is.
async fn search_resident_page(
    vault: &crate::Vault,
    config: &SyncClientConfig,
    query: &str,
    limit: usize,
    cursor: Option<&ResidenceSearchCursor>,
) -> Result<ResidenceSearchPage, TransportError> {
    if config.residence_mode != SyncResidenceMode::Opened {
        return Err(refused());
    }
    let budgets = residence_budgets(vault)?;
    if query.trim().is_empty() || query.len() > budgets.search_query_max_bytes || limit == 0 {
        return Err(refused());
    }
    let selector = config.residence_selector.as_ref().ok_or_else(refused)?;
    let selector_wire = encode_sync_selector(selector).map_err(|_| refused())?;
    match ResidenceRpc::connect(vault, config, budgets).await? {
        Some(mut rpc) => {
            super::search::search_page(vault, &mut rpc, query, limit, &selector_wire, cursor).await
        }
        None if cursor.is_some() => Err(refused()),
        None => Ok(ResidenceSearchPage {
            hits: local_only_hits(vault, &budgets, query, limit)?,
            source: SearchSource::LocalOnly,
            next: None,
            restarted: false,
        }),
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
///
/// With `filter`, the caller's own retrieval filter (FIX 3977), the home
/// binds it on its reader before the candidate cut and signs it with the
/// request. A filtered search never falls back to this device's unfiltered
/// offline scan.
#[expect(
    clippy::too_many_arguments,
    reason = "a home search carries every field its signed request names"
)]
pub(crate) async fn search_resident(
    vault: &crate::Vault,
    config: &SyncClientConfig,
    query: &str,
    limit: usize,
    scope: Option<&crate::sync::residence::ResolvedRecallSelection>,
    as_of: Option<u64>,
    filter: Option<&crate::memory::ReadFilterInput>,
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
    match ResidenceRpc::connect(vault, config, budgets).await? {
        Some(mut rpc) => {
            super::search::search_pages(
                vault,
                &mut rpc,
                query,
                limit,
                &selector_wire,
                scope,
                as_of,
                filter,
                caller,
            )
            .await
        }
        None if caller.is_some() || scope.is_some() || filter.is_some() => Err(refused()),
        None => Ok(ResidenceSearch {
            hits: local_only_hits(vault, &budgets, query, limit)?,
            source: SearchSource::LocalOnly,
            complete: false,
        }),
    }
}

/// This device's partial offline answer: its opened items whose cached
/// bytes hold `query`, then its own text index's hits in promoted windows,
/// at most `limit` of them.
fn local_only_hits(
    vault: &crate::Vault,
    budgets: &ResidenceOperationBudgets,
    query: &str,
    limit: usize,
) -> Result<Vec<ResidenceHit>, TransportError> {
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
    Ok(hits)
}
