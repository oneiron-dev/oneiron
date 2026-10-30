//! The home's half of a text search on a device that syncs only what it
//! opened (OF-534, FIX 3876). `/api/search_text` and the `vault.search.bm25`
//! door both ask it here, under the caller as its ingress admitted it: an
//! owner-grade caller as the device's paired owner, a narrower one on its own
//! holder proof, and one with no proof to forward not at all, never as the
//! device's owner in its place.

use std::time::Instant;

use oneiron::memory::{HomeRecallCaller, RecallResidence, RecallResidenceHit};
use oneiron::sync::{DeviceResidence, ResidenceSearch, SearchSource};
use oneiron::task_verb::sdk::Bm25Search;
use oneiron::{EntityId, Vault};

/// What a text search's home said.
pub(crate) enum HomeText {
    /// The device holds every window it may read: its page is whole.
    Whole,
    /// The home was not asked (no live connection, or a narrower caller with
    /// no proof to forward), was out of reach, refused or ran late: the page
    /// is the device's alone, and not the whole answer.
    LocalOnly,
    /// The home's answer. `capped`: the home's pages stopped short of the
    /// search's limit (a page ran late, or its list went on past the pages
    /// the limit asks), and the pages it gave stand (FIX 9257).
    Answered {
        search: ResidenceSearch,
        capped: bool,
    },
}

/// Asks `vault`'s home `query` for `caller`, before `due`: the whole `limit`,
/// a page of the residence `search_limit` at a time. A device whose own sync
/// connection dropped still syncs only what it opened, so its page stays
/// local-only rather than reading whole.
pub(crate) async fn ask_home_text(
    vault: &Vault,
    caller: &HomeRecallCaller,
    query: &str,
    limit: usize,
    due: Option<Instant>,
) -> HomeText {
    let DeviceResidence::Opened { search } = vault.device_residence() else {
        return HomeText::Whole;
    };
    let Some(home) = search else {
        return HomeText::LocalOnly;
    };
    let forwarded = match (caller.owner_grade, caller.forwarded.as_ref()) {
        (true, _) => None,
        (false, Some(proof)) => Some(proof),
        (false, None) => return HomeText::LocalOnly,
    };
    // Each page runs within its own RPC timeout and `due`, so a search cut
    // short keeps the home's pages it got.
    let answer = match forwarded {
        Some(proof) => {
            home.search_for(query, limit, proof, caller.locality, due)
                .await
        }
        None => home.search(query, limit, due).await,
    };
    match answer {
        Ok(found) => HomeText::Answered {
            capped: found.source == SearchSource::Home && !found.complete,
            search: found,
        },
        Err(_) => HomeText::LocalOnly,
    }
}

/// Completes `page`, a `vault.search.bm25` page read on the caller's own
/// surface, with what the opened device's home holds beside it (FIX 3876):
/// the home is asked `query` under `home`, the caller as its ingress
/// admitted it, and its references the page does not hold ride in
/// `residence`, apart from the page's hits. Only the home's own answer
/// counts: one out of reach, a refusal or a caller with nothing to ask under
/// leaves the page local-only and incomplete. A device that holds every
/// window it may read keeps its page as it is. Beside it, the home's
/// references.
pub(crate) async fn complete_bm25_with_home(
    vault: &Vault,
    mut page: Bm25Search,
    query: &str,
    limit: usize,
    home: &HomeRecallCaller,
) -> (Bm25Search, Vec<EntityId>) {
    if page.residence.is_none() {
        return (page, Vec::new());
    }
    let held: Vec<String> = page
        .value
        .iter()
        .filter_map(|hit| hit.record.as_ref())
        .map(|record| record.id.clone())
        .collect();
    let residence = match ask_home_text(vault, home, query, limit, None).await {
        HomeText::Answered { search, capped } if search.source == SearchSource::Home => {
            home_residence(search, capped, &held)
        }
        HomeText::Whole | HomeText::LocalOnly | HomeText::Answered { .. } => {
            RecallResidence::local_only()
        }
    };
    let rows = residence
        .hits
        .iter()
        .filter_map(|hit| EntityId::from_hex(&hit.id).ok())
        .collect();
    page.residence = Some(residence);
    (page, rows)
}

/// The home's answer as a residence beside a page holding `held`.
fn home_residence(search: ResidenceSearch, capped: bool, held: &[String]) -> RecallResidence {
    let hits = search.hits.into_iter().map(|hit| RecallResidenceHit {
        id: hit.entity_id,
        score: hit.score,
        window: hit.window.to_string(),
    });
    RecallResidence::home_text(hits, search.complete, capped, held)
}
