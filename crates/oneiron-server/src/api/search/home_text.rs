//! The home's half of a text search on a device that syncs only what it
//! opened (OF-534, FIX 3876). `/api/search_text` and the `vault.search.bm25`
//! door both ask it here, under the caller as its ingress admitted it: an
//! owner-grade caller as the device's paired owner, a narrower one on its own
//! holder proof, and one with no proof to forward not at all, never as the
//! device's owner in its place.

use std::sync::Arc;
use std::time::Instant;

use oneiron::authority::VerifiedSlip;
use oneiron::claim::CallerLocality;
use oneiron::memory::{
    HomeRecallCaller, MEMORY_CODE_INTERNAL, MemoryError, MemoryResult, ProducerRows,
    RecallResidence, RecallResidenceHit,
};
use oneiron::sync::{DeviceResidence, ResidenceSearch, SearchSource};
use oneiron::task_verb::sdk::{Bm25Search, QueryBm25Request};
use oneiron::{EdgeActorClass, EntityId, Vault};

use crate::server::SyncServer;

/// What a text search's home said.
pub(super) enum HomeText {
    /// The device holds every window it may read: its page is whole.
    Whole,
    /// The home was not asked (no live connection, or a narrower caller with
    /// no proof to forward), was out of reach, refused or ran late: the page
    /// is the device's alone, and not the whole answer.
    LocalOnly,
    /// The home's answer. `capped`: the ask was cut to the residence
    /// `search_limit`.
    Answered {
        search: ResidenceSearch,
        capped: bool,
    },
}

/// Asks `vault`'s home `query` for `caller`, before `due`. A device whose
/// own sync connection dropped still syncs only what it opened, so its page
/// stays local-only rather than reading whole.
pub(super) async fn ask_home_text(
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
    let capped = vault
        .residence_operation_budgets()
        .ok()
        .flatten()
        .is_some_and(|budgets| limit > budgets.search_limit);
    let asked = async {
        match forwarded {
            Some(proof) => home.search_for(query, limit, proof).await,
            None => home.search(query, limit).await,
        }
    };
    let answer = match due {
        Some(due) => tokio::time::timeout_at(due.into(), asked).await.ok(),
        None => Some(asked.await),
    };
    match answer {
        Some(Ok(found)) => HomeText::Answered {
            search: found,
            capped,
        },
        Some(Err(_)) | None => HomeText::LocalOnly,
    }
}

impl SyncServer {
    /// `vault.search.bm25`, the door every server transport shares: this
    /// device's BM25 page under the caller's own read, then, on a device
    /// that syncs only what it opened, its home's answer under `home`, the
    /// caller as its ingress admitted it (FIX 3876). The home's references
    /// the page does not hold ride in `residence`, apart from the page's
    /// hits; only the home's own answer counts, so one out of reach, a
    /// refusal or a caller with nothing to ask under leaves the page
    /// local-only and incomplete. A room turn serves no BM25 search, as the
    /// turn itself refuses it. Beside it, the rows the page's read admitted
    /// and the home's references.
    #[expect(
        clippy::too_many_arguments,
        reason = "a server door's parameters plus the caller it asks the home for"
    )]
    pub(crate) async fn bm25_home_listing(
        self: &Arc<Self>,
        actor: EntityId,
        class: EdgeActorClass,
        proof: Option<VerifiedSlip>,
        locality: CallerLocality,
        room: Option<EntityId>,
        input: QueryBm25Request,
        home: HomeRecallCaller,
    ) -> (MemoryResult<Bm25Search>, Vec<EntityId>) {
        const VERB: &str = "vault.search.bm25";
        let producers = Arc::new(ProducerRows::default());
        let listing = Arc::clone(&producers);
        let (query, limit) = (input.query.clone(), input.limit);
        let server = Arc::clone(self);
        let page = tokio::task::spawn_blocking(move || {
            let memory = server.vault().memory(actor, class);
            let memory = match &proof {
                Some(proof) => memory.with_read_proof(proof),
                None => memory,
            }
            .at(locality)
            .listing_producers(&listing);
            match room {
                Some(room) => {
                    let value = serde_json::to_value(&input).map_err(|_| internal(VERB))?;
                    let output = memory.for_room_turn(room)?.invoke(VERB, value)?;
                    serde_json::from_value(output).map_err(|_| internal(VERB))
                }
                None => oneiron::task_verb::sdk::search_bm25(&memory, input),
            }
        })
        .await
        .unwrap_or_else(|_| Err(internal(VERB)));
        let mut rows = producers.take();
        let answer = match page {
            Ok(mut page) if page.residence.is_some() => {
                let held: Vec<String> = page
                    .value
                    .iter()
                    .filter_map(|hit| hit.record.as_ref())
                    .map(|record| record.id.clone())
                    .collect();
                let asked = ask_home_text(self.vault(), &home, &query, limit, None).await;
                let residence = match asked {
                    HomeText::Answered { search, capped }
                        if search.source == SearchSource::Home =>
                    {
                        home_residence(search, capped, &held)
                    }
                    HomeText::Whole | HomeText::LocalOnly | HomeText::Answered { .. } => {
                        RecallResidence::local_only()
                    }
                };
                // The home's references, found under the caller's own proof.
                rows.extend(
                    residence
                        .hits
                        .iter()
                        .filter_map(|hit| EntityId::from_hex(&hit.id).ok()),
                );
                page.residence = Some(residence);
                Ok(page)
            }
            other => other,
        };
        (answer, rows)
    }
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

fn internal(verb: &str) -> MemoryError {
    MemoryError::new(MEMORY_CODE_INTERNAL, format!("{verb} did not finish"), &[])
}
