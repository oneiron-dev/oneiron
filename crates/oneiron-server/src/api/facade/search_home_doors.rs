//! `vault.search.bm25`'s facade door (FIX 3876): the page is read on the
//! call's own caller surface, the one a plain row's `facade_invoke` builds,
//! with the row's hooks crossed around it by the dispatch; then an opened
//! device's home is asked under the call's own caller
//! ([`crate::api::search::complete_bm25_with_home`]).
use std::sync::Arc;

use oneiron::memory::{MemoryResult, ProducerRows};
use oneiron::task_verb::sdk::{Bm25Search, QueryBm25Request};
use oneiron::{EdgeActorClass, EntityId};

use super::{FacadeApiError, FacadeCall, facade_invocation};
use crate::server::SyncServer;

const VERB: &str = "vault.search.bm25";

/// `vault.search.bm25` for `call`: its page, then the home's references the
/// page does not hold. Beside it, the rows the page's read admitted and the
/// home's references.
pub(super) async fn vault_search_bm25(
    server: &Arc<SyncServer>,
    call: &FacadeCall<'_>,
    actor: EntityId,
    class: EdgeActorClass,
    input: QueryBm25Request,
) -> (MemoryResult<Bm25Search>, Vec<EntityId>) {
    let producers = ProducerRows::default();
    let (query, limit) = (input.query.clone(), input.limit);
    let page = crate::server::blocking(|| read_page(server, call, actor, class, input, &producers));
    let mut rows = producers.take();
    let answer = match page {
        Ok(page) => {
            let home = call.home_caller();
            let (page, found) = crate::api::search::complete_bm25_with_home(
                server.vault(),
                page,
                &query,
                limit,
                &home,
            )
            .await;
            rows.extend(found);
            Ok(page)
        }
        Err(refusal) => Err(refusal),
    };
    (answer, rows)
}

/// The page on the caller's surface: its credential at its locality, in the
/// call's off-record session and under its invocation, its reads listed in
/// `producers`. A room turn serves no BM25 search; the turn's own refusal
/// answers.
fn read_page(
    server: &SyncServer,
    call: &FacadeCall<'_>,
    actor: EntityId,
    class: EdgeActorClass,
    input: QueryBm25Request,
    producers: &ProducerRows,
) -> MemoryResult<Bm25Search> {
    let auth = call.auth();
    let memory = facade_invocation(
        crate::api::credential_memory(&server.vault, Some(auth), actor, class)
            .at(auth.locality())
            .listing_producers(producers),
        call,
    )
    .map_err(FacadeApiError::into_memory_error)?;
    match call
        .room_turn()
        .map_err(FacadeApiError::into_memory_error)?
    {
        Some(room) => {
            let value = serde_json::to_value(&input).map_err(|_| undecoded())?;
            let output = memory.for_room_turn(room)?.invoke(VERB, value)?;
            serde_json::from_value(output).map_err(|_| undecoded())
        }
        None => oneiron::task_verb::sdk::vault_search_bm25(&memory, input),
    }
}

fn undecoded() -> oneiron::memory::MemoryError {
    super::host_doors::internal(VERB)
}
