//! Doors for `tests/compaction_seat_exact_model.rs` (FIX-LIST
//! SELF-WRITER-HOUSE-FALLBACK-SEAT-EXACT-REFUSED): one pass on code mode's
//! house compaction backend, and one on the writer an agent definition's run
//! compacts on, each built as a run gets it. And for
//! `tests/live_fork_refuses_erased_prefix_source.rs` (FIX-LIST
//! ERASE-SERVED-KV-CACHE-OUTLIVES-SOURCE): a breakpoint's live fork bind,
//! and the request one call of a live flight sends, on the house route.
//! Compiled only under `--cfg oneiron_test_support`; never API.

use std::sync::Arc;

use oneiron::code_run::{LiveCompactionFork, LiveForkRung, bind_compaction_caller};
use oneiron::compaction::{CompactionBackend, CompactionRequest};
use oneiron::llm::run_admission::{KeyCustody, OfferBinding, OfferRoute, Payer};
use oneiron::llm::{ContentPart, LlmMessage, LlmMessageRole, SelfCompactionSource};
use oneiron::settings::CallerLocality;
use oneiron::{EdgeActorClass, EntityId, LlmRequest, WriteActor};

use super::live_fork::{LiveBind, bind_live_compaction_fork};
use super::{
    AnsweringRungSlot, CodeModeCompaction, LiveAdmission, LiveCompaction, ServedCompactionBackend,
};
use crate::models::{AnsweringRung, RoleCall, RoleRefusal};
use crate::server::SyncServer;

/// What one pass answered.
#[derive(Debug)]
pub struct PassAnswer {
    /// The summary text the pass's model wrote.
    pub summary: String,
    /// For a self-written pass, the model its receipt names as admitted.
    pub admitted_model: Option<String>,
    /// For a self-written pass, how many model calls it files as its steps.
    pub filed_calls: usize,
}

/// The code-mode compaction the host bound at attach, while it is live.
fn live(server: &SyncServer) -> Result<Arc<LiveCompaction>, String> {
    match server.ai.writer_compaction.get() {
        Some(CodeModeCompaction::Live(live)) => Ok(Arc::clone(live)),
        Some(CodeModeCompaction::Off(why)) => {
            Err(format!("code mode's compaction is off: {why:?}"))
        }
        None => Err("no code-mode compaction is bound".to_owned()),
    }
}

/// One pass of `request` on the house route's backend: the one a run
/// whose agent writes no compaction of its own compacts on. A pass blocks
/// on the host's runtime, so call it off that runtime.
///
/// # Errors
///
/// The pass's refusal, in its debug words.
pub fn house_pass(server: &SyncServer, request: &CompactionRequest) -> Result<PassAnswer, String> {
    let live = live(server)?;
    let house = live
        .served
        .first()
        .ok_or("code mode's compaction serves no house seat")?;
    let product = house
        .compact(request, None)
        .map_err(|refusal| format!("{refusal:?}"))?;
    Ok(PassAnswer {
        summary: product.summary_text,
        admitted_model: None,
        filed_calls: 0,
    })
}

/// One pass of `request` on the writer the run of `agent`, an agent
/// definition, compacts on (its memory profile as `run_profile` reads it,
/// its writer as `self_registry` registers it): its flight prepared on
/// this device, then sent as the agent's own. A pass blocks on the host's
/// runtime, so call it off that runtime.
///
/// # Errors
///
/// Why the run writes no compaction of its own, or the flight's or the
/// pass's refusal, in its debug words.
pub fn self_written_pass(
    server: &SyncServer,
    agent: EntityId,
    request: &CompactionRequest,
) -> Result<PassAnswer, String> {
    let live = live(server)?;
    let byline = WriteActor::new(agent, EdgeActorClass::Agent);
    let (profile, definition) = live.run_profile(byline);
    let definition = definition.ok_or("the agent's run does not write its own compaction")?;
    let host = bind_compaction_caller(byline, CallerLocality::OnDevice, None);
    let admission: Arc<dyn LiveAdmission> = Arc::new(NoLiveFork);
    let registry = live
        .self_registry(&profile, definition, host, None, &admission)
        .map_err(|why| format!("{why:?}"))?;
    let writer = registry
        .resolve(&profile)
        .map_err(|error| error.to_string())?;
    writer
        .prepare_flight(false)
        .map_err(|why| format!("{why:?}"))?;
    let answer = writer.compact_as_writer(request, None);
    writer.end_flight();
    let (product, execution) = answer.map_err(|refusal| format!("{refusal:?}"))?;
    Ok(PassAnswer {
        summary: product.summary_text,
        admitted_model: execution
            .as_ref()
            .map(|execution| execution.admitted_model.clone()),
        filed_calls: execution.map_or(0, |execution| execution.calls.len()),
    })
}

/// The input room a door's live fork is captured with: the test models'
/// configured context. The request a call sends never reads it.
const LIVE_FORK_ROOM: u64 = 32_768;

/// The house route's backend: the one a run whose agent writes no
/// compaction of its own compacts on.
fn house(live: &LiveCompaction) -> Result<&ServedCompactionBackend, String> {
    live.served
        .first()
        .map(AsRef::as_ref)
        .ok_or_else(|| "code mode's compaction serves no house seat".to_owned())
}

/// A run's live request as a breakpoint forks it: the house call over
/// `request` on the house route's wire, then `live_text` as the run's last
/// message.
fn live_request(
    house: &ServedCompactionBackend,
    request: &CompactionRequest,
    live_text: &str,
) -> LlmRequest {
    let mut live = house.llm_request(request, None);
    live.messages.push(LlmMessage {
        role: LlmMessageRole::User,
        content: vec![ContentPart::Text {
            text: live_text.to_owned(),
            signature: None,
        }],
    });
    live
}

/// A local keyless rung on the house route's model, for a fork whose
/// request is all a door reads: the request a call sends never reads the
/// fork's rung.
fn local_rung(house: &ServedCompactionBackend) -> Result<LiveForkRung, String> {
    Ok(LiveForkRung {
        provider: "local".to_owned(),
        position: 0,
        wire_model: house.model.as_str().to_owned(),
        offer: OfferBinding {
            offer: format!("{}@device", house.model.as_str()),
            model: house.model.clone(),
            route: OfferRoute::new("local", "device").map_err(|error| format!("{error:?}"))?,
            locality: house.locality,
            payer: Payer::Local,
            credential_binding: None,
            catalog_revision: None,
            custody: KeyCustody::Keyless,
            rates: Vec::new(),
            payer_person: None,
        },
    })
}

/// Whether a breakpoint on the house route binds a live fork (FIX 4465 C)
/// of a run's live request ([`live_request`] over `request` and
/// `live_text`) read from `prefix_sources`, for `agent`, under the vault's
/// self-compaction row with its source forced to the live fork. The run here
/// has no live call its host admits, so a bind that gets past the prefix's
/// own checks is refused as `LiveRungUnbound`.
///
/// # Errors
///
/// Why no fork binds, in its debug words.
pub fn house_live_fork_bind(
    server: &SyncServer,
    agent: EntityId,
    request: &CompactionRequest,
    live_text: &str,
    prefix_sources: Vec<EntityId>,
) -> Result<LiveCompactionFork, String> {
    let live = live(server)?;
    let house = house(&live)?;
    let frame = house
        .self_writer_frame
        .clone()
        .ok_or("code mode's prompt package holds no self-writer frame")?;
    let mut row = server
        .vault()
        .purpose_default_table()
        .map_err(|error| error.to_string())?
        .self_compaction()
        .clone();
    row.source = SelfCompactionSource::LiveFork;
    match bind_live_compaction_fork(
        house,
        &frame,
        &NoLiveFork,
        agent,
        &row,
        &live_request(house, request, live_text),
        Some(prefix_sources),
        request.summary_token_budget,
        LiveBind::Forced,
    ) {
        Some(Ok(fork)) => Ok(fork),
        Some(Err(why)) => Err(format!("{why:?}")),
        None => Err("no live fork was bound, and none was refused".to_owned()),
    }
}

/// The request one call of a live flight on the house route sends (FIX
/// 4465 C, FIX 4931) for a fork of a run's live request ([`live_request`]
/// over `request` and `live_text`), captured for `agent` from
/// `prefix_sources`, over `request`: in its wire JSON, or why nothing is
/// sent. Nothing goes to a provider here.
///
/// # Errors
///
/// Why the call sends nothing, in its debug words.
pub fn house_live_fork_request(
    server: &SyncServer,
    agent: EntityId,
    request: &CompactionRequest,
    live_text: &str,
    prefix_sources: Vec<EntityId>,
) -> Result<String, String> {
    let live = live(server)?;
    let house = house(&live)?;
    let fork = LiveCompactionFork::capture(
        live_request(house, request, live_text),
        local_rung(house)?,
        agent,
        LIVE_FORK_ROOM,
        prefix_sources,
    );
    let call = house
        .fork_request(&fork, request, None)
        .map_err(|refusal| format!("{refusal:?}"))?;
    serde_json::to_string(&call).map_err(|error| error.to_string())
}

/// A run with no live call to fork: a flight on the retained turns, or on
/// `auto` with no capture, never asks it.
struct NoLiveFork;

impl LiveAdmission for NoLiveFork {
    fn admit_live(&self, _: LlmRequest) -> Result<RoleCall, RoleRefusal> {
        Err(RoleRefusal::NoSeat)
    }

    fn hold_answering_rungs(&self, _: &LlmRequest) -> Option<Arc<AnsweringRungSlot>> {
        None
    }

    fn answering_rung(&self, _: &LlmRequest) -> Option<AnsweringRung> {
        None
    }
}
