//! The agent's own compaction writer (FIX 4465, owner 10-19: "the toggle sets
//! WHO writes, not which model"). One per run, bound to the actor its host
//! authenticated; there is no process-wide current agent. Each flight it
//! reads the vault's self-compaction row and the agent's home once, under the
//! agent's own Grant, and freezes them for the flight's calls. A flight on
//! the retained turns is the house compaction call on the cheap writer,
//! wearing that home: the agent's own compaction model when its definition
//! names one (FIX 4472), else the row's cheap model (FIX 6029), and the
//! house route's model, writing as the agent, where that one is not served.
//! Each call is admitted as exactly that model. The agent writes only the
//! summary; the host records who wrote it, what ran it and what it cost.
//!
//! When the row reads the live context (FIX 4465 C), the flight's calls fork
//! the run's live request instead, captured at its breakpoint on the rung
//! that admitted it, and the same receipt names that rung's model. A row on
//! `auto` (FIX 6029, the shipped default) resolves per flight: the live fork
//! while the live prefix is still warm in its provider's prompt cache, at
//! the breakpoint and again right before the flight's first call, else the
//! cheap writer. Every later call of the flight, its retries and folds,
//! keeps the source its first call ran on, and each receipt names it.

use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use oneiron::LlmRequest;
use oneiron::agent_def::AgentDefinition;
use oneiron::code_run::{
    AdmittedLiveFork, CompactionHome, CompactionHostBinding, LiveCompactionFork,
    compaction_home_budget, load_compaction_home,
};
use oneiron::compaction::{
    CompactionBackend, CompactionCall, CompactionCheck, CompactionExecution, CompactionHomeRef,
    CompactionProduct, CompactionRefusal, CompactionRequest, CompactionTierClass,
    SelfCompactionUnavailable, compaction_usage_projection,
};
use oneiron::llm::{
    ContentPart, ModelId, ModelLocality, SelfCompactionDefault, SelfCompactionSource,
};

use super::live_fork::{LiveBind, bind_live_compaction_fork};
use super::serve::{Admit, Served, product_of};
use super::{LiveAdmission, ServedCompactionBackend};

/// The words that turn the house compaction call into the agent's own: the
/// home the call wears follows them. The one hook a ruling on this text
/// changes; the persona itself comes only from the agent's home.
pub(super) const SELF_WRITER_FRAME: &str = "You are writing this summary as yourself, in your own voice: it \
    is your own memory of your own work. What follows is your home, read under your own Grant \
    (your voice, your lessons and your diary). Keep the reply's JSON shape and the span's facts \
    exactly as the window gives them.";

/// The cheap writer a flight runs on: its model and where it is served, or
/// why there is none.
type ColdWriter = Result<(ModelId, ModelLocality), SelfCompactionUnavailable>;

/// What a breakpoint read for its flight (FIX 6029): the row and the cheap
/// writer, so the flight is sized and frozen on the same ones.
#[derive(Clone)]
struct Staged {
    row: SelfCompactionDefault,
    cold: ColdWriter,
}

/// What one flight froze: the cheap writer it runs on or keeps standing by,
/// the home it wears, for a live flight the fork its calls send (FIX 4465
/// C), and the source its first call ran on (FIX 6029), held until the
/// flight ends.
#[derive(Clone)]
struct Frozen {
    /// The flight's own writer on the retained turns. Under `auto`, the one
    /// a live flight's first call falls to when the prefix went cold before
    /// it was sent; `None` for a forced live fork, and for a live one with
    /// no cheap writer served.
    cold: Option<(ModelId, ModelLocality)>,
    home: CompactionHome,
    live: Option<Arc<LiveCompactionFork>>,
    /// The source the flight's first call ran on, for every later call.
    executed: Arc<OnceLock<SelfCompactionSource>>,
}

/// `select_live_compaction_binding` (FIX 4465 C, amending FIX 4465 A's
/// per-wake model; FIX 6029): the captured live binding wins for a row that
/// selects the live fork, and for a row on `auto` whose breakpoint found
/// the prefix warm and captured it. A row on the retained turns, and `auto`
/// with no capture, run on the cheap writer and let go of any capture. A
/// live row with no capture keeps the window and says why.
fn select_live_compaction_binding(
    row: &SelfCompactionDefault,
    live: Option<AdmittedLiveFork>,
) -> Result<Option<LiveCompactionFork>, SelfCompactionUnavailable> {
    match (row.source, live) {
        (SelfCompactionSource::RetainedTurns, _) | (SelfCompactionSource::Auto, None) => Ok(None),
        (SelfCompactionSource::Auto | SelfCompactionSource::LiveFork, Some(fork)) => {
            Ok(Some(fork.into_fork()))
        }
        (SelfCompactionSource::LiveFork, None) => {
            Err(SelfCompactionUnavailable::LiveForkNotCaptured)
        }
    }
}

/// `model` served at `locality`, held to the row's bound: an egress limit,
/// never a test of where the agent runs.
fn within(row: &SelfCompactionDefault, model: ModelId, locality: ModelLocality) -> ColdWriter {
    if locality > row.locality {
        Err(SelfCompactionUnavailable::RouteWiderThanPolicy)
    } else {
        Ok((model, locality))
    }
}

pub(super) struct SelfCompactionBackend {
    /// The registry key the agent's profile names.
    key: String,
    /// The house compaction route the writer's calls take.
    route: ServedCompactionBackend,
    /// The agent's definition, read when its seat was made.
    definition: AgentDefinition,
    /// The run's authenticated actor, its caller's place and its proof.
    host: CompactionHostBinding,
    /// How the run's live rung is read at a breakpoint (FIX 4465 C).
    admission: Arc<dyn LiveAdmission>,
    /// What the last breakpoint read for its flight (FIX 6029).
    staged: Mutex<Option<Staged>>,
    flight: Mutex<Option<Frozen>>,
}

impl SelfCompactionBackend {
    pub(super) fn new(
        key: String,
        route: ServedCompactionBackend,
        definition: AgentDefinition,
        host: CompactionHostBinding,
        admission: Arc<dyn LiveAdmission>,
    ) -> Self {
        Self {
            key,
            route,
            definition,
            host,
            admission,
            staged: Mutex::new(None),
            flight: Mutex::new(None),
        }
    }

    /// The cheap writer under `row` (FIX 6029; FIX 4472): the agent's own
    /// compaction model when its definition names one, else the row's cheap
    /// model. One not served here, or the row's served wider than the row
    /// allows, gives way to the house route's model, which writes as the
    /// agent: a flight that compacted before still compacts. The agent's
    /// own model served wider than the row is refused, as it always was.
    fn cold_writer(&self, row: &SelfCompactionDefault) -> ColdWriter {
        let served = |model: &ModelId| {
            self.route
                .models
                .router()
                .and_then(|router| router.served(model))
                .map(|(locality, _)| locality)
        };
        let own = self.definition.compaction_model.is_some();
        let preferred =
            oneiron::agent_def::resolve_compaction_model(&self.definition, &row.cheap_model);
        if let Some(locality) = served(preferred)
            && (own || locality <= row.locality)
        {
            return within(row, preferred.clone(), locality);
        }
        let house = self
            .route
            .house_model()
            .ok_or(SelfCompactionUnavailable::ModelNotServed)?;
        let locality = served(&house).ok_or(SelfCompactionUnavailable::ModelNotServed)?;
        within(row, house, locality)
    }

    /// The vault's self-compaction row, as it reads now.
    fn row(&self) -> Result<SelfCompactionDefault, SelfCompactionUnavailable> {
        Ok(self
            .route
            .vault
            .purpose_default_table()
            .map_err(|_| SelfCompactionUnavailable::PolicyUnreadable)?
            .self_compaction()
            .clone())
    }

    /// What `staged` read at the flight's breakpoint, else the row and its
    /// cheap writer as they read now.
    fn read_flight(&self, staged: Option<Staged>) -> Result<Staged, SelfCompactionUnavailable> {
        match staged {
            Some(staged) => Ok(staged),
            None => {
                let row = self.row()?;
                Ok(Staged {
                    cold: self.cold_writer(&row),
                    row,
                })
            }
        }
    }

    /// What this flight wears, or why it cannot be written as its agent. A
    /// room's run is written as its agent too (FIX 4465 B): its calls file
    /// and its summary lands on the route the run captured at entry. A live
    /// flight wears its fork's rung (FIX 4465 C).
    fn freeze(&self, live: Option<AdmittedLiveFork>) -> Result<Frozen, SelfCompactionUnavailable> {
        let staged = self
            .staged
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let Staged { row, cold } = self.read_flight(staged)?;
        let executed = Arc::new(OnceLock::new());
        if let Some(fork) = select_live_compaction_binding(&row, live)? {
            // The row read now bounds the captured rung, as it bounds the
            // retained route's model.
            let locality = fork.rung().offer.locality;
            if locality > row.locality {
                return Err(SelfCompactionUnavailable::RouteWiderThanPolicy);
            }
            let home = load_compaction_home(&self.route.vault, &self.host)?;
            return Ok(Frozen {
                // Only `auto` keeps the cheap writer standing by.
                cold: cold
                    .ok()
                    .filter(|_| row.source == SelfCompactionSource::Auto),
                home,
                live: Some(Arc::new(fork)),
                executed,
            });
        }
        let cold = cold?;
        let home = load_compaction_home(&self.route.vault, &self.host)?;
        Ok(Frozen {
            cold: Some(cold),
            home,
            live: None,
            executed,
        })
    }

    fn frozen(&self) -> Option<Frozen> {
        self.flight
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Freezes the flight, or clears it with why it cannot be written.
    fn prepare(&self, live: Option<AdmittedLiveFork>) -> Result<(), SelfCompactionUnavailable> {
        let frozen = self.freeze(live);
        let mut slot = self.flight.lock().unwrap_or_else(PoisonError::into_inner);
        match frozen {
            Ok(frozen) => {
                *slot = Some(frozen);
                Ok(())
            }
            Err(why) => {
                *slot = None;
                Err(why)
            }
        }
    }

    /// A retained-turn call: the house compaction call on the cheap writer's
    /// own model, wearing the home in its system message.
    fn serve_retained(
        &self,
        frozen: &Frozen,
        request: &CompactionRequest,
        retry: Option<CompactionCheck>,
    ) -> Result<Served<Vec<CompactionHomeRef>>, CompactionRefusal> {
        let Some((model, locality)) = frozen.cold.clone() else {
            return Err(SelfCompactionUnavailable::ModelNotServed.refusal());
        };
        let admit = Admit::Exact { model, locality };
        self.route.serve(request, retry, &admit, |call, room| {
            let frame = oneiron::count_context_pack_tokens(SELF_WRITER_FRAME) as u64;
            let home = frozen.home.render(compaction_home_budget(
                room.context,
                room.input,
                room.output,
                frame,
            ));
            if let Some(system) = call.messages.first_mut() {
                system.content.push(ContentPart::Text {
                    text: format!("\n\n{SELF_WRITER_FRAME}\n\n{}", home.text),
                });
            }
            Ok(home.refs)
        })
    }

    /// One call of the frozen flight, and the source it ran on (FIX 6029).
    /// Under `auto` the flight's first call goes out on the live fork only
    /// while its prefix is still warm, else on the cheap writer standing by,
    /// before anything is sent; every later call of the flight keeps the
    /// source the first one ran on, never switching after a live call that
    /// may have been paid.
    fn serve_flight(
        &self,
        frozen: &Frozen,
        request: &CompactionRequest,
        retry: Option<CompactionCheck>,
    ) -> Result<(Served<Vec<CompactionHomeRef>>, SelfCompactionSource), CompactionRefusal> {
        let executed = frozen.executed.get().copied();
        let fork = match (&frozen.live, executed) {
            (Some(fork), None | Some(SelfCompactionSource::LiveFork)) => fork,
            _ => {
                return self
                    .serve_retained(frozen, request, retry)
                    .map(|served| (served, SelfCompactionSource::RetainedTurns));
            }
        };
        let while_warm = frozen.cold.is_some() && executed.is_none();
        match self
            .route
            .serve_live_fork(fork, &frozen.home, request, retry, while_warm)
        {
            Ok(None) => {
                let _ = frozen.executed.set(SelfCompactionSource::RetainedTurns);
                self.serve_retained(frozen, request, retry)
                    .map(|served| (served, SelfCompactionSource::RetainedTurns))
            }
            Ok(Some(served)) => {
                let _ = frozen.executed.set(SelfCompactionSource::LiveFork);
                Ok((served, SelfCompactionSource::LiveFork))
            }
            Err(refusal) => {
                let _ = frozen.executed.set(SelfCompactionSource::LiveFork);
                Err(refusal)
            }
        }
    }
}

impl CompactionBackend for SelfCompactionBackend {
    fn backend_key(&self) -> &str {
        &self.key
    }

    /// Its house route's recovery count (FIX 1112).
    fn recoveries(&self) -> u64 {
        self.route.recoveries()
    }

    /// Its house route's payer read (FIX 3740).
    fn funded(&self) -> bool {
        self.route.funded()
    }

    /// The cheap compaction route, wearing the agent's home.
    fn tier_class(&self) -> CompactionTierClass {
        CompactionTierClass::Cheap
    }

    /// What the flight's writer holds beside the reply and the prompt; the
    /// home takes only what the sealed window leaves. A frozen flight's
    /// own: its live fork's room (under `auto` no more than its cheap
    /// writer's), else its cheap writer's. Before a flight freezes, the
    /// cheap writer its breakpoint staged, else the one the row reads now.
    /// `None` when no cheap writer is served: nothing bounds the input, and
    /// the flight says why when it freezes.
    fn input_token_limit(&self, summary_token_budget: u64) -> Option<u64> {
        if let Some(frozen) = self.frozen() {
            return match &frozen.live {
                Some(fork) => Some(fork.input_room()),
                None => frozen
                    .cold
                    .map(|(model, _)| self.route.input_room(&model, summary_token_budget)),
            };
        }
        let staged = self
            .staged
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let (model, _) = self.read_flight(staged).ok()?.cold.ok()?;
        Some(self.route.input_room(&model, summary_token_budget))
    }

    fn prepare_flight(&self, _session_bound: bool) -> Result<(), SelfCompactionUnavailable> {
        self.prepare(None)
    }

    /// Binds the live rung for a row that reads the live context: forced
    /// under one that selects it, and under `auto` only while the prefix is
    /// still warm (FIX 6029). Stages the row and the cheap writer it read
    /// for the flight, so the flight is sized and frozen on the same ones; a
    /// row that cannot be read is named when the flight freezes.
    fn capture_live_fork(
        &self,
        live: &LlmRequest,
        summary_token_budget: u64,
    ) -> Option<Result<LiveCompactionFork, SelfCompactionUnavailable>> {
        let staged = self.row().ok().map(|row| Staged {
            cold: self.cold_writer(&row),
            row,
        });
        *self.staged.lock().unwrap_or_else(PoisonError::into_inner) = staged.clone();
        let Staged { row, cold } = staged?;
        let how = match row.source {
            SelfCompactionSource::RetainedTurns => return None,
            SelfCompactionSource::LiveFork => LiveBind::Forced,
            SelfCompactionSource::Auto => LiveBind::WhileWarm {
                cold_room: cold
                    .ok()
                    .map(|(model, _)| self.route.input_room(&model, summary_token_budget)),
            },
        };
        bind_live_compaction_fork(
            &self.route,
            self.admission.as_ref(),
            self.host.actor().entity_ref(),
            &row,
            live,
            summary_token_budget,
            how,
        )
    }

    fn prepare_live_flight(
        &self,
        _session_bound: bool,
        fork: AdmittedLiveFork,
    ) -> Result<(), SelfCompactionUnavailable> {
        self.prepare(Some(fork))
    }

    fn end_flight(&self) {
        *self.flight.lock().unwrap_or_else(PoisonError::into_inner) = None;
        *self.staged.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }

    fn compact(
        &self,
        request: &CompactionRequest,
        retry: Option<CompactionCheck>,
    ) -> Result<CompactionProduct, CompactionRefusal> {
        self.compact_as_writer(request, retry)
            .map(|(product, _)| product)
    }

    fn compact_as_writer(
        &self,
        request: &CompactionRequest,
        retry: Option<CompactionCheck>,
    ) -> Result<(CompactionProduct, Option<CompactionExecution>), CompactionRefusal> {
        let Some(frozen) = self.frozen() else {
            return Err(SelfCompactionUnavailable::FlightNotPrepared.refusal());
        };
        let (served, source) = self.serve_flight(&frozen, request, retry)?;
        let usage = &served.response.usage;
        let sent = served.sent.zip(serde_json::to_vec(&served.response).ok());
        let mut execution = CompactionExecution {
            writer: self.host.actor().entity_ref(),
            source,
            admitted_model: served.model.to_string(),
            served_provider: usage.served_provider().map(str::to_owned),
            served_model: usage
                .raw_provider
                .get("reported_model")
                .and_then(|model| model.as_str())
                .map(str::to_owned),
            usage: compaction_usage_projection(usage),
            rejected_tries: Vec::new(),
            step_hash: served
                .step_hash
                .map(|hash| hash.iter().map(|byte| format!("{byte:02x}")).collect()),
            home: served.worn,
            snapshot_hash: None,
            snapshot_len: None,
            step: None,
            rejected_steps: Vec::new(),
            step_unfiled: None,
            evidence: None,
            calls: Vec::new(),
        };
        // The paid call, for its host to file in the model-step family on
        // the run's captured route (FIX 4465 B), with the summary's own
        // lineage: the request's sources, then each home part the call wore
        // that they do not name (FIX 5977).
        let mut sources = request.sources.clone();
        for row in execution.home_dependencies() {
            if !sources.contains(&row) {
                sources.push(row);
            }
        }
        execution.calls = sent
            .map(|(request, response)| CompactionCall {
                request,
                response,
                sources,
            })
            .into_iter()
            .collect();
        Ok((
            product_of(&served.response, served.latency),
            Some(execution),
        ))
    }
}
