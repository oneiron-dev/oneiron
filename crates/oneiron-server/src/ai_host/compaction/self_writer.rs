//! The agent's own compaction writer (FIX 4465, owner 10-19: "the toggle sets
//! WHO writes, not which model"). One per run, bound to the actor its host
//! authenticated; there is no process-wide current agent. Each flight it
//! reads the vault's self-compaction row and the agent's home once, under the
//! agent's own Grant, and freezes them for the flight's calls. Each call is
//! the house compaction call on the cheap route, wearing that home, on the
//! agent's own compaction model when its definition names one (FIX 4472),
//! admitted as exactly that model. The agent writes only the summary; the
//! host records who wrote it, what ran it and what it cost.
//!
//! When the row reads the live context (FIX 4465 C), the flight's calls fork
//! the run's live request instead, captured at its breakpoint on the rung
//! that admitted it, and the same receipt names that rung's model.

use std::sync::{Arc, Mutex, PoisonError};

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
use oneiron::llm::{ContentPart, ModelId, SelfCompactionDefault, SelfCompactionSource};

use super::live_fork::bind_live_compaction_fork;
use super::serve::{Admit, Served, product_of};
use super::{LiveAdmission, ServedCompactionBackend};

/// The words that turn the house compaction call into the agent's own: the
/// home the call wears follows them. The one hook a ruling on this text
/// changes; the persona itself comes only from the agent's home.
pub(super) const SELF_WRITER_FRAME: &str = "You are writing this summary as yourself, in your own voice: it \
    is your own memory of your own work. What follows is your home, read under your own Grant \
    (your voice, your lessons and your diary). Keep the reply's JSON shape and the span's facts \
    exactly as the window gives them.";

/// What one flight froze: the row it is served by, the model it runs on and
/// the home it wears, and for a live flight the fork its calls send (FIX
/// 4465 C), held until the flight ends.
#[derive(Clone)]
struct Frozen {
    row: SelfCompactionDefault,
    admit: (ModelId, oneiron::llm::ModelLocality),
    home: CompactionHome,
    live: Option<Arc<LiveCompactionFork>>,
}

/// `select_live_compaction_binding` (FIX 4465 C, amending FIX 4465 A's
/// per-wake model): the captured live binding wins only for a row that
/// selects the live fork. A row on the retained turns resolves the agent's
/// own compaction model, else the house's, as before, and lets go of any
/// capture. A live row with no capture keeps the window and says why.
fn select_live_compaction_binding(
    row: &SelfCompactionDefault,
    live: Option<AdmittedLiveFork>,
) -> Result<Option<LiveCompactionFork>, SelfCompactionUnavailable> {
    match (row.source, live) {
        (SelfCompactionSource::RetainedTurns, _) => Ok(None),
        (SelfCompactionSource::LiveFork, Some(fork)) => Ok(Some(fork.into_fork())),
        (SelfCompactionSource::LiveFork, None) => {
            Err(SelfCompactionUnavailable::LiveForkNotCaptured)
        }
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
            flight: Mutex::new(None),
        }
    }

    /// The model the writer's calls run on (FIX 4472): the agent's own
    /// compaction model, else the house route's.
    fn writer_model(&self) -> Option<ModelId> {
        let house = self.route.house_model()?;
        Some(oneiron::agent_def::resolve_compaction_model(&self.definition, &house).clone())
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

    /// What this flight wears, or why it cannot be written as its agent. A
    /// room's run is written as its agent too (FIX 4465 B): its calls file
    /// and its summary lands on the route the run captured at entry. A live
    /// flight wears its fork's rung (FIX 4465 C).
    fn freeze(&self, live: Option<AdmittedLiveFork>) -> Result<Frozen, SelfCompactionUnavailable> {
        let row = self.row()?;
        if let Some(fork) = select_live_compaction_binding(&row, live)? {
            // The row read now bounds the captured rung, as it bounds the
            // retained route's model.
            let locality = fork.rung().offer.locality;
            if locality > row.locality {
                return Err(SelfCompactionUnavailable::RouteWiderThanPolicy);
            }
            let home = load_compaction_home(&self.route.vault, &self.host)?;
            return Ok(Frozen {
                row,
                admit: (fork.request().model.clone(), locality),
                home,
                live: Some(Arc::new(fork)),
            });
        }
        let model = self
            .writer_model()
            .ok_or(SelfCompactionUnavailable::ModelNotServed)?;
        let locality = self
            .route
            .models
            .router()
            .and_then(|router| router.served(&model))
            .map(|(locality, _)| locality)
            .ok_or(SelfCompactionUnavailable::ModelNotServed)?;
        // The row bounds where the call may be served: an egress limit,
        // never a test of where the agent runs.
        if locality > row.locality {
            return Err(SelfCompactionUnavailable::RouteWiderThanPolicy);
        }
        let home = load_compaction_home(&self.route.vault, &self.host)?;
        Ok(Frozen {
            row,
            admit: (model, locality),
            home,
            live: None,
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

    /// A retained-turn call: the house compaction call on the writer's own
    /// model, wearing the home in its system message.
    fn serve_retained(
        &self,
        frozen: &Frozen,
        request: &CompactionRequest,
        retry: Option<CompactionCheck>,
    ) -> Result<Served<Vec<CompactionHomeRef>>, CompactionRefusal> {
        let admit = Admit::Exact {
            model: frozen.admit.0.clone(),
            locality: frozen.admit.1,
        };
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
}

impl CompactionBackend for SelfCompactionBackend {
    fn backend_key(&self) -> &str {
        &self.key
    }

    /// The cheap compaction route, wearing the agent's home.
    fn tier_class(&self) -> CompactionTierClass {
        CompactionTierClass::Cheap
    }

    /// What the writer's model holds beside the reply and the prompt; the
    /// home takes only what the sealed window leaves.
    fn input_token_limit(&self, summary_token_budget: u64) -> Option<u64> {
        let model = self.writer_model()?;
        Some(self.route.input_room(&model, summary_token_budget))
    }

    fn prepare_flight(&self, _session_bound: bool) -> Result<(), SelfCompactionUnavailable> {
        self.prepare(None)
    }

    /// Binds the live rung only for a row that reads the live context; a row
    /// that cannot be read is named when the flight freezes.
    fn capture_live_fork(
        &self,
        live: &LlmRequest,
        summary_token_budget: u64,
    ) -> Option<Result<LiveCompactionFork, SelfCompactionUnavailable>> {
        let row = self
            .row()
            .ok()
            .filter(|row| row.source == SelfCompactionSource::LiveFork)?;
        Some(bind_live_compaction_fork(
            &self.route,
            self.admission.as_ref(),
            self.host.actor().entity_ref(),
            &row,
            live,
            summary_token_budget,
        ))
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
        let served = match &frozen.live {
            Some(fork) => self
                .route
                .serve_live_fork(fork, &frozen.home, request, retry)?,
            None => self.serve_retained(&frozen, request, retry)?,
        };
        let usage = &served.response.usage;
        // The paid call, for its host to file in the model-step family on
        // the run's captured route (FIX 4465 B).
        let calls = served
            .sent
            .zip(serde_json::to_vec(&served.response).ok())
            .map(|(request, response)| CompactionCall { request, response })
            .into_iter()
            .collect();
        let execution = CompactionExecution {
            writer: self.host.actor().entity_ref(),
            source: frozen.row.source,
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
            calls,
        };
        Ok((
            product_of(&served.response, served.latency),
            Some(execution),
        ))
    }
}
