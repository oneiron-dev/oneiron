//! The agent's own compaction writer (FIX 4465, owner 10-19: "the toggle sets
//! WHO writes, not which model"). One per run, bound to the actor its host
//! authenticated; there is no process-wide current agent. Each flight it
//! reads the vault's self-compaction row and the agent's home once, under the
//! agent's own Grant, and freezes them for the flight's calls. Each call is
//! the house compaction call on the cheap route, wearing that home, on the
//! agent's own compaction model when its definition names one (FIX 4472),
//! admitted as exactly that model. The agent writes only the summary; the
//! host records who wrote it, what ran it and what it cost.

use std::sync::{Mutex, PoisonError};

use oneiron::agent_def::AgentDefinition;
use oneiron::code_run::{
    CompactionHome, CompactionHostBinding, compaction_home_budget, load_compaction_home,
};
use oneiron::compaction::{
    CompactionBackend, CompactionCheck, CompactionExecution, CompactionProduct, CompactionRefusal,
    CompactionRequest, CompactionTierClass, SelfCompactionUnavailable, compaction_usage_projection,
};
use oneiron::llm::{ContentPart, ModelId, SelfCompactionDefault, SelfCompactionSource};

use super::ServedCompactionBackend;
use super::serve::{Admit, product_of};

/// The words that turn the house compaction call into the agent's own: the
/// home the call wears follows them. The one hook a ruling on this text
/// changes; the persona itself comes only from the agent's home.
const SELF_WRITER_FRAME: &str = "You are writing this summary as yourself, in your own voice: it \
    is your own memory of your own work. What follows is your home, read under your own Grant \
    (your voice, your lessons and your diary). Keep the reply's JSON shape and the span's facts \
    exactly as the window gives them.";

/// What one flight froze: the row it is served by, the model it runs on and
/// the home it wears.
#[derive(Clone)]
struct Frozen {
    row: SelfCompactionDefault,
    admit: (ModelId, oneiron::llm::ModelLocality),
    home: CompactionHome,
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
    flight: Mutex<Option<Frozen>>,
}

impl SelfCompactionBackend {
    pub(super) fn new(
        key: String,
        route: ServedCompactionBackend,
        definition: AgentDefinition,
        host: CompactionHostBinding,
    ) -> Self {
        Self {
            key,
            route,
            definition,
            host,
            flight: Mutex::new(None),
        }
    }

    /// The model the writer's calls run on (FIX 4472): the agent's own
    /// compaction model, else the house route's.
    fn writer_model(&self) -> Option<ModelId> {
        let house = self.route.house_model()?;
        Some(oneiron::agent_def::resolve_compaction_model(&self.definition, &house).clone())
    }

    /// What this flight wears, or why it cannot be written as its agent.
    fn freeze(&self, session_bound: bool) -> Result<Frozen, SelfCompactionUnavailable> {
        if session_bound {
            return Err(SelfCompactionUnavailable::SessionReceiptsNotBuilt);
        }
        let row = self
            .route
            .vault
            .purpose_default_table()
            .map_err(|_| SelfCompactionUnavailable::PolicyUnreadable)?
            .self_compaction()
            .clone();
        if row.source == SelfCompactionSource::LiveFork {
            return Err(SelfCompactionUnavailable::LiveForkNotBuilt);
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
        })
    }

    fn frozen(&self) -> Option<Frozen> {
        self.flight
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
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

    fn prepare_flight(&self, session_bound: bool) -> Result<(), SelfCompactionUnavailable> {
        let frozen = self.freeze(session_bound);
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
        let admit = Admit::Exact {
            model: frozen.admit.0.clone(),
            locality: frozen.admit.1,
        };
        let served = self.route.serve(request, retry, &admit, |call, room| {
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
        })?;
        let usage = &served.response.usage;
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
        };
        Ok((
            product_of(&served.response, served.latency),
            Some(execution),
        ))
    }
}
