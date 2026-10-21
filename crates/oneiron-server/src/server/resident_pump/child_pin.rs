//! A seatless planned child's binding (FIX 2310, OF-541 PR H).
//!
//! A planned child no seat binds runs its plan's pick exactly where its
//! provider routes that model so and its frozen definition lists it, else
//! the provider's own model, each call another model answers marked on its
//! receipts. Its first entry decides that once, and its attempt row keeps
//! the decision with the executor model it runs, written under its lease
//! before any pack load stamps that model (FIX 7720). Every later entry runs
//! what the row keeps, exactness included, and never asks the provider or
//! the catalog again (FIX 7721). A continuation (FIX 3694) takes its source
//! try's binding on its forked config, and records that it inherited no
//! exactness when its source recorded none (FIX 7723). The agent's diary
//! notes the model the binding runs, as a seated wake's does (FIX 7726).

use oneiron::agent_def::{AgentDefinition, ensure_listed};
use oneiron::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, PlannedBinding, PlannedExactness,
};
use oneiron::engine_executor::EngineExecutorConfig;
use oneiron::engine_executor::continuation::run_continuation;
use oneiron::{EntityId, ModelId, ModelLocality, Vault, WriteActor};

use crate::mcp::{McpCodeModeProvider, PlannedModel};

/// The binding a planned child runs this entry under: the one its row
/// keeps, or the one this entry chose, not yet kept.
pub(super) struct ChildPin {
    binding: PlannedBinding,
    kept: bool,
}

/// The binding `attempt`, a planned child no seat binds whose plan picked
/// `pick`, runs under, with `config` set to it. A row that keeps one runs
/// it: the executor model it stamped, on the route it kept. Else a
/// continuation (`continues`) takes its source try's, and any other child
/// decides at its first entry: its pick, exactly, where [`exact_route`]
/// finds a route, else `config` as it stands.
pub(super) fn select(
    vault: &Vault,
    provider: &dyn McpCodeModeProvider,
    attempt: &AttemptRecord,
    definition: &AgentDefinition,
    pick: &ModelId,
    continues: bool,
    config: &mut EngineExecutorConfig,
) -> ChildPin {
    if let Some(binding) = kept(attempt, config) {
        return ChildPin {
            binding,
            kept: true,
        };
    }
    let binding = if continues {
        inherited(vault, attempt, pick, config)
    } else {
        let route = exact_route(vault, provider, definition, pick);
        if let Some(locality) = route {
            config.model = pick.clone();
            config.model_locality = locality;
        }
        PlannedBinding {
            pick: pick.clone(),
            locality: config.model_locality,
            exactness: match route {
                Some(_) => PlannedExactness::Exact,
                None => PlannedExactness::NonExact,
            },
            source: None,
        }
    };
    ChildPin {
        binding,
        kept: false,
    }
}

impl ChildPin {
    /// Keeps this entry's binding on `attempt`'s row (FIX 7720) when the row
    /// keeps none yet, notes in the agent's diary which model the wake runs
    /// on (FIX 7726), and answers the plan binding `child`'s calls and
    /// compaction take. A row that kept another binding first runs that
    /// one. A write or a note that fails is logged, and the run goes on
    /// with the binding it chose, as it would today.
    pub(super) fn bind(
        self,
        vault: &Vault,
        attempt: &AttemptRecord,
        actor: WriteActor,
        child: EntityId,
        config: &mut EngineExecutorConfig,
    ) -> PlannedModel {
        let mut binding = self.binding;
        if !self.kept {
            match AttemptQueue::new(vault).bind_planned_executor(
                attempt,
                config.model.as_str(),
                &binding,
            ) {
                Ok(row) => {
                    if let Some(first) = kept(&row, config) {
                        binding = first;
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, run = %child.to_hex(), "a planned child's binding was not kept on its row; it runs as it would today");
                }
            }
        }
        let why = match binding.exactness {
            PlannedExactness::Exact => "its plan's pick, run exactly".to_owned(),
            PlannedExactness::NonExact => {
                format!("its provider's own route; its plan picked {}", binding.pick)
            }
            PlannedExactness::Inherited => format!(
                "the run it continues, which kept no exact route; its plan picked {}",
                binding.pick
            ),
        };
        if let Err(error) = vault.note_wake_model(actor.entity_ref(), &config.model, &why) {
            tracing::warn!(%error, agent = %actor.entity_ref().to_hex(), "a wake's model change was not noted in the agent's diary");
        }
        PlannedModel {
            child,
            exact: binding.exactness == PlannedExactness::Exact,
            pick: binding.pick,
        }
    }
}

/// The binding `attempt`'s row keeps, with `config` set to the executor
/// model and route it kept. `None` when the row keeps none.
fn kept(attempt: &AttemptRecord, config: &mut EngineExecutorConfig) -> Option<PlannedBinding> {
    let binding = attempt.planned_binding.clone()?;
    config.model = ModelId::new(attempt.executor_model.as_deref()?).ok()?;
    config.model_locality = binding.locality;
    Some(binding)
}

/// A continuation's binding (FIX 7723), on its forked config's model and
/// route: its source, the try whose run its checkpoint forks (never the
/// latest retry), and that try's pick and exactness as its row kept them;
/// with none kept, its plan's pick, and [`PlannedExactness::Inherited`],
/// never guessed from today's catalog.
fn inherited(
    vault: &Vault,
    attempt: &AttemptRecord,
    pick: &ModelId,
    config: &EngineExecutorConfig,
) -> PlannedBinding {
    let source = match run_continuation(vault, attempt.id) {
        Ok(continuation) => continuation.and_then(|continuation| {
            AttemptId::from_bytes(continuation.checkpoint.source_run.as_bytes()).ok()
        }),
        Err(error) => {
            tracing::warn!(%error, "a continuation's source did not read; its binding names none");
            None
        }
    };
    let recorded = source.and_then(|source| match AttemptQueue::new(vault).get(source) {
        Ok(row) => row.and_then(|row| row.planned_binding),
        Err(error) => {
            tracing::warn!(%error, "a continuation's source row did not read; it inherits no exactness");
            None
        }
    });
    let (pick, exactness) = match recorded {
        Some(recorded) => (recorded.pick, recorded.exactness),
        None => (pick.clone(), PlannedExactness::Inherited),
    };
    PlannedBinding {
        pick,
        locality: config.model_locality,
        exactness,
        source,
    }
}

/// Where `provider` routes `pick`, a planned child's model, exactly, when
/// the child's frozen definition lists it too (FIX 2310, Engine C1/C2). A
/// provider that lists no model routes none: the child runs as today. The
/// first entry's one fresh decision; no later entry asks it.
fn exact_route(
    vault: &Vault,
    provider: &dyn McpCodeModeProvider,
    definition: &AgentDefinition,
    pick: &ModelId,
) -> Option<ModelLocality> {
    provider
        .planned_route(vault, pick)
        .filter(|_| ensure_listed(definition, pick).is_ok())
}
