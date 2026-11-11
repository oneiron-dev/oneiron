//! The host doors of the engine-control knob verbs (untangle 6.6d; owner
//! 9 Nov 22:47, every substrate control is a public verb behind a grant):
//! the vault owner under its proof, or a person or agent on a verified slip
//! of its own, as a holder of `engine.controls`, which the knob's writer
//! checks in the write. `host_doors` re-exports them, so the generated HTTP
//! facade handler and the MCP dispatcher call them by the name every host
//! door has.
//!
//! Each lists no row (`host_door_lists`): the knobs and their receipts live
//! in side tables, which hold none.
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::EngineControlActor;
use oneiron::memory::{MemoryError, MemoryResult};
use oneiron::settings::snapshot_read::SnapshotReadSettings;
use oneiron::task_verb::sdk::{
    self, ConsolidationSelectionTimingSetRequest, ConsolidationStrengthSetRequest,
    CuratorCadenceSetRequest, DreamerProjectorSetRequest, EngineControlChangeEntry,
    FreeTimeScheduleSetRequest, ProactivityPeriodSetRequest, RetuneThresholdsSetRequest,
    SieveBudgetsLowerRequest, StewardshipRulePeriodSetRequest,
};

use super::FacadeApiError;
use super::host_doors::support::{Listed, internal};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// Who may call a knob verb: the owner under its proof (`Some`), or a
/// person or agent on its own verified slip (`None`), whose
/// `engine.controls` grant the knob's writer checks. Anyone else keeps the
/// owner refusal. The same admission as a substrate read (6.6c).
pub(super) fn engine_controller(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> MemoryResult<Option<AuthenticatedOwner>> {
    super::substrate_read_doors::substrate_reader(server, auth, verb)
}

/// The caller of a knob verb, resolved before the write.
enum Controller {
    Owner(AuthenticatedOwner),
    Holder(EntityId),
}

/// `act` off the runtime, as the owner or the holder the request binds:
/// every knob door writes LMDB.
async fn as_controller<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&SyncServer, EngineControlActor<'_>) -> oneiron::Result<T> + Send + 'static,
) -> MemoryResult<T> {
    let controller = match engine_controller(server, auth, verb)? {
        Some(owner) => Controller::Owner(owner),
        None => Controller::Holder(
            super::facade_actor(server, auth)
                .map_err(FacadeApiError::into_memory_error)?
                .0,
        ),
    };
    let server = Arc::clone(server);
    super::clock_ingress::run_blocking(move || {
        let actor = match &controller {
            Controller::Owner(owner) => EngineControlActor::Owner(owner),
            Controller::Holder(holder) => EngineControlActor::Holder(*holder),
        };
        act(&server, actor).map_err(MemoryError::from)
    })
    .await
    .map_err(|_| internal(verb))?
}

/// `vault.consolidation.selection_timing.set`.
pub(crate) async fn vault_consolidation_selection_timing_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ConsolidationSelectionTimingSetRequest,
) -> Listed<EngineControlChangeEntry> {
    let answer = as_controller(
        server,
        auth,
        "vault.consolidation.selection_timing.set",
        move |server, actor| {
            sdk::set_consolidation_selection_timing_as(server.vault(), actor, input)
        },
    )
    .await;
    (answer, Vec::new())
}

/// `vault.consolidation.strength.set`.
pub(crate) async fn vault_consolidation_strength_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ConsolidationStrengthSetRequest,
) -> Listed<EngineControlChangeEntry> {
    let answer = as_controller(
        server,
        auth,
        "vault.consolidation.strength.set",
        move |server, actor| sdk::set_consolidation_strength_as(server.vault(), actor, input),
    )
    .await;
    (answer, Vec::new())
}

/// `vault.curator.cadence.set`.
pub(crate) async fn vault_curator_cadence_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CuratorCadenceSetRequest,
) -> Listed<EngineControlChangeEntry> {
    let answer = as_controller(
        server,
        auth,
        "vault.curator.cadence.set",
        move |server, actor| sdk::set_curator_cadence_as(server.vault(), actor, input),
    )
    .await;
    (answer, Vec::new())
}

/// `vault.proactivity.period.set`.
pub(crate) async fn vault_proactivity_period_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ProactivityPeriodSetRequest,
) -> Listed<EngineControlChangeEntry> {
    let answer = as_controller(
        server,
        auth,
        "vault.proactivity.period.set",
        move |server, actor| sdk::set_proactivity_period_as(server.vault(), actor, input),
    )
    .await;
    (answer, Vec::new())
}

/// `vault.evaluation.retune_thresholds.set`.
pub(crate) async fn vault_evaluation_retune_thresholds_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: RetuneThresholdsSetRequest,
) -> Listed<EngineControlChangeEntry> {
    let answer = as_controller(
        server,
        auth,
        "vault.evaluation.retune_thresholds.set",
        move |server, actor| sdk::set_retune_thresholds_as(server.vault(), actor, input),
    )
    .await;
    (answer, Vec::new())
}

/// `vault.stewardship.rules.period.set`.
pub(crate) async fn vault_stewardship_rules_period_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: StewardshipRulePeriodSetRequest,
) -> Listed<EngineControlChangeEntry> {
    let answer = as_controller(
        server,
        auth,
        "vault.stewardship.rules.period.set",
        move |server, actor| sdk::set_stewardship_rule_period_as(server.vault(), actor, input),
    )
    .await;
    (answer, Vec::new())
}

/// `vault.dreamer.projector.set`.
pub(crate) async fn vault_dreamer_projector_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: DreamerProjectorSetRequest,
) -> Listed<EngineControlChangeEntry> {
    let answer = as_controller(
        server,
        auth,
        "vault.dreamer.projector.set",
        move |server, actor| sdk::set_dreamer_projector_as(server.vault(), actor, input),
    )
    .await;
    (answer, Vec::new())
}

/// `vault.sieve.budgets.lower`.
pub(crate) async fn vault_sieve_budgets_lower(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SieveBudgetsLowerRequest,
) -> Listed<EngineControlChangeEntry> {
    let answer = as_controller(
        server,
        auth,
        "vault.sieve.budgets.lower",
        move |server, actor| sdk::lower_sieve_budgets_as(server.vault(), actor, input),
    )
    .await;
    (answer, Vec::new())
}

/// `vault.settings.snapshot_read.lower`.
pub(crate) async fn vault_settings_snapshot_read_lower(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SnapshotReadSettings,
) -> Listed<EngineControlChangeEntry> {
    let answer = as_controller(
        server,
        auth,
        "vault.settings.snapshot_read.lower",
        move |server, actor| sdk::lower_snapshot_read_bounds_as(server.vault(), actor, input),
    )
    .await;
    (answer, Vec::new())
}

/// `vault.free_time.schedule.set`.
pub(crate) async fn vault_free_time_schedule_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: FreeTimeScheduleSetRequest,
) -> Listed<EngineControlChangeEntry> {
    let answer = as_controller(
        server,
        auth,
        "vault.free_time.schedule.set",
        move |server, actor| sdk::set_free_time_schedule_as(server.vault(), actor, input),
    )
    .await;
    (answer, Vec::new())
}
