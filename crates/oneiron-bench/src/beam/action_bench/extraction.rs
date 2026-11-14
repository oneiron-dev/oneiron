//! The extraction arms (ARCH-0042 #action-bench: "online-only,
//! background-only, combined; each probed right after a correction and again
//! after consolidation"). RULING L9-34-EXTRACT-ARMS = A (Engine 14 Nov 12:22)
//! maps them onto the engine's Dreamer lanes:
//! - online is the Micro lane, run after each turn (the turn producer's
//!   wake, `Vault::wake_dreamer_on_turn`);
//! - background is the Meso lane at each sitting's end
//!   (`Vault::end_session_with_wake` plans the sitting's turns) plus the
//!   timer Macro lane at the freeze;
//! - combined is all three, the shipped schedule.
//!
//! That is LightMem's split of an online update and a sleep-time update
//! ([`EXTRACTION_ARMS_MAPPING`], which the report carries).
//!
//! Each history gets one fresh vault per extraction arm, started as a
//! self-hosted server starts (keystore, root, install profile, the engine's
//! machine writers). Only the raw turns go in, replayed in time order with
//! the user's deletes; the history's authored claims never enter it, so
//! every claim an extraction arm reads is one its Dreamer extracted. The
//! extractor is the engine's `ConsolidationExecutor` over the run's pinned
//! extraction model, reached through the same host transport as the reader.
//!
//! RULING L9-34-EXTRACT-LOCALITY = A: each vault's purpose table admits the
//! pin's locality through the host's own setter, and the report names it.
//! That is allowed only because the vault holds the bench's synthetic
//! history: the bench opens it only on a fresh, empty temp dir and refuses
//! any other. RULING L9-34-EXTRACT-PENDED = A: no owner act is simulated; a
//! pended correction stays pended, and each probe counts landed and pended
//! claims.

mod executor;

use std::{collections::BTreeMap, path::Path, sync::Arc, time::Instant};

use oneiron::authority::{HOST_ISSUER_SEED_BYTES, HostSlipIssuer, MachineRole};
use oneiron::dreamer_runner::DreamerAttemptPayload;
use oneiron::dreamer_wake::{WakeTurnSubject, request_wake};
use oneiron::serialize::msgpack_value_from_json;
use oneiron::session_lifecycle::{SessionClosePredicate, SessionKey, SessionMintOutcome};
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, CallPurpose, ConsolidationDecisions,
    DREAMER_CONSOLIDATION_MACRO_ATTEMPT_KIND, DreamerConsolidationScope, DreamerRunnerStore,
    DreamerWakeDriver, EdgeActorClass, EntityId, ModelId, ModelLocality, RunWakePass, Vault,
    VaultConfig, WakeCancellation, WakePassDeadline, WakePassReport, WakePassStop, WakeTrigger,
};
use oneiron_keystore::MemoryKeystore;
use serde::{Deserialize, Serialize};

use super::super::{
    BeamResult,
    llm_host::{HostConfig, ServedModel, served_backend},
    model_usage::{PriceTable, sum_costs},
    report_model::CostComponentReport,
};
use super::arms::{MemoryArm, VaultView, create_worlds, delete_message, memory_failure, witness};
use super::tasks::{History, Turn};
use super::{elapsed_us, refusal};
use executor::{BenchExecutor, ExtractionCall, RecordingBackend};

/// What the report says each extraction arm stands for (RULING
/// L9-34-EXTRACT-ARMS = A: name the LightMem mapping in the report).
pub(super) const EXTRACTION_ARMS_MAPPING: &str = "extract_online = LightMem's online update: the Dreamer's Micro lane after each turn. \
     extract_background = LightMem's sleep-time update: the Meso lane at each sitting's end and the timer Macro lane at the freeze. \
     extract_combined = both, the shipped schedule.";
/// Two turns further apart than this sit in two sittings.
const SITTING_GAP_SECS: u64 = 1_800;
/// The units each admission of a wake pass reserves.
const PASS_RESERVE_UNITS: u64 = 100;
/// A pass's deadline: the engine's 180 s ceiling.
const PASS_DEADLINE_MS: u64 = 180_000;
/// The most passes one lane's drain runs before the report names it undrained.
const MAX_PASSES_PER_DRAIN: usize = 12;
/// The lease owner every pass names.
const LEASE_OWNER: &str = "oneiron-bench-action-bench";
/// The bench host's slip issuer seed domain: one fixed host per process.
const BENCH_HOST_ISSUER_DOMAIN: &[u8] = b"oneiron-bench/action-bench/host-issuer/v1\0";

/// The run's extraction model: one pin on the reader's host, at the
/// locality the bench sets each extraction vault's purpose table to.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ExtractionPin {
    pub(super) model_id: ModelId,
    pub(super) provider_model: String,
    pub(super) locality: ModelLocality,
    /// The budget units of each wake pass, on a ledger line of its own.
    pub(super) pass_budget_units: u64,
}

/// When an extraction arm reads the vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Probe {
    /// Right after the correcting turn's own step: its witness, and for an
    /// arm with the Micro lane, that lane drained. Corrected-source
    /// follow-ups only.
    AfterCorrection,
    /// At the freeze, every lane of the arm drained. Every follow-up.
    AfterConsolidation,
}

/// The Dreamer lanes an arm runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Lane {
    Micro,
    Meso,
    Macro,
}

impl Lane {
    fn scope(self) -> DreamerConsolidationScope {
        match self {
            Self::Micro => DreamerConsolidationScope::Micro,
            Self::Meso => DreamerConsolidationScope::Meso,
            Self::Macro => DreamerConsolidationScope::Macro,
        }
    }

    fn trigger(self) -> WakeTrigger {
        match self {
            Self::Micro => WakeTrigger::Event,
            Self::Meso => WakeTrigger::SessionEnd,
            Self::Macro => WakeTrigger::Timer,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Micro => "micro",
            Self::Meso => "meso",
            Self::Macro => "macro",
        }
    }
}

/// Which lanes an extraction arm runs (RULING L9-34-EXTRACT-ARMS = A).
fn lanes(arm: MemoryArm) -> &'static [Lane] {
    match arm {
        MemoryArm::ExtractOnline => &[Lane::Micro],
        MemoryArm::ExtractBackground => &[Lane::Meso, Lane::Macro],
        MemoryArm::ExtractCombined => &[Lane::Micro, Lane::Meso, Lane::Macro],
        _ => &[],
    }
}

/// The run's extraction host: the pinned model's backend and the runtime
/// its wake passes run on.
pub(super) struct ExtractionHost {
    backend: RecordingBackend,
    runtime: tokio::runtime::Runtime,
    pin: ExtractionPin,
}

impl ExtractionHost {
    pub(super) fn connect(host: &HostConfig, pin: &ExtractionPin) -> BeamResult<Self> {
        if pin.pass_budget_units <= PASS_RESERVE_UNITS {
            return Err(refusal(
                "extraction.pass_budget_units must exceed one admission's reserve of 100",
            ));
        }
        let inner = served_backend(
            host,
            &[ServedModel {
                model_id: pin.model_id.clone(),
                provider_model: pin.provider_model.clone(),
                max_output_tokens: None,
                locality: pin.locality,
            }],
        )?;
        Ok(Self {
            backend: RecordingBackend::new(inner),
            runtime: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?,
            pin: pin.clone(),
        })
    }

    pub(super) fn model(&self) -> &ModelId {
        &self.pin.model_id
    }

    pub(super) fn locality(&self) -> ModelLocality {
        self.pin.locality
    }
}

/// One lane's work in one extraction vault, summed over its drains.
#[derive(Debug, Clone, Default, Serialize)]
pub(super) struct LaneTally {
    passes: u32,
    attempts_admitted: u32,
    attempts_completed: u32,
    attempts_failed: u32,
    attempts_deferred: u32,
    attempts_parked: u32,
    /// Attempts this host lends no model or writer for, answered as a host
    /// that lends none answers them.
    attempts_unlent: u32,
    model_calls: usize,
    /// Claims landed with `Auto` approval.
    claims_landed: usize,
    /// Claims kept as Proposed: every destructive replacement among them.
    claims_pended: usize,
    claims_held: usize,
    claims_rejected: usize,
    /// Each drain that stopped on anything but an empty queue, and why.
    stops: Vec<String>,
}

impl LaneTally {
    fn add(&mut self, report: &WakePassReport) {
        self.passes += 1;
        self.attempts_admitted += report.admitted;
        self.attempts_completed += report.completed;
        self.attempts_failed += report.failed;
        self.attempts_deferred += report.deferred;
        self.attempts_parked += report.parked;
    }
}

/// One lane's tally in a report row.
#[derive(Debug, Serialize)]
pub(super) struct LaneRow {
    lane: Lane,
    #[serde(flatten)]
    tally: LaneTally,
}

/// What an extraction vault held by a probe, over every lane.
#[derive(Debug, Clone, Serialize)]
pub(super) struct ProbeTally {
    probe: Probe,
    model_calls: usize,
    claims_landed: usize,
    claims_pended: usize,
    claims_rejected: usize,
    attempts_parked: u32,
}

impl ProbeTally {
    fn of(probe: Probe, lanes: &BTreeMap<Lane, LaneTally>) -> Self {
        Self {
            probe,
            model_calls: lanes.values().map(|tally| tally.model_calls).sum(),
            claims_landed: lanes.values().map(|tally| tally.claims_landed).sum(),
            claims_pended: lanes.values().map(|tally| tally.claims_pended).sum(),
            claims_rejected: lanes.values().map(|tally| tally.claims_rejected).sum(),
            attempts_parked: lanes.values().map(|tally| tally.attempts_parked).sum(),
        }
    }
}

/// One history under one extraction arm: what went in, what each lane did,
/// what each probe saw, and the extraction stage's cost.
#[derive(Debug, Serialize)]
pub(super) struct ExtractionRow {
    history: String,
    arm: MemoryArm,
    locality: ModelLocality,
    sittings: usize,
    turns_witnessed: usize,
    items_deleted: usize,
    probes: Vec<ProbeTally>,
    lanes: Vec<LaneRow>,
    /// Stage: extraction, as the provider counted each call.
    extraction: CostComponentReport,
    /// Model calls that failed, with no usage to price.
    failed_calls: usize,
    /// Wall time of the replay and its passes, probes excluded.
    replay_elapsed_us: u64,
}

/// One step of a history's replay into an extraction vault.
#[derive(Debug, Clone, Copy)]
enum Step {
    Turn(usize),
    DeleteTurn(usize),
    EndSitting,
}

/// The history's replay, in time order: each turn before the freeze, each
/// delete, and each sitting's end after its last turn. A sitting ends where
/// the next turn comes more than [`SITTING_GAP_SECS`] later. At one time a
/// turn comes before a delete, and a delete before a sitting's end.
fn replay_steps(history: &History) -> (Vec<(u64, Step)>, usize) {
    let mut held: Vec<(usize, &Turn)> = history
        .turns
        .iter()
        .enumerate()
        .filter(|(_, turn)| turn.at < history.frozen_at)
        .collect();
    held.sort_by_key(|(_, turn)| turn.at);
    let mut ranked: Vec<(u64, u8, Step)> = Vec::new();
    let mut sittings = 0;
    let mut last: Option<u64> = None;
    for &(index, turn) in &held {
        match last {
            Some(previous) if turn.at.saturating_sub(previous) > SITTING_GAP_SECS => {
                ranked.push((previous, 2, Step::EndSitting));
                sittings += 1;
            }
            Some(_) => {}
            None => sittings += 1,
        }
        ranked.push((turn.at, 0, Step::Turn(index)));
        if let Some(at) = turn.deleted_at {
            ranked.push((at, 1, Step::DeleteTurn(index)));
        }
        last = Some(turn.at);
    }
    if let Some(previous) = last {
        ranked.push((previous, 2, Step::EndSitting));
    }
    ranked.sort_by_key(|&(at, rank, _)| (at, rank));
    let steps = ranked.into_iter().map(|(at, _, step)| (at, step)).collect();
    (steps, sittings)
}

/// One history's vault for one extraction arm: fresh, host-started, holding
/// only the turns replayed so far.
pub(super) struct ExtractionVault<'h> {
    // Field order is drop order: the vault closes before its folder goes.
    vault: Vault,
    owner: EntityId,
    worlds: BTreeMap<String, EntityId>,
    _dir: tempfile::TempDir,
    history: &'h History,
    arm: MemoryArm,
    /// The history's one conversation: the first witness mints it.
    conversation: EntityId,
    /// The owner's sitting on this install, for an arm with the Meso lane:
    /// a sitting's end is that lane's trigger. The online arm opens none.
    sitting_key: Option<SessionKey>,
    sitting: Option<EntityId>,
    /// Each witnessed turn's message id, by the turn's place in the history.
    messages: Vec<Option<EntityId>>,
    steps: Vec<(u64, Step)>,
    next_step: usize,
    sittings: usize,
    turns_witnessed: usize,
    items_deleted: usize,
    lanes: BTreeMap<Lane, LaneTally>,
    passes: u32,
    probes: Vec<ProbeTally>,
    /// The host's first call index that belongs to this vault.
    first_call: usize,
    replay_elapsed_us: u64,
}

impl<'h> ExtractionVault<'h> {
    pub(super) fn open(
        history: &'h History,
        arm: MemoryArm,
        host: &ExtractionHost,
    ) -> BeamResult<Self> {
        let started = Instant::now();
        let dir = tempfile::tempdir()?;
        refuse_unless_fresh(dir.path())?;
        let vault = Vault::open_owned(dir.path(), VaultConfig::device())?;
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        vault.prepare_install_signing()?;
        let owner = vault
            .ensure_embedded_owner_actor()
            .map_err(|error| memory_failure(&history.id, &error.to_string()))?;
        start_host(&vault, host.pin.locality)?;
        let worlds = create_worlds(&vault, owner, &history.worlds)
            .map_err(|reason| memory_failure(&history.id, &reason))?;
        let sitting_key = if lanes(arm).contains(&Lane::Meso) {
            Some(vault.local_session_key(owner)?)
        } else {
            None
        };
        let (steps, sittings) = replay_steps(history);
        Ok(Self {
            vault,
            owner,
            worlds,
            _dir: dir,
            history,
            arm,
            conversation: EntityId::now(),
            sitting_key,
            sitting: None,
            messages: vec![None; history.turns.len()],
            steps,
            next_step: 0,
            sittings,
            turns_witnessed: 0,
            items_deleted: 0,
            lanes: BTreeMap::new(),
            passes: 0,
            probes: Vec::new(),
            first_call: host.backend.call_count(),
            replay_elapsed_us: elapsed_us(started),
        })
    }

    pub(super) fn view(&self) -> VaultView<'_> {
        VaultView {
            vault: &self.vault,
            owner: self.owner,
            worlds: &self.worlds,
        }
    }

    /// Replays through the correcting turn's step: every step before it in
    /// time, and every turn said at its time. A sitting that ends with it
    /// stays open, as it is when the turn has just been said.
    pub(super) fn replay_through_correction(
        &mut self,
        correction_at: u64,
        host: &ExtractionHost,
    ) -> BeamResult<()> {
        let started = Instant::now();
        while let Some(&(at, step)) = self.steps.get(self.next_step) {
            let due = at < correction_at || (at == correction_at && matches!(step, Step::Turn(_)));
            if !due {
                break;
            }
            self.next_step += 1;
            self.apply(step, host)?;
        }
        self.probes
            .push(ProbeTally::of(Probe::AfterCorrection, &self.lanes));
        self.replay_elapsed_us += elapsed_us(started);
        Ok(())
    }

    /// Replays the rest of the history, then drains every lane of the arm
    /// at the freeze: the timer Macro lane runs here.
    pub(super) fn replay_to_freeze(&mut self, host: &ExtractionHost) -> BeamResult<()> {
        let started = Instant::now();
        while let Some(&(_, step)) = self.steps.get(self.next_step) {
            self.next_step += 1;
            self.apply(step, host)?;
        }
        for &lane in lanes(self.arm) {
            self.drain(lane, host)?;
        }
        self.probes
            .push(ProbeTally::of(Probe::AfterConsolidation, &self.lanes));
        self.replay_elapsed_us += elapsed_us(started);
        Ok(())
    }

    fn apply(&mut self, step: Step, host: &ExtractionHost) -> BeamResult<()> {
        let history = self.history;
        match step {
            Step::Turn(index) => {
                let Some(turn) = history.turns.get(index) else {
                    return Err(memory_failure(&history.id, "a replayed turn is missing"));
                };
                self.witness_turn(index, turn)?;
                if lanes(self.arm).contains(&Lane::Micro) {
                    self.drain(Lane::Micro, host)?;
                }
            }
            Step::DeleteTurn(index) => {
                let Some(Some(message)) = self.messages.get(index).copied() else {
                    return Err(memory_failure(
                        &history.id,
                        "a deleted turn was never witnessed",
                    ));
                };
                // As the memory arms' vault does: the user deletes what they
                // said, the turn's message, as its author, through the room
                // door.
                let stood = delete_message(&self.vault, self.conversation, message, self.owner)
                    .map_err(|reason| memory_failure(&history.id, &reason))?;
                if !stood {
                    return Err(memory_failure(
                        &history.id,
                        "a deleted turn's message did not stand",
                    ));
                }
                self.items_deleted += 1;
            }
            Step::EndSitting => {
                if let Some(session) = self.sitting.take() {
                    let wake = self.vault.plan_session_end_wake(&session)?;
                    self.vault.end_session_with_wake(
                        &session,
                        SessionClosePredicate::Explicit,
                        self.vault.now_recorded_at(),
                        &wake,
                    )?;
                    self.drain(Lane::Meso, host)?;
                }
            }
        }
        Ok(())
    }

    /// Witnesses one turn as the owner, in the open sitting when the arm
    /// keeps sittings (minting one at a sitting's first turn).
    fn witness_turn(&mut self, index: usize, turn: &Turn) -> BeamResult<()> {
        if let Some(key) = self.sitting_key
            && self.sitting.is_none()
        {
            let session = match self.vault.mint_session(key, self.vault.now_recorded_at())? {
                SessionMintOutcome::Minted(session) | SessionMintOutcome::AlreadyOpen(session) => {
                    session
                }
            };
            self.sitting = Some(session);
        }
        let memory = self.vault.memory(self.owner, EdgeActorClass::Human);
        let memory = match self.sitting_key {
            Some(key) => memory.with_session(key),
            None => memory,
        };
        let message = witness(&memory, self.conversation, turn)
            .map_err(|reason| memory_failure(&self.history.id, &reason))?;
        if let Some(slot) = self.messages.get_mut(index) {
            *slot = Some(message);
        }
        self.turns_witnessed += 1;
        Ok(())
    }

    /// Runs one lane's passes until its queue is empty: the Micro lane
    /// after the turn producer's wake, the Macro lane after a timer wake,
    /// the Meso lane over what a sitting's end queued.
    fn drain(&mut self, lane: Lane, host: &ExtractionHost) -> BeamResult<()> {
        let calls_before = host.backend.call_count();
        let mut tally = self.lanes.remove(&lane).unwrap_or_default();
        let drained = self.drain_into(lane, host, &mut tally);
        tally.model_calls += host.backend.call_count().saturating_sub(calls_before);
        self.lanes.insert(lane, tally);
        drained
    }

    fn drain_into(
        &mut self,
        lane: Lane,
        host: &ExtractionHost,
        tally: &mut LaneTally,
    ) -> BeamResult<()> {
        let now = self.vault.now_recorded_at();
        let node = {
            let store = DreamerRunnerStore::new(&self.vault);
            let home = store.local_home_node_candidate(true, true, true)?;
            let node = home.node_id;
            if store.elect_home_node(&[home], now)?.is_none() {
                tally.stops.push("no home node".to_owned());
                return Ok(());
            }
            match lane {
                Lane::Micro => {
                    self.vault
                        .wake_dreamer_on_turn(WakeTurnSubject::Vault, now)?;
                }
                Lane::Macro => {
                    let run = format!("{LEASE_OWNER}-timer-{}", self.passes);
                    request_wake(
                        &store,
                        WakeTrigger::Timer,
                        DreamerConsolidationScope::Macro,
                        DreamerAttemptPayload {
                            attempt_type: DREAMER_CONSOLIDATION_MACRO_ATTEMPT_KIND.to_owned(),
                            input: msgpack_value_from_json(&serde_json::Value::Null)?,
                            parent_attempt: None,
                        },
                        Some(run.clone()),
                        Some(run),
                        now,
                    )?;
                }
                Lane::Meso => {}
            }
            node
        };
        for _ in 0..MAX_PASSES_PER_DRAIN {
            let report = self.pass(lane, node, host, tally)?;
            match report.stop {
                WakePassStop::QueueEmpty => return Ok(()),
                WakePassStop::BudgetExhausted
                | WakePassStop::BacklogLeft
                | WakePassStop::DeadlineHardCut => {}
                other => {
                    tally.stops.push(format!("{other:?}"));
                    return Ok(());
                }
            }
        }
        tally.stops.push("undrained".to_owned());
        Ok(())
    }

    /// One wake pass of `lane`, its budget on a ledger line of its own.
    fn pass(
        &mut self,
        lane: Lane,
        node: u64,
        host: &ExtractionHost,
        tally: &mut LaneTally,
    ) -> BeamResult<WakePassReport> {
        self.passes += 1;
        let run_id = format!("{LEASE_OWNER}-{}-{}", lane.name(), self.passes);
        let units = host.pin.pass_budget_units;
        let guard = BudgetGuard::with_reserve_units(
            run_id.clone(),
            units,
            PASS_RESERVE_UNITS,
            BudgetExhaustionPolicy::Suspend,
        );
        let mut driver = DreamerWakeDriver::new(
            &self.vault,
            run_id.clone(),
            WakePassDeadline::new(PASS_DEADLINE_MS),
        )
        .with_budget_guard(guard.clone());
        let mut executor = BenchExecutor {
            vault: &self.vault,
            backend: &host.backend,
            guard: &guard,
            actor: self.vault.dreamer_authority()?,
            model: host.pin.model_id.clone(),
            locality: host.pin.locality,
            decisions: ConsolidationDecisions::shipped()?,
            run_id,
            tally: &mut *tally,
        };
        let input = RunWakePass {
            trigger: lane.trigger(),
            scope: lane.scope(),
            local_node_id: node,
            lease_owner: LEASE_OWNER.to_owned(),
            budget_total_units: units,
            reserve_units: PASS_RESERVE_UNITS,
            now: self.vault.now_recorded_at(),
            host_scope: None,
            destination_bound: None,
        };
        let cancel = WakeCancellation::new();
        let report = host
            .runtime
            .block_on(driver.run_wake_pass(input, &mut executor, &cancel))?;
        tally.add(&report);
        Ok(report)
    }

    /// The vault's report row: its lanes, its probes and the cost of every
    /// extraction call made for it.
    pub(super) fn row(
        &self,
        host: &ExtractionHost,
        prices: &PriceTable,
    ) -> BeamResult<ExtractionRow> {
        let calls: Vec<ExtractionCall> = host
            .backend
            .calls()
            .into_iter()
            .skip(self.first_call)
            .collect();
        let costs = calls
            .iter()
            .filter_map(|call| {
                call.usage
                    .as_ref()
                    .map(|usage| prices.cost(&host.pin.model_id, usage, call.elapsed_us))
            })
            .collect::<BeamResult<Vec<_>>>()?;
        Ok(ExtractionRow {
            history: self.history.id.clone(),
            arm: self.arm,
            locality: host.pin.locality,
            sittings: self.sittings,
            turns_witnessed: self.turns_witnessed,
            items_deleted: self.items_deleted,
            probes: self.probes.clone(),
            lanes: self
                .lanes
                .iter()
                .map(|(&lane, tally)| LaneRow {
                    lane,
                    tally: tally.clone(),
                })
                .collect(),
            extraction: sum_costs(&costs)?,
            failed_calls: calls.iter().filter(|call| call.usage.is_none()).count(),
            replay_elapsed_us: self.replay_elapsed_us,
        })
    }
}

/// The bench sets a purpose table only on a vault holding its own synthetic
/// seed (RULING L9-34-EXTRACT-LOCALITY = A), so it opens only an empty folder
/// it just made, never a path a plan names.
fn refuse_unless_fresh(dir: &Path) -> BeamResult<()> {
    if std::fs::read_dir(dir)?.next().is_some() {
        return Err(refusal(
            "an extraction vault opens only on a fresh, empty temp dir: the bench widens its purpose table for a synthetic history alone",
        ));
    }
    Ok(())
}

/// Starts the vault as a self-hosted server's start does (roots it, profiles
/// this install, enrols the engine's machine writers, without which the
/// Dreamer's writes are refused), then admits the pin's locality for
/// extraction through the host's own purpose-table setter.
fn start_host(vault: &Vault, locality: ModelLocality) -> BeamResult<()> {
    let seed: [u8; HOST_ISSUER_SEED_BYTES] = *blake3::hash(BENCH_HOST_ISSUER_DOMAIN).as_bytes();
    let issuer = HostSlipIssuer::from_seed(&seed)?;
    vault.ensure_host_root_slip(&issuer)?;
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    vault.provision_engine_machine_identities(&issuer)?;
    let mut table = vault.purpose_default_table()?;
    table.extraction_max_locality = locality;
    let Some(row) = table.purposes.get_mut(&CallPurpose::Extraction) else {
        return Err(refusal("the vault's purpose table has no extraction row"));
    };
    row.locality = locality;
    vault.set_purpose_default_table(&table)?;
    Ok(())
}
