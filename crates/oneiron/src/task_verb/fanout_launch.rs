//! Durable fan-out launches: a wave cut held for the owner's launch approval
//! under the vault's approval mode, and the width check of a fan-out that
//! went out with no hold (OF-393).
//!
//! A gated wave apply freezes its whole cut and creator before anything is
//! minted. The approval mode then gates it at any width, through the same
//! controller and policy a consult fan-out reads: `manual` holds it, `auto`
//! launches it on the learned decider's allow and otherwise holds it for the
//! escalated role, `full-access` launches it. The threshold only marks the
//! exceptional-width check: it rides a held launch's pause row, and on a
//! launch that went out it is a non-blocking question row. A held launch
//! waits for the owner; it has no expiry. A held ask on a project's TASK
//! also waits for that project's live lead and board (ARCH-0067: the first
//! answer lands); the project is bound at admission, its holders read again
//! at each ruling.
//!
//! The owner rules on a hold by the digest they saw, with no replacement
//! payload: an approval launches the frozen cut, records the ruling and any
//! remembered standing row, and re-leases and completes the parked planning
//! attempt, all in one transaction; a denial stays durable and visible. A
//! lead or board holder approves once or denies; only the owner remembers.
//! A width check is acknowledged, never denied, because nothing was held.
//!
//! Entry: `admit_wave_launch_in`.
//! Shared launch types stay here; hold/check/resume operations live in children.

use std::collections::BTreeMap;

use super::ask_effect::AskEffect;
use super::consult_fanout_admission::CachedAuto;
use super::consult_fanout_store::{append_human_ruling, encode, policy_in};
use super::create_origin::TaskCreateOrigin;
use super::create_validation::consult_refusal;
use super::task_actor::TaskActor;
use super::wave_port;
use super::{
    ConsultFanOutChoice, ConsultFanOutMode, ConsultFanOutPause, ConsultFanOutScope, TaskAskClass,
    TaskAskHandle, TaskAskHoldReason, TaskAskLaunchHold, TaskAskReceipt, TaskAskSpec,
};
use crate::Vault;
use crate::WriteActor;
use crate::agent_dispatch::{FanoutStatement, WidthCheckClass};
use crate::attempt_queue::{
    AttemptId, AttemptInterventionKind, AttemptQueue, AttemptRecord, AttemptResumePoint,
    ClaimAttempt, ClaimOutcome, CompleteAttempt, HoldAttemptForFanout, InterveneAttempt,
};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::edit_distance::escalation::{
    EscalationReceipt, EscalationRuling, EscalationTrigger, StandingPolicy,
    record_explicit_ruling_in_txn, standing_policy_for, standing_policy_for_in,
};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::fanout_auto::{
    FanoutAskContext, FanoutAskTrigger, FanoutDecisions, LearningFanoutAutoDecider,
};
use crate::gate::fanout_policy::ResolvedFanoutPolicy;
use crate::llm::decision::{AskAct, AskRole, AskTo, HolderKind, RoleHolder, RoleRank};
use crate::memory::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult,
    actor_is_vault_owner_in_txn, verify_actor_binding_in_txn,
};
use crate::outbound_chokepoint::{
    FanoutAdmission, FanoutApprovalChoice, FanoutApprovalError, FanoutApprovalRow,
    FanoutAutoDecider, FanoutAutoDisposition, FanoutEstimate, FanoutHistory, FanoutPlan,
    FanoutPlanEdge, FanoutSurfaceSink, FanoutWidthCheck, FanoutWidthClass,
    admit_fanout_with_history, answer_fanout_width_check, approve_and_resume_fanout,
    fanout_estimate, fanout_plan_digest, fanout_width_check_row,
};
use crate::receipt::ReceiptRecord;
use crate::side_table::{self, HexId, Named, SideTable};
use crate::wave_orchestration::{
    ValidatedWavePlan, WAVE_PLAN_SCHEMA_VERSION, WavePlan, WaveTaskWrite,
};
use serde::{Deserialize, Serialize};

mod ask_auto;
mod checks;
mod hold;
mod resume;
pub(super) use self::ask_auto::AskAutoGate;
use self::checks::settle_held_attempts_in;
pub(super) use self::checks::{AskCheck, WaveCheck, record_ask_check_in, record_wave_check_in};
pub(super) use self::hold::{
    AskHold, ReleasedAsk, ask_launch_needs_approval, held_ask_owner_in, held_ask_receipt_in,
    hold_ask_in, hold_planning_attempt_in, mark_launched_in,
};
use self::hold::{launch_role_is_held_in, require_holder_launch_choice};

/// One fan-out launch, keyed by its launch ref.
pub(super) const FANOUT_LAUNCHES: SideTable<HexId, StoredLaunch, Named> =
    SideTable::new(&side_table::TASK_FANOUT_LAUNCH);

/// Domain of a wave launch's ref: one launch per actor and plan_ref.
const LAUNCH_REF_DOMAIN: &[u8] = b"oneiron.tasks.fanout.launch.v1";

/// The plan target of a wave task with no assignee: the default realization.
const WAVE_DEFAULT_REALIZATION: &str = "tasks.realize";

/// The lease an approval re-leases a held planning attempt under, for the
/// instant it completes it.
const FANOUT_LAUNCH_LEASE_OWNER: &str = "engine:fanout_launch";

/// The gate ledger's content kind for a launch ruling.
const FANOUT_LAUNCH_CONTENT_KIND: &str = "task_fanout_launch";

/// One fan-out launch as it stands: held for the owner's ruling, denied and
/// parked, or launched. Every read returns the statement frozen before
/// anything launched; it is never re-priced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FanoutLaunchReceipt {
    pub launch_ref: EntityId,
    /// The frozen plan digest a ruling names.
    pub plan_digest: [u8; 32],
    pub statement: FanoutStatement,
    /// The durable hold while the launch waits; `None` once it launched.
    pub paused: Option<ConsultFanOutPause>,
    /// The width-check row of a launch that went out above the threshold:
    /// the owner acknowledges it.
    pub check_row_ref: Option<String>,
    pub choice_receipt_ref: Option<String>,
    /// The TASKs it launched; none while it is held.
    pub task_refs: Vec<EntityId>,
    /// The project whose live lead and board may rule on the hold beside the
    /// owner; `None` leaves it to the owner.
    pub approval_project: Option<EntityId>,
}

/// An answer to the width check of a fan-out that already went out. The
/// check held nothing, so there is no deny: ack records the ruling, and
/// ack-and-remember also persists the receipted standing row AUTO reads
/// next time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FanoutCheckChoice {
    Ack,
    AckAndRemember,
}

/// What one launch launches, frozen whole before anything is minted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum LaunchPayload {
    /// A wave cut, and the creator its planning attempt witnessed: never an
    /// origin read from the wire.
    Wave {
        cut: WavePlan,
        creator_origin: Option<TaskCreateOrigin>,
    },
    /// An ask the approval mode held (ASK-3): what it asked, the census
    /// it froze, and the effect its door composes, kept until the owner
    /// releases it. No member TASK, guest grant or group exists meanwhile.
    Ask {
        group_ref: EntityId,
        requested: TaskAskSpec,
        effective: TaskAskSpec,
        holders: Vec<EntityId>,
        context_class: Option<TaskAskClass>,
        question_digest: [u8; 32],
        request_digest: String,
        created_at: u64,
        effect: Option<AskEffect>,
    },
    /// An ask admitted at once; its record holds only the width check.
    AdmittedAsk {
        group_ref: EntityId,
        request_digest: String,
        question: String,
        recipients: Vec<EntityId>,
    },
}

impl LaunchPayload {
    fn wave(cut: &ValidatedWavePlan, origin: Option<&TaskCreateOrigin>) -> Self {
        Self::Wave {
            cut: WavePlan {
                schema_version: WAVE_PLAN_SCHEMA_VERSION,
                plan_ref: cut.plan_ref().to_owned(),
                epic_task_ref: cut.epic_task_ref(),
                tasks: cut.tasks().values().cloned().collect(),
            },
            creator_origin: origin.cloned(),
        }
    }

    const fn kind(&self) -> &'static str {
        match self {
            Self::Wave { .. } => "wave",
            Self::Ask { .. } | Self::AdmittedAsk { .. } => "ask",
        }
    }

    /// The counted plan this payload launches. Its plan_ref binds the hash
    /// of the WHOLE payload, so the frozen digest moves with any field, not
    /// only with peer counts. Edges run from the launch's root (the epic, the
    /// ask group), never from the actor, so a cut that assigns its own actor
    /// is no consult cycle.
    fn plan(
        &self,
        launch_ref: EntityId,
        actor: EntityId,
        mode: ConsultFanOutMode,
    ) -> Result<FanoutPlan> {
        let payload_hash = blake3::hash(&encode(self)?).to_hex().to_string();
        let (root, brief_ref, targets): (String, String, Vec<String>) = match self {
            Self::Wave { cut, .. } => (
                cut.epic_task_ref.to_hex(),
                cut.epic_task_ref.to_hex(),
                cut.tasks
                    .iter()
                    .map(|task| {
                        task.assignee_ref.map_or_else(
                            || WAVE_DEFAULT_REALIZATION.to_owned(),
                            |assignee| assignee.to_hex(),
                        )
                    })
                    .collect(),
            ),
            Self::Ask {
                group_ref,
                effective,
                holders,
                ..
            } => (
                group_ref.to_hex(),
                effective.what.reference.short_ref(),
                holders.iter().map(EntityId::to_hex).collect(),
            ),
            Self::AdmittedAsk {
                group_ref,
                question,
                recipients,
                ..
            } => (
                group_ref.to_hex(),
                question.clone(),
                recipients.iter().map(EntityId::to_hex).collect(),
            ),
        };
        let mut counts = BTreeMap::<String, u32>::new();
        for target in targets {
            let count = counts.entry(target).or_default();
            *count = count
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("fan-out launch per-target count"))?;
        }
        Ok(FanoutPlan {
            plan_ref: format!("{}:{payload_hash}", launch_ref.to_hex()),
            brief_ref,
            actor_ref: actor.to_hex(),
            mode,
            edges: counts
                .into_iter()
                .map(|(to_peer_ref, count)| FanoutPlanEdge {
                    from_peer_ref: root.clone(),
                    to_peer_ref,
                    count,
                })
                .collect(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct StoredLaunch {
    pub(super) launch_ref: EntityId,
    pub(super) actor: TaskActor,
    /// The actor's [`EdgeActorClass`] byte: the launch runs as this actor.
    actor_class: u8,
    /// The project whose live lead and board may rule on this launch beside
    /// the owner, bound at admission; `None` leaves it to the owner.
    approval_project: Option<EntityId>,
    pub(super) payload: LaunchPayload,
    pub(super) plan: FanoutPlan,
    estimate: FanoutEstimate,
    /// Stated before anything launched; every read returns this copy.
    pub(super) statement: FanoutStatement,
    policy_scope: ConsultFanOutScope,
    /// The standing-policy scope AUTO reads and a ruling records under.
    pub(super) scope: String,
    pause: Option<FanoutApprovalRow>,
    /// The non-blocking question row of a launch that went out above the
    /// threshold.
    check_row: Option<FanoutApprovalRow>,
    /// Planning attempts parked under the fan-out hold for this launch.
    pub(super) held_attempts: Vec<AttemptId>,
    pub(super) dispatched_at: Option<u64>,
    pub(super) task_refs: Vec<EntityId>,
    denied: bool,
    choice_receipt_ref: Option<String>,
    /// Shipped default rows the admission read in place of rows missing
    /// from the vault manifest.
    shipped_policy_rows: Vec<String>,
    /// The requester a held ask was admitted under (FIX 11691): the agent
    /// dispatches its release queues keep it, as the asker's own surface
    /// would have. `None` for a wave no credential caller applied (FIX 11811),
    /// and for an ask no credential caller made.
    requester: Option<crate::agent_dispatch::QueuedRequester>,
}

impl StoredLaunch {
    fn class(&self) -> MemoryResult<EdgeActorClass> {
        EdgeActorClass::try_from_u8(self.actor_class)
            .ok_or_else(|| Error::CorruptedIndex("fan-out launch actor class").into())
    }

    /// The actor the launch runs as; an erased one refuses (FIX 3520).
    fn launcher(&self) -> MemoryResult<EntityId> {
        self.actor.id().ok_or_else(|| {
            consult_refusal(
                MEMORY_CODE_INVALID_STATE,
                "the fan-out's launcher was erased",
                "Its launch stays as history; there is nothing left to rule on.",
            )
        })
    }

    fn pause_row_ref(&self) -> String {
        format!(
            "fanout_row:{}:{}",
            self.payload.kind(),
            self.launch_ref.to_hex()
        )
    }

    fn check_row_ref(&self) -> String {
        check_row_ref(self.payload.kind(), self.launch_ref)
    }

    pub(super) fn receipt(&self) -> FanoutLaunchReceipt {
        FanoutLaunchReceipt {
            launch_ref: self.launch_ref,
            plan_digest: self.estimate.plan_digest,
            statement: self.statement.clone(),
            paused: self
                .pause
                .as_ref()
                .filter(|_| self.dispatched_at.is_none())
                .map(|row| ConsultFanOutPause {
                    surface_ref: row.row_ref.clone(),
                    denied: self.denied,
                }),
            check_row_ref: self.check_row.as_ref().map(|row| row.row_ref.clone()),
            choice_receipt_ref: self.choice_receipt_ref.clone(),
            task_refs: self.task_refs.clone(),
            approval_project: self.approval_project,
        }
    }
}

fn check_row_ref(kind: &str, launch_ref: EntityId) -> String {
    format!("fanout_check_row:{kind}:{}", launch_ref.to_hex())
}

fn load_launch(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    launch_ref: EntityId,
) -> Result<Option<StoredLaunch>> {
    FANOUT_LAUNCHES.get(&vault.store, txn, &HexId(launch_ref))
}

fn save_launch(vault: &Vault, txn: &mut heed::RwTxn<'_>, launch: &StoredLaunch) -> Result<()> {
    FANOUT_LAUNCHES.put(&vault.store, txn, &HexId(launch.launch_ref), launch)
}

/// The ref of `actor`'s launch of the cut named `plan_ref`.
pub(super) fn wave_launch_ref(actor: EntityId, plan_ref: &str) -> Result<EntityId> {
    EntityId::derive(
        LAUNCH_REF_DOMAIN,
        &[b"wave", actor.as_bytes(), plan_ref.as_bytes()],
    )
}

fn wave_scope(actor: EntityId, epic: EntityId) -> String {
    format!("wave:{}:{}", actor.to_hex(), epic.to_hex())
}

/// The standing-policy scope and the durable width-check row ref of
/// `actor`'s ungated apply of `cut`.
pub(super) fn wave_check_keys(
    actor: EntityId,
    cut: &ValidatedWavePlan,
) -> Result<(String, String)> {
    Ok((
        wave_scope(actor, cut.epic_task_ref()),
        check_row_ref("wave", wave_launch_ref(actor, cut.plan_ref())?),
    ))
}

/// The standing-policy scope and the durable width-check row ref of
/// `actor`'s ask of `question` in the group `group_ref`. An ask's launch
/// is keyed by its group.
pub(super) fn ask_check_keys(
    actor: EntityId,
    group_ref: EntityId,
    question: &str,
) -> (String, String) {
    (
        format!("ask:{}:{question}", actor.to_hex()),
        check_row_ref("ask", group_ref),
    )
}

/// The consult-graph history a wave launch, and a held ask, is judged
/// against: none. A wave cut is a planned TASK graph, not a consult chain,
/// so neither a consult cycle nor a per-peer consult rate spike pauses it;
/// the approval mode alone does.
const fn wave_launch_history() -> FanoutHistory<'static> {
    FanoutHistory {
        edges: &[],
        peer_rates: &[],
    }
}

fn stale_digest() -> MemoryError {
    consult_refusal(
        MEMORY_CODE_INVALID_STATE,
        "fan-out launch digest does not match the frozen plan",
        "Read the surfaced digest and rule on that exact plan.",
    )
}

fn reused_cut() -> MemoryError {
    MemoryError::bad_request("wave plan_ref reused for a different cut")
}

fn approval_error(error: FanoutApprovalError) -> MemoryError {
    match error {
        FanoutApprovalError::StalePlanDigest => stale_digest(),
        FanoutApprovalError::Engine(error) => error.into(),
    }
}

/// The transaction-owned sink of one launch: rows land on the launch
/// record, named by the launch ref; rulings land on the gate ledger.
struct LaunchSurface<'a, 'env> {
    vault: &'a Vault,
    txn: &'a mut heed::RwTxn<'env>,
    launch: &'a mut StoredLaunch,
    /// The accepted standing policy row an AUTO clearance stood on, if any.
    clearance: Option<String>,
}

impl FanoutSurfaceSink for LaunchSurface<'_, '_> {
    fn persist_pause_row(&mut self, row: &FanoutApprovalRow) -> Result<String> {
        let mut row = row.clone();
        row.row_ref = self.launch.pause_row_ref();
        let row_ref = row.row_ref.clone();
        self.launch.pause = Some(row);
        save_launch(self.vault, self.txn, self.launch)?;
        Ok(row_ref)
    }

    fn persist_width_check(&mut self, check: &FanoutWidthCheck) -> Result<Option<String>> {
        let (classification, row) = match &check.class {
            FanoutWidthClass::AutoClear => (
                WidthCheckClass::AutoClear {
                    policy_ref: self.clearance.clone(),
                },
                None,
            ),
            FanoutWidthClass::Asked { row } => (
                WidthCheckClass::Asked {
                    row_ref: self.launch.check_row_ref(),
                },
                Some(row),
            ),
        };
        self.launch
            .statement
            .raise_width_check(u64::from(check.threshold), classification);
        let surface_ref = row.map(|row| {
            let mut row = (**row).clone();
            row.row_ref = self.launch.check_row_ref();
            row.statement = Some(self.launch.statement.clone());
            let row_ref = row.row_ref.clone();
            self.launch.check_row = Some(row);
            row_ref
        });
        save_launch(self.vault, self.txn, self.launch)?;
        Ok(surface_ref)
    }

    fn persist_choice_receipt(&mut self, receipt: &ReceiptRecord) -> Result<String> {
        let receipt_ref = append_human_ruling(
            self.vault,
            self.txn,
            receipt,
            FANOUT_LAUNCH_CONTENT_KIND,
            self.launch.launch_ref.to_hex(),
            self.launch.estimate.plan_digest,
        )?;
        self.launch.choice_receipt_ref = Some(receipt_ref.clone());
        Ok(receipt_ref)
    }
}

/// A gated wave apply's policy snapshot and AUTO answer, both taken outside
/// the writer: decision IO never holds it. The writer rechecks the snapshot
/// before admitting the launch.
#[derive(Debug, Clone)]
pub(super) struct WaveLaunchGate {
    governed: ResolvedFanoutPolicy,
    standing: Option<StandingPolicy>,
    disposition: FanoutAutoDisposition,
    clearance: Option<String>,
}

impl WaveLaunchGate {
    /// Snapshots the vault's fan-out policy and, under `auto`, asks the
    /// host's learned decider about `actor`'s launch of `cut`. Absent
    /// decisions, an abstaining ladder and a failing decider all hold the
    /// launch for the escalated role. A launch already recorded is ruled
    /// on, so it asks no one again.
    pub(super) fn decide(
        vault: &Vault,
        actor: EntityId,
        cut: &ValidatedWavePlan,
        origin: Option<&TaskCreateOrigin>,
        decisions: Option<&FanoutDecisions<'_>>,
    ) -> MemoryResult<Self> {
        let launch_ref = wave_launch_ref(actor, cut.plan_ref())?;
        let (governed, recorded) = {
            let txn = vault.store.env.read_txn().map_err(Error::from)?;
            (
                policy_in(vault, &txn, &ConsultFanOutScope::default())?,
                load_launch(vault, &txn, launch_ref)?.is_some(),
            )
        };
        let scope = wave_scope(actor, cut.epic_task_ref());
        let standing = standing_policy_for(vault, &scope, EscalationTrigger::Budget)?;
        let disposition = if !recorded && governed.policy.mode == ConsultFanOutMode::Auto {
            let plan =
                LaunchPayload::wave(cut, origin).plan(launch_ref, actor, governed.policy.mode)?;
            let estimate = fanout_estimate(&plan)?;
            LearningFanoutAutoDecider::new(
                vault,
                FanoutAskContext {
                    task_ref: cut.epic_task_ref(),
                    scope: scope.clone(),
                    trigger: FanoutAskTrigger::Budget {
                        magnitude: u64::from(estimate.total_count),
                    },
                    question: cut.plan_ref().to_owned(),
                },
                decisions,
            )?
            .decide(&plan, &estimate)
            .unwrap_or(FanoutAutoDisposition::SurfaceHuman)
        } else {
            FanoutAutoDisposition::SurfaceHuman
        };
        // An accepted standing row answers alone when it exists, so an Allow
        // beside one stood on it.
        let clearance = standing
            .as_ref()
            .filter(|_| disposition == FanoutAutoDisposition::Allow)
            .map(|row| row.row_ref.to_hex());
        Ok(Self {
            governed,
            standing,
            disposition,
            clearance,
        })
    }
}

/// One gated wave apply's launch, as the port's writer hands it over.
pub(super) struct WaveLaunchInput<'a> {
    pub(super) actor: EntityId,
    pub(super) actor_class: EdgeActorClass,
    pub(super) cut: &'a ValidatedWavePlan,
    pub(super) origin: Option<&'a TaskCreateOrigin>,
    /// The cut's statement, read in the writer; the controller classifies
    /// its width check.
    pub(super) statement: FanoutStatement,
    pub(super) gate: &'a WaveLaunchGate,
    pub(super) now: u64,
    /// The credential caller whose request applied the wave, if one did.
    pub(super) requester: Option<crate::agent_dispatch::QueuedRequester>,
}

/// What a gated wave apply's writer decided.
pub(super) enum WaveLaunchAdmission {
    /// Mint the cut under this launch's frozen statement.
    Launch(Box<StoredLaunch>),
    /// The launch waits for the owner; mint nothing.
    Held(Box<StoredLaunch>),
}

/// Admits one wave launch in the port's writer. A launch already recorded
/// for this actor and plan_ref is replayed, never admitted twice: a landed
/// one lands again idempotently, a held or denied one stays held. A
/// recorded launch of a different cut or creator under the same plan_ref is
/// refused.
pub(super) fn admit_wave_launch_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    input: WaveLaunchInput<'_>,
) -> MemoryResult<WaveLaunchAdmission> {
    let payload = LaunchPayload::wave(input.cut, input.origin);
    let launch_ref = wave_launch_ref(input.actor, input.cut.plan_ref())?;
    if let Some(launch) = load_launch(vault, txn, launch_ref)? {
        if launch.payload != payload {
            return Err(reused_cut());
        }
        return Ok(if launch.dispatched_at.is_some() {
            WaveLaunchAdmission::Launch(Box::new(launch))
        } else {
            WaveLaunchAdmission::Held(Box::new(launch))
        });
    }
    let gate = input.gate;
    let scope = wave_scope(input.actor, input.cut.epic_task_ref());
    if policy_in(vault, txn, &ConsultFanOutScope::default())? != gate.governed
        || standing_policy_for_in(vault, txn, &scope, EscalationTrigger::Budget)? != gate.standing
    {
        return Err(consult_refusal(
            MEMORY_CODE_INVALID_STATE,
            "fan-out policy changed during admission",
            "Retry admission under the current policy.",
        ));
    }
    let policy = &gate.governed.policy;
    let plan = payload.plan(launch_ref, input.actor, policy.mode)?;
    let estimate = fanout_estimate(&plan)?;
    let mut launch = StoredLaunch {
        launch_ref,
        actor: TaskActor::Actor(input.actor),
        actor_class: input.actor_class as u8,
        approval_project: None,
        payload,
        plan: plan.clone(),
        estimate,
        statement: input.statement,
        policy_scope: ConsultFanOutScope::default(),
        scope,
        pause: None,
        check_row: None,
        held_attempts: Vec::new(),
        dispatched_at: None,
        task_refs: Vec::new(),
        denied: false,
        choice_receipt_ref: None,
        shipped_policy_rows: gate.governed.shipped_rows.clone(),
        requester: input.requester.clone(),
    };
    let admission = admit_fanout_with_history(
        &plan,
        Some(policy.approval_threshold),
        wave_launch_history(),
        &CachedAuto(gate.disposition),
        &mut LaunchSurface {
            vault,
            txn,
            launch: &mut launch,
            clearance: gate.clearance.clone(),
        },
        input.now.saturating_mul(1000),
    )?;
    match admission {
        // Above the threshold the sink has already recorded the classified
        // width check; the cut launches either way.
        FanoutAdmission::Proceed { estimate } => {
            launch.estimate = estimate;
            Ok(WaveLaunchAdmission::Launch(Box::new(launch)))
        }
        FanoutAdmission::Paused {
            estimate,
            surface_ref,
            ..
        } => {
            launch.estimate = estimate;
            record_hold_in(
                vault,
                txn,
                &mut launch,
                &surface_ref,
                policy.approval_threshold,
            )?;
            Ok(WaveLaunchAdmission::Held(Box::new(launch)))
        }
    }
}

/// Records a launch the controller paused: the pause row the sink
/// persisted, carrying the statement and, above the threshold, the width
/// check a held launch asks on its own pause row.
fn record_hold_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    launch: &mut StoredLaunch,
    surface_ref: &str,
    threshold: u32,
) -> MemoryResult<()> {
    let mut row = launch
        .pause
        .clone()
        .filter(|row| row.row_ref == surface_ref)
        .ok_or(Error::InvariantViolation("fan-out launch surface identity"))?;
    let threshold = u64::from(threshold);
    if launch.statement.crosses(threshold) {
        launch.statement.raise_width_check(
            threshold,
            WidthCheckClass::Asked {
                row_ref: row.row_ref.clone(),
            },
        );
    }
    row.statement = Some(launch.statement.clone());
    launch.pause = Some(row);
    save_launch(vault, txn, launch)?;
    Ok(())
}
