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

use std::collections::BTreeMap;

use super::ask_effect::AskEffect;
use super::consult_fanout_admission::CachedAuto;
use super::consult_fanout_store::{append_human_ruling, encode, policy_in};
use super::create_origin::TaskCreateOrigin;
use super::create_validation::consult_refusal;
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
    record_explicit_ruling_in_txn, standing_policy_for,
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

/// One fan-out launch, keyed by its launch ref.
const FANOUT_LAUNCHES: SideTable<HexId, StoredLaunch, Named> =
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
    launch_ref: EntityId,
    actor: EntityId,
    /// The actor's [`EdgeActorClass`] byte: the launch runs as this actor.
    actor_class: u8,
    /// The project whose live lead and board may rule on this launch beside
    /// the owner, bound at admission; `None` leaves it to the owner.
    approval_project: Option<EntityId>,
    payload: LaunchPayload,
    plan: FanoutPlan,
    estimate: FanoutEstimate,
    /// Stated before anything launched; every read returns this copy.
    pub(super) statement: FanoutStatement,
    policy_scope: ConsultFanOutScope,
    /// The standing-policy scope AUTO reads and a ruling records under.
    scope: String,
    pause: Option<FanoutApprovalRow>,
    /// The non-blocking question row of a launch that went out above the
    /// threshold.
    check_row: Option<FanoutApprovalRow>,
    /// Planning attempts parked under the fan-out hold for this launch.
    held_attempts: Vec<AttemptId>,
    dispatched_at: Option<u64>,
    task_refs: Vec<EntityId>,
    denied: bool,
    choice_receipt_ref: Option<String>,
    /// Shipped default rows the admission read in place of rows missing
    /// from the vault manifest.
    shipped_policy_rows: Vec<String>,
}

impl StoredLaunch {
    fn class(&self) -> MemoryResult<EdgeActorClass> {
        EdgeActorClass::try_from_u8(self.actor_class)
            .ok_or_else(|| Error::CorruptedIndex("fan-out launch actor class").into())
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
fn wave_launch_ref(actor: EntityId, plan_ref: &str) -> Result<EntityId> {
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
        || standing_policy_for(vault, &scope, EscalationTrigger::Budget)? != gate.standing
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
        actor: input.actor,
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

/// ASK-3: whether an ask waits for its launch approval. Only the `manual`
/// approval mode holds an ask, and an ask whose every recipient is a
/// principal who would answer that approval, a live vault owner or a live
/// holder of `approval_project`'s lead or board, goes straight out: holding
/// it would ask the approver to approve asking them.
pub(super) fn ask_launch_needs_approval(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    recipients: &[EntityId],
    approval_project: Option<EntityId>,
) -> MemoryResult<bool> {
    if policy_in(vault, txn, &ConsultFanOutScope::default())?
        .policy
        .mode
        != ConsultFanOutMode::Manual
    {
        return Ok(false);
    }
    let holders = launch_role_holders_in(vault, txn, approval_project)?;
    for recipient in recipients {
        let approver = (vault.get_entity_type_in_txn(txn, recipient)?
            == Some(crate::registry::ENTITY_TYPE_PERSON)
            && actor_is_vault_owner_in_txn(vault, txn, *recipient, EdgeActorClass::Human)?)
            || holders.iter().any(|holder| holder.actor == *recipient);
        if !approver {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The live holders of a launch's approval role beside the owner: the
/// current lead of `project`, then that project's own board, as the decision
/// ladder resolves them now. A parent's board and the owners are never
/// collected here; no project holds no one.
fn launch_role_holders_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: Option<EntityId>,
) -> MemoryResult<Vec<RoleHolder>> {
    let Some(project) = project else {
        return Ok(Vec::new());
    };
    let Some((_, effective)) = vault.effective_project_in_txn(txn, project)? else {
        return Ok(Vec::new());
    };
    let to = AskTo {
        role: AskRole::Responsible {
            actor: EntityId::from_hex(&effective.leader)?,
            project: Some(project),
        },
        ceiling: RoleRank::Board,
        act: AskAct::Judgment,
    };
    let board = AskRole::Board { project };
    let mut after: Option<AskRole> = None;
    let mut holders = Vec::new();
    while let Some(resolved) = vault.next_ask_role_in_txn(txn, &to, after.as_ref())? {
        if resolved.role == to.role {
            holders.extend(resolved.holders);
            after = Some(resolved.role);
        } else {
            // The project's own board ends the walk; a parent's board is
            // past it.
            if resolved.role == board {
                holders.extend(resolved.holders);
            }
            break;
        }
    }
    Ok(holders)
}

/// Whether `actor`, as `class`, is a live holder of the launch role bound to
/// `project`: a person as a human, a bound agent as an agent.
fn launch_role_is_held_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: Option<EntityId>,
    actor: EntityId,
    class: EdgeActorClass,
) -> MemoryResult<bool> {
    Ok(launch_role_holders_in(vault, txn, project)?
        .iter()
        .any(|holder| {
            holder.actor == actor
                && matches!(
                    (class, holder.kind),
                    (EdgeActorClass::Human, HolderKind::Person)
                        | (EdgeActorClass::Agent, HolderKind::Agent)
                )
        }))
}

/// The CALLS-row policy on a holder's launch ruling: a lead or board holder
/// approves once or denies; only the owner remembers a standing cap.
fn require_holder_launch_choice(
    choice: ConsultFanOutChoice,
    remembered_cap: Option<u64>,
) -> MemoryResult<()> {
    if choice == ConsultFanOutChoice::ApproveAndRemember || remembered_cap.is_some() {
        return Err(consult_refusal(
            MEMORY_CODE_FORBIDDEN,
            "only the vault owner may remember a launch approval",
            "Approve once or deny; ask the owner to remember a cap.",
        ));
    }
    Ok(())
}

/// One ask the approval mode holds, as its admission froze it.
pub(super) struct AskHold<'a> {
    pub(super) group_ref: EntityId,
    /// The project whose lead and board may release it beside the owner.
    pub(super) approval_project: Option<EntityId>,
    pub(super) actor: EntityId,
    pub(super) actor_class: EdgeActorClass,
    pub(super) requested: &'a TaskAskSpec,
    pub(super) effective: TaskAskSpec,
    pub(super) holders: Vec<EntityId>,
    pub(super) context_class: Option<TaskAskClass>,
    pub(super) question_digest: [u8; 32],
    pub(super) request_digest: &'a str,
    pub(super) statement: FanoutStatement,
    pub(super) scope: String,
    pub(super) effect: Option<AskEffect>,
    pub(super) now: u64,
}

/// Holds an ask for the owner's launch approval, in its admission
/// transaction: the whole request, census and composed effect are frozen
/// on a launch keyed by the ask's group, and the controller's pause row is
/// recorded. Nothing is minted. The receipt names the hold.
pub(super) fn hold_ask_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    hold: AskHold<'_>,
) -> MemoryResult<TaskAskReceipt> {
    let governed = policy_in(vault, txn, &ConsultFanOutScope::default())?;
    let policy = &governed.policy;
    let payload = LaunchPayload::Ask {
        group_ref: hold.group_ref,
        requested: hold.requested.clone(),
        effective: hold.effective,
        holders: hold.holders,
        context_class: hold.context_class,
        question_digest: hold.question_digest,
        request_digest: hold.request_digest.to_owned(),
        created_at: hold.now,
        effect: hold.effect,
    };
    let plan = payload.plan(hold.group_ref, hold.actor, policy.mode)?;
    let mut launch = StoredLaunch {
        launch_ref: hold.group_ref,
        actor: hold.actor,
        actor_class: hold.actor_class as u8,
        approval_project: hold.approval_project,
        payload,
        estimate: fanout_estimate(&plan)?,
        plan: plan.clone(),
        statement: hold.statement,
        policy_scope: ConsultFanOutScope::default(),
        scope: hold.scope,
        pause: None,
        check_row: None,
        held_attempts: Vec::new(),
        dispatched_at: None,
        task_refs: Vec::new(),
        denied: false,
        choice_receipt_ref: None,
        shipped_policy_rows: governed.shipped_rows.clone(),
    };
    let admission = admit_fanout_with_history(
        &plan,
        Some(policy.approval_threshold),
        wave_launch_history(),
        &CachedAuto(FanoutAutoDisposition::SurfaceHuman),
        &mut LaunchSurface {
            vault,
            txn,
            launch: &mut launch,
            clearance: None,
        },
        hold.now.saturating_mul(1000),
    )?;
    let FanoutAdmission::Paused {
        estimate,
        surface_ref,
        ..
    } = admission
    else {
        return Err(Error::InvariantViolation("a held ask's approval mode did not hold it").into());
    };
    launch.estimate = estimate;
    record_hold_in(
        vault,
        txn,
        &mut launch,
        &surface_ref,
        policy.approval_threshold,
    )?;
    held_ask_receipt(&launch, false)
}

/// The receipt of an ask still held for its launch approval.
fn held_ask_receipt(launch: &StoredLaunch, replay: bool) -> MemoryResult<TaskAskReceipt> {
    let pause = launch
        .pause
        .as_ref()
        .ok_or(Error::InvariantViolation("a held ask has no pause row"))?;
    Ok(TaskAskReceipt::new(
        TaskAskHandle {
            group_ref: launch.launch_ref,
        },
        Vec::new(),
        Some(TaskAskHoldReason::ApprovalRequired),
        replay,
        Some(launch.statement.clone()),
    )
    .with_launch(TaskAskLaunchHold {
        launch_ref: launch.launch_ref,
        plan_digest: bytes_to_hex_lower(&launch.estimate.plan_digest),
        surface_ref: pause.row_ref.clone(),
        denied: launch.denied,
    }))
}

/// The ask still held under `group_ref`, if one is.
fn held_ask_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    group_ref: EntityId,
) -> MemoryResult<Option<StoredLaunch>> {
    Ok(load_launch(vault, txn, group_ref)?.filter(|launch| {
        launch.dispatched_at.is_none() && matches!(launch.payload, LaunchPayload::Ask { .. })
    }))
}

/// A replay of a held ask: the same receipt, never a second hold. The same
/// intent key with other arguments, or from another actor, is refused.
pub(super) fn held_ask_receipt_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    group_ref: EntityId,
    actor: EntityId,
    request_digest: &str,
) -> MemoryResult<Option<TaskAskReceipt>> {
    let Some(launch) = held_ask_in(vault, txn, group_ref)? else {
        return Ok(None);
    };
    let LaunchPayload::Ask {
        request_digest: frozen,
        ..
    } = &launch.payload
    else {
        return Ok(None);
    };
    if launch.actor != actor || frozen != request_digest {
        return Err(MemoryError::bad_request(
            "ask intent key was used for different arguments",
        ));
    }
    held_ask_receipt(&launch, true).map(Some)
}

/// The asker of the ask still held under `group_ref`, if one is: status and
/// wait read a held ask before they fail an unknown group.
pub(super) fn held_ask_owner_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    group_ref: EntityId,
) -> MemoryResult<Option<EntityId>> {
    Ok(held_ask_in(vault, txn, group_ref)?.map(|launch| launch.actor))
}

/// A held ask as its approval releases it.
pub(super) struct ReleasedAsk<'a> {
    pub(super) requested: &'a TaskAskSpec,
    pub(super) holders: &'a [EntityId],
    pub(super) context_class: &'a Option<TaskAskClass>,
    pub(super) question_digest: [u8; 32],
    pub(super) request_digest: &'a str,
    pub(super) statement: &'a FanoutStatement,
}

/// Parks the planning attempt a held launch waits on, in the writer that
/// recorded the hold, and remembers it for the approval to re-lease.
pub(super) fn hold_planning_attempt_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    launch: &mut StoredLaunch,
    attempt: &AttemptRecord,
    now: u64,
) -> MemoryResult<()> {
    let lease_owner = attempt
        .lease_owner
        .clone()
        .ok_or_else(|| MemoryError::bad_request("wave planner lease has no owner"))?;
    AttemptQueue::new(vault).hold_for_fanout_in_txn(
        txn,
        HoldAttemptForFanout {
            id: attempt.id,
            lease_owner,
            attempt_count: attempt.attempt_count,
            launch_ref: launch.launch_ref,
            resume_point: AttemptResumePoint::new(
                format!("fanout_launch:{}", launch.launch_ref.to_hex()),
                now,
            ),
            now,
        },
    )?;
    if !launch.held_attempts.contains(&attempt.id) {
        launch.held_attempts.push(attempt.id);
    }
    save_launch(vault, txn, launch)?;
    Ok(())
}

/// Marks a launch landed with the TASKs its cut minted. A replayed landing
/// keeps the first stamp.
pub(super) fn mark_launched_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    launch: &mut StoredLaunch,
    writes: &[WaveTaskWrite],
) -> MemoryResult<()> {
    if launch.dispatched_at.is_some() {
        return Ok(());
    }
    launch.dispatched_at = Some(vault.now_recorded_at());
    launch.task_refs = writes.iter().map(|write| write.task_ref).collect();
    save_launch(vault, txn, launch)?;
    Ok(())
}

/// The width check an ungated wave apply asked, beside the cut it landed.
pub(super) struct WaveCheck<'a> {
    pub(super) actor: EntityId,
    pub(super) actor_class: EdgeActorClass,
    pub(super) cut: &'a ValidatedWavePlan,
    pub(super) origin: Option<&'a TaskCreateOrigin>,
    pub(super) statement: &'a FanoutStatement,
    pub(super) writes: &'a [WaveTaskWrite],
    pub(super) now: u64,
}

/// Records the durable row an ungated wave apply's asked width check names,
/// in the apply's transaction, for the owner to acknowledge.
pub(super) fn record_wave_check_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    check: WaveCheck<'_>,
) -> MemoryResult<()> {
    record_dispatched_check_in(
        vault,
        txn,
        DispatchedCheck {
            launch_ref: wave_launch_ref(check.actor, check.cut.plan_ref())?,
            actor: check.actor,
            actor_class: check.actor_class,
            payload: LaunchPayload::wave(check.cut, check.origin),
            statement: check.statement,
            scope: wave_scope(check.actor, check.cut.epic_task_ref()),
            task_refs: check.writes.iter().map(|write| write.task_ref).collect(),
            now: check.now,
        },
    )
}

/// The width check an ask admitted at once asked, beside its census.
pub(super) struct AskCheck<'a> {
    pub(super) group_ref: EntityId,
    pub(super) actor: EntityId,
    pub(super) actor_class: EdgeActorClass,
    pub(super) request_digest: &'a str,
    pub(super) question: String,
    pub(super) recipients: &'a [EntityId],
    pub(super) task_refs: Vec<EntityId>,
    pub(super) statement: &'a FanoutStatement,
    pub(super) scope: String,
    pub(super) now: u64,
}

/// Records the durable row an ask's asked width check names, in the ask's
/// admission transaction, for the owner to acknowledge. It touches no
/// member TASK.
pub(super) fn record_ask_check_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    check: AskCheck<'_>,
) -> MemoryResult<()> {
    record_dispatched_check_in(
        vault,
        txn,
        DispatchedCheck {
            launch_ref: check.group_ref,
            actor: check.actor,
            actor_class: check.actor_class,
            payload: LaunchPayload::AdmittedAsk {
                group_ref: check.group_ref,
                request_digest: check.request_digest.to_owned(),
                question: check.question,
                recipients: check.recipients.to_vec(),
            },
            statement: check.statement,
            scope: check.scope,
            task_refs: check.task_refs,
            now: check.now,
        },
    )
}

struct DispatchedCheck<'a> {
    launch_ref: EntityId,
    actor: EntityId,
    actor_class: EdgeActorClass,
    payload: LaunchPayload,
    statement: &'a FanoutStatement,
    scope: String,
    task_refs: Vec<EntityId>,
    now: u64,
}

/// A launch that went out with its width check asked. A launch already
/// recorded for the same payload keeps its rows and is marked launched; one
/// recorded for another payload is refused.
fn record_dispatched_check_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    check: DispatchedCheck<'_>,
) -> MemoryResult<()> {
    let mut launch = match load_launch(vault, txn, check.launch_ref)? {
        Some(launch) if launch.payload != check.payload => return Err(reused_cut()),
        Some(launch) => launch,
        None => {
            let governed = policy_in(vault, txn, &ConsultFanOutScope::default())?;
            let plan = check
                .payload
                .plan(check.launch_ref, check.actor, governed.policy.mode)?;
            StoredLaunch {
                launch_ref: check.launch_ref,
                actor: check.actor,
                actor_class: check.actor_class as u8,
                approval_project: None,
                payload: check.payload,
                estimate: fanout_estimate(&plan)?,
                plan,
                statement: check.statement.clone(),
                policy_scope: ConsultFanOutScope::default(),
                scope: check.scope,
                pause: None,
                check_row: None,
                held_attempts: Vec::new(),
                dispatched_at: None,
                task_refs: Vec::new(),
                denied: false,
                choice_receipt_ref: None,
                shipped_policy_rows: governed.shipped_rows,
            }
        }
    };
    if launch.check_row.is_none() {
        let mut row = fanout_width_check_row(
            &launch.plan,
            launch.check_row_ref(),
            check.now.saturating_mul(1000),
        )?;
        row.statement = Some(check.statement.clone());
        launch.check_row = Some(row);
    }
    if launch.dispatched_at.is_none() {
        launch.dispatched_at = Some(vault.now_recorded_at());
        launch.task_refs = check.task_refs;
    }
    save_launch(vault, txn, &launch)?;
    Ok(())
}

/// Re-leases and completes each planning attempt still parked under this
/// launch's hold, through the ordinary resume intervention, in the
/// approval's transaction. A row a person resumed or cancelled since is
/// theirs and stays as it is: a resumed one finds the cut landed and
/// completes on its own next apply.
fn settle_held_attempts_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    launch: &StoredLaunch,
    owner_actor: EntityId,
    now: u64,
) -> MemoryResult<()> {
    let queue = AttemptQueue::new(vault);
    for id in &launch.held_attempts {
        let Some(record) = queue.get_in_write_txn(txn, *id)? else {
            continue;
        };
        if !record.fanout_hold_for(launch.launch_ref) {
            continue;
        }
        queue.intervene_in_txn(
            txn,
            InterveneAttempt {
                id: *id,
                kind: AttemptInterventionKind::Resume,
                actor: format!("owner:{}", owner_actor.to_hex()),
                note: Some(format!(
                    "fanout launch {} approved",
                    launch.launch_ref.to_hex()
                )),
                now,
            },
        )?;
        let ClaimOutcome::Claimed(leased) = queue.claim_id_in_txn(
            txn,
            *id,
            ClaimAttempt {
                lease_owner: FANOUT_LAUNCH_LEASE_OWNER.to_owned(),
                now,
            },
        )?
        else {
            return Err(consult_refusal(
                MEMORY_CODE_INVALID_STATE,
                "the held planning attempt could not be re-leased",
                "Retry the approval.",
            ));
        };
        queue.complete_in_txn(
            txn,
            CompleteAttempt {
                id: *id,
                lease_owner: FANOUT_LAUNCH_LEASE_OWNER.to_owned(),
                attempt_count: leased.attempt_count,
                now,
            },
        )?;
    }
    Ok(())
}

impl Memory<'_> {
    /// One held or launched fan-out, for its own actor, the vault's owner or
    /// a live holder of its bound lead or board role. Any other reader, and
    /// a ref that names nothing, read `None`.
    pub fn task_fanout_launch(
        &self,
        launch_ref: EntityId,
    ) -> MemoryResult<Option<FanoutLaunchReceipt>> {
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        verify_actor_binding_in_txn(vault, &txn, self.actor(), self.actor_class())?;
        let Some(launch) = load_launch(vault, &txn, launch_ref)? else {
            return Ok(None);
        };
        let own = launch.actor == self.actor() && launch.actor_class == self.actor_class() as u8;
        if !own
            && !actor_is_vault_owner_in_txn(vault, &txn, self.actor(), self.actor_class())?
            && !launch_role_is_held_in(
                vault,
                &txn,
                launch.approval_project,
                self.actor(),
                self.actor_class(),
            )?
        {
            return Ok(None);
        }
        Ok(Some(launch.receipt()))
    }

    /// Rules on a held launch by the digest the authenticated owner saw; no
    /// replacement payload is accepted. Approve-once launches the frozen
    /// payload; approve-and-remember also persists the receipted standing row
    /// AUTO reads next time, under a cap no smaller than this launch; deny
    /// records the ruling and keeps the hold, durable and visible. Before it
    /// launches, the original actor's binding and task-create authority and
    /// its creator's run and spend lease are checked again. The ruling, any
    /// remembered row and the launched TASKs commit together, and each
    /// planning attempt parked under the hold is re-leased and completed in
    /// the same transaction. A replay returns the same launch and TASKs and
    /// never launches again.
    pub fn resume_task_fanout(
        &self,
        launch_ref: EntityId,
        expected_digest: [u8; 32],
        choice: ConsultFanOutChoice,
        owner: &AuthenticatedOwner,
        remembered_cap: Option<u64>,
    ) -> MemoryResult<FanoutLaunchReceipt> {
        let owner_actor = self.reauthenticate_fanout_owner(owner)?;
        if remembered_cap.is_some() && choice != ConsultFanOutChoice::ApproveAndRemember {
            return Err(consult_refusal(
                MEMORY_CODE_INVALID_STATE,
                "a remembered cap requires a standing approval",
                "Choose approve-and-remember for this cap.",
            ));
        }
        let now = self.vault().now_recorded_at();
        let receipt = self
            .vault()
            .memory(owner_actor, EdgeActorClass::Human)
            .with_verified_actor_write_txn(|txn| {
                self.reauthenticate_fanout_owner(owner)?;
                self.resume_task_fanout_in(
                    txn,
                    launch_ref,
                    expected_digest,
                    choice,
                    remembered_cap,
                    Some(owner),
                    &WriteActor::new(owner_actor, EdgeActorClass::Human),
                    now,
                )
            })?;
        self.vault().store.notify_attempt_observers();
        Ok(receipt)
    }

    /// A live holder's ruling on a held launch whose bound project it leads
    /// or sits on the board of, by the digest it saw: approve once or deny,
    /// never remember. The holder is verified as the writer and its role
    /// read again in the ruling's transaction; the launch commits as
    /// [`Self::resume_task_fanout`]'s does, with the holder as the approver.
    pub fn resume_task_fanout_as(
        &self,
        launch_ref: EntityId,
        expected_digest: [u8; 32],
        choice: ConsultFanOutChoice,
        holder: &WriteActor,
        remembered_cap: Option<u64>,
    ) -> MemoryResult<FanoutLaunchReceipt> {
        require_holder_launch_choice(choice, remembered_cap)?;
        let now = self.vault().now_recorded_at();
        let receipt = self.vault().try_with_write_txn_grouped(|txn| {
            self.resume_task_fanout_in(
                txn,
                launch_ref,
                expected_digest,
                choice,
                None,
                None,
                holder,
                now,
            )
        })?;
        self.vault().store.notify_attempt_observers();
        Ok(receipt)
    }

    /// One ruling on a held launch in the approval's transaction, by the
    /// owner (`owner` names its proof, revalidated by the caller) or by a
    /// live holder of the launch's bound role, authorized here before any
    /// replay or write. Only the owner's ruling is recorded as an explicit
    /// escalation ruling: that record carries the owner's authentication.
    #[expect(clippy::too_many_arguments)]
    fn resume_task_fanout_in(
        &self,
        txn: &mut heed::RwTxn<'_>,
        launch_ref: EntityId,
        expected_digest: [u8; 32],
        choice: ConsultFanOutChoice,
        remembered_cap: Option<u64>,
        owner: Option<&AuthenticatedOwner>,
        approver: &WriteActor,
        now: u64,
    ) -> MemoryResult<FanoutLaunchReceipt> {
        let (mut launch, plan) = self.frozen_launch_in(txn, launch_ref, expected_digest)?;
        let principal_ref = match owner {
            Some(owner) => owner.principal_ref_in_txn(self.vault(), &*txn)?.to_owned(),
            None => {
                self.vault().verify_write_actor_in_txn(&*txn, approver)?;
                if !launch_role_is_held_in(
                    self.vault(),
                    &*txn,
                    launch.approval_project,
                    approver.entity_ref(),
                    approver.actor_class(),
                )? {
                    return Err(consult_refusal(
                        MEMORY_CODE_FORBIDDEN,
                        "actor does not hold this launch's approval role",
                        "Ask a live project lead, its board, or the vault owner.",
                    ));
                }
                approver.entity_ref().to_hex()
            }
        };
        if launch.dispatched_at.is_some() {
            if choice == ConsultFanOutChoice::Deny {
                return Err(consult_refusal(
                    MEMORY_CODE_INVALID_STATE,
                    "a launched fan-out cannot be denied retroactively",
                    "Use the TASK cancellation door.",
                ));
            }
            return Ok(launch.receipt());
        }
        let row = launch.pause.clone().ok_or_else(|| {
            consult_refusal(
                MEMORY_CODE_INVALID_STATE,
                "fan-out launch has no surfaced approval",
                "Apply the plan again.",
            )
        })?;
        let count = u64::from(launch.estimate.total_count);
        if remembered_cap.is_some_and(|cap| cap < count) {
            return Err(consult_refusal(
                MEMORY_CODE_INVALID_STATE,
                "a standing cap cannot exclude the approved launch",
                "Set a cap at or above the approved estimate.",
            ));
        }
        let core_choice = match choice {
            ConsultFanOutChoice::ApproveOnce => FanoutApprovalChoice::ApproveOnce,
            ConsultFanOutChoice::ApproveAndRemember => {
                FanoutApprovalChoice::ApproveAndRememberBriefVerb
            }
            ConsultFanOutChoice::Deny => FanoutApprovalChoice::KeepPaused,
        };
        let action = core_choice.action_id();
        let resumed = approve_and_resume_fanout(
            &plan,
            &row,
            core_choice,
            action,
            &principal_ref,
            &mut LaunchSurface {
                vault: self.vault(),
                txn,
                launch: &mut launch,
                clearance: None,
            },
            now.saturating_mul(1000),
        )
        .map_err(approval_error)?;
        let approved = resumed.is_some();
        if let Some(owner) = owner {
            record_explicit_ruling_in_txn(
                self.vault(),
                txn,
                owner,
                EscalationReceipt {
                    task_ref: launch_ref,
                    scope: launch.scope.clone(),
                    trigger: EscalationTrigger::Budget,
                    question: launch.plan.brief_ref.clone(),
                    ruling: if approved {
                        EscalationRuling::Approve
                    } else {
                        EscalationRuling::Deny
                    },
                    rationale: launch.choice_receipt_ref.clone().unwrap_or_default(),
                    // The launch's TASK count is the magnitude; the ED-06
                    // ceiling comparison enforces <=, never an unbounded grant.
                    budget_band: Some(remembered_cap.unwrap_or(count)),
                },
                choice == ConsultFanOutChoice::ApproveAndRemember,
                now,
            )?;
        }
        launch.denied = !approved;
        if let Some(resume) = resumed {
            if resume.plan_digest != expected_digest {
                return Err(stale_digest());
            }
            launch.choice_receipt_ref = Some(resume.choice_receipt_ref);
            // A remembered width approval is not an outbound grant:
            // the primitive's verb intent has no count cap and MUST
            // NOT widen the remembered cap.
            drop(resume.grant_mint_intent);
            self.launch_approved_in(txn, &mut launch, approver.entity_ref(), now)?;
        }
        save_launch(self.vault(), txn, &launch)?;
        Ok(launch.receipt())
    }

    /// The owner's answer to the width check of a fan-out that went out
    /// above the threshold, an ask or a wave, by the digest they saw. It
    /// held nothing, so the answers are ack and ack-and-remember, never a
    /// denial, and no TASK is touched. The answer receipt and any remembered
    /// standing row, under a cap no smaller than the launch, commit
    /// together; a repeated answer returns the recorded one.
    pub fn ack_task_fanout_check(
        &self,
        launch_ref: EntityId,
        expected_digest: [u8; 32],
        choice: FanoutCheckChoice,
        owner: &AuthenticatedOwner,
        remembered_cap: Option<u64>,
    ) -> MemoryResult<FanoutLaunchReceipt> {
        let owner_actor = self.reauthenticate_fanout_owner(owner)?;
        if remembered_cap.is_some() && choice != FanoutCheckChoice::AckAndRemember {
            return Err(consult_refusal(
                MEMORY_CODE_INVALID_STATE,
                "a remembered cap requires ack-and-remember",
                "Choose ack-and-remember for this cap.",
            ));
        }
        let now = self.vault().now_recorded_at();
        self.vault()
            .memory(owner_actor, EdgeActorClass::Human)
            .with_verified_actor_write_txn(|txn| {
                self.reauthenticate_fanout_owner(owner)?;
                let (mut launch, plan) = self.frozen_launch_in(txn, launch_ref, expected_digest)?;
                let Some(row) = launch
                    .check_row
                    .clone()
                    .filter(|_| launch.dispatched_at.is_some())
                else {
                    return Err(consult_refusal(
                        MEMORY_CODE_INVALID_STATE,
                        "fan-out launch has no width check to acknowledge",
                        "Rule on a held launch through its resume door.",
                    ));
                };
                // One ruling per check: a repeated answer returns the recorded one.
                if launch.choice_receipt_ref.is_some() {
                    return Ok(launch.receipt());
                }
                let count = u64::from(launch.estimate.total_count);
                if remembered_cap.is_some_and(|cap| cap < count) {
                    return Err(consult_refusal(
                        MEMORY_CODE_INVALID_STATE,
                        "a standing cap cannot exclude the acknowledged launch",
                        "Set a cap at or above the acknowledged estimate.",
                    ));
                }
                let core_choice = match choice {
                    FanoutCheckChoice::Ack => FanoutApprovalChoice::Ack,
                    FanoutCheckChoice::AckAndRemember => FanoutApprovalChoice::AckAndRemember,
                };
                let action = core_choice.action_id();
                let principal_ref = owner.principal_ref_in_txn(self.vault(), &*txn)?;
                answer_fanout_width_check(
                    &plan,
                    &row,
                    core_choice,
                    action,
                    principal_ref,
                    &mut LaunchSurface {
                        vault: self.vault(),
                        txn,
                        launch: &mut launch,
                        clearance: None,
                    },
                    now.saturating_mul(1000),
                )
                .map_err(approval_error)?;
                record_explicit_ruling_in_txn(
                    self.vault(),
                    txn,
                    owner,
                    EscalationReceipt {
                        task_ref: launch_ref,
                        scope: launch.scope.clone(),
                        trigger: EscalationTrigger::Budget,
                        question: launch.plan.brief_ref.clone(),
                        ruling: EscalationRuling::Approve,
                        rationale: launch.choice_receipt_ref.clone().unwrap_or_default(),
                        // The band AUTO's standing read compares the next
                        // width against.
                        budget_band: Some(remembered_cap.unwrap_or(count)),
                    },
                    choice == FanoutCheckChoice::AckAndRemember,
                    now,
                )?;
                save_launch(self.vault(), txn, &launch)?;
                Ok(launch.receipt())
            })
    }

    /// The launch under `launch_ref`, with its plan recomputed from the
    /// frozen payload and bound to the digest the owner saw: never a
    /// comparison of two caller-supplied hashes. The original actor must
    /// still bind; its launch runs as it.
    fn frozen_launch_in(
        &self,
        txn: &heed::RoTxn<'_>,
        launch_ref: EntityId,
        expected_digest: [u8; 32],
    ) -> MemoryResult<(StoredLaunch, FanoutPlan)> {
        let launch = load_launch(self.vault(), txn, launch_ref)?
            .ok_or_else(|| MemoryError::not_found("fan-out launch not found"))?;
        verify_actor_binding_in_txn(self.vault(), txn, launch.actor, launch.class()?)?;
        if launch.estimate.plan_digest != expected_digest {
            return Err(stale_digest());
        }
        let plan = launch
            .payload
            .plan(launch_ref, launch.actor, launch.plan.mode)?;
        if plan != launch.plan || fanout_plan_digest(&plan)? != expected_digest {
            return Err(stale_digest());
        }
        Ok((launch, plan))
    }

    /// Launches an approved hold's frozen payload in the approval's
    /// transaction and settles the planning attempts parked under it.
    fn launch_approved_in(
        &self,
        txn: &mut heed::RwTxn<'_>,
        launch: &mut StoredLaunch,
        owner_actor: EntityId,
        now: u64,
    ) -> MemoryResult<()> {
        let class = launch.class()?;
        let task_refs: Vec<EntityId> = match &launch.payload {
            LaunchPayload::Wave {
                cut,
                creator_origin,
            } => super::wave_port::land_approved_cut_in(
                self.vault(),
                txn,
                super::wave_port::ApprovedCut {
                    actor: launch.actor,
                    actor_class: class,
                    origin: creator_origin.clone(),
                    cut: cut.clone(),
                    statement: &launch.statement,
                    now,
                },
            )?
            .iter()
            .map(|write| write.task_ref)
            .collect(),
            // The ask goes out as its asker, then its door's effect runs,
            // revalidated in this same transaction.
            LaunchPayload::Ask {
                group_ref,
                requested,
                holders,
                context_class,
                question_digest,
                request_digest,
                effect,
                ..
            } => {
                let asker = self.vault().memory(launch.actor, class);
                let task_refs = asker.release_held_ask_in(
                    txn,
                    *group_ref,
                    ReleasedAsk {
                        requested,
                        holders,
                        context_class,
                        question_digest: *question_digest,
                        request_digest,
                        statement: &launch.statement,
                    },
                )?;
                if let Some(effect) = effect {
                    asker.apply_ask_effect_in(txn, *group_ref, effect)?;
                }
                task_refs
            }
            LaunchPayload::AdmittedAsk { .. } => {
                return Err(Error::InvariantViolation("an admitted ask is never held").into());
            }
        };
        launch.dispatched_at = Some(self.vault().now_recorded_at());
        launch.task_refs = task_refs;
        settle_held_attempts_in(self.vault(), txn, launch, owner_actor, now)
    }
}

impl Memory<'_> {
    /// Every fan-out launch that waits on the owner, as the board shows it
    /// (OF-393): a held launch, denied or not, and a launched one whose width
    /// check is not yet answered. The vault's owner reads all of them; any
    /// other actor reads its own and those whose bound lead or board role it
    /// holds live, as [`Self::task_fanout_launch`] does.
    pub fn pending_task_fanout_launches(&self) -> MemoryResult<Vec<FanoutLaunchReceipt>> {
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        verify_actor_binding_in_txn(vault, &txn, self.actor(), self.actor_class())?;
        let owner = actor_is_vault_owner_in_txn(vault, &txn, self.actor(), self.actor_class())?;
        let mut pending = Vec::new();
        for (_, launch) in FANOUT_LAUNCHES.scan(&vault.store, &txn)? {
            let own =
                launch.actor == self.actor() && launch.actor_class == self.actor_class() as u8;
            if !owner
                && !own
                && !launch_role_is_held_in(
                    vault,
                    &txn,
                    launch.approval_project,
                    self.actor(),
                    self.actor_class(),
                )?
            {
                continue;
            }
            let receipt = launch.receipt();
            if receipt.paused.is_some()
                || (receipt.check_row_ref.is_some() && receipt.choice_receipt_ref.is_none())
            {
                pending.push(receipt);
            }
        }
        Ok(pending)
    }
}
