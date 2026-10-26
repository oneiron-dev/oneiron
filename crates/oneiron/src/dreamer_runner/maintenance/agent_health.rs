//! The Coach's agent-health review (OF-568, agent-mind §3): a closed-form T1
//! recipe on the gated maintenance lane, run on the Coach's timer wake, and
//! over one agent attempt at its terminal receipt and at each Dreamer wake
//! while it runs (`targeted`). It reads call receipts, step replay
//! capsules, attempt rows, run coordination and sealed attempt receipts.
//! Each finding is one `agent_health` DIAGNOSTIC, merged into one card per
//! actor, signal and task. Every dial resolves for the project and task type
//! of the attempt it judges (`learning_setting` scoped rows).
//!
//! It never stops an agent and never narrows a grant or scope: its output is
//! cards and proposed moves, and an agent-health event never feeds the auto
//! arm (`Vault::is_signed_tripwire`). It reads no diary. A card's recipient
//! settles it (`self.inbox.concern.outcome`), as the owner does through
//! `/v1/owner/inbox/concern/outcome`, and may ask the Coach for a proposal
//! (`self.inbox.concern.move`, `ask`), or say a note or steer through the
//! doors that carry them, each receipt kept on the card (`moves`). The owner
//! alone applies the Coach's skill edit (`/v1/owner/inbox/concern/apply`,
//! `apply`).

use std::collections::BTreeMap;

use crate::EntityId;
use crate::agent_dispatch::{
    AGENT_DISPATCH_ATTEMPT_TYPE, AgentDispatchInput, agent_dispatch_actor,
    decode_agent_dispatch_input,
};
use crate::attempt_queue::{AttemptId, AttemptRecord, AttemptState};
use crate::llm::OpenTrapWait;
use crate::llm::run_admission::LeaseUnit;

mod apply;
mod ask;
mod brief;
mod call_evidence;
mod call_loop;
mod check_repeat;
mod delivery;
mod detectors;
mod dials;
mod doors;
mod duplicate;
mod environment;
mod erase;
mod loaded;
mod moves;
mod outcomes;
mod pipeline;
mod policy;
mod rollups;
mod run_loop;
mod silence;
mod sources;
mod targeted;
mod trend;
mod trend_output;
mod trend_policy;
mod vocabulary;
pub use apply::{
    AgentHealthApplicationState, AgentHealthCoachApplication, ConcernApplyOutcome,
    ConcernApplyRequest,
};
pub use ask::{
    AgentHealthCoachAnswer, AgentHealthCoachAsk, AgentHealthCoachDraft, AgentHealthCoachRoute,
    AgentHealthPadRead, COACH_AGENT_HEALTH_ASK_FACET, CoachHealthBrief, CoachHealthHost,
};
pub use brief::{HealthBriefPin, HealthObservedBrief};
pub(crate) use delivery::agent_health_inbox_items;
use detectors::{
    cost_spike_findings, covered, duplicate_findings, long_wait_findings, misalignment_findings,
    said_blocked, unsupported_done_findings, widen_denial_findings,
};
use dials::{DialBook, read_dials};
pub(super) use doors::card_touched_in;
pub use doors::{
    AgentHealthCardView, AgentHealthPromptInject, AgentHealthRunTree, ConcernCardRequest,
    ConcernCardSummary, ConcernOutcome, ConcernOutcomeRequest,
};
pub(crate) use doors::{agent_health_card_in_txn, agent_health_cards_in_txn};
use doors::{forbidden, may_read, settle};
pub use environment::HealthCauseSource;
pub(crate) use erase::{erase_actor_sources_in_txn, erase_sources_in_txn};
pub use loaded::{AgentHealthLoadedSkill, AgentHealthSkillTarget};
pub use moves::{
    ConcernMove, ConcernMoveBasis, ConcernMoveLink, ConcernMoveOutcome, ConcernMoveReceipt,
    ConcernMoveRequest,
};
pub use outcomes::{HEALTH_REVIEW_RECEIPT_PREFIX, HealthReviewReceipt};
pub(super) use pipeline::run;
use pipeline::{add_recipients, land};
pub(crate) use policy::{AGENT_HEALTH_REVIEW_SKILL_ID, REVIEWER_POLICY_FILE};
pub use rollups::{
    HealthTrendRollup, HealthTrendRollups, TrendMargin, TrendRatio, TrendSignalTally, TrendSource,
    TrendSpendTally, TrendStratum, health_trend_rollups,
};
pub use silence::{HealthOtherSession, HealthSilenceActivity};
use silence::{SilenceCalls, silent_findings};
pub(super) use targeted::review;
pub use trend::{
    COACH_HEALTH_TRENDS_FACET, HealthTrendComparison, HealthTrendInput, HealthTrendReview,
    TrendDirection, TrendMetric, TrendSide, TrendUnknown, review_health_trends,
};
pub(super) use trend_output::run_health_trends;
pub use trend_policy::{DetectionDialChanges, HEALTH_TREND_PERIOD_DAYS, TrendPeriods, TrendWindow};
pub use vocabulary::{
    AgentHealthCard, AgentHealthConfidence, AgentHealthCounter, AgentHealthMove,
    AgentHealthOutcome, AgentHealthTone, HEALTH_CARD_FLOOR, HEALTH_CHECK_FAILS,
    HEALTH_COST_MIN_RUNS, HEALTH_COST_SPIKE, HEALTH_DUP_MIN_COST, HEALTH_ESCALATE_TTL_HOURS,
    HEALTH_LOOP_REPEATS, HEALTH_OWNER_COPY, HEALTH_REVIEW, HEALTH_REVIEW_WINDOW_HOURS,
    HEALTH_SILENT_MINUTES, HEALTH_WAIT_MINUTES, HEALTH_WAIT_SHARE, HEALTH_WIDEN_DENIALS,
};
use vocabulary::{CARDS, Finding, card_key, card_ref, parse_card_ref};

/// The recipe's facet. It rides the Coach's timer jobs (`MAINTENANCE_FACETS`),
/// deduped per wake.
pub const COACH_AGENT_HEALTH_FACET: &str = "coach.agent_health";

/// The unit `health.dup.min_cost` is read in: the policy budget's, which
/// every model-call receipt settles in and an ordinary launch scope meters.
/// A duplicate whose scope meters another unit, or none, is never held
/// cheap.
fn dup_cost_unit() -> LeaseUnit {
    LeaseUnit::tokens()
}

/// A wait on a person is not a problem (agent-mind §3.4).
const WAIT_PERSON: &str = "person";
const HEALTH_DIGEST_DOMAIN: &[u8] = b"oneiron.coach.agent_health.evidence.v1";
const CARD_REF_PREFIX: &str = "health:";

/// The working set's attempts, and its agent dispatches, by attempt bytes.
type Attempts = BTreeMap<[u8; 16], AttemptRecord>;
type Dispatches = BTreeMap<[u8; 16], Dispatched>;
/// The open trap waits, by attempt bytes.
type Traps = BTreeMap<[u8; 16], Vec<OpenTrapWait>>;

/// An agent-dispatch attempt's actor, project, parent, task type and plan.
struct Dispatched {
    actor: EntityId,
    project: Option<EntityId>,
    parent: Option<AttemptId>,
    /// The task type's node (OF-543), across tree versions.
    type_node: String,
    /// The launch plan's expected spend, and its unit.
    expected: Option<(LeaseUnit, u64)>,
}

impl Dispatched {
    fn of(record: &AttemptRecord) -> Option<Self> {
        if record.kind != crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND {
            return None;
        }
        let payload =
            crate::dreamer_runner::decode_dreamer_attempt_payload(&record.payload).ok()?;
        if payload.attempt_type != AGENT_DISPATCH_ATTEMPT_TYPE {
            return None;
        }
        let input: AgentDispatchInput = decode_agent_dispatch_input(&payload.input).ok()?;
        Some(Self {
            actor: agent_dispatch_actor(&input).ok()?.entity_ref(),
            project: input.project_ref,
            parent: payload.parent_attempt,
            type_node: input.type_ref.node_id.clone(),
            expected: input
                .launch
                .as_ref()
                .map(|launch| (launch.unit.clone(), launch.expected.units)),
        })
    }
}

fn entity(attempt: AttemptId) -> Option<EntityId> {
    EntityId::from_bytes(*attempt.as_bytes()).ok()
}

fn task_of(record: &AttemptRecord) -> Option<EntityId> {
    record
        .task_ref
        .as_deref()
        .and_then(|task| EntityId::from_hex(task).ok())
}

fn settled(state: AttemptState) -> bool {
    matches!(
        state,
        AttemptState::Completed
            | AttemptState::Failed
            | AttemptState::Cancelled
            | AttemptState::Abandoned
    )
}

/// No new input between two equal calls, by their action digests: both
/// captured and equal. A call whose inputs were not captured (it reads the
/// world, or names too many entities) shows no input change, so its
/// arguments alone decide.
fn same_inputs(first: Option<&str>, second: Option<&str>) -> bool {
    match (first, second) {
        (Some(first), Some(second)) => first == second,
        _ => true,
    }
}
