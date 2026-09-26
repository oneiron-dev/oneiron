//! Typed asks: response coverage, decision reducers, and policy-bound revisions.

use super::ConsultPayloadRef;
use crate::consent::{ActionClass, ActionEnvelope};
use crate::entity_id::EntityId;
use crate::memory::{MemoryError, MemoryResult};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Selects a scope, never its authority holders. Holders come from live grants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "AskAuthorityScopeWire", into = "AskAuthorityScopeWire")]
pub struct AskAuthorityScope {
    pub class: ActionClass,
    pub envelope: ActionEnvelope,
}

impl schemars::JsonSchema for AskAuthorityScope {
    fn schema_name() -> String {
        "AskAuthorityScope".to_owned()
    }

    fn json_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        AskAuthorityScopeWire::json_schema(generator)
    }
}

/// A question is either addressed to one executor, or resolved to every
/// authority holder. There is no caller-picked authority holder allowlist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TaskAskTarget {
    Authority(AskAuthorityScope),
    Responder(super::TaskAssignee),
    People(BTreeSet<EntityId>),
}

/// Stable option identity. Display text is never a predicate.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(try_from = "String", into = "String")]
pub struct TaskAskOptionId(String);

impl TaskAskOptionId {
    pub fn new(id: impl Into<String>) -> MemoryResult<Self> {
        let id = id.into();
        if id.is_empty()
            || id.len() > 64
            || !id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'))
        {
            return Err(MemoryError::bad_request("invalid ask option id"));
        }
        Ok(Self(id))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl TryFrom<String> for TaskAskOptionId {
    type Error = MemoryError;
    fn try_from(id: String) -> MemoryResult<Self> {
        Self::new(id)
    }
}
impl From<TaskAskOptionId> for String {
    fn from(id: TaskAskOptionId) -> Self {
        id.0
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskAskQuestion {
    pub reference: ConsultPayloadRef,
    pub revision: u64,
    pub options: BTreeMap<TaskAskOptionId, String>,
    pub context_refs: Vec<ConsultPayloadRef>,
    pub label: Option<String>,
    pub outcome_binding: Option<crate::llm::decision::questions::OutcomeBinding>,
}
impl TaskAskQuestion {
    pub fn new(reference: ConsultPayloadRef) -> Self {
        Self {
            reference,
            revision: 1,
            options: BTreeMap::new(),
            context_refs: Vec::new(),
            label: None,
            outcome_binding: None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TaskAskElectorate {
    #[default]
    Any,
    People(BTreeSet<EntityId>),
}
impl TaskAskElectorate {
    pub(super) fn seats(&self, who: &BTreeSet<EntityId>) -> MemoryResult<BTreeSet<EntityId>> {
        let seats = match self {
            Self::Any => who.clone(),
            Self::People(people) => people.clone(),
        };
        if seats.is_empty() || !seats.is_subset(who) {
            return Err(MemoryError::bad_request(
                "ask electorate must be inside who",
            ));
        }
        Ok(seats)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskAskNeed {
    pub count: u16,
    #[serde(default)]
    pub of: TaskAskElectorate,
}
impl Default for TaskAskNeed {
    fn default() -> Self {
        Self {
            count: 1,
            of: TaskAskElectorate::Any,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum TaskAskDecide {
    First,
    All {
        of: TaskAskElectorate,
        answer: TaskAskOptionId,
    },
    AtLeast {
        count: u16,
        of: TaskAskElectorate,
        answer: TaskAskOptionId,
    },
}

#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum TaskAskDefault {
    Proceed,
    Hold,
    #[default]
    AskMe,
}
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum TaskAskProvisional {
    #[default]
    Inform,
}
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum TaskAskBranch {
    #[default]
    Hold,
    Proceed,
}
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum TaskAskSurface {
    #[default]
    Card,
    None,
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskAskDisagree {
    pub branch: TaskAskBranch,
    pub surface: TaskAskSurface,
}

/// Policy rows are supplied as data or read from the owning TASK context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskAskClass {
    pub key: String,
    pub version: u64,
    pub governance: bool,
    pub deadline_seconds: u64,
    pub allowed_recipients: BTreeSet<EntityId>,
    pub required_people: BTreeSet<EntityId>,
    pub minimum_responses: u16,
    pub required_sources: BTreeSet<ConsultPayloadRef>,
    pub decision: Option<TaskAskDecide>,
    pub disclosure: BTreeMap<EntityId, BTreeSet<ConsultPayloadRef>>,
    pub fallback: BTreeSet<TaskAskDefault>,
    pub remind: Vec<u64>,
}

/// One ask revision. The nine ruled fields describe the ask; the remaining
/// fields bind its retry identity and owning task's policy context.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskAskSpec {
    pub intent_key: String,
    #[serde(default)]
    pub task_ref: Option<EntityId>,
    #[serde(default)]
    pub class: Option<TaskAskClass>,
    #[serde(default)]
    pub who: Option<TaskAskTarget>,
    pub what: TaskAskQuestion,
    #[serde(default)]
    pub until: Option<u64>,
    #[serde(default)]
    pub default: TaskAskDefault,
    #[serde(default)]
    pub need: TaskAskNeed,
    #[serde(default)]
    pub decide: Option<TaskAskDecide>,
    #[serde(default)]
    pub provisional: TaskAskProvisional,
    #[serde(default)]
    pub on_disagree: TaskAskDisagree,
    #[serde(default)]
    pub remind: Option<Vec<u64>>,
}
impl TaskAskSpec {
    pub fn shorthand(
        who: Option<TaskAskTarget>,
        what: TaskAskQuestion,
        until: Option<u64>,
        default: TaskAskDefault,
    ) -> Self {
        Self {
            intent_key: format!("{}/{}", what.reference.short_ref(), what.revision),
            task_ref: None,
            class: None,
            who,
            what,
            until,
            default,
            need: TaskAskNeed::default(),
            decide: Some(TaskAskDecide::First),
            provisional: TaskAskProvisional::Inform,
            on_disagree: TaskAskDisagree::default(),
            remind: None,
        }
    }

    pub(super) fn effective(
        &self,
        who: &BTreeSet<EntityId>,
        now: u64,
        bound: Option<TaskAskClass>,
    ) -> MemoryResult<Self> {
        if self.intent_key.trim().is_empty()
            || self.intent_key.len() > 256
            || self.what.revision == 0
            || self.what.revision > u64::from(u32::MAX)
            || self.what.options.len() > 256
            || self.what.options.values().any(|text| text.len() > 4096)
            || self.what.context_refs.len() > 64
            || who.is_empty()
            || who.len() > 64
        {
            return Err(MemoryError::bad_request("invalid ask spec"));
        }
        if rmp_serde::to_vec_named(self)
            .map_err(|_| MemoryError::bad_request("ask encoding"))?
            .len()
            > 64 * 1024
        {
            return Err(MemoryError::bad_request("ask spec too large"));
        }
        let mut effective = self.clone();
        if let Some(bound) = bound {
            if self.class.as_ref().is_some_and(|class| class != &bound) {
                return Err(MemoryError::bad_request(
                    "ask cannot replace its task's class",
                ));
            }
            effective.class = Some(bound);
        }
        if let Some(binding) = &self.what.outcome_binding {
            binding.validate()?;
        }
        if let Some(class) = &effective.class {
            if class.key.is_empty()
                || class.key.len() > 256
                || class.version == 0
                || class.deadline_seconds == 0
                || !who.is_subset(&class.allowed_recipients)
                || !class.required_people.is_subset(who)
                || usize::from(class.minimum_responses) > who.len()
            {
                return Err(MemoryError::bad_request("impossible ask class obligations"));
            }
            if class.governance {
                match effective.default {
                    TaskAskDefault::Proceed => {
                        return Err(MemoryError::bad_request(
                            "governance ask cannot default to proceed",
                        ));
                    }
                    TaskAskDefault::AskMe => effective.default = TaskAskDefault::Hold,
                    TaskAskDefault::Hold => {}
                }
                if effective.on_disagree.branch == TaskAskBranch::Proceed {
                    return Err(MemoryError::bad_request(
                        "governance disagreement cannot proceed",
                    ));
                }
            }
            let disagreement = match effective.on_disagree.branch {
                TaskAskBranch::Hold => TaskAskDefault::Hold,
                TaskAskBranch::Proceed => TaskAskDefault::Proceed,
            };
            if !class.fallback.contains(&effective.default)
                || !class.fallback.contains(&disagreement)
            {
                return Err(MemoryError::bad_request("ask fallback violates class"));
            }
            if self.need.count < class.minimum_responses {
                return Err(MemoryError::bad_request("ask coverage violates class"));
            }
            if let Some(decide) = &class.decision {
                if effective
                    .decide
                    .as_ref()
                    .is_some_and(|requested| requested != decide)
                {
                    return Err(MemoryError::bad_request("ask decision violates class"));
                }
                effective.decide = Some(decide.clone());
            }
            let disclosed: BTreeSet<_> = std::iter::once(self.what.reference)
                .chain(self.what.context_refs.iter().copied())
                .collect();
            if !class.required_sources.is_subset(&disclosed)
                || who.iter().any(|actor| {
                    class
                        .disclosure
                        .get(actor)
                        .is_none_or(|allowed| !disclosed.is_subset(allowed))
                })
            {
                return Err(MemoryError::bad_request(
                    "ask sources or disclosure violate class",
                ));
            }
            if effective.until.is_none() {
                effective.until = Some(
                    now.checked_add(class.deadline_seconds)
                        .ok_or_else(|| MemoryError::bad_request("ask deadline overflow"))?,
                );
            }
            if effective.remind.is_none() {
                effective.remind = Some(class.remind.clone());
            }
        }
        if effective.until.is_none_or(|until| until <= now) {
            return Err(MemoryError::bad_request(
                "ask needs a future deadline or a class deadline policy",
            ));
        }
        let seats = effective.need.of.seats(who)?;
        if effective.need.count == 0 || usize::from(effective.need.count) > seats.len() {
            return Err(MemoryError::bad_request("impossible ask response coverage"));
        }
        match &effective.decide {
            Some(TaskAskDecide::First)
                if effective.need.count > 1
                    || effective
                        .class
                        .as_ref()
                        .is_some_and(|class| class.required_people.len() > 1) =>
            {
                return Err(MemoryError::bad_request(
                    "first decision cannot require multiple responses",
                ));
            }
            Some(TaskAskDecide::All { of, answer } | TaskAskDecide::AtLeast { of, answer, .. }) => {
                let seats = of.seats(who)?;
                if !effective.what.options.contains_key(answer) {
                    return Err(MemoryError::bad_request(
                        "ask decision names an unknown option",
                    ));
                }
                if let Some(TaskAskDecide::AtLeast { count, .. }) = &effective.decide
                    && (*count == 0 || usize::from(*count) > seats.len())
                {
                    return Err(MemoryError::bad_request(
                        "impossible ask decision threshold",
                    ));
                }
            }
            _ => {}
        }
        let remind = effective.remind.get_or_insert_with(Vec::new);
        if remind.iter().any(|delay| now.checked_add(*delay).is_none())
            || remind.len() > 16
            || remind.first() == Some(&0)
            || remind.windows(2).any(|pair| pair.first() >= pair.get(1))
        {
            return Err(MemoryError::bad_request(
                "ask reminders must be bounded and increasing",
            ));
        }
        Ok(effective)
    }
}

/// Live ask routing. `None` means no native channel, not a promise of delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskAskPreflightRecipient {
    pub who: EntityId,
    pub face: Option<String>,
    pub channel: Option<String>,
    pub word_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskAskPreflight {
    pub recipients: Vec<TaskAskPreflightRecipient>,
}

/// The group is an engine-authored TASK fact, not a local queue id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskAskHandle {
    pub group_ref: EntityId,
}

/// A typed explanation emitted at admission, without waiting for TTL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskAskHoldReason {
    /// Mailbox TASKs are queued, but no native delivery route is known now.
    NoLiveRoute,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskAskReceipt {
    pub handle: TaskAskHandle,
    pub task_refs: Vec<EntityId>,
    pub hold: Option<TaskAskHoldReason>,
    pub idempotent_replay: bool,
}

/// One admitted word's durable identity. This is evidence, never approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAskAnswer {
    pub task_ref: EntityId,
    pub actor_ref: EntityId,
    pub result_ref: EntityId,
    pub word_ref: EntityId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskAskWord {
    pub result_ref: EntityId,
    pub option: Option<TaskAskOptionId>,
    pub inform_for: Option<EntityId>,
    #[serde(default)]
    pub provenance_refs: BTreeSet<ConsultPayloadRef>,
}
impl TaskAskWord {
    pub fn new(result_ref: EntityId) -> Self {
        Self {
            result_ref,
            option: None,
            inform_for: None,
            provenance_refs: BTreeSet::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskAskSource {
    Human,
    Inform,
    Executor,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskAskEvidenceReason {
    Counted,
    Inform,
    HumanDominates,
    Executor,
    Superseded,
    OutsideElectorate,
    MissingSource,
    Late,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAskEvidence {
    pub answer: TaskAskAnswer,
    pub word: TaskAskWord,
    pub source: TaskAskSource,
    pub person_ref: EntityId,
    pub order: u64,
    pub reason: TaskAskEvidenceReason,
}
/// One person's attributed answer at this read. `Unknown` carries no answer;
/// the agent's cutoff branch is never serialized as a person's default word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskAskPersonKind {
    Word,
    Companion,
    Default,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAskPersonEvidence {
    pub who: EntityId,
    pub answer: Option<TaskAskWord>,
    pub kind: TaskAskPersonKind,
    pub at: u64,
    /// Actual speaker. In particular, a companion hint is not a human word.
    pub source: Option<EntityId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAskCoverage {
    pub met: bool,
    pub required: u16,
    pub responded: BTreeSet<EntityId>,
    pub unknown: BTreeSet<EntityId>,
    pub unmet_people: BTreeSet<EntityId>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskAskDecision {
    Collected,
    First(TaskAskAnswer),
    Answer(TaskAskOptionId),
    No,
    Conflict,
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAskFallback {
    pub branch: TaskAskDefault,
    pub surface: TaskAskSurface,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskAskSettlementReason {
    FirstWord,
    AllResponded,
    Deadline,
    Stale,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAskSettlement {
    pub group_ref: EntityId,
    pub reference: EntityId,
    pub revision: u64,
    pub at: u64,
    pub cutoff_order: u64,
    pub reason: TaskAskSettlementReason,
    pub requested: TaskAskSpec,
    pub effective: TaskAskSpec,
    pub base_policy_version: u16,
    pub electorate: BTreeSet<EntityId>,
    pub question_digest: [u8; 32],
    pub unmet_sources: BTreeSet<ConsultPayloadRef>,
    pub outcome_answer_ref: Option<EntityId>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAskResult {
    pub coverage: TaskAskCoverage,
    pub decision: TaskAskDecision,
    pub fallback: Option<TaskAskFallback>,
    pub evidence: Vec<TaskAskEvidence>,
    pub settlement: TaskAskSettlement,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TaskAskStatus {
    Pending { hold: Option<TaskAskHoldReason> },
    Settled(Box<TaskAskResult>),
}

/// This is a signal contract, not a blocking read or a polling loop.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TaskAskWait {
    Pending { trap_ref: String },
    Ready(Box<TaskAskResult>),
    Park(crate::code_run::SelfDurableWait),
}

#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct AskAuthorityScopeWire {
    class: String,
    selectors: Vec<String>,
    target: Option<String>,
    budget: Option<u64>,
    receipt_required: bool,
}

impl TryFrom<AskAuthorityScopeWire> for AskAuthorityScope {
    type Error = crate::Error;

    fn try_from(wire: AskAuthorityScopeWire) -> crate::Result<Self> {
        let mut envelope = ActionEnvelope::new(wire.selectors)?;
        if let Some(target) = wire.target {
            envelope = envelope.with_target(target)?;
        }
        if let Some(budget) = wire.budget {
            envelope = envelope.with_budget(budget);
        }
        Ok(Self {
            class: ActionClass::new(wire.class)?,
            envelope: envelope.with_receipt_required(wire.receipt_required),
        })
    }
}

impl From<AskAuthorityScope> for AskAuthorityScopeWire {
    fn from(scope: AskAuthorityScope) -> Self {
        Self {
            class: scope.class.as_str().to_owned(),
            selectors: scope.envelope.selectors().to_vec(),
            target: scope.envelope.target().map(str::to_owned),
            budget: scope.envelope.budget(),
            receipt_required: scope.envelope.receipt_required(),
        }
    }
}
