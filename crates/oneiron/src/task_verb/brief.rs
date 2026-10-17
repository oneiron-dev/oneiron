//! The queue task brief (OF-220): the typed why-carrier one TASK holds.
//!
//! It lives on the TASK body. The task's need, done-means, read-first handles
//! and settled decisions belong to the task, not the project (ARCH-0079), and
//! the brief that travels with queue work is a different thing from the
//! shareable `NOTE { kind: Plugin("brief") }` (ARCH-0032). OF-368's
//! `anchored_annotation::TaskBrief` is a third record and is left alone.
//!
//! A brief holds ids and digests, never pasted context: no code path reads
//! context text back into state (ARCH-0067). Its policy and budget refs
//! describe the rules enforced underneath; they grant nothing.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::llm::decision::Reversibility;
use crate::llm::decision::questions::OutcomeBinding;
use crate::memory::{Memory, MemoryError, MemoryResult};

use super::ask_types::{TaskAskDefault, TaskAskTarget};
use super::consts::TASK_BRIEF_SCHEMA;
use super::consult_payload::ConsultPayloadRef;

/// Domain of [`brief_digest`].
const BRIEF_DIGEST_DOMAIN: &[u8] = b"oneiron.tasks.brief.digest.v1";
/// Domain of a pin's digest over the row it names.
const PIN_DIGEST_DOMAIN: &[u8] = b"oneiron.tasks.brief.pin.v1";
/// Largest encoded brief one TASK body carries.
const MAX_BRIEF_BYTES: usize = 65_536;
/// The typed record slots of a brief (OF-063): each must resolve under the
/// writer's own read. The type ref is not among them: it names a node of the
/// team's type tree, not a record.
const BRIEF_RECORD_SLOTS: &[&str] = &[
    "/context/pack/pack_ref",
    "/context/read_first/*/target",
    "/success/yes_if_all/*/evidence_ref",
    "/success/no_if_any/*/evidence_ref",
    "/constraints/policy_refs/*",
    "/constraints/budget_ref",
    "/settled/*",
    "/project_ref",
    "/escalation/question_ref/claim",
    "/escalation/question_ref/turn",
];

/// Fixed-width byte strings travel as lowercase hex on every wire.
pub(super) fn decode_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != N * 2 {
        return None;
    }
    let mut out = [0_u8; N];
    for (index, pair) in text.as_bytes().chunks(2).enumerate() {
        let pair = std::str::from_utf8(pair).ok()?;
        out[index] = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}

/// Serde for a 32-byte digest as 64 hex characters.
pub(super) mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn serialize<S: Serializer>(
        bytes: &[u8; 32],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&crate::entity_id::bytes_to_hex_lower(bytes))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(deserializer)?;
        super::decode_hex::<32>(&text)
            .ok_or_else(|| serde::de::Error::custom("expected a 64-character hex digest"))
    }

    /// The same for an optional digest.
    pub(crate) mod option {
        use serde::{Deserialize, Deserializer, Serializer};

        pub(crate) fn serialize<S: Serializer>(
            bytes: &Option<[u8; 32]>,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            match bytes {
                Some(bytes) => {
                    serializer.serialize_some(&crate::entity_id::bytes_to_hex_lower(bytes))
                }
                None => serializer.serialize_none(),
            }
        }

        pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Option<[u8; 32]>, D::Error> {
            Option::<String>::deserialize(deserializer)?
                .map(|text| {
                    super::super::decode_hex::<32>(&text).ok_or_else(|| {
                        serde::de::Error::custom("expected a 64-character hex digest")
                    })
                })
                .transpose()
        }
    }
}

/// The learned type a task instantiates: a node and the tree version it was
/// read at (ARCH-0079). Required: a missing type is invalid, never untyped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TypeRef {
    pub node_id: EntityId,
    pub tree_version: u64,
}

/// How much care the work needs; inferred by the planner when absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Care {
    Light,
    Medium,
    High,
    Xhigh,
    Max,
}

/// The task's intent: canon's `need`, apart from any prompt, and its `care`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BriefIntent {
    pub need: String,
    #[serde(default)]
    pub care: Option<Care>,
}

/// Spawn seeds a caller may pin; unset is planned.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SpawnPins {
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub width: Option<u16>,
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default)]
    pub budget: Option<u64>,
}

/// Constraints the work runs under. The refs describe policy and budget
/// rows; holding one authorizes nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BriefConstraints {
    #[serde(default)]
    pub notes: Vec<String>,
    #[serde(default)]
    pub policy_refs: Vec<EntityId>,
    #[serde(default)]
    pub budget_ref: Option<EntityId>,
    #[serde(default)]
    pub deadline: Option<u64>,
    #[serde(default)]
    pub pins: SpawnPins,
}

/// A context pack pinned by digest: a pack ref promises no immutability, so
/// the brief keeps what it read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PinnedPack {
    pub pack_ref: EntityId,
    #[serde(default)]
    pub context_version: Option<u64>,
    #[serde(default)]
    pub retrieval_run_id: Option<EntityId>,
    #[serde(with = "hex32")]
    #[schemars(with = "String")]
    pub digest: [u8; 32],
}

/// One read-first handle pinned by digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PinnedRef {
    pub target: EntityId,
    #[serde(default)]
    pub frontier: Option<Vec<u8>>,
    #[serde(with = "hex32")]
    #[schemars(with = "String")]
    pub digest: [u8; 32],
}

/// Handles, never pasted bodies (ARCH-0079).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BriefContext {
    #[serde(default)]
    pub pack: Option<PinnedPack>,
    #[serde(default)]
    pub read_first: Vec<PinnedRef>,
}

/// One criterion of the done-means question.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Criterion {
    pub text: String,
    #[serde(default)]
    pub evidence_ref: Option<EntityId>,
}

/// Done means: one typed question, yes if all of these and no if any of
/// these, plus the outcome binding an ask already carries, so done-means and
/// asks never drift as prose twins.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DoneMeans {
    pub question: String,
    #[serde(default)]
    pub yes_if_all: Vec<Criterion>,
    #[serde(default)]
    pub no_if_any: Vec<Criterion>,
    #[serde(default)]
    pub outcome_binding: Option<OutcomeBinding>,
}

/// What makes the work ask up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EscalationTrigger {
    Blocked,
    CriteriaUnmet,
    ScopeWiden,
    SpendOver,
    Deadline,
    BriefRevised,
    RetryRequested,
}

impl EscalationTrigger {
    /// Stable wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Blocked => "blocked",
            Self::CriteriaUnmet => "criteria_unmet",
            Self::ScopeWiden => "scope_widen",
            Self::SpendOver => "spend_over",
            Self::Deadline => "deadline",
            Self::BriefRevised => "brief_revised",
            Self::RetryRequested => "retry_requested",
        }
    }
}

/// Who the work asks, when, and what it does if nobody answers. The target
/// and default reuse the ask vocabulary, so an escalation IS an ask.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EscalationRule {
    pub to: TaskAskTarget,
    #[serde(default)]
    pub triggers: Vec<EscalationTrigger>,
    #[serde(default)]
    pub default: TaskAskDefault,
    #[serde(default)]
    pub until: Option<u64>,
    #[schemars(with = "String")]
    pub reversibility: Reversibility,
    /// The CLAIM or TURN an escalation ask points its question at. An ask
    /// always names a typed reference; without one the engine cannot open
    /// an ask, and takes [`Self::default`] as the agent's own act instead.
    #[serde(default)]
    pub question_ref: Option<ConsultPayloadRef>,
}

/// Provenance of a model-composed brief. Excluded from the digest: who
/// drafted a brief never changes what it asks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ComposerStamp {
    pub seat: String,
    #[serde(with = "hex32")]
    #[schemars(with = "String")]
    pub one_liner_digest: [u8; 32],
    #[serde(default)]
    pub lens_refs: Vec<EntityId>,
    pub at: u64,
}

/// The typed brief one TASK carries: objective, intent, constraints, context
/// pack, success criteria and escalation rule (workbench-engine-asks.md:76).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QueueTaskBrief {
    pub schema: u8,
    pub type_ref: TypeRef,
    /// The task's one line (ARCH-0079).
    pub objective: String,
    pub intent: BriefIntent,
    #[serde(default)]
    pub constraints: BriefConstraints,
    #[serde(default)]
    pub context: BriefContext,
    pub success: DoneMeans,
    /// `decision.settled` CLAIM refs.
    #[serde(default)]
    pub settled: Vec<EntityId>,
    pub escalation: EscalationRule,
    /// Link into the existing project record; no second registry.
    #[serde(default)]
    pub project_ref: Option<EntityId>,
    #[serde(default)]
    pub composed: Option<ComposerStamp>,
}

/// The brief as the TASK body stores it: `rev` plus `digest` is its version.
/// History is the settled `tasks.brief` CLAIM values, so no revision store
/// exists beside it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredBrief {
    pub rev: u32,
    #[serde(with = "hex32")]
    pub digest: [u8; 32],
    pub brief: QueueTaskBrief,
}

/// The version one try was leased under. ATTEMPT payloads and receipts carry
/// it, so a running try is never retargeted by a later revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BriefStamp {
    pub rev: u32,
    #[serde(with = "hex32")]
    #[schemars(with = "String")]
    pub digest: [u8; 32],
    pub type_ref: TypeRef,
}

impl StoredBrief {
    /// The first revision of `brief`.
    pub(super) fn first(brief: QueueTaskBrief) -> Self {
        Self {
            rev: 1,
            digest: brief_digest(&brief),
            brief,
        }
    }

    /// This revision's stamp.
    #[must_use]
    pub fn stamp(&self) -> BriefStamp {
        BriefStamp {
            rev: self.rev,
            digest: self.digest,
            type_ref: self.brief.type_ref,
        }
    }
}

/// Canonical MessagePack of every field except `composed`, hashed. Named
/// encoding writes fields in declaration order and every map in the brief is
/// ordered, so one brief has one digest.
#[must_use]
pub fn brief_digest(brief: &QueueTaskBrief) -> [u8; 32] {
    let mut canonical = brief.clone();
    canonical.composed = None;
    let bytes = rmp_serde::to_vec_named(&canonical).expect("a typed brief always encodes");
    let mut hasher = blake3::Hasher::new();
    hasher.update(BRIEF_DIGEST_DOMAIN);
    hasher.update(&bytes);
    *hasher.finalize().as_bytes()
}

/// The digest a pin carries: of the named row exactly as this vault stores it
/// now. `None` when the row is absent.
pub(super) fn pin_digest_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    target: EntityId,
) -> MemoryResult<Option<[u8; 32]>> {
    let Some(raw) = vault.get_raw_in(txn, &target)? else {
        return Ok(None);
    };
    let mut hasher = blake3::Hasher::new();
    hasher.update(PIN_DIGEST_DOMAIN);
    hasher.update(target.as_bytes());
    hasher.update(&raw);
    Ok(Some(*hasher.finalize().as_bytes()))
}

fn check_pin(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    target: EntityId,
    digest: &[u8; 32],
) -> MemoryResult<()> {
    match pin_digest_in(vault, txn, target)? {
        None => Err(MemoryError::from(Error::EntityNotFound)),
        Some(held) if held == *digest => Ok(()),
        Some(_) => Err(MemoryError::bad_request(
            "a brief pin's digest does not match the row it names",
        )),
    }
}

fn require_entity(vault: &Vault, txn: &heed::RoTxn<'_>, id: EntityId) -> MemoryResult<()> {
    if vault.get_entity_type_in_txn(txn, &id)?.is_some() {
        Ok(())
    } else {
        Err(MemoryError::from(Error::EntityNotFound))
    }
}

fn require_text(text: &str, what: &str) -> MemoryResult<()> {
    if text.trim().is_empty() {
        return Err(MemoryError::bad_request(format!(
            "task brief {what} must not be blank"
        )));
    }
    Ok(())
}

impl QueueTaskBrief {
    /// Refuses a brief that names a record its writer cannot read (OF-063):
    /// every typed slot must resolve under `memory`'s own scoped read, and a
    /// refusal is receipted as the `row` write it refused. Run before the
    /// write's own transaction; [`Self::validate_in`] still checks each
    /// pin's digest and each ref's kind.
    pub(super) fn admit_references(
        &self,
        memory: &Memory<'_>,
        row: &'static str,
    ) -> MemoryResult<()> {
        crate::gate::record_references::admit_row_references(memory, row, self, BRIEF_RECORD_SLOTS)
    }

    /// Refuses a brief before any write: a known schema, a non-blank
    /// objective and need, a done-means question with at least one
    /// criterion, a resolvable escalation target, and every pin resolvable
    /// with a digest that matches the row it names.
    pub(super) fn validate_in(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> MemoryResult<()> {
        if self.schema != TASK_BRIEF_SCHEMA {
            return Err(MemoryError::bad_request("unknown task brief schema"));
        }
        require_text(&self.objective, "objective")?;
        require_text(&self.intent.need, "need")?;
        require_text(&self.success.question, "done-means question")?;
        if self.success.yes_if_all.is_empty() && self.success.no_if_any.is_empty() {
            return Err(MemoryError::bad_request(
                "task brief done-means needs at least one criterion",
            ));
        }
        for criterion in self
            .success
            .yes_if_all
            .iter()
            .chain(&self.success.no_if_any)
        {
            require_text(&criterion.text, "criterion")?;
        }
        if let Some(binding) = &self.success.outcome_binding {
            binding.validate()?;
        }
        let encoded = rmp_serde::to_vec_named(self)
            .map_err(|_| MemoryError::bad_request("task brief does not encode"))?;
        if encoded.len() > MAX_BRIEF_BYTES {
            return Err(MemoryError::bad_request(format!(
                "task brief must encode to at most {MAX_BRIEF_BYTES} bytes"
            )));
        }
        match &self.escalation.to {
            TaskAskTarget::Authority(_) => {}
            TaskAskTarget::Responder(assignee) => assignee.validate_in(vault, txn)?,
            TaskAskTarget::People(people) => {
                for person in people {
                    require_entity(vault, txn, *person)?;
                }
            }
            TaskAskTarget::Guests(guests) => {
                for guest in guests.keys() {
                    require_entity(vault, txn, *guest)?;
                }
            }
        }
        if let Some(reference) = self.escalation.question_ref
            && vault.get_entity_type_in_txn(txn, &reference.entity_ref())?
                != Some(reference.entity_type())
        {
            return Err(MemoryError::bad_request(
                "escalation question ref does not resolve to an entity of its declared kind",
            ));
        }
        if let Some(pack) = &self.context.pack {
            check_pin(vault, txn, pack.pack_ref, &pack.digest)?;
        }
        for pin in &self.context.read_first {
            check_pin(vault, txn, pin.target, &pin.digest)?;
        }
        Ok(())
    }
}

impl Memory<'_> {
    /// Pins one read-first handle for a brief: the row's digest as this vault
    /// holds it now. A composer pins what it read; settlement refuses a pin
    /// whose row has moved since.
    pub fn pin_brief_ref(&self, target: EntityId) -> MemoryResult<PinnedRef> {
        crate::memory::verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        if self.credential_withholds(target)? {
            return Err(MemoryError::from(Error::EntityNotFound));
        }
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        let digest = pin_digest_in(self.vault(), &txn, target)?.ok_or(Error::EntityNotFound)?;
        Ok(PinnedRef {
            target,
            frontier: None,
            digest,
        })
    }
}
