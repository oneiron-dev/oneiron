//! Goal-axis tradeoff policy for optimizer admissions. The scalar gate stays intact.
//!
//! The host supplies held-out axis scores and a Jev verdict; the engine owns
//! rule order, binding, the pending A/B question, and learned human picks.
use super::admission::born_on_optimize_road;
use super::*;
use crate::consent::AuthenticatedOwner;
use crate::error::ArtifactError;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_SKILL;

const fn retry(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::SkillEditGateRetry(reason))
}
use serde::{Deserialize, Serialize};

const GOAL_PREFIX: &[u8] = b"skill_optimize/tradeoff_goal/v1\0";
const ASK_PREFIX: &[u8] = b"skill_optimize/tradeoff_ask/v1\0";
const LABEL: &str = "skill tradeoff record";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TradeoffChoice {
    Incumbent,
    Candidate,
}

/// A rule matches the names of axes improved and worsened, not unbound prose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TradeoffRule {
    pub gains: BTreeSet<String>,
    pub losses: BTreeSet<String>,
    pub choice: TradeoffChoice,
}

/// Host-pinned goal axis. Floor regressions are never tradeable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TradeoffAxis {
    PrimaryHigher,
    PrimaryLower,
    FloorHigher,
    FloorLower,
    CostHigher,
    CostLower,
}
impl TradeoffAxis {
    fn delta(self, before: f32, after: f32) -> f32 {
        match self {
            Self::PrimaryHigher | Self::FloorHigher | Self::CostHigher => after - before,
            Self::PrimaryLower | Self::FloorLower | Self::CostLower => before - after,
        }
    }
    fn floor(self) -> bool {
        matches!(self, Self::FloorHigher | Self::FloorLower)
    }
}

/// Owner-authored binding to a goal-intake result. Updating it invalidates old
/// pending asks; learning a pick does NOT change its pinned version.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillTradeoffGoal {
    pub goal_ref: EntityId,
    pub responsible: EntityId,
    pub version: u32,
    pub axes: BTreeMap<String, TradeoffAxis>,
    pub rules: Vec<TradeoffRule>,
    pub learned: Vec<TradeoffRule>,
    pub jev_band: crate::llm::decision::DecisionBand,
}
impl SkillTradeoffGoal {
    fn validate(&self) -> Result<()> {
        if self.version == 0
            || self.axes.is_empty()
            || self.axes.keys().any(|key| key.trim().is_empty())
            || self.rules.iter().chain(&self.learned).any(|rule| {
                rule.gains.is_empty()
                    || rule.losses.is_empty()
                    || !rule.gains.is_disjoint(&rule.losses)
                    || rule
                        .gains
                        .iter()
                        .chain(&rule.losses)
                        .any(|name| !self.axes.contains_key(name))
            })
        {
            return Err(invalid("invalid skill tradeoff goal"));
        }
        self.jev_band
            .validate()
            .map_err(|_| invalid("invalid skill tradeoff band"))
    }
    fn validate_config(&self, limits: crate::gate::SkillTradeoffLimits) -> Result<()> {
        self.validate()?;
        if u64::try_from(self.axes.len()).unwrap_or(u64::MAX) > limits.max_axes
            || self.axes.keys().any(|name| {
                u64::try_from(name.len()).unwrap_or(u64::MAX) > limits.max_axis_name_bytes
            })
            || u64::try_from(self.rules.len()).unwrap_or(u64::MAX) > limits.max_authored_rules
        {
            return Err(invalid(
                "skill tradeoff goal exceeds resolved policy limits",
            ));
        }
        Ok(())
    }
    fn preference(
        &self,
        gains: &BTreeSet<String>,
        losses: &BTreeSet<String>,
    ) -> Option<TradeoffChoice> {
        self.rules
            .iter()
            .chain(&self.learned)
            .find(|rule| &rule.gains == gains && &rule.losses == losses)
            .map(|rule| rule.choice)
    }
}

/// Version and learned-preference frontier pinned on an accepted verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SkillTradeoffBinding {
    pub goal_ref: EntityId,
    pub version: u32,
    pub learned_count: u64,
}

pub(super) fn binding_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    skill: &EntityId,
) -> Result<Option<SkillTradeoffBinding>> {
    goal_in_txn(vault, txn, skill)?
        .map(|goal| {
            Ok(SkillTradeoffBinding {
                goal_ref: goal.goal_ref,
                version: goal.version,
                learned_count: u64::try_from(goal.learned.len())
                    .map_err(|_| invalid("too many preferences"))?,
            })
        })
        .transpose()
}
/// Exact scored question; Jev must echo its digest before its answer can rule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillTradeoffQuestion {
    pub goal_ref: EntityId,
    pub goal_version: u32,
    pub responsible: EntityId,
    pub proposal: EntityId,
    pub proposal_digest: String,
    pub target_digest: String,
    pub evidence_digest: String,
    pub world_digest: String,
    pub before: BTreeMap<String, f32>,
    pub after: BTreeMap<String, f32>,
    pub gains: BTreeSet<String>,
    pub losses: BTreeSet<String>,
}
impl SkillTradeoffQuestion {
    pub fn digest(&self) -> Result<String> {
        let bytes = rmp_serde::to_vec_named(self)
            .map_err(|_| invalid("tradeoff question encoding failed"))?;
        let mut hash = Sha256::new();
        hash.update(b"skill_optimize:tradeoff_question:v1\0");
        hash.update(bytes);
        Ok(bytes_to_hex_lower(&hash.finalize()))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JevTradeoffVerdict {
    pub question_digest: String,
    pub choice: TradeoffChoice,
    pub probability: f64,
    pub pin: crate::llm::decision::ProviderPin,
}

/// Durable A/B request; a host can render it for the bound responsible person.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillTradeoffAsk {
    pub question: SkillTradeoffQuestion,
    pub jev: Option<JevTradeoffVerdict>,
}

fn key(prefix: &[u8], id: &EntityId) -> Vec<u8> {
    let mut key = prefix.to_vec();
    key.extend_from_slice(id.as_bytes());
    key
}
fn load<T: serde::de::DeserializeOwned>(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &[u8],
) -> Result<Option<T>> {
    vault
        .store
        .vault_meta
        .get(txn, key)?
        .map(|raw| rmp_serde::from_slice(&raw).map_err(|_| Error::CorruptedIndex(LABEL)))
        .transpose()
}
fn save<T: Serialize>(vault: &Vault, txn: &mut heed::RwTxn<'_>, key: &[u8], row: &T) -> Result<()> {
    let bytes =
        rmp_serde::to_vec_named(row).map_err(|_| invalid("tradeoff row encoding failed"))?;
    vault.store.vault_meta.put(txn, key, &bytes)?;
    Ok(())
}
/// Resolve a logical skill's goal through the immutable optimizer predecessor
/// links in stored SKILL bodies. Vault-meta goal rows do not ride sync, but a
/// replica holding the owner's incumbent goal and the peer's lawful successor
/// bodies can still resolve the same ruler without trusting a remote verdict.
/// Read every link in this transaction: no replica-side activation callback is
/// needed, and a newer owner edit on the predecessor wins over a stale copy.
pub(super) fn goal_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    skill: &EntityId,
) -> Result<Option<SkillTradeoffGoal>> {
    let mut id = *skill;
    let mut seen = BTreeSet::new();
    let mut effective: Option<SkillTradeoffGoal> = None;
    loop {
        if !seen.insert(id) {
            return Err(Error::CorruptedIndex("skill tradeoff lineage cycle"));
        }
        if let Some(goal) = load::<SkillTradeoffGoal>(vault, txn, &key(GOAL_PREFIX, &id))? {
            goal.validate().map_err(|_| Error::CorruptedIndex(LABEL))?;
            effective = Some(match effective {
                None => goal,
                Some(current) => choose_goal(goal, current)?,
            });
        }
        let Some(row) = vault.store.port_entity_record(txn, &id)? else {
            break;
        };
        if row.entity_type != ENTITY_TYPE_SKILL {
            return Err(Error::CorruptedIndex("skill tradeoff lineage type"));
        }
        let record = crate::skill::decode_skill_record(&row.body)?;
        if !born_on_optimize_road(&record) {
            break;
        }
        let Some(parent_hex) = provenance_str(&record, PROVENANCE_OPTIMIZE_OF_ENTITY_KEY) else {
            break;
        };
        let parent = EntityId::from_hex(&parent_hex)
            .map_err(|_| Error::CorruptedIndex("skill tradeoff predecessor"))?;
        let Some(parent_row) = vault.store.port_entity_record(txn, &parent)? else {
            if effective.is_some() {
                break;
            } // local carry survives ancestor purge
            return Err(Error::CorruptedIndex("skill tradeoff predecessor missing"));
        };
        if parent_row.entity_type != ENTITY_TYPE_SKILL {
            return Err(Error::CorruptedIndex("skill tradeoff predecessor type"));
        }
        let predecessor = crate::skill::decode_skill_record(&parent_row.body)?;
        if predecessor.skill_id != record.skill_id
            || provenance_str(&record, PROVENANCE_OPTIMIZE_OF_VERSION_KEY).as_deref()
                != Some(predecessor.version.as_str())
        {
            return Err(Error::CorruptedIndex("skill tradeoff predecessor identity"));
        }
        id = parent;
    }
    Ok(effective)
}

/// Latest goal version wins. At one version, learned picks extend by prefix;
/// divergent same-version rows cannot be silently selected by read order.
fn choose_goal(source: SkillTradeoffGoal, dest: SkillTradeoffGoal) -> Result<SkillTradeoffGoal> {
    if source == dest || dest.version > source.version {
        return Ok(dest);
    }
    if source.version > dest.version {
        return Ok(source);
    }
    if source.goal_ref != dest.goal_ref
        || source.responsible != dest.responsible
        || source.axes != dest.axes
        || source.rules != dest.rules
        || source.jev_band != dest.jev_band
    {
        return Err(invalid("conflicting same-version skill goals"));
    }
    if source.learned.starts_with(&dest.learned) {
        Ok(source)
    } else if dest.learned.starts_with(&source.learned) {
        Ok(dest)
    } else {
        Err(invalid("conflicting learned skill picks"))
    }
}

/// Carry the exact goal (including learned picks) into an admitted successor.
/// This is part of the admission transaction, not a later best-effort copy:
/// the next Active revision must never fall back to scalar-only admission.
pub(super) fn carry_goal_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    incumbent: &EntityId,
    successor: &EntityId,
) -> Result<()> {
    if let Some(goal) = goal_in_txn(vault, txn, incumbent)? {
        let destination = key(GOAL_PREFIX, successor);
        if let Some(existing) = load::<SkillTradeoffGoal>(vault, txn, &destination)? {
            if existing != goal {
                return Err(invalid("successor has a different tradeoff goal"));
            }
        } else {
            save(vault, txn, &destination, &goal)?;
        }
    }
    Ok(())
}

/// The gap between admission and supersession is another write window. A
/// later owner edit or human pick on the old Active revision must not vanish
/// behind the admission-time copy when that revision is finally frozen.
/// Independent, conflicting same-version edits fail closed rather than pick
/// a winner by whichever door happened to run last.
pub(crate) fn reconcile_goal_on_supersession_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    old: &EntityId,
    new: &EntityId,
) -> Result<()> {
    let source = goal_in_txn(vault, txn, old)?;
    let destination = goal_in_txn(vault, txn, new)?;
    let winning = match (source, destination) {
        (None, None) => return Ok(()),
        (None, Some(_)) => return Ok(()),
        (Some(source), None) => source,
        (Some(source), Some(dest)) => choose_goal(source, dest)?,
    };
    save(vault, txn, &key(GOAL_PREFIX, new), &winning)
}

/// A pending ask is reusable only while its exact scored question is still
/// present. Called with the gate's snapshot; do not open a nested read txn.
pub(super) fn ask_matches_verdict_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    verdict: &HeldOutVerdict,
) -> Result<bool> {
    let Some(ask): Option<SkillTradeoffAsk> =
        load(vault, txn, &key(ASK_PREFIX, &verdict.proposal))?
    else {
        return Ok(false);
    };
    let question = &ask.question;
    let goal = goal_in_txn(vault, txn, &verdict.skill)?;
    let limits =
        crate::gate::skill_tradeoff_limits_in_txn(&vault.store, txn, &question.responsible)?;
    if goal.as_ref().is_some_and(|goal| {
        limits
            .max_learned_rules
            .is_some_and(|cap| u64::try_from(goal.learned.len()).unwrap_or(u64::MAX) >= cap)
    }) {
        return Ok(false);
    }
    Ok(question.proposal == verdict.proposal
        && question.proposal_digest == verdict.proposal_digest
        && question.target_digest == verdict.target_digest
        && question.evidence_digest == verdict.held_out_digest
        && verdict
            .measurements
            .as_ref()
            .is_some_and(|m| question.world_digest == m.world_labels_digest)
        && verdict.goal_binding.is_some_and(|binding| {
            binding.goal_ref == question.goal_ref && binding.version == question.goal_version
        })
        && ask.jev == verdict.tradeoff_jev)
}

/// Bind a skill's goal to an authenticated responsible human. Config changes
/// require a new version; preferences from an older goal do not cross over.
pub fn set_skill_tradeoff_goal(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    skill: &EntityId,
    goal: SkillTradeoffGoal,
) -> Result<()> {
    if goal.responsible != owner.actor() || !goal.learned.is_empty() {
        return Err(invalid("only the responsible human may configure a goal"));
    }
    vault.with_write_txn(|txn| {
        owner.revalidate_in_txn(vault, txn)?;
        goal.validate_config(crate::gate::skill_tradeoff_limits_in_txn(
            &vault.store,
            txn,
            &owner.actor(),
        )?)?;
        let previous = goal_in_txn(vault, txn, skill)?;
        if previous
            .as_ref()
            .is_some_and(|old| old.responsible != owner.actor() || goal.version <= old.version)
        {
            return Err(invalid(
                "tradeoff goal version must advance under its responsible human",
            ));
        }
        save(vault, txn, &key(GOAL_PREFIX, skill), &goal)
    })
}

pub fn skill_tradeoff_ask(vault: &Vault, proposal: &EntityId) -> Result<Option<SkillTradeoffAsk>> {
    // The read door is only a presentation projection; settlement rechecks
    // the body and goal together under the committing write transaction.
    let Some(staged) = vault.get_skill_record(proposal)? else {
        return Ok(None);
    };
    if staged.lifecycle_status != SkillLifecycle::Candidate
        || staged.approval_status != ClaimApprovalStatus::Proposed
    {
        return Ok(None);
    }
    let skill = target_of(&staged)?;
    let txn = vault.store.env.read_txn()?;
    let Some(ask): Option<SkillTradeoffAsk> = load(vault, &txn, &key(ASK_PREFIX, proposal))? else {
        return Ok(None);
    };
    let goal = goal_in_txn(vault, &txn, &skill)?;
    let limits =
        crate::gate::skill_tradeoff_limits_in_txn(&vault.store, &txn, &ask.question.responsible)?;
    Ok(goal
        .filter(|goal| {
            goal.goal_ref == ask.question.goal_ref
                && goal.version == ask.question.goal_version
                && limits
                    .max_learned_rules
                    .is_none_or(|cap| u64::try_from(goal.learned.len()).unwrap_or(u64::MAX) < cap)
        })
        .map(|_| ask))
}

/// The pick is a durable preference on the exact goal version and axis
/// signature. The expected question digest must name what the person saw;
/// an older response cannot answer a replacement question at the same key.
/// No model callback can write this row or impersonate the person.
pub fn settle_skill_tradeoff_ask(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    proposal: &EntityId,
    expected_question_digest: &str,
    choice: TradeoffChoice,
) -> Result<()> {
    vault.with_write_txn(|txn| {
        owner.revalidate_in_txn(vault, txn)?;
        let ask: SkillTradeoffAsk = load(vault, txn, &key(ASK_PREFIX, proposal))?
            .ok_or(invalid("no pending skill tradeoff ask"))?;
        let question = &ask.question;
        if question.digest()? != expected_question_digest {
            return Err(invalid("tradeoff reply does not bind the pending question"));
        }
        if question.responsible != owner.actor() {
            return Err(invalid("tradeoff pick must come from responsible person"));
        }
        let staged = vault.read_skill_record_in_txn(txn, proposal)?;
        require_open_optimizer_proposal(&staged)?;
        let skill = target_of(&staged)?;
        let current = vault.read_skill_record_in_txn(txn, &skill)?;
        if !target_is_current(&staged, &current)
            || skill_body_binding_digest(&staged)? != question.proposal_digest
            || skill_body_binding_digest(&current)? != question.target_digest
            || evidence_identity(&held_out_receipts_in_txn(vault, txn, &skill)?).1
                != question.evidence_digest
            || world_labels_digest(&held_out_outcome_results_in_txn(vault, txn, &skill)?)
                != question.world_digest
        {
            return Err(invalid(
                "tradeoff question is no longer about the open scored basis",
            ));
        }
        let mut goal = goal_in_txn(vault, txn, &skill)?.ok_or(invalid("tradeoff goal retired"))?;
        if goal.goal_ref != question.goal_ref
            || goal.version != question.goal_version
            || goal.responsible != owner.actor()
        {
            return Err(invalid("tradeoff goal changed before the pick"));
        }
        if goal.preference(&question.gains, &question.losses).is_some() {
            return Err(invalid("tradeoff already has a preference"));
        }
        let limits = crate::gate::skill_tradeoff_limits_in_txn(&vault.store, txn, &owner.actor())?;
        if limits
            .max_learned_rules
            .is_some_and(|cap| u64::try_from(goal.learned.len()).unwrap_or(u64::MAX) >= cap)
        {
            return Err(invalid(
                "tradeoff learning capacity exhausted; revise policy before another ask",
            ));
        }
        goal.learned.push(TradeoffRule {
            gains: question.gains.clone(),
            losses: question.losses.clone(),
            choice,
        });
        save(vault, txn, &key(GOAL_PREFIX, &skill), &goal)?;
        vault
            .store
            .vault_meta
            .delete(txn, &key(ASK_PREFIX, proposal))?;
        Ok(())
    })
}

pub(super) enum TradeoffPlan {
    None,
    /// Mandatory rejection independent of (possibly contradictory) preferences.
    Floor(SkillTradeoffQuestion),
    Decided(
        SkillTradeoffQuestion,
        TradeoffChoice,
        Option<JevTradeoffVerdict>,
    ),
    Ask(SkillTradeoffAsk),
}

/// Called OUTSIDE write transactions. A rule hit never calls Jev. A Jev
/// choice is usable only with the exact question binding and confidence at
/// or above the high threshold; lower confidence asks the person.
pub(super) fn plan(
    vault: &Vault,
    skill: &EntityId,
    proposal: &EntityId,
    basis: &ScoredBasis,
    scorer: &dyn HeldOutReplayScorer,
    before: &HeldOutReplayCase<'_>,
    after: &HeldOutReplayCase<'_>,
) -> Result<TradeoffPlan> {
    let txn = vault.store.env.read_txn()?;
    let goal = goal_in_txn(vault, &txn, skill)?;
    drop(txn);
    let Some(goal) = goal else {
        return Ok(TradeoffPlan::None);
    };
    let left = scorer
        .goal_axes(before)?
        .ok_or(invalid("configured goal requires held-out axis scores"))?;
    let right = scorer
        .goal_axes(after)?
        .ok_or(invalid("configured goal requires held-out axis scores"))?;
    if left.len() != goal.axes.len()
        || right.len() != goal.axes.len()
        || left.keys().ne(goal.axes.keys())
        || right.keys().ne(goal.axes.keys())
    {
        return Err(invalid("goal axes differ from held-out measurement"));
    }
    let mut gains = BTreeSet::new();
    let mut losses = BTreeSet::new();
    let mut floor_loss = false;
    for (name, axis) in &goal.axes {
        let (a, b) = (left[name], right[name]);
        if !a.is_finite() || !b.is_finite() {
            return Err(invalid("nonfinite goal-axis score"));
        }
        let delta = axis.delta(a, b);
        if !delta.is_finite() {
            return Err(invalid("goal-axis delta overflowed"));
        }
        if delta > 0.0 {
            gains.insert(name.clone());
        }
        if delta < 0.0 {
            losses.insert(name.clone());
            if axis.floor() {
                floor_loss = true;
            }
        }
    }
    let question = SkillTradeoffQuestion {
        goal_ref: goal.goal_ref,
        goal_version: goal.version,
        responsible: goal.responsible,
        proposal: *proposal,
        proposal_digest: basis.proposal_digest.clone(),
        target_digest: basis.target_digest.clone(),
        evidence_digest: basis.evidence_digest.clone(),
        world_digest: basis.world_digest.clone(),
        before: left,
        after: right,
        gains,
        losses,
    };
    if floor_loss {
        return Ok(TradeoffPlan::Floor(question));
    }
    if question.gains.is_empty() {
        return Ok(TradeoffPlan::Decided(
            question,
            TradeoffChoice::Incumbent,
            None,
        ));
    }
    if question.losses.is_empty() {
        return Ok(TradeoffPlan::Decided(
            question,
            TradeoffChoice::Candidate,
            None,
        ));
    }
    if let Some(choice) = goal.preference(&question.gains, &question.losses) {
        return Ok(TradeoffPlan::Decided(question, choice, None));
    }
    // A body, held-out outcome or goal may have moved since an older ask.
    // Only an exact match may skip Jev on re-delivery.
    // A policy cap is admission to the ASK, not a trap sprung only when the
    // person answers. An exhausted class has no pending question to display.
    let txn = vault.store.env.read_txn()?;
    let limits = crate::gate::skill_tradeoff_limits_in_txn(&vault.store, &txn, &goal.responsible)?;
    if limits
        .max_learned_rules
        .is_some_and(|cap| u64::try_from(goal.learned.len()).unwrap_or(u64::MAX) >= cap)
    {
        return Err(invalid(
            "tradeoff learning capacity exhausted; revise policy before another ask",
        ));
    }
    drop(txn);
    if let Some(prior) = skill_tradeoff_ask(vault, proposal)?
        && prior.question == question
    {
        return Ok(TradeoffPlan::Ask(prior));
    }
    let advice = scorer.jev_tradeoff(&question)?;
    if let Some(ref verdict) = advice {
        if verdict.question_digest != question.digest()?
            || verdict.pin.rung != crate::llm::decision::DecisionRung::SystemOne
            || verdict.pin.model.trim().is_empty()
            || verdict.pin.version.trim().is_empty()
            || !verdict.probability.is_finite()
            || !(0.0..=1.0).contains(&verdict.probability)
        {
            return Err(invalid(
                "Jev verdict does not bind the goal tradeoff question",
            ));
        }
        // Choice probability is confidence in the chosen option, not P(yes).
        // The lower tail is uncertainty, never a confident negative.
        if verdict.probability >= goal.jev_band.high {
            return Ok(TradeoffPlan::Decided(question, verdict.choice, advice));
        }
    }
    Ok(TradeoffPlan::Ask(SkillTradeoffAsk {
        question,
        jev: advice,
    }))
}

pub(super) fn apply(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    skill: &EntityId,
    plan: &TradeoffPlan,
) -> Result<Option<SkillEditDisposition>> {
    let question = match plan {
        TradeoffPlan::None => {
            if goal_in_txn(vault, txn, skill)?.is_some() {
                return Err(retry("tradeoff goal arrived while scoring"));
            }
            return Ok(None);
        }
        TradeoffPlan::Decided(question, _, _) | TradeoffPlan::Floor(question) => question,
        TradeoffPlan::Ask(ask) => &ask.question,
    };
    let goal = goal_in_txn(vault, txn, skill)?.ok_or(retry("tradeoff goal moved while scoring"))?;
    if goal.goal_ref != question.goal_ref
        || goal.version != question.goal_version
        || goal.responsible != question.responsible
        || goal.axes.keys().ne(question.before.keys())
    {
        return Err(retry("tradeoff goal moved while scoring"));
    }
    match plan {
        TradeoffPlan::None => unreachable!(),
        TradeoffPlan::Floor(_) => {
            vault
                .store
                .vault_meta
                .delete(txn, &key(ASK_PREFIX, &question.proposal))?;
            Ok(Some(SkillEditDisposition::Rejected))
        }
        TradeoffPlan::Decided(_, choice, _) => {
            if goal
                .preference(&question.gains, &question.losses)
                .is_some_and(|latest| latest != *choice)
            {
                return Err(retry("tradeoff preference moved while scoring"));
            }
            // A rule or Jev has answered; a prior human question on this
            // proposal must not remain visible after the answer commits.
            vault
                .store
                .vault_meta
                .delete(txn, &key(ASK_PREFIX, &question.proposal))?;
            if *choice == TradeoffChoice::Incumbent {
                Ok(Some(SkillEditDisposition::Rejected))
            } else {
                Ok(None)
            }
        }
        TradeoffPlan::Ask(ask) => {
            if goal.preference(&question.gains, &question.losses).is_some() {
                return Err(retry("tradeoff preference moved while scoring"));
            }
            let ask_key = key(ASK_PREFIX, &question.proposal);
            if let Some(prior) = load::<SkillTradeoffAsk>(vault, txn, &ask_key)? {
                if prior.question == ask.question && prior != *ask {
                    // Concurrent Jev replies to the SAME question cannot
                    // replace the first durable prior with another answer.
                    return Err(retry("tradeoff question was already asked"));
                }
                if prior.question != ask.question {
                    save(vault, txn, &ask_key, ask)?;
                }
            } else {
                save(vault, txn, &ask_key, ask)?;
            }
            Ok(Some(SkillEditDisposition::DeferredTradeoffAsk))
        }
    }
}

pub(super) fn jev_of(plan: &TradeoffPlan) -> Option<JevTradeoffVerdict> {
    match plan {
        TradeoffPlan::None | TradeoffPlan::Floor(_) => None,
        TradeoffPlan::Decided(_, _, jev) => jev.clone(),
        TradeoffPlan::Ask(ask) => ask.jev.clone(),
    }
}
