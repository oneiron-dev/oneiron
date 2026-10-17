//! The ARCH-0053 §10a tradeoff ladder: what happens to a
//! [`SkillEditDisposition::NeedsTradeoffDecision`].
//!
//! A mixed non-floor goal vector is a pending tradeoff. When the goal holds
//! tradeoff preferences, three rungs may settle it, in order: a stored
//! preference rule (authored or learned) for the exact gained and lost axes,
//! then a typed decision bound to the exact question at or above the goal's high
//! band, then a durable A/B ask to the responsible person, whose pick becomes a
//! learned preference. Every settlement is a resolution row that answers the
//! pending row, written by the decision door. A goal without preferences waits
//! for the owner door ([`super::resolve_skill_edit_tradeoff`]).
//!
//! Preferences are part of the goal record. They are keyed by the portable goal
//! identity and hashed into the goal revision, so a successor revision on any
//! replica inherits them, and every pending ask, acceptance and verdict binds
//! the preferences it was ruled under. The host supplies the shared decision ladder; the
//! engine owns rule order, binding, the pending question and the learned picks.
//!
//! A goal joined to a project's goal record ([`super::project_goal`]) climbs
//! the same ladder without authored preferences: the record's stated
//! preferences rule after the authored ones, no band means no judged rung, and
//! the A/B ask goes to the project's board, then up its parents' boards to the
//! vault's owners. A pick there is learned for this goal and proposed, never
//! written, to the project's record.
use super::project_goal::{
    TradeoffRole, project_goal_in_txn, project_rules, propose_learned_preference_in_txn,
    responsible_roles_in_txn,
};
use super::*;
use crate::consent::AuthenticatedOwner;
use crate::error::ArtifactError;
use crate::gate::{SkillTradeoffLimits, skill_tradeoff_limits_in_txn};
use crate::llm::decision::{DecisionAnswer, DecisionBand, DecisionRung, ProviderPin};
use serde::{Deserialize, Serialize};

const PREFERENCES_PREFIX: &[u8] = b"skill_optimize/tradeoff_preferences/v1\0";
const ASK_PREFIX: &[u8] = b"skill_optimize/tradeoff_ask/v1\0";
const LABEL: &str = "skill tradeoff record";
const CAPACITY_EXHAUSTED: &str =
    "tradeoff learning capacity exhausted; revise policy before another ask";

const fn retry(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::SkillEditGateRetry(reason))
}

/// A rule matches the exact sets of axes gained and lost, not unbound prose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TradeoffRule {
    pub gains: BTreeSet<String>,
    pub losses: BTreeSet<String>,
    pub choice: TradeoffChoice,
}

/// The preference part of a skill's goal record. The responsible person
/// authors the rules and the judgment band. Learned rules come only from that
/// person's A/B picks and are kept when the rules or band are revised.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillTradeoffPreferences {
    /// Minted on every configuration write, as the goal-axis override is.
    pub revision: EntityId,
    pub responsible: EntityId,
    pub rules: Vec<TradeoffRule>,
    pub learned: Vec<TradeoffRule>,
    /// No band: the judged rung is skipped and an unmatched tradeoff is asked.
    pub jev_band: Option<DecisionBand>,
}

impl SkillTradeoffPreferences {
    fn validate(&self) -> Result<()> {
        if self.rules.iter().chain(&self.learned).any(|rule| {
            rule.gains.is_empty() || rule.losses.is_empty() || !rule.gains.is_disjoint(&rule.losses)
        }) {
            return Err(invalid("invalid skill tradeoff rule"));
        }
        self.jev_band.as_ref().map_or(Ok(()), |band| {
            band.validate()
                .map_err(|_| invalid("invalid skill tradeoff band"))
        })
    }
}

/// The first matching rule and its citation: authored, then the project
/// goal's stated preferences, then learned picks.
fn matching_rule(
    preferences: Option<&SkillTradeoffPreferences>,
    project: &[(TradeoffRule, String)],
    gains: &BTreeSet<String>,
    losses: &BTreeSet<String>,
) -> Option<(TradeoffChoice, String)> {
    let matching = |rule: &TradeoffRule| &rule.gains == gains && &rule.losses == losses;
    let indexed = |rules: &[TradeoffRule], label: &str| {
        rules
            .iter()
            .position(matching)
            .map(|index| (rules[index].choice, format!("{label}:{index}")))
    };
    preferences
        .and_then(|preferences| indexed(&preferences.rules, "authored_rule"))
        .or_else(|| {
            project
                .iter()
                .find(|(rule, _)| matching(rule))
                .map(|(rule, citation)| (rule.choice, citation.clone()))
        })
        .or_else(|| {
            preferences.and_then(|preferences| indexed(&preferences.learned, "learned_rule"))
        })
}

fn learning_full(
    preferences: Option<&SkillTradeoffPreferences>,
    limits: SkillTradeoffLimits,
) -> bool {
    let learned = preferences.map_or(0, |preferences| preferences.learned.len());
    limits
        .max_learned_rules
        .is_some_and(|cap| u64::try_from(learned).unwrap_or(u64::MAX) >= cap)
}

/// Whose learning policy bounds the picks: the preferences' author, or for a
/// project goal with none yet, the first person the ask reaches.
fn limits_holder(
    preferences: Option<&SkillTradeoffPreferences>,
    question: &SkillTradeoffQuestion,
) -> Result<EntityId> {
    match preferences {
        Some(preferences) => Ok(preferences.responsible),
        None => question
            .accountable()
            .ok_or(Error::CorruptedIndex("tradeoff question without a role")),
    }
}

/// The exact scored question. Jev must echo its digest before its answer can
/// rule, and the person's pick must name it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillTradeoffQuestion {
    pub goal_id: EntityId,
    pub goal_revision: String,
    /// The project whose goal record the goal is joined to, if any.
    pub project: Option<EntityId>,
    /// The responsible-role chain the ask climbs, nearest first.
    pub roles: Vec<TradeoffRole>,
    pub proposal: EntityId,
    pub proposal_digest: String,
    pub target_digest: String,
    pub evidence_digest: String,
    pub world_digest: String,
    pub axes: BTreeMap<String, GoalAxisScore>,
    pub gains: BTreeSet<String>,
    pub losses: BTreeSet<String>,
}

impl SkillTradeoffQuestion {
    /// Canonical digest of the question.
    /// # Errors
    /// Encoding failure.
    pub fn digest(&self) -> Result<String> {
        let bytes = rmp_serde::to_vec_named(self)
            .map_err(|_| invalid("tradeoff question encoding failed"))?;
        let mut hash = Sha256::new();
        hash.update(b"skill_optimize:tradeoff_question:v1\0");
        hash.update(bytes);
        Ok(bytes_to_hex_lower(&hash.finalize()))
    }

    /// The person a rule or judgment settles on behalf of: the first person
    /// of the nearest role.
    #[must_use]
    pub fn accountable(&self) -> Option<EntityId> {
        self.roles.first().and_then(TradeoffRole::first)
    }
}

/// Jev's answer to one question. `probability` is the confidence in `choice`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JevTradeoffVerdict {
    pub question_digest: String,
    pub choice: TradeoffChoice,
    pub probability: f64,
    pub pin: ProviderPin,
}

impl JevTradeoffVerdict {
    pub(super) fn validate(&self) -> Result<()> {
        if self.question_digest.len() != 64
            || !self
                .question_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || !matches!(
                self.pin.rung,
                DecisionRung::Rule
                    | DecisionRung::Local
                    | DecisionRung::SystemOne
                    | DecisionRung::Escalation
                    | DecisionRung::Big
            )
            || self.pin.model.trim().is_empty()
            || self.pin.version.trim().is_empty()
            || !self.probability.is_finite()
            || !(0.0..=1.0).contains(&self.probability)
        {
            return Err(invalid("invalid Jev tradeoff verdict"));
        }
        Ok(())
    }
}

/// The durable A/B request a host renders for the responsible person. It is
/// bound to the pending verdict it would answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillTradeoffAsk {
    pub pending: EntityId,
    pub question: SkillTradeoffQuestion,
    pub jev: Option<JevTradeoffVerdict>,
    /// The highest rung of `question.roles` the ask has reached. Every role
    /// at or below it may answer.
    pub rung: u32,
}

impl SkillTradeoffAsk {
    /// Whether `person` holds a role the ask has reached.
    #[must_use]
    pub fn may_answer(&self, person: &EntityId) -> bool {
        let reached = usize::try_from(self.rung).map_or(usize::MAX, |rung| rung.saturating_add(1));
        self.question
            .roles
            .iter()
            .take(reached)
            .any(|role| role.holds(person))
    }
}

fn key(prefix: &[u8], id: &EntityId) -> Vec<u8> {
    [prefix, id.as_bytes()].concat()
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

fn preferences_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    goal_id: &EntityId,
) -> Result<Option<SkillTradeoffPreferences>> {
    let preferences: Option<SkillTradeoffPreferences> =
        load(vault, txn, &key(PREFERENCES_PREFIX, goal_id))?;
    if let Some(preferences) = &preferences {
        preferences
            .validate()
            .map_err(|_| Error::CorruptedIndex(LABEL))?;
    }
    Ok(preferences)
}

/// The stored preferences, for [`goal_definition_in_txn`] to fold into the
/// goal revision: a changed rule, band or learned pick is a changed goal.
pub(super) fn preferences_bytes_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    goal_id: &EntityId,
) -> Result<Option<Vec<u8>>> {
    let Some(raw) = vault
        .store
        .vault_meta
        .get(txn, &key(PREFERENCES_PREFIX, goal_id))?
    else {
        return Ok(None);
    };
    rmp_serde::from_slice::<SkillTradeoffPreferences>(&raw)
        .ok()
        .filter(|preferences| preferences.validate().is_ok())
        .ok_or(Error::CorruptedIndex(LABEL))?;
    Ok(Some(raw.into_owned()))
}

pub(super) fn clear_ask_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    proposal: &EntityId,
) -> Result<()> {
    vault
        .store
        .vault_meta
        .delete(txn, &key(ASK_PREFIX, proposal))?;
    Ok(())
}

/// Author the tradeoff preferences of a skill's goal. The first write binds
/// the authenticated owner as the responsible person; only that person may
/// revise the rules or the band. Learned picks are kept. Returns the new goal
/// revision: every pending ask and standing acceptance is re-ruled.
/// # Errors
/// An invalid rule or band, a rule naming an axis outside the goal, more rules
/// than the resolved policy allows, another person's goal, or storage errors.
pub fn set_skill_tradeoff_preferences(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    skill: &EntityId,
    rules: Vec<TradeoffRule>,
    jev_band: Option<DecisionBand>,
) -> Result<String> {
    vault.with_write_txn_grouped(|txn| {
        let actor = owner.revalidate_in_txn(vault, txn)?;
        let definition = goal_definition_in_txn(vault, txn, skill)?;
        let previous = preferences_in_txn(vault, txn, &definition.goal_id)?;
        if previous
            .as_ref()
            .is_some_and(|previous| previous.responsible != actor)
        {
            return Err(invalid(
                "only the responsible person may revise tradeoff preferences",
            ));
        }
        let limits = skill_tradeoff_limits_in_txn(&vault.store, txn, &actor)?;
        if u64::try_from(rules.len()).unwrap_or(u64::MAX) > limits.max_authored_rules {
            return Err(invalid("tradeoff rules exceed the resolved policy limit"));
        }
        if rules
            .iter()
            .flat_map(|rule| rule.gains.iter().chain(&rule.losses))
            .any(|name| !definition.axes.iter().any(|axis| &axis.name == name))
        {
            return Err(invalid("a tradeoff rule names an axis outside the goal"));
        }
        let preferences = SkillTradeoffPreferences {
            revision: vault.store.clock.entity_id()?,
            responsible: actor,
            rules,
            learned: previous.map_or_else(Vec::new, |previous| previous.learned),
            jev_band,
        };
        preferences.validate()?;
        save(
            vault,
            txn,
            &key(PREFERENCES_PREFIX, &definition.goal_id),
            &preferences,
        )?;
        Ok(goal_definition_in_txn(vault, txn, skill)?.revision)
    })
}

/// The tradeoff preferences of a skill's goal, if any were authored.
/// # Errors
/// An unreadable goal or preference row, or storage errors.
pub fn skill_tradeoff_preferences(
    vault: &Vault,
    skill: &EntityId,
) -> Result<Option<SkillTradeoffPreferences>> {
    let txn = vault.store.env.read_txn()?;
    let definition = goal_definition_in_txn(vault, &txn, skill)?;
    preferences_in_txn(vault, &txn, &definition.goal_id)
}

/// The ask bound to this pending verdict, while the proposal is open and the
/// goal, preferences included, is the one the question was put under. The
/// preferences are absent only for a project-bound goal with no picks yet.
fn bound_ask_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    pending: &HeldOutVerdict,
) -> Result<Option<(SkillTradeoffAsk, Option<SkillTradeoffPreferences>)>> {
    if pending.disposition != SkillEditDisposition::NeedsTradeoffDecision
        || pending.displaced_by_revision.is_some()
    {
        return Ok(None);
    }
    let Some(ask) = load::<SkillTradeoffAsk>(vault, txn, &key(ASK_PREFIX, &pending.proposal))?
    else {
        return Ok(None);
    };
    if ask.pending != pending.id
        || require_open_optimizer_proposal(&vault.read_skill_record_in_txn(txn, &pending.proposal)?)
            .is_err()
        || goal_definition_in_txn(vault, txn, &pending.skill)?.revision
            != ask.question.goal_revision
    {
        return Ok(None);
    }
    let preferences = preferences_in_txn(vault, txn, &ask.question.goal_id)?;
    if preferences.is_none() && ask.question.project.is_none() {
        return Ok(None);
    }
    Ok(Some((ask, preferences)))
}

/// The A/B question pending on `proposal`, for a host to render to the
/// responsible person. `None` once the proposal is answered, when its goal has
/// moved since the question was put, or while policy leaves no capacity to
/// learn the answer.
/// # Errors
/// An unreadable verdict, goal, ask or policy row, or storage errors.
pub fn skill_tradeoff_ask(vault: &Vault, proposal: &EntityId) -> Result<Option<SkillTradeoffAsk>> {
    let txn = vault.store.env.read_txn()?;
    skill_tradeoff_ask_in_txn(vault, &txn, proposal)
}

/// [`skill_tradeoff_ask`] in the caller's snapshot, so a host that settles
/// the ask reads it in the transaction it settles in.
/// # Errors
/// As [`skill_tradeoff_ask`].
pub(crate) fn skill_tradeoff_ask_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    proposal: &EntityId,
) -> Result<Option<SkillTradeoffAsk>> {
    let Some(pending) = standing_verdict_in_txn(vault, txn, proposal)? else {
        return Ok(None);
    };
    let Some((ask, preferences)) = bound_ask_in_txn(vault, txn, &pending)? else {
        return Ok(None);
    };
    let holder = limits_holder(preferences.as_ref(), &ask.question)?;
    let limits = skill_tradeoff_limits_in_txn(&vault.store, txn, &holder)?;
    Ok((!learning_full(preferences.as_ref(), limits)).then_some(ask))
}

/// The bound asks `person` may answer now, for a host to render as that
/// person's queue. An ask reaches a person when it has climbed to a role
/// they hold ([`escalate_skill_tradeoff_ask`]).
/// # Errors
/// An unreadable ask, verdict or goal row, or storage errors.
pub fn skill_tradeoff_asks_for(vault: &Vault, person: &EntityId) -> Result<Vec<SkillTradeoffAsk>> {
    let txn = vault.store.env.read_txn()?;
    let mut rows: Vec<SkillTradeoffAsk> = Vec::new();
    for row in vault.store.vault_meta.prefix_iter(&txn, ASK_PREFIX)? {
        let (_, raw) = row?;
        rows.push(rmp_serde::from_slice(&raw).map_err(|_| Error::CorruptedIndex(LABEL))?);
    }
    let mut asks = Vec::new();
    for ask in rows {
        let Some(pending) = standing_verdict_in_txn(vault, &txn, &ask.question.proposal)? else {
            continue;
        };
        if let Some((bound, _)) = bound_ask_in_txn(vault, &txn, &pending)?
            && bound.may_answer(person)
        {
            asks.push(bound);
        }
    }
    Ok(asks)
}

/// Every bound ask still pending, whoever may answer it, for the scheduler
/// that climbs them past their reminder ([`escalate_skill_tradeoff_ask`]).
/// # Errors
/// An unreadable ask, verdict or goal row, or storage errors.
pub fn pending_skill_tradeoff_asks(vault: &Vault) -> Result<Vec<SkillTradeoffAsk>> {
    let txn = vault.store.env.read_txn()?;
    let mut rows: Vec<SkillTradeoffAsk> = Vec::new();
    for row in vault.store.vault_meta.prefix_iter(&txn, ASK_PREFIX)? {
        let (_, raw) = row?;
        rows.push(rmp_serde::from_slice(&raw).map_err(|_| Error::CorruptedIndex(LABEL))?);
    }
    let mut asks = Vec::new();
    for ask in rows {
        let Some(pending) = standing_verdict_in_txn(vault, &txn, &ask.question.proposal)? else {
            continue;
        };
        if let Some((bound, _)) = bound_ask_in_txn(vault, &txn, &pending)? {
            asks.push(bound);
        }
    }
    Ok(asks)
}

/// Climb one rung: the pending ask now also reaches the next role up its
/// chain, the last being the vault's owners ("it goes up by role, ending at
/// the vault owner role"). The scheduler calls this when an ask has waited
/// past its reminder; a role lower down may still answer. Returns the ask as
/// it stands after the climb, `None` while no bound ask is pending.
/// # Errors
/// An unreadable ask, verdict or goal row, or storage errors.
pub fn escalate_skill_tradeoff_ask(
    vault: &Vault,
    proposal: &EntityId,
) -> Result<Option<SkillTradeoffAsk>> {
    vault.with_write_txn_grouped(|txn| {
        let Some(pending) = standing_verdict_in_txn(vault, txn, proposal)? else {
            return Ok(None);
        };
        let Some((mut ask, _)) = bound_ask_in_txn(vault, txn, &pending)? else {
            return Ok(None);
        };
        let top = u32::try_from(ask.question.roles.len().saturating_sub(1)).unwrap_or(u32::MAX);
        if ask.rung < top {
            ask.rung += 1;
            save(vault, txn, &key(ASK_PREFIX, proposal), &ask)?;
        }
        Ok(Some(ask))
    })
}

/// Whether a standing pending verdict may be returned to a redelivery as it
/// is. A goal without preferences waits for the owner door. A goal with them
/// waits on its bound A/B ask; a pending verdict with no bound ask is ruled
/// again. While policy leaves no capacity to learn the pick, the delivery is
/// refused before any judge is paid, and a policy revision recovers it.
pub(super) fn pending_waits_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    pending: &HeldOutVerdict,
) -> Result<bool> {
    let goal_id = pending.goal_id.ok_or(Error::CorruptedIndex(
        "pending skill tradeoff without a goal",
    ))?;
    if preferences_in_txn(vault, txn, &goal_id)?.is_none()
        && project_goal_in_txn(vault, txn, &goal_id)?.is_none()
    {
        return Ok(true);
    }
    let Some((ask, preferences)) = bound_ask_in_txn(vault, txn, pending)? else {
        return Ok(false);
    };
    let holder = limits_holder(preferences.as_ref(), &ask.question)?;
    if learning_full(
        preferences.as_ref(),
        skill_tradeoff_limits_in_txn(&vault.store, txn, &holder)?,
    ) {
        return Err(invalid(CAPACITY_EXHAUSTED));
    }
    Ok(true)
}

/// What the ladder decided outside the write transaction.
pub(super) enum TradeoffPlan {
    /// Not a pending tradeoff, or its goal holds no preferences.
    None,
    /// A preference rule, or a confident bound Jev verdict, answered.
    Decided {
        question: SkillTradeoffQuestion,
        choice: TradeoffChoice,
        rung: TradeoffRung,
        authentication: String,
        jev: Option<JevTradeoffVerdict>,
    },
    /// Nothing answered; the responsible person is asked.
    Ask {
        question: SkillTradeoffQuestion,
        jev: Option<JevTradeoffVerdict>,
    },
}

/// Climb the ladder for a scored vector, OUTSIDE any write transaction. A rule
/// hit never calls Jev. A Jev choice rules only when it echoes the exact
/// question digest with a choice confidence at or above the band's high edge;
/// anything lower asks the person. Learning capacity bounds only the ask: it
/// is checked after Jev and before a question is put, so a confident Jev still
/// decides at a full cap and no person receives a pick that cannot be learned.
pub(super) fn plan(
    vault: &Vault,
    proposal: &EntityId,
    basis: &ScoredBasis,
    definition: &GoalDefinition,
    axes: &BTreeMap<String, GoalAxisScore>,
    scorer: &dyn HeldOutReplayNotes,
) -> Result<TradeoffPlan> {
    if floor_regressed(axes) || !is_tradeoff(axes) {
        return Ok(TradeoffPlan::None);
    }
    let txn = vault.store.env.read_txn()?;
    let preferences = preferences_in_txn(vault, &txn, &basis.goal_id)?;
    let prior: Option<SkillTradeoffAsk> = load(vault, &txn, &key(ASK_PREFIX, proposal))?;
    if preferences.is_none() && definition.project.is_none() {
        return Ok(TradeoffPlan::None);
    }
    let roles = responsible_roles_in_txn(
        vault,
        &txn,
        definition.project.as_ref(),
        preferences
            .as_ref()
            .map(|preferences| preferences.responsible),
    )?;
    drop(txn);
    let project = definition
        .project
        .as_ref()
        .map(|join| project_rules(join, &definition.axes))
        .unwrap_or_default();
    let moved = |keep: fn(&GoalAxisScore) -> bool| -> BTreeSet<String> {
        axes.iter()
            .filter(|(_, axis)| keep(axis))
            .map(|(name, _)| name.clone())
            .collect()
    };
    let question = SkillTradeoffQuestion {
        goal_id: basis.goal_id,
        goal_revision: basis.goal_revision.clone(),
        project: definition.project.as_ref().map(|join| join.project),
        roles,
        proposal: *proposal,
        proposal_digest: basis.proposal_digest.clone(),
        target_digest: basis.target_digest.clone(),
        evidence_digest: basis.evidence_digest.clone(),
        world_digest: basis.world_digest.clone(),
        axes: axes.clone(),
        gains: moved(|axis| axis.after > axis.before),
        losses: moved(|axis| axis.after < axis.before),
    };
    if let Some((choice, authentication)) = matching_rule(
        preferences.as_ref(),
        &project,
        &question.gains,
        &question.losses,
    ) {
        return Ok(TradeoffPlan::Decided {
            question,
            choice,
            rung: TradeoffRung::Preference,
            authentication,
            jev: None,
        });
    }
    // Reuse a measurement only for this exact question. Every fresh answer
    // comes from the shared typed-decision ladder, never a supplied scalar.
    let band = preferences
        .as_ref()
        .and_then(|preferences| preferences.jev_band);
    let jev = match (prior.filter(|prior| prior.question == question), band) {
        (Some(prior), _) => prior.jev,
        // No band was authored, so no judgment can rule: ask the role.
        (None, None) => None,
        (None, Some(band)) => {
            if let Some(decision) = scorer.tradeoff_decision(&question, band)? {
                let choice = match &decision.answer {
                    DecisionAnswer::Choice(value) if value == "approve" => {
                        Some(TradeoffChoice::Approve)
                    }
                    DecisionAnswer::Choice(value) if value == "reject" => {
                        Some(TradeoffChoice::Reject)
                    }
                    _ => None,
                };
                // Choice probability is confidence in the chosen option, not
                // P(yes): the lower tail is uncertainty, never a confident no.
                if let (Some(choice), Some(probability), Some(pin)) = (
                    choice,
                    decision.probability,
                    decision.receipt.providers.last(),
                ) && decision.human_ask.is_none()
                    && probability >= band.high
                {
                    let verdict = JevTradeoffVerdict {
                        question_digest: question.digest()?,
                        choice,
                        probability,
                        pin: pin.clone(),
                    };
                    verdict.validate()?;
                    return Ok(TradeoffPlan::Decided {
                        authentication: format!("{}@{}", pin.model, pin.version),
                        question,
                        choice,
                        rung: TradeoffRung::Judgment,
                        jev: Some(verdict),
                    });
                }
            }
            None
        }
    };
    let holder = limits_holder(preferences.as_ref(), &question)?;
    let txn = vault.store.env.read_txn()?;
    let limits = skill_tradeoff_limits_in_txn(&vault.store, &txn, &holder)?;
    drop(txn);
    if learning_full(preferences.as_ref(), limits) {
        return Err(invalid(CAPACITY_EXHAUSTED));
    }
    Ok(TradeoffPlan::Ask { question, jev })
}

/// Settle or park a pending ruling inside the gate's committing transaction,
/// after the tier checks. That transaction re-checked the goal revision
/// against the scored basis, so the preferences the plan read are still in
/// force; only the learning policy, which is not part of the goal, is read
/// again. Returns the resolution the decision door writes after the pending
/// row. An approval under a spent cycle cap defers like a dominating win.
pub(super) fn apply_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    cycle: &SkillEditCycle,
    verdict: &mut HeldOutVerdict,
    plan: &TradeoffPlan,
) -> Result<Option<(TradeoffChoice, TradeoffResolution)>> {
    if verdict.disposition != SkillEditDisposition::NeedsTradeoffDecision {
        // Any other ruling answers or voids an earlier question.
        clear_ask_in_txn(vault, txn, &verdict.proposal)?;
        return Ok(None);
    }
    match plan {
        TradeoffPlan::None => Ok(None),
        TradeoffPlan::Decided {
            question,
            choice,
            rung,
            authentication,
            jev,
        } => {
            verdict.tradeoff_jev.clone_from(jev);
            clear_ask_in_txn(vault, txn, &verdict.proposal)?;
            if *choice == TradeoffChoice::Approve
                && accepted_in_cycle_in_txn(vault, txn, cycle, &verdict.proposal)?
                    >= cycle_cap_in_txn(vault, txn)?
            {
                verdict.disposition = SkillEditDisposition::DeferredCycleCap;
                return Ok(None);
            }
            Ok(Some((
                *choice,
                TradeoffResolution {
                    pending: verdict.id,
                    owner: question
                        .accountable()
                        .ok_or(Error::CorruptedIndex("tradeoff question without a role"))?,
                    authentication: authentication.clone(),
                    evidence: question.digest()?,
                    rung: *rung,
                },
            )))
        }
        TradeoffPlan::Ask { question, jev } => {
            let preferences = preferences_in_txn(vault, txn, &question.goal_id)?;
            if preferences.is_none() && question.project.is_none() {
                return Err(retry("tradeoff preferences moved while scoring"));
            }
            // A policy contraction while Jev was thinking cannot commit an
            // ask the person is no longer permitted to settle.
            let holder = limits_holder(preferences.as_ref(), question)?;
            if learning_full(
                preferences.as_ref(),
                skill_tradeoff_limits_in_txn(&vault.store, txn, &holder)?,
            ) {
                return Err(retry(
                    "tradeoff learning capacity moved before the ask commit",
                ));
            }
            verdict.tradeoff_jev.clone_from(jev);
            // Re-ruling the same question keeps the rung its ask climbed to.
            let rung = load::<SkillTradeoffAsk>(vault, txn, &key(ASK_PREFIX, &verdict.proposal))?
                .filter(|prior| prior.question == *question)
                .map_or(0, |prior| prior.rung);
            save(
                vault,
                txn,
                &key(ASK_PREFIX, &verdict.proposal),
                &SkillTradeoffAsk {
                    pending: verdict.id,
                    question: question.clone(),
                    jev: jev.clone(),
                    rung,
                },
            )?;
            Ok(None)
        }
    }
}

/// The responsible role's answer to the pending A/B question. The digest
/// must name the exact question the person saw, so an older reply cannot
/// answer a replacement question on the same proposal. Any live person
/// holding a role the ask has reached may pick. The pick is learned as a
/// preference for the axis signature and settles the pending tradeoff
/// through the decision door in the same transaction; no model callback can
/// write it or impersonate the person. For a project-bound goal the pick is
/// also proposed for the project's goal record, which only its interview
/// revises. An approval under a spent cycle cap is still learned and defers
/// the proposal: a later cycle re-rules it through the new preference.
/// # Errors
/// No pending ask, a digest for another question, a person holding no role the
/// ask has reached, a question stale against the goal, bodies, tier or
/// evidence, no capacity to learn, or storage errors. An error writes nothing.
pub fn settle_skill_tradeoff_ask(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    proposal: &EntityId,
    expected_question_digest: &str,
    choice: TradeoffChoice,
    at: u64,
) -> Result<HeldOutVerdict> {
    vault.with_write_txn_grouped(|txn| {
        settle_skill_tradeoff_ask_in_txn(
            vault,
            txn,
            owner,
            proposal,
            expected_question_digest,
            choice,
            at,
        )
    })
}

/// [`settle_skill_tradeoff_ask`] in the caller's write transaction, so a
/// host commits the pick with its own writes (a project ask's answer and its
/// route) or not at all.
/// # Errors
/// As [`settle_skill_tradeoff_ask`].
pub(crate) fn settle_skill_tradeoff_ask_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    owner: &AuthenticatedOwner,
    proposal: &EntityId,
    expected_question_digest: &str,
    choice: TradeoffChoice,
    at: u64,
) -> Result<HeldOutVerdict> {
    let actor = owner.revalidate_person_in_txn(vault, txn)?;
    settle_ask_in_txn(
        vault,
        txn,
        actor,
        format!("{:?}", owner.decision_id()),
        TradeoffRung::Person,
        proposal,
        expected_question_digest,
        choice,
        at,
    )
}

/// [`settle_skill_tradeoff_ask`] for a live person or a bound agent, owner
/// or not, that holds a responsible role the ask has reached
/// (ROLES-EVERYWHERE): a board member answers on their own behalf. The role
/// check is the authorization; a person's pick is learned at the person
/// rung, an agent's at the role rung.
/// # Errors
/// A writer that is no live person or bound agent, plus every error of
/// [`settle_skill_tradeoff_ask`]. An error writes nothing.
pub fn settle_skill_tradeoff_ask_as(
    vault: &Vault,
    by: &crate::write_envelope::WriteActor,
    proposal: &EntityId,
    expected_question_digest: &str,
    choice: TradeoffChoice,
    at: u64,
) -> Result<HeldOutVerdict> {
    vault.with_write_txn_grouped(|txn| {
        settle_skill_tradeoff_ask_as_in_txn(
            vault,
            txn,
            by,
            proposal,
            expected_question_digest,
            choice,
            at,
        )
    })
}

/// [`settle_skill_tradeoff_ask_as`] in the caller's write transaction.
/// # Errors
/// As [`settle_skill_tradeoff_ask_as`].
pub(crate) fn settle_skill_tradeoff_ask_as_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    by: &crate::write_envelope::WriteActor,
    proposal: &EntityId,
    expected_question_digest: &str,
    choice: TradeoffChoice,
    at: u64,
) -> Result<HeldOutVerdict> {
    vault.verify_write_actor_in_txn(txn, by)?;
    let actor = by.entity_ref();
    let (authentication, rung) = match by.actor_class() {
        crate::edge::EdgeActorClass::Human => {
            if !crate::consent::person_is_live_in_txn(vault, txn, &actor)? {
                return Err(invalid("a person's tradeoff pick requires a live person"));
            }
            (format!("person:{}", actor.to_hex()), TradeoffRung::Person)
        }
        crate::edge::EdgeActorClass::Agent => {
            (format!("agent:{}", actor.to_hex()), TradeoffRung::Role)
        }
        _ => return Err(invalid("a tradeoff pick comes from a person or an agent")),
    };
    settle_ask_in_txn(
        vault,
        txn,
        actor,
        authentication,
        rung,
        proposal,
        expected_question_digest,
        choice,
        at,
    )
}

/// [`settle_skill_tradeoff_ask`] for an agent that holds a responsible role
/// the ask has reached (ROLES-EVERYWHERE). The agent must be a live, bound
/// writer in the settling transaction; the role check is the authorization,
/// and its pick is learned as the role's preference like a person's.
/// # Errors
/// A writer that is not a live agent, plus every error of
/// [`settle_skill_tradeoff_ask`]. An error writes nothing.
pub fn settle_skill_tradeoff_ask_as_agent(
    vault: &Vault,
    agent: &crate::write_envelope::WriteActor,
    proposal: &EntityId,
    expected_question_digest: &str,
    choice: TradeoffChoice,
    at: u64,
) -> Result<HeldOutVerdict> {
    if agent.actor_class() != crate::edge::EdgeActorClass::Agent {
        return Err(invalid("an agent tradeoff pick requires an agent actor"));
    }
    settle_skill_tradeoff_ask_as(vault, agent, proposal, expected_question_digest, choice, at)
}

#[allow(clippy::too_many_arguments)]
fn settle_ask_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    authentication: String,
    rung: TradeoffRung,
    proposal: &EntityId,
    expected_question_digest: &str,
    choice: TradeoffChoice,
    at: u64,
) -> Result<HeldOutVerdict> {
    {
        let ask: SkillTradeoffAsk = load(vault, txn, &key(ASK_PREFIX, proposal))?
            .ok_or(invalid("no pending skill tradeoff ask"))?;
        let question = &ask.question;
        if question.digest()? != expected_question_digest {
            return Err(invalid("tradeoff reply does not bind the pending question"));
        }
        if !ask.may_answer(&actor) {
            return Err(invalid(
                "tradeoff pick must come from a responsible role the ask has reached",
            ));
        }
        let latest = standing_verdict_in_txn(vault, txn, proposal)?.ok_or(invalid(
            "no scored tradeoff verdict stands for this proposal",
        ))?;
        let pending = open_pending_tradeoff_in_txn(vault, txn, proposal, ask.pending, latest, at)?;
        if pending.goal_revision != question.goal_revision {
            return Err(invalid("tradeoff goal changed before the pick"));
        }
        let previous = preferences_in_txn(vault, txn, &question.goal_id)?;
        let project = project_goal_in_txn(vault, txn, &question.goal_id)?;
        if project.as_ref().map(|join| join.project) != question.project
            || (previous.is_none() && project.is_none())
        {
            return Err(invalid("tradeoff goal changed before the pick"));
        }
        let holder = previous
            .as_ref()
            .map_or(actor, |previous| previous.responsible);
        if learning_full(
            previous.as_ref(),
            skill_tradeoff_limits_in_txn(&vault.store, txn, &holder)?,
        ) {
            return Err(invalid(CAPACITY_EXHAUSTED));
        }
        let mut preferences = match previous {
            Some(previous) => previous,
            None => SkillTradeoffPreferences {
                revision: vault.store.clock.entity_id()?,
                responsible: actor,
                rules: Vec::new(),
                learned: Vec::new(),
                jev_band: None,
            },
        };
        if let Some(join) = &project {
            propose_learned_preference_in_txn(vault, txn, join, question, choice, actor, at)?;
        }
        preferences.learned.push(TradeoffRule {
            gains: question.gains.clone(),
            losses: question.losses.clone(),
            choice,
        });
        save(
            vault,
            txn,
            &key(PREFERENCES_PREFIX, &question.goal_id),
            &preferences,
        )?;
        let cycle = SkillEditCycle::new(pending.cycle.clone())?;
        if choice == TradeoffChoice::Approve
            && accepted_in_cycle_in_txn(vault, txn, &cycle, proposal)?
                >= cycle_cap_in_txn(vault, txn)?
        {
            let deferred = HeldOutVerdict {
                id: vault.store.clock.entity_id()?,
                disposition: SkillEditDisposition::DeferredCycleCap,
                accepted: false,
                goal_revision: goal_definition_in_txn(vault, txn, &pending.skill)?.revision,
                at,
                ..pending
            };
            record_verdict_in_txn(vault, txn, &deferred)?;
            clear_ask_in_txn(vault, txn, proposal)?;
            return Ok(deferred);
        }
        let resolution = TradeoffResolution {
            pending: pending.id,
            owner: actor,
            authentication,
            evidence: expected_question_digest.to_owned(),
            rung,
        };
        record_tradeoff_resolution_in_txn(vault, txn, pending, resolution, choice, &cycle, at)
    }
}
