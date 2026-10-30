//! The ARCH-0053 §10a tradeoff ladder: what happens to a
//! [`SkillEditDisposition::NeedsTradeoffDecision`].
//!
//! A mixed non-floor goal vector is a pending tradeoff. When the goal holds
//! tradeoff preferences, three rungs may settle it, in order: a stored
//! preference rule (authored or learned) for the exact gained and lost axes,
//! then a typed decision bound to the exact question at or above the goal's high
//! band, then a durable A/B ask to the responsible person, whose pick becomes a
//! learned preference. Every settlement is a resolution row that answers the
//! pending row, written by the decision door. A goal with neither preferences
//! nor a project climbs the same ladder with no rule and no band: its A/B ask
//! goes to the vault's owners, and the first pick starts the goal's
//! preferences, whose author later asks reach first.
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
//!
//! Rule counts meet the policy limits only as an advisory (`tradeoff_capacity`,
//! FIX 8847): no preference write, ask or pick is refused or hidden for a
//! count, and every pending decision keeps its durable ask.
use super::project_goal::{
    ProjectGoalJoin, TradeoffRole, current_roles_in_txn, project_goal_in_txn, project_rules,
    propose_learned_preference_in_txn, responsible_roles_in_txn,
};
use super::*;
use crate::consent::AuthenticatedOwner;
use crate::llm::decision::{DecisionAnswer, DecisionBand, DecisionRung, ProviderPin};
use serde::{Deserialize, Serialize};

mod ladder;

pub(super) use self::ladder::{TradeoffPlan, apply_in_txn, plan};
pub use self::ladder::{
    settle_skill_tradeoff_ask, settle_skill_tradeoff_ask_as, settle_skill_tradeoff_ask_as_agent,
};

const PREFERENCES_PREFIX: &[u8] = b"skill_optimize/tradeoff_preferences/v1\0";
const ASK_PREFIX: &[u8] = b"skill_optimize/tradeoff_ask/v1\0";
const LABEL: &str = "skill tradeoff record";

/// A rule matches the exact sets of axes gained and lost, not unbound prose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TradeoffRule {
    pub gains: BTreeSet<String>,
    pub losses: BTreeSet<String>,
    pub choice: TradeoffChoice,
}

/// The preference part of a skill's goal record. The responsible person
/// authors the rules and the judgment band. Learned rules come only from that
/// person's A/B picks and are kept when the rules or band are revised.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
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

/// The exact scored question. Jev must echo its digest before its answer can
/// rule, and the person's pick must name it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillTradeoffAsk {
    pub pending: EntityId,
    /// The ACTIVE skill the pending verdict revises, stamped from the
    /// verdict at ask creation (FIX 10383).
    pub skill: EntityId,
    pub question: SkillTradeoffQuestion,
    pub jev: Option<JevTradeoffVerdict>,
    /// The highest rung of `question.roles` the ask has reached. Every role
    /// at or below it may answer.
    pub rung: u32,
    /// The pin (BLAKE3, lower hex) of the judge rubric in force when `jev`
    /// was asked; `None` while none was. A kept `jev` answers the same
    /// question again only under this rubric: after a rubric edit Jev is
    /// asked again (FIX 12083).
    pub judge_rubric_digest: Option<String>,
}

impl SkillTradeoffAsk {
    /// Whether `role`, as the chain stands now, is a rung the ask has
    /// reached: matched by kind and project, never by position.
    fn reached(&self, role: &TradeoffRole) -> bool {
        let reached = usize::try_from(self.rung).map_or(usize::MAX, |rung| rung.saturating_add(1));
        self.question
            .roles
            .iter()
            .take(reached)
            .any(|asked| asked.same_rung(role))
    }
}

/// Whether `person` holds NOW a role the ask has reached (FIX 5967). The
/// chain is read again in `txn` and each reached rung is matched to its
/// current holders, so a former board member or owner answers nothing and a
/// replacement may. A reached rung no live person holds now answers for
/// nobody: the ask stays pending and climbs on, never to a former holder.
fn may_answer_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    ask: &SkillTradeoffAsk,
    project: Option<&ProjectGoalJoin>,
    preferences: Option<&SkillTradeoffPreferences>,
    person: &EntityId,
) -> Result<bool> {
    let current = current_roles_in_txn(
        vault,
        txn,
        project,
        preferences.map(|preferences| preferences.responsible),
    )?;
    Ok(current
        .iter()
        .any(|role| ask.reached(role) && role.holds(person)))
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
/// More rules than the resolved policy names is an advisory, never a refusal.
/// # Errors
/// An invalid rule or band, a rule naming an axis outside the goal, another
/// person's goal, or storage errors.
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
        tradeoff_capacity::advise_in_txn(vault, txn, &definition.goal_id, &preferences);
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
/// preferences are absent until the goal's first pick.
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
    Ok(Some((ask, preferences)))
}

/// The A/B question pending on `proposal`, for a host to render to the
/// responsible person. `None` once the proposal is answered, or when its goal
/// has moved since the question was put. No rule count hides it.
/// # Errors
/// An unreadable verdict, goal or ask row, or storage errors.
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
    Ok(bound_ask_in_txn(vault, txn, &pending)?.map(|(ask, _)| ask))
}

/// The bound asks `person` may answer now, for a host to render as that
/// person's queue. An ask reaches a person when it has climbed to a role
/// they hold now ([`escalate_skill_tradeoff_ask`]).
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
        let Some((bound, preferences)) = bound_ask_in_txn(vault, &txn, &pending)? else {
            continue;
        };
        let project = project_goal_in_txn(vault, &txn, &bound.question.goal_id)?;
        if may_answer_in_txn(
            vault,
            &txn,
            &bound,
            project.as_ref(),
            preferences.as_ref(),
            person,
        )? {
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
/// is. It waits on its bound A/B ask, however many picks its goal has
/// learned; a pending verdict with no bound ask is ruled again.
pub(super) fn pending_waits_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    pending: &HeldOutVerdict,
) -> Result<bool> {
    pending.goal_id.ok_or(Error::CorruptedIndex(
        "pending skill tradeoff without a goal",
    ))?;
    Ok(bound_ask_in_txn(vault, txn, pending)?.is_some())
}
