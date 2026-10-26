//! The health check past a threshold (OF-520, ARCH-0044 C5). Wire counters,
//! `[limits]` rows, engine scans and the e-sign ceremony's burst counters
//! (ARCH-0064a) keep their crossings as questions, and
//! none refuses for a count. This worker reads the kept crossings off every
//! lock and write path and asks each one typed question on the host's ladder:
//! "is everything okay: a bot, or a valid burst?". A known actor under a
//! grant passes at the rule rung, the model rungs answer the rest, and a
//! crossing they leave in the band waits in the vault owner's ask queue; an
//! e-sign burst's goes first to its document's sender and climbs to the
//! owners (ARCH-0076 #roles-everywhere). A
//! held check is durable work, never a drop. Each decision binds to its
//! crossing's unit, so what happened next (the owner's answer, or an outcome
//! the owner records later) is a label for the loop.
//!
//! Admission's queue stays the only wait: a check never holds, narrows or
//! refuses the work that crossed.
use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::llm::decision::catalogue::WIRE_HEALTH;
use oneiron::llm::decision::questions::{
    HEALTH_OUTCOME_PREDICATE, HealthAnswer, OutcomeBinding, OutcomeSource,
};
use oneiron::llm::decision::{
    AnswerContract, AskAct, AskRole, AskTo, DecisionAnswer, DecisionCall, DecisionProvider,
    DecisionQuestion, DecisionRung, HeldLadder, ProviderCapability, ProviderDecision, ProviderPin,
    Reversibility, RoleRank,
};
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::{EntityId, Error, Result, Vault};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::server::SyncServer;

mod evidence;
pub(crate) use evidence::raise_verdict_spend;
use evidence::{fold, unread};

/// One check per crossing subject.
const CHECK: &str = "wire:health:v1:check:";
/// How often the worker reads new crossings and asks the held checks.
const SWEEP_EVERY: Duration = Duration::from_secs(15);
/// The clock one check's ladder call runs under.
const ASK_BUDGET: Duration = Duration::from_secs(30);
/// An answered check covers its subject's later crossings, and a later
/// revision of its crossing, this long; past it a crossing asks again.
const COVER_SECS: u64 = 3_600;
/// How long after a decision an outcome still labels it.
const OUTCOME_HORIZON_SECS: u64 = 30 * 86_400;
/// The host's wording of the question (ARCH-0044 C5), unless
/// `[models.decisions].wire_health` words it (FIX 1088).
const WORDING: &str = "Is everything okay past this threshold: a bot, or a valid burst?";
pub const VALID_BURST: &str = "valid_burst";
pub const BOT: &str = "bot";
/// The wire actor a request with no credential counts under.
const UNAUTHENTICATED: &str = "unauthenticated";
/// The grant rule's identity when the host has no rule table.
const GRANT_RULE: &str = "wire-health-grants";

/// What crossed.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CrossingSource {
    /// A wire call-volume window, per verb or per actor.
    Wire,
    /// A `[limits]` row.
    Limit,
    /// An engine scan's threshold row.
    Scan,
    /// One signing document's, or one recipient's, ceremony calls past
    /// their window's threshold.
    Esign,
    /// One caller's `ai.verdict` spend past its window's check (FIX 1123).
    Spend,
}

/// Who answered a check.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AnsweredBy {
    /// A ladder rung, below the person.
    Ladder(DecisionRung),
    /// The vault owner role, from its ask queue.
    Owner,
    /// The answer to an earlier revision of the same crossing that still
    /// covers this one: the check cites that answer's question and unit and
    /// was not asked itself (FIX 9531).
    Cover,
}

/// Where a check stands.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum CheckState {
    /// Kept and not asked yet: the next sweep asks it.
    Held,
    /// The ladder left it in the band; it waits in the owner's ask queue.
    Asked { question: String, unit: String },
    Answered {
        answer: String,
        probability: Option<f64>,
        by: AnsweredBy,
        at: u64,
        question: String,
        unit: String,
    },
}

/// One subject's health check, kept on this server's vault.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct HealthCheck {
    pub subject: String,
    pub source: CrossingSource,
    /// The first crossing, as the server kept it: what the question reads.
    pub crossing: Value,
    pub first_raised: u64,
    pub last_raised: u64,
    /// Crossings this check covers, the first included.
    pub crossings: u64,
    pub state: CheckState,
    /// The wording the check was asked in, which its question's identity
    /// holds, so a later change of wording still finds its answer; `None`
    /// until it is asked.
    #[serde(default)]
    pub asked_in: Option<String>,
}

impl HealthCheck {
    fn open(&self) -> bool {
        matches!(self.state, CheckState::Held | CheckState::Asked { .. })
    }

    fn covers(&self, at: u64) -> bool {
        match self.state {
            CheckState::Answered { at: answered, .. } => {
                at <= answered.max(self.last_raised).saturating_add(COVER_SECS)
            }
            _ => true,
        }
    }

    /// The check's own question, worded `wording`: one per crossing it first
    /// asked about.
    fn question(&self, wording: &str) -> Result<DecisionQuestion> {
        WIRE_HEALTH.question(
            &[self.subject.as_bytes(), &self.first_raised.to_be_bytes()],
            wording.to_owned(),
            AnswerContract::Choice {
                options: vec![VALID_BURST.to_owned(), BOT.to_owned()],
            },
        )
    }
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(value).map_err(|_| Error::CorruptedIndex("wire health check"))
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    rmp_serde::from_slice(bytes).map_err(|_| Error::CorruptedIndex("wire health check"))
}

/// Every health check this server keeps, by subject.
pub fn checks(vault: &Vault) -> Result<Vec<HealthCheck>> {
    let mut checks = Vec::new();
    for key in vault.sync_state_keys_with_prefix(CHECK)? {
        if let Some(bytes) = vault.sync_state_get(&key)? {
            checks.push(decode(&bytes)?);
        }
    }
    Ok(checks)
}

fn put_check(vault: &Vault, check: &HealthCheck) -> Result<()> {
    vault.sync_state_put(&format!("{CHECK}{}", check.subject), &encode(check)?)
}

/// Whether `actor`, as the wire counted it, is a known actor under a grant:
/// it came with a credential that names a live actor of this vault.
fn known_under_grant(vault: &Vault, owner: EntityId, actor: &str) -> bool {
    actor != UNAUTHENTICATED
        && EntityId::from_hex(actor)
            .is_ok_and(|id| id == owner || vault.entity_exists(&id).unwrap_or(false))
}

/// The call's state: the crossing, how often its subject crossed, and for a
/// wire crossing whether every actor past its row is known under a grant:
/// every one the crossing kept, not only the busiest it names (FIX 9531).
fn state(vault: &Vault, owner: EntityId, check: &HealthCheck) -> Value {
    let actors: Vec<Value> = check.crossing["actors"]
        .as_array()
        .map(|actors| {
            actors
                .iter()
                .filter_map(|row| {
                    let actor = row["actor"].as_str()?;
                    Some(json!({
                        "actor": actor,
                        "calls": row["calls"],
                        "known_under_grant": known_under_grant(vault, owner, actor),
                    }))
                })
                .collect()
        })
        .unwrap_or_default();
    let crossed: Vec<&str> = check.crossing["crossed"]["actors"]
        .as_array()
        .map(|actors| actors.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let granted = !crossed.is_empty()
        && crossed
            .iter()
            .all(|actor| known_under_grant(vault, owner, actor));
    json!({
        "source": check.source,
        "crossing": check.crossing,
        "crossings": check.crossings,
        "first_raised": check.first_raised,
        "last_raised": check.last_raised,
        "actors": actors,
        "actors_known_under_grant": granted,
    })
}

/// The host's rule rung with one rule in front: a crossing whose every
/// actor is known under a grant is a valid burst. Anything else is the host
/// table's to answer, or the next rung's.
struct GrantRule {
    inner: Option<Arc<dyn DecisionProvider>>,
}

impl DecisionProvider for GrantRule {
    fn pin(&self) -> ProviderPin {
        self.inner.as_ref().map_or_else(
            || ProviderPin {
                rung: DecisionRung::Rule,
                model: GRANT_RULE.to_owned(),
                version: "1".to_owned(),
            },
            |inner| inner.pin(),
        )
    }

    fn capability(&self) -> ProviderCapability {
        self.inner
            .as_ref()
            .map_or_else(ProviderCapability::default, |inner| inner.capability())
    }

    fn decide(&self, call: &DecisionCall<'_>) -> Result<ProviderDecision> {
        if call.state["actors_known_under_grant"].as_bool() == Some(true) {
            return Ok(ProviderDecision {
                answer: DecisionAnswer::Choice(VALID_BURST.to_owned()),
                probability: Some(1.0),
                paired: None,
                person: None,
                served: None,
            });
        }
        match &self.inner {
            Some(inner) => inner.decide(call),
            None => Ok(ProviderDecision {
                answer: DecisionAnswer::Abstain,
                probability: None,
                paired: None,
                person: None,
                served: None,
            }),
        }
    }
}

/// What happened next labels the decision: a bot is the positive label.
fn binding() -> OutcomeBinding {
    OutcomeBinding {
        source: OutcomeSource::Claim {
            predicate: HEALTH_OUTCOME_PREDICATE.to_owned(),
        },
        horizon: OUTCOME_HORIZON_SECS,
        mapping: [(BOT.to_owned(), true), (VALID_BURST.to_owned(), false)].into(),
        noise_weight: 0.0,
        linked_by: None,
    }
}

/// Who a check's ask goes to: an e-sign burst's first to its document's
/// sender, then up the chain to the owners, agent or person; every other
/// check to the owners. The ladder call stays the owner's, so [`poll`] finds
/// the answer whoever gave it.
fn ask_to(vault: &Vault, check: &HealthCheck) -> Result<Option<AskTo>> {
    if check.source != CrossingSource::Esign {
        return Ok(None);
    }
    let Some(document) = check
        .crossing
        .get("document")
        .and_then(Value::as_str)
        .and_then(|hex| EntityId::from_hex(hex).ok())
    else {
        return Ok(None);
    };
    Ok(vault.esign_sender(document)?.map(|actor| AskTo {
        role: AskRole::Responsible {
            actor: oneiron::llm::decision::AnswerActor::Actor(actor),
            project: None,
        },
        ceiling: RoleRank::Owner,
        act: AskAct::Judgment,
    }))
}

/// Asks one held check on the ladder and binds the decision to its unit.
fn ask(server: &SyncServer, owner: EntityId, mut check: HealthCheck) -> Result<()> {
    let vault = server.vault();
    let host = server.decision_host();
    let wording = host.wire_health_wording().unwrap_or(WORDING).to_owned();
    let question = check.question(&wording)?;
    let mut ladder: HeldLadder = host.ladder().clone();
    ladder.rule = Some(Arc::new(GrantRule {
        inner: ladder.rule.take(),
    }));
    let dial = host.dial(DecisionRung::Human);
    let to = ask_to(vault, &check)?;
    let mut rungs = ladder.ladder();
    rungs.ask_to = to.as_ref();
    let decision = rungs.run(
        &question,
        owner,
        &[],
        &state(vault, owner, &check),
        dial,
        &host.bands(),
        Reversibility::ReversibleRead,
        &RetrievalDeadline::hard(Instant::now(), ASK_BUDGET),
    )?;
    let now = oneiron_vault_contract::now_ts();
    let bound = vault.bind_health_answer(&HealthAnswer {
        principal: owner,
        question: &question,
        dial,
        decision: &decision,
        crossing: &check.crossing,
        binding: &binding(),
        now,
    })?;
    let (question, unit) = (question.id.to_hex(), bound.unit.to_hex());
    check.state = match &decision.answer {
        DecisionAnswer::Choice(answer) if decision.human_ask.is_none() => CheckState::Answered {
            answer: answer.clone(),
            probability: decision.probability,
            by: AnsweredBy::Ladder(
                decision
                    .receipt
                    .providers
                    .last()
                    .map_or(DecisionRung::Rule, |pin| pin.rung),
            ),
            at: now,
            question,
            unit,
        },
        _ => CheckState::Asked { question, unit },
    };
    check.asked_in = Some(wording);
    if let CheckState::Answered { answer, .. } = &check.state
        && answer == BOT
    {
        tracing::warn!(
            kind = "wire_health",
            subject = %check.subject,
            crossings = check.crossings,
            "the health check answered bot; the work it covers still runs"
        );
    }
    put_check(vault, &check)
}

/// Looks for a role holder's answer to an asked check. The answer is what
/// happened next: it lands as the decision's outcome.
fn poll(server: &SyncServer, owner: EntityId, mut check: HealthCheck) -> Result<()> {
    let CheckState::Asked { question, unit } = &check.state else {
        return Ok(());
    };
    let Some(ask) = server.decision_host().asks().latest(
        &check.question(check.asked_in.as_deref().unwrap_or(WORDING))?,
        owner,
    )?
    else {
        return Ok(());
    };
    let Some(answer) = ask.answer else {
        return Ok(());
    };
    let DecisionAnswer::Choice(label) = answer.answer else {
        return Ok(());
    };
    let unit_id = EntityId::from_hex(unit)?;
    server.vault().record_health_outcome(
        owner,
        unit_id,
        &label,
        oneiron_vault_contract::now_ts(),
    )?;
    check.state = CheckState::Answered {
        answer: label,
        probability: None,
        by: AnsweredBy::Owner,
        at: answer.answered_at,
        question: question.clone(),
        unit: unit.clone(),
    };
    put_check(server.vault(), &check)
}

/// One pass: fold every new crossing in, ask each held check, and look for
/// the owner's answers. A check that fails stays as it was for the next pass.
fn sweep(server: &SyncServer) -> Result<()> {
    for crossing in unread(server)? {
        fold(server.vault(), crossing)?;
    }
    let open: Vec<HealthCheck> = checks(server.vault())?
        .into_iter()
        .filter(HealthCheck::open)
        .collect();
    if open.is_empty() {
        return Ok(());
    }
    let owner = server
        .vault()
        .ensure_embedded_owner_actor()
        .map_err(|error| Error::InvalidConfig(format!("no owner principal: {error}")))?;
    for check in open {
        let subject = check.subject.clone();
        let asked = match check.state {
            CheckState::Held => ask(server, owner, check),
            CheckState::Asked { .. } => poll(server, owner, check),
            CheckState::Answered { .. } => Ok(()),
        };
        if let Err(error) = asked {
            tracing::warn!(%error, %subject, "wire health check stays held for the next pass");
        }
    }
    Ok(())
}

/// The owner records what happened next to a check's crossing `unit`: a bot
/// or a valid burst. It labels the bound decision.
pub fn record_outcome(vault: &Vault, unit: EntityId, outcome: &str) -> Result<EntityId> {
    if outcome != VALID_BURST && outcome != BOT {
        return Err(Error::InvalidConfig(format!(
            "a health outcome is {VALID_BURST} or {BOT}"
        )));
    }
    let owner = vault
        .ensure_embedded_owner_actor()
        .map_err(|error| Error::InvalidConfig(format!("no owner principal: {error}")))?;
    vault.record_health_outcome(owner, unit, outcome, oneiron_vault_contract::now_ts())
}

/// Starts the worker. Each pass runs on a blocking thread, held by `admit`
/// (a managed vault frozen for reap skips the tick): the ladder's model
/// rungs block on the server's runtime.
pub(crate) fn spawn(
    server: &Arc<SyncServer>,
    admit: crate::server::HousekeepingAdmission,
) -> tokio::task::JoinHandle<()> {
    let weak = Arc::downgrade(server);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(SWEEP_EVERY);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let Some(server) = weak.upgrade() else {
                break;
            };
            let Some(pass) = admit() else {
                continue;
            };
            match tokio::task::spawn_blocking(move || {
                let _pass = pass;
                sweep(&server)
            })
            .await
            {
                Ok(Err(error)) => {
                    tracing::warn!(%error, "wire health sweep failed; it runs again next tick");
                }
                Err(error) => tracing::warn!(%error, "wire health sweep stopped"),
                Ok(Ok(())) => {}
            }
        }
    })
}
