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

use oneiron::blob_artifact::esign::EsignRateCheck;
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
use oneiron::scan_check::ScanCheck;
use oneiron::{EntityId, Error, Result, Vault};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::server::SyncServer;
use crate::wire_telemetry::{WireLimitQuestion, WireQuestion, WireThresholds};

/// One check per crossing subject.
const CHECK: &str = "wire:health:v1:check:";
/// How far the check has read the kept call-volume questions.
const CURSOR_WIRE: &str = "wire:health:v1:cursor:wire";
/// How far it has read one `[limits]` row's questions.
const CURSOR_LIMIT: &str = "wire:health:v1:cursor:limit:";
/// How far it has read the e-sign ceremony's burst checks.
const CURSOR_ESIGN: &str = "wire:health:v1:cursor:esign";
/// How often the worker reads new crossings and asks the held checks.
const SWEEP_EVERY: Duration = Duration::from_secs(15);
/// The clock one check's ladder call runs under.
const ASK_BUDGET: Duration = Duration::from_secs(30);
/// An answered check covers its subject's later crossings this long; past it
/// a crossing asks again.
const COVER_SECS: u64 = 3_600;
/// How long after a decision an outcome still labels it.
const OUTCOME_HORIZON_SECS: u64 = 30 * 86_400;
/// The host's wording of the question (ARCH-0044 C5).
const WORDING: &str = "Is everything okay past this threshold: a bot, or a valid burst?";
pub const VALID_BURST: &str = "valid_burst";
pub const BOT: &str = "bot";
/// The wire actor a request with no credential counts under.
const UNAUTHENTICATED: &str = "unauthenticated";
/// Most actors or verbs one crossing's state names, busiest first.
const MAX_NAMED: usize = 16;
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
}

/// Who answered a check.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AnsweredBy {
    /// A ladder rung, below the person.
    Ladder(DecisionRung),
    /// The vault owner role, from its ask queue.
    Owner,
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

    /// The check's own question: one per crossing it first asked about.
    fn question(&self) -> Result<DecisionQuestion> {
        WIRE_HEALTH.question(
            &[self.subject.as_bytes(), &self.first_raised.to_be_bytes()],
            WORDING.to_owned(),
            AnswerContract::Choice {
                options: vec![VALID_BURST.to_owned(), BOT.to_owned()],
            },
        )
    }
}

/// A kept crossing the check has not read yet.
struct Crossing {
    subject: String,
    source: CrossingSource,
    raised_at: u64,
    summary: Value,
    /// The cursor to move once it is folded in.
    read: Option<(String, String)>,
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(value).map_err(|_| Error::CorruptedIndex("wire health check"))
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    rmp_serde::from_slice(bytes).map_err(|_| Error::CorruptedIndex("wire health check"))
}

fn cursor(vault: &Vault, key: &str) -> Result<Option<String>> {
    vault
        .sync_state_get(key)?
        .map(|bytes| {
            String::from_utf8(bytes).map_err(|_| Error::CorruptedIndex("wire health cursor"))
        })
        .transpose()
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

fn named(counts: &std::collections::BTreeMap<String, u64>, over: u64) -> Vec<(String, u64)> {
    let mut named: Vec<(String, u64)> = counts
        .iter()
        .filter(|(_, calls)| **calls > over)
        .map(|(name, calls)| (name.clone(), *calls))
        .collect();
    named.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    named.truncate(MAX_NAMED);
    named
}

fn wire_crossing(key: String, question: &WireQuestion, thresholds: &WireThresholds) -> Crossing {
    let window = &question.evidence;
    let actors = named(&window.by_actor, thresholds.per_actor);
    let verbs = named(&window.by_verb, thresholds.per_verb);
    // The subject is who or what crossed: the actors past their row, else
    // the verbs past theirs.
    let names: Vec<&str> = if actors.is_empty() {
        verbs.iter().map(|(verb, _)| verb.as_str()).collect()
    } else {
        actors.iter().map(|(actor, _)| actor.as_str()).collect()
    };
    let digest = blake3::hash(names.join("\n").as_bytes()).to_hex();
    Crossing {
        subject: format!("wire:{}", &digest[..32]),
        source: CrossingSource::Wire,
        raised_at: window.started_at,
        summary: json!({
            "window": [window.started_at, window.ended_at],
            "per_verb": thresholds.per_verb,
            "per_actor": thresholds.per_actor,
            "calls": window.by_actor.values().fold(0u64, |sum, calls| sum.saturating_add(*calls)),
            "verbs": verbs.iter().map(|(verb, calls)| json!({"verb": verb, "calls": calls})).collect::<Vec<_>>(),
            "actors": actors.iter().map(|(actor, calls)| json!({"actor": actor, "calls": calls})).collect::<Vec<_>>(),
        }),
        read: Some((CURSOR_WIRE.to_owned(), key)),
    }
}

fn limit_crossing(key: String, question: &WireLimitQuestion) -> Crossing {
    Crossing {
        subject: format!("limit:{}", question.row),
        source: CrossingSource::Limit,
        raised_at: question.raised_at,
        summary: json!({
            "row": question.row,
            "bound": question.bound,
            "observed": question.observed,
            "crossings": question.crossings,
        }),
        read: Some((format!("{CURSOR_LIMIT}{}", question.row), key)),
    }
}

fn scan_crossing(check: &ScanCheck) -> Crossing {
    let scope = check.scope.as_deref().unwrap_or("vault");
    Crossing {
        subject: format!("scan:{}:{scope}", check.scan),
        source: CrossingSource::Scan,
        raised_at: check.raised_at,
        summary: json!({
            "scan": check.scan,
            "scope": check.scope,
            "threshold": check.threshold,
            "rows": check.rows,
        }),
        read: None,
    }
}

fn esign_crossing(key: String, check: &EsignRateCheck) -> Crossing {
    let receipt = &check.receipt;
    let scope = receipt.recipient.as_deref().unwrap_or("all");
    Crossing {
        subject: format!("esign:{}:{scope}", receipt.document),
        source: CrossingSource::Esign,
        raised_at: receipt.window_started_at_secs,
        summary: json!({
            "kind": EsignRateCheck::KIND,
            "document": receipt.document,
            "recipient": receipt.recipient,
            "window_started_at": receipt.window_started_at_secs,
            "calls": receipt.count,
            "threshold": check.threshold,
        }),
        read: Some((CURSOR_ESIGN.to_owned(), key)),
    }
}

/// The kept crossings past each cursor. A scan check is sticky, so one with
/// a check of its own is read.
fn unread(server: &SyncServer) -> Result<Vec<Crossing>> {
    let vault = server.vault();
    let telemetry = &server.wire_telemetry;
    let thresholds = telemetry.thresholds()?;
    let mut unread = Vec::new();
    let wire_after = cursor(vault, CURSOR_WIRE)?;
    for (key, question) in telemetry.kept_questions()? {
        if wire_after.as_ref().is_none_or(|after| key > *after) {
            unread.push(wire_crossing(key, &question, &thresholds));
        }
    }
    for (key, question) in telemetry.kept_limit_questions()? {
        let after = cursor(vault, &format!("{CURSOR_LIMIT}{}", question.row))?;
        if after.is_none_or(|after| key > after) {
            unread.push(limit_crossing(key, &question));
        }
    }
    let esign_after = cursor(vault, CURSOR_ESIGN)?;
    for (key, check) in vault.esign_rate_checks_after(esign_after.as_deref())? {
        unread.push(esign_crossing(key, &check));
    }
    for check in vault.scan_checks()? {
        let crossing = scan_crossing(&check);
        if vault
            .sync_state_get(&format!("{CHECK}{}", crossing.subject))?
            .is_none()
        {
            unread.push(crossing);
        }
    }
    Ok(unread)
}

/// Folds one crossing into its subject's check: an open check, or an answered
/// one that still covers it, counts it; otherwise it is a new held check.
fn fold(vault: &Vault, crossing: Crossing) -> Result<()> {
    let key = format!("{CHECK}{}", crossing.subject);
    let existing: Option<HealthCheck> = vault
        .sync_state_get(&key)?
        .map(|b| decode(&b))
        .transpose()?;
    let check = match existing {
        Some(mut check) if check.open() || check.covers(crossing.raised_at) => {
            check.crossings = check.crossings.saturating_add(1);
            check.last_raised = check.last_raised.max(crossing.raised_at);
            check
        }
        _ => HealthCheck {
            subject: crossing.subject,
            source: crossing.source,
            crossing: crossing.summary,
            first_raised: crossing.raised_at,
            last_raised: crossing.raised_at,
            crossings: 1,
            state: CheckState::Held,
        },
    };
    put_check(vault, &check)?;
    if let Some((cursor, read)) = crossing.read {
        vault.sync_state_put(&cursor, read.as_bytes())?;
    }
    Ok(())
}

/// Whether `actor`, as the wire counted it, is a known actor under a grant:
/// it came with a credential that names a live actor of this vault.
fn known_under_grant(vault: &Vault, owner: EntityId, actor: &str) -> bool {
    actor != UNAUTHENTICATED
        && EntityId::from_hex(actor)
            .is_ok_and(|id| id == owner || vault.entity_exists(&id).unwrap_or(false))
}

/// The call's state: the crossing, how often its subject crossed, and for a
/// wire crossing whether every actor past its row is known under a grant.
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
    let granted = !actors.is_empty()
        && actors
            .iter()
            .all(|row| row["known_under_grant"].as_bool() == Some(true));
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
            });
        }
        match &self.inner {
            Some(inner) => inner.decide(call),
            None => Ok(ProviderDecision {
                answer: DecisionAnswer::Abstain,
                probability: None,
                paired: None,
                person: None,
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
            actor,
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
    let question = check.question()?;
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
    let Some(ask) = server
        .decision_host()
        .asks()
        .latest(&check.question()?, owner)?
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
