//! The consolidation conflict settlement (untangle 6.9d): rules the
//! Dreamer's open conflicts through bound verdicts and commits the rulings
//! as Settle items.
//!
//! The job pages `vault.consolidation.conflicts.page` and takes up to eight
//! conflicts after its input cursor, wrapping to the oldest. It skips a
//! conflict whose values the page omitted or whose settlement was reverted:
//! both stay parked for the owner. It rules each other conflict whole, or in
//! pages and rounds when one ask does not hold it, as the engine's parked
//! settlement did. Each ask is one `ai.verdict` on the host's lent ladder.
//! The run's rulings land as the Settle items of one `vault.derive.commit`.
//! The engine rechecks each marker, member, hold and settlement in its own
//! savepoint and refuses an item that no longer holds; a refusal lands
//! nothing.
//!
//! A repeat of the job settles nothing twice: a settled marker no longer
//! opens, so no later page offers it.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Instant;

use oneiron_remote::OneironClient;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};

/// The read the job pages.
pub const CONFLICTS_PAGE_VERB: &str = "vault.consolidation.conflicts.page";
/// The ask the job rules each page with.
pub const AI_VERDICT_VERB: &str = "ai.verdict";
/// The commit the job lands its Settle items with.
pub const DERIVE_COMMIT_VERB: &str = "vault.derive.commit";

/// The most conflicts one run rules: the server's limit per home-timer pass
/// before the move.
const MAX_CONFLICTS_PER_RUN: usize = 8;

/// What one run's verdict asks may spend between them, in milliseconds: the
/// server's sixty seconds per home-timer pass before the move.
const SETTLEMENT_BUDGET_MS: u64 = 60_000;

/// The most bytes one settlement ask's state holds: the engine's
/// `MAX_DECISION_STATE_BYTES`.
const MAX_SETTLEMENT_STATE_BYTES: usize = 65_536;

/// The most keep options one settlement ask offers: the engine's
/// `MAX_KEEP_OPTIONS`, under the Choice contract's 64 options with hold
/// both, dismiss and escalate beside them.
const MAX_SETTLEMENT_KEEP_OPTIONS: usize = 61;

/// How the job words a settlement ask, as the server worded it before the
/// move.
const SETTLEMENT_WORDING: &str = "These claims about one subject contradict each other. Keep the one member that is true and let it supersede the rest, hold both if both can stand, dismiss if they do not really conflict, or escalate if you cannot tell.";

const HOLD_BOTH: &str = "hold_both";
const DISMISS: &str = "dismiss";
const ESCALATE: &str = "escalate";
const KEEP_PREFIX: &str = "keep:";
/// The answer kind of a Choice verdict.
const CHOICE_KIND: &str = "choice";

/// The code a verdict refuses with when no host lends a ladder: the run
/// stops, since no later ask could be answered either.
const MODEL_UNAVAILABLE_CODE: &str = "MODEL_UNAVAILABLE";

/// What the host gives one run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Input {
    /// The marker hex the run starts after, wrapping to the oldest: the
    /// previous run's last marker, or none to start at the oldest.
    pub after: Option<String>,
}

/// What one run did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Outcome {
    /// Conflicts the run finished asking about, ruled or left parked.
    pub asked: u64,
    /// Settle items the engine landed.
    pub settled: u64,
    /// Settle items the engine refused, each with its receipt.
    pub refused: u64,
    /// Conflicts the run left parked: escalated, abstained, answered outside
    /// their options, or refused by the verdict.
    pub left_parked: u64,
    /// Derive batches committed, none or one.
    pub batches: u64,
    /// The last marker the run finished asking about, or none when it
    /// finished none.
    pub last: Option<String>,
}

/// Why a run stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The client refused a call; `code` and `message` are the engine's.
    Client {
        verb: &'static str,
        code: String,
        message: String,
    },
    /// A verb's answer did not read as the job reads it.
    Decode { verb: &'static str, message: String },
}

impl Error {
    /// The engine's code for a refused call, such as `LEASE_REQUIRED` or
    /// `MODEL_UNAVAILABLE`; `None` for an answer that did not decode.
    #[must_use]
    pub fn code(&self) -> Option<&str> {
        match self {
            Self::Client { code, .. } => Some(code),
            Self::Decode { .. } => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Client {
                verb,
                code,
                message,
            } => write!(formatter, "{verb} refused ({code}): {message}"),
            Self::Decode { verb, message } => write!(
                formatter,
                "{verb} answered what the conflict settlement cannot read: {message}"
            ),
        }
    }
}

impl std::error::Error for Error {}

/// Runs the conflict settlement once over `client`, the job client of one
/// admitted conflict-settlement attempt.
///
/// The run stops asking when its budget is spent; a conflict it was asking
/// about then stays uncounted, and `last` stays on the one before it. The
/// rulings the run made land in one batch, also when it stops on an error.
///
/// # Errors
///
/// [`Error::Client`] when the client refuses a conflicts page or the commit,
/// or a verdict refuses with `MODEL_UNAVAILABLE` because no host lends a
/// ladder. [`Error::Decode`] when an answer does not read as a page, a
/// verdict or a commit view, or a page's cursor does not advance. A verdict
/// refusal with another code leaves its conflict parked, and the run goes
/// on.
pub fn run(client: &OneironClient, input: &Input) -> Result<Outcome, Error> {
    let start = Instant::now();
    let mut outcome = Outcome::default();
    let conflicts = collect_conflicts(client, input.after.as_deref())?;
    let mut rulings: Vec<(String, PageAnswer)> = Vec::new();
    for conflict in &conflicts {
        let rows = rows_from_observed(conflict);
        let ruled = match rule_one(client, conflict, &rows, &start) {
            Ok(ruled) => ruled,
            Err(error) => {
                if !rulings.is_empty() {
                    commit(client, settle_items(&rulings))?;
                }
                return Err(error);
            }
        };
        match ruled {
            RuleOutcome::Settled(settlement) => {
                outcome.asked += 1;
                outcome.last = Some(conflict.marker.clone());
                rulings.push((conflict.marker.clone(), settlement));
            }
            RuleOutcome::Parked => {
                outcome.asked += 1;
                outcome.left_parked += 1;
                outcome.last = Some(conflict.marker.clone());
            }
            RuleOutcome::BudgetExhausted => break,
        }
    }
    if !rulings.is_empty() {
        let view = commit(client, settle_items(&rulings))?;
        outcome.batches += 1;
        for item in &view.items {
            if item.landed {
                outcome.settled += 1;
            } else {
                outcome.refused += 1;
            }
        }
    }
    Ok(outcome)
}

/// Takes up to [`MAX_CONFLICTS_PER_RUN`] conflicts: those after `after`,
/// then from the oldest up to `after`, so the conflicts a ladder leaves
/// parked never starve newer ones.
fn collect_conflicts(
    client: &OneironClient,
    after: Option<&str>,
) -> Result<Vec<ObservedConflict>, Error> {
    let mut taken: Vec<ObservedConflict> = Vec::new();
    sweep_from_start(client, after, true, &mut taken)?;
    if taken.len() < MAX_CONFLICTS_PER_RUN && after.is_some() {
        sweep_from_start(client, after, false, &mut taken)?;
    }
    Ok(taken)
}

/// Pages the conflicts from the first page and adds to `taken` each one the
/// sweep wants, until the run holds [`MAX_CONFLICTS_PER_RUN`] or the pages
/// end.
fn sweep_from_start(
    client: &OneironClient,
    after: Option<&str>,
    past_after: bool,
    taken: &mut Vec<ObservedConflict>,
) -> Result<(), Error> {
    let mut cursor: Option<String> = None;
    loop {
        if taken.len() >= MAX_CONFLICTS_PER_RUN {
            return Ok(());
        }
        let page = read_page(client, cursor.as_deref())?;
        for conflict in page.conflicts {
            if taken.len() >= MAX_CONFLICTS_PER_RUN {
                return Ok(());
            }
            if conflict.values_omitted || conflict.reverted {
                continue;
            }
            if wanted_in_sweep(&conflict.marker, after, past_after) {
                taken.push(conflict);
            }
        }
        match page.next {
            None => return Ok(()),
            Some(next) if cursor.as_deref() == Some(next.as_str()) => {
                return Err(Error::Decode {
                    verb: CONFLICTS_PAGE_VERB,
                    message: "the page cursor did not advance".to_owned(),
                });
            }
            Some(next) => cursor = Some(next),
        }
    }
}

/// Whether a sweep takes `marker`: the first sweep takes the markers after
/// `after` (every marker when there is none), the wrap those up to it.
/// Markers are lowercase hex of one length, so text order is id order.
fn wanted_in_sweep(marker: &str, after: Option<&str>, past_after: bool) -> bool {
    match after {
        None => past_after,
        Some(after) => {
            if past_after {
                marker > after
            } else {
                marker <= after
            }
        }
    }
}

/// Reads one conflicts page at `cursor`, the page's own default limit.
fn read_page(client: &OneironClient, cursor: Option<&str>) -> Result<Page, Error> {
    let answer = call(
        client,
        CONFLICTS_PAGE_VERB,
        json!({ "cursor": cursor, "limit": null }),
    )?;
    decode::<PageEnvelope>(CONFLICTS_PAGE_VERB, answer).map(|envelope| envelope.value)
}

/// Commits `items` as one derive batch with no sources.
fn commit(client: &OneironClient, items: Vec<Value>) -> Result<CommitView, Error> {
    let answer = call(
        client,
        DERIVE_COMMIT_VERB,
        json!({ "items": items, "sources": [] }),
    )?;
    decode(DERIVE_COMMIT_VERB, answer)
}

/// Calls `verb` over the attempt's client.
fn call(client: &OneironClient, verb: &'static str, input: Value) -> Result<Value, Error> {
    client
        .agent_verb(verb, input)
        .map_err(|error| Error::Client {
            verb,
            code: error.code,
            message: error.message,
        })
}

/// Reads `verb`'s answer as `T`.
fn decode<T: DeserializeOwned>(verb: &'static str, answer: Value) -> Result<T, Error> {
    serde_json::from_value(answer).map_err(|error| Error::Decode {
        verb,
        message: error.to_string(),
    })
}

/// One stored member or retained alternative as a settlement ask offers it:
/// its id, whether a Keep may name it, and the fields the ask shows.
struct SettleRow {
    id: String,
    keep: bool,
    fields: Map<String, Value>,
}

impl SettleRow {
    /// The row as one call shows it, by `label`: the engine's shape.
    fn shown(&self, label: &str) -> Value {
        let mut row = Map::new();
        row.insert("id".to_owned(), Value::from(label));
        let keep_option = self.keep.then(|| format!("{KEEP_PREFIX}{label}"));
        row.insert("keep_option".to_owned(), json!(keep_option));
        row.extend(self.fields.clone());
        Value::Object(row)
    }

    /// What the row counts against a page's room: its length shown with its
    /// full id, never less than any label shows it.
    fn bytes(&self) -> usize {
        json_len(&self.shown(&self.id))
    }
}

/// Each stored member, then each retained alternative the page serves, in
/// the conflict's order.
fn rows_from_observed(conflict: &ObservedConflict) -> Vec<SettleRow> {
    let mut rows = Vec::new();
    for member in &conflict.members {
        rows.push(SettleRow {
            id: member.claim.clone(),
            keep: member.keep,
            fields: member_fields(member),
        });
    }
    for alternative in &conflict.alternatives {
        rows.push(SettleRow {
            id: alternative.selector.clone(),
            keep: true,
            fields: alternative_fields(alternative),
        });
    }
    rows
}

/// A stored member's shown fields, as the engine shows them.
fn member_fields(member: &ConflictMember) -> Map<String, Value> {
    let mut fields = Map::new();
    fields.insert(
        "predicate".to_owned(),
        Value::from(member.predicate.clone()),
    );
    fields.insert("value".to_owned(), member.value.clone());
    fields.insert("source".to_owned(), json!(member.source));
    fields.insert("approval".to_owned(), Value::from(member.approval.clone()));
    fields.insert("confidence".to_owned(), json!(member.confidence));
    fields.insert("valid_from".to_owned(), json!(member.valid_from));
    fields.insert("valid_to".to_owned(), json!(member.valid_to));
    fields
}

/// A retained alternative's shown fields, as the engine shows them.
fn alternative_fields(alternative: &ConflictAlternative) -> Map<String, Value> {
    let mut fields = Map::new();
    fields.insert("retained".to_owned(), Value::from(true));
    fields.insert(
        "predicate".to_owned(),
        Value::from(alternative.predicate.clone()),
    );
    fields.insert("value".to_owned(), alternative.value.clone());
    fields.insert("source".to_owned(), Value::from(alternative.source.clone()));
    fields.insert("confidence".to_owned(), json!(alternative.confidence));
    fields
}

/// One measured call's `C` labels, numbered in the order the call shows its
/// rows, as the engine labels them.
struct CallLabels {
    numbers: BTreeMap<String, usize>,
}

impl CallLabels {
    fn empty() -> Self {
        Self {
            numbers: BTreeMap::new(),
        }
    }

    /// `id`'s label, assigned now when it has none.
    fn assign(&mut self, id: &str) -> String {
        if let Some(number) = self.numbers.get(id) {
            return format!("C{number}");
        }
        let number = self.numbers.len() + 1;
        self.numbers.insert(id.to_owned(), number);
        format!("C{number}")
    }

    /// `id`'s label, when the call labelled it.
    fn label(&self, id: &str) -> Option<String> {
        self.numbers.get(id).map(|number| format!("C{number}"))
    }
}

/// What one page, or one whole ask, answered short of leaving the conflict
/// parked.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PageAnswer {
    Keep(String),
    HoldBoth,
    Dismiss,
}

impl PageAnswer {
    /// The answer as a call shows it: a Keep by the member's label there, or
    /// `keep` when the call does not show that member.
    fn shown(&self, labels: &CallLabels) -> String {
        match self {
            Self::Keep(id) => labels.label(id).map_or_else(
                || "keep".to_owned(),
                |label| format!("{KEEP_PREFIX}{label}"),
            ),
            Self::HoldBoth => HOLD_BOTH.to_owned(),
            Self::Dismiss => DISMISS.to_owned(),
        }
    }

    /// The answer as the bound verdict's page state names it.
    fn canonical(&self) -> String {
        match self {
            Self::Keep(id) => format!("{KEEP_PREFIX}{id}"),
            Self::HoldBoth => HOLD_BOTH.to_owned(),
            Self::Dismiss => DISMISS.to_owned(),
        }
    }
}

/// Where one ask sits: its round, page and the round's page count when the
/// conflict is asked in more than one, and what the round before answered.
struct AskPart<'p> {
    at: Option<(usize, usize, usize)>,
    before: &'p [PageAnswer],
}

/// `value`'s serialized length.
fn json_len(value: &Value) -> usize {
    serde_json::to_vec(value).map_or(usize::MAX, |bytes| bytes.len())
}

/// The state an ask over `rows` at `part` reads, as the engine builds it:
/// the contested predicates and every row whole, with the page and the
/// round before's answers when the ask has them.
fn state_of(
    predicates: &[String],
    rows: &[&SettleRow],
    part: &AskPart<'_>,
    labels: &mut CallLabels,
) -> Value {
    let mut members: Vec<Value> = Vec::new();
    for row in rows {
        let label = labels.assign(&row.id);
        members.push(row.shown(&label));
    }
    let mut state = Map::new();
    state.insert("predicates".to_owned(), json!(predicates));
    state.insert("members".to_owned(), Value::Array(members));
    if let Some((_, page, pages)) = part.at.filter(|(_, _, pages)| *pages > 1) {
        state.insert("page".to_owned(), json!(page + 1));
        state.insert("pages".to_owned(), json!(pages));
    }
    if !part.before.is_empty() {
        let answers: Vec<String> = part
            .before
            .iter()
            .map(|answer| answer.shown(labels))
            .collect();
        state.insert("page_answers".to_owned(), json!(answers));
    }
    Value::Object(state)
}

/// The bytes an ask over `rows` at `part` would read.
fn state_bytes(predicates: &[String], rows: &[&SettleRow], part: &AskPart<'_>) -> usize {
    json_len(&state_of(predicates, rows, part, &mut CallLabels::empty()))
}

/// Splits `entries` into pages in their order, as the engine's splitter
/// does: each page starts at `frame` bytes, and an entry that would take a
/// page past the state bound, or that `admits` refuses, opens the next. A
/// single entry wider than the bound goes whole on a page of its own.
fn split_pages<T: Copy>(
    frame: usize,
    entries: &[T],
    adds: impl Fn(&[T], T) -> usize,
    admits: impl Fn(&[T], T) -> bool,
) -> Vec<Vec<T>> {
    let mut pages: Vec<Vec<T>> = Vec::new();
    let mut page: Vec<T> = Vec::new();
    let mut bytes = frame;
    for &entry in entries {
        let mut added = adds(&page, entry);
        if !page.is_empty()
            && (bytes.saturating_add(added) > MAX_SETTLEMENT_STATE_BYTES || !admits(&page, entry))
        {
            pages.push(std::mem::take(&mut page));
            bytes = frame;
            added = adds(&page, entry);
        }
        page.push(entry);
        bytes = bytes.saturating_add(added);
    }
    if !page.is_empty() || pages.is_empty() {
        pages.push(page);
    }
    pages
}

/// How many of `rows` a Keep may name.
fn keeps(rows: &[&SettleRow]) -> usize {
    rows.iter().filter(|row| row.keep).count()
}

/// Whether a page holding `page` takes `row` beside it: past
/// [`MAX_SETTLEMENT_KEEP_OPTIONS`] keep options a keepable row opens the
/// next page.
fn admits(page: &[&SettleRow], row: &SettleRow) -> bool {
    !row.keep || keeps(page) < MAX_SETTLEMENT_KEEP_OPTIONS
}

/// The canonical options of an ask over `rows`: hold both, dismiss,
/// escalate, then a Keep of each keepable row by its full id.
fn canonical_options(rows: &[&SettleRow]) -> Vec<String> {
    let mut options = vec![
        HOLD_BOTH.to_owned(),
        DISMISS.to_owned(),
        ESCALATE.to_owned(),
    ];
    for row in rows.iter().filter(|row| row.keep) {
        options.push(format!("{KEEP_PREFIX}{}", row.id));
    }
    options
}

/// How the run's asks about one conflict ended.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RuleOutcome {
    /// One settlement: hold both, dismiss, or keep one row.
    Settled(PageAnswer),
    /// Escalated, abstained, answered outside its options, or refused: the
    /// conflict stays parked.
    Parked,
    /// The run's budget was spent before the conflict's asks finished.
    BudgetExhausted,
}

/// What is left of the run's budget, or `None` once it is spent.
fn remaining_ms(start: &Instant) -> Option<u64> {
    let elapsed = start.elapsed().as_millis();
    let budget = u128::from(SETTLEMENT_BUDGET_MS);
    if elapsed >= budget {
        None
    } else {
        u64::try_from(budget - elapsed).ok()
    }
}

/// The bound verdict request for one ask over `page_rows`: the marker and
/// the offered rows as evidence, the canonical options, outbound-effect
/// reversibility, the page state when the ask is one of several, and what is
/// left of the budget as its deadline.
fn verdict_request(
    marker: &str,
    page_rows: &[&SettleRow],
    at: Option<(usize, usize, usize)>,
    before: &[PageAnswer],
    deadline_ms: u64,
) -> Value {
    let mut evidence: Vec<String> = Vec::new();
    evidence.push(marker.to_owned());
    for row in page_rows {
        evidence.push(row.id.clone());
    }
    let state = at.map_or(Value::Null, |(round, page, pages)| {
        let answers: Vec<String> = before.iter().map(PageAnswer::canonical).collect();
        json!({ "round": round, "page": page, "pages": pages, "page_answers": answers })
    });
    json!({
        "question": SETTLEMENT_WORDING,
        "contract": { "kind": "choice", "options": canonical_options(page_rows) },
        "evidence": evidence,
        "reversibility": "outbound_effect",
        "state": state,
        "deadline_ms": deadline_ms,
    })
}

/// Asks one page, or one whole ask, of `marker`'s conflict.
fn ask_one(
    client: &OneironClient,
    marker: &str,
    page_rows: &[&SettleRow],
    at: Option<(usize, usize, usize)>,
    before: &[PageAnswer],
    start: &Instant,
) -> Result<RuleOutcome, Error> {
    let Some(deadline_ms) = remaining_ms(start) else {
        return Ok(RuleOutcome::BudgetExhausted);
    };
    let input = verdict_request(marker, page_rows, at, before, deadline_ms);
    let answer = match call(client, AI_VERDICT_VERB, input) {
        Ok(answer) => answer,
        Err(error) if error.code() == Some(MODEL_UNAVAILABLE_CODE) => return Err(error),
        Err(_) => return Ok(RuleOutcome::Parked),
    };
    let verdict: VerdictView = decode(AI_VERDICT_VERB, answer)?;
    parse_verdict(verdict.answer, page_rows)
}

/// The settlement a verdict's answer names. A Choice outside the ask's
/// options, an abstention or any other answer kind leaves the conflict
/// parked.
fn parse_verdict(answer: Value, page_rows: &[&SettleRow]) -> Result<RuleOutcome, Error> {
    let parsed: VerdictAnswer = decode(AI_VERDICT_VERB, answer)?;
    if parsed.kind != CHOICE_KIND {
        return Ok(RuleOutcome::Parked);
    }
    let Some(choice) = parsed.value.as_str() else {
        return Err(Error::Decode {
            verb: AI_VERDICT_VERB,
            message: "a choice answer names no option".to_owned(),
        });
    };
    Ok(choice_outcome(choice, page_rows))
}

/// The settlement a canonical Choice names: hold both, dismiss, or keep a
/// keepable row this ask offered. Escalate and anything else park.
fn choice_outcome(value: &str, page_rows: &[&SettleRow]) -> RuleOutcome {
    if value == HOLD_BOTH {
        return RuleOutcome::Settled(PageAnswer::HoldBoth);
    }
    if value == DISMISS {
        return RuleOutcome::Settled(PageAnswer::Dismiss);
    }
    if let Some(hex) = value.strip_prefix(KEEP_PREFIX)
        && page_rows.iter().any(|row| row.keep && row.id == hex)
    {
        return RuleOutcome::Settled(PageAnswer::Keep(hex.to_owned()));
    }
    RuleOutcome::Parked
}

/// The pages of one round. Round zero asks once when every row fits one ask
/// with at most [`MAX_SETTLEMENT_KEEP_OPTIONS`] keep options, and otherwise
/// splits the rows by bytes; a later round splits its kept rows by count.
fn pages_for_round<'r>(
    predicates: &[String],
    asked: &mut Vec<&'r SettleRow>,
    round: usize,
) -> Vec<Vec<&'r SettleRow>> {
    if round > 0 {
        return split_pages(0, asked, |_, _| 0, admits);
    }
    let whole = AskPart {
        at: None,
        before: &[],
    };
    if keeps(asked) <= MAX_SETTLEMENT_KEEP_OPTIONS
        && state_bytes(predicates, asked, &whole) <= MAX_SETTLEMENT_STATE_BYTES
    {
        return vec![std::mem::take(asked)];
    }
    let paged = AskPart {
        at: Some((0, 0, 2)),
        before: &[],
    };
    let frame = state_bytes(predicates, &[], &paged);
    split_pages(frame, asked, |_, row| row.bytes().saturating_add(1), admits)
}

/// Rules on one conflict, whole or in pages and rounds, as the engine's
/// parked settlement did:
///
/// - one ask that holds the conflict is its ruling;
/// - a page that escalates, abstains or answers outside its options leaves
///   the conflict parked;
/// - every page holding both is hold both, every page dismissing is dismiss;
/// - otherwise the next round asks among the members the pages kept, with
///   each page's answer beside them. A round whose pages kept none asks one
///   final question over the marker alone.
fn rule_one(
    client: &OneironClient,
    conflict: &ObservedConflict,
    rows: &[SettleRow],
    start: &Instant,
) -> Result<RuleOutcome, Error> {
    let mut asked: Vec<&SettleRow> = rows.iter().collect();
    let mut before: Vec<PageAnswer> = Vec::new();
    let mut round = 0;
    loop {
        let pages = pages_for_round(&conflict.predicates, &mut asked, round);
        let paged = pages.len() > 1 || round > 0;
        let mut answers: Vec<PageAnswer> = Vec::with_capacity(pages.len());
        for (page, page_rows) in pages.iter().enumerate() {
            let at = paged.then_some((round, page, pages.len()));
            match ask_one(client, &conflict.marker, page_rows, at, &before, start)? {
                RuleOutcome::BudgetExhausted => return Ok(RuleOutcome::BudgetExhausted),
                RuleOutcome::Parked => return Ok(RuleOutcome::Parked),
                RuleOutcome::Settled(answer) => {
                    if pages.len() == 1 {
                        return Ok(RuleOutcome::Settled(answer));
                    }
                    answers.push(answer);
                }
            }
        }
        if answers.iter().all(|answer| *answer == PageAnswer::HoldBoth) {
            return Ok(RuleOutcome::Settled(PageAnswer::HoldBoth));
        }
        if answers.iter().all(|answer| *answer == PageAnswer::Dismiss) {
            return Ok(RuleOutcome::Settled(PageAnswer::Dismiss));
        }
        asked = kept_rows(rows, &answers);
        before = answers;
        round += 1;
    }
}

/// The rows the pages' Keep answers name, in the pages' order.
fn kept_rows<'r>(rows: &'r [SettleRow], answers: &[PageAnswer]) -> Vec<&'r SettleRow> {
    let mut kept: Vec<&SettleRow> = Vec::new();
    for answer in answers {
        if let PageAnswer::Keep(id) = answer
            && let Some(row) = rows.iter().find(|row| &row.id == id)
        {
            kept.push(row);
        }
    }
    kept
}

/// One Settle item per ruling, in the derive parser's shape: a Keep names
/// the stored member or the retained alternative's selector.
fn settle_items(rulings: &[(String, PageAnswer)]) -> Vec<Value> {
    let mut items = Vec::new();
    for (marker, settlement) in rulings {
        let outcome = match settlement {
            PageAnswer::HoldBoth => json!(HOLD_BOTH),
            PageAnswer::Dismiss => json!(DISMISS),
            PageAnswer::Keep(id) => json!({ "keep": { "stored": id } }),
        };
        items.push(json!({
            "kind": "settle",
            "spec": {
                "local": format!("settle-{marker}"),
                "marker": { "stored": marker },
                "settlement": outcome,
            },
        }));
    }
    items
}

#[derive(Deserialize)]
struct PageEnvelope {
    value: Page,
}

#[derive(Deserialize)]
struct Page {
    conflicts: Vec<ObservedConflict>,
    next: Option<String>,
}

#[derive(Deserialize)]
struct ObservedConflict {
    marker: String,
    predicates: Vec<String>,
    members: Vec<ConflictMember>,
    alternatives: Vec<ConflictAlternative>,
    reverted: bool,
    values_omitted: bool,
}

#[derive(Deserialize)]
struct ConflictMember {
    claim: String,
    keep: bool,
    predicate: String,
    value: Value,
    source: Option<String>,
    approval: String,
    confidence: f32,
    valid_from: Option<u64>,
    valid_to: Option<u64>,
}

#[derive(Deserialize)]
struct ConflictAlternative {
    selector: String,
    predicate: String,
    value: Value,
    source: String,
    confidence: f32,
}

#[derive(Deserialize)]
struct VerdictView {
    answer: Value,
}

/// A verdict's answer, as `ai.verdict` serializes the engine's
/// `DecisionAnswer`: its kind, and its value when the kind has one.
#[derive(Deserialize)]
struct VerdictAnswer {
    kind: String,
    #[serde(default)]
    value: Value,
}

#[derive(Deserialize)]
struct CommitView {
    items: Vec<CommitItem>,
}

#[derive(Deserialize)]
struct CommitItem {
    landed: bool,
}
