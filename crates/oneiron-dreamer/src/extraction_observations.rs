//! One extraction attempt's consolidation observations, paged to the end.
//!
//! [`read_observations`] pages `vault.consolidation.extraction.observations.page`
//! from the first cursor to the last, carrying the attempt, its clock and the
//! caller's candidates on every call, and gathers the pages' candidate,
//! prior and replay observations with their similarity scores into one
//! [`Observations`]. It sends no `limit`, so each page holds whatever the
//! engine's effective cap allows. It judges nothing: the later policy reads
//! the gathered mirrors.
//!
//! Every page echoes the attempt and its clock and names the policy and facts
//! pins it was read under. The reader refuses a page that echoes another
//! attempt or clock or another policy pin, and it stops stale when a later
//! page names another facts pin; a cursor that does not advance stops the
//! read as undecodable.

use std::fmt;

use oneiron_remote::OneironClient;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// The read the reader pages to the end.
pub const OBSERVATIONS_PAGE_VERB: &str = "vault.consolidation.extraction.observations.page";

/// One extraction attempt's consolidation observations, gathered across every page.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Observations {
    /// The extraction attempt the pages read.
    pub attempt: String,
    /// The attempt's clock, in Unix milliseconds, that every page echoed.
    pub now_ms: u64,
    /// The pin of the effective policy every page was read under.
    pub policy_pin: String,
    /// The pin of the facts every page was read under.
    pub facts_pin: String,
    /// The pages' candidate observations, in page order.
    pub candidates: Vec<CandidateObservation>,
    /// The pages' listing observations, in page order.
    pub listed: Vec<ListedObservation>,
    /// The pages' prior observations, in page order.
    pub priors: Vec<PriorObservation>,
    /// The pages' replay observations, in page order.
    pub replay: Vec<ReplayObservation>,
    /// The pages' similarity scores, in page order.
    pub scores: Vec<SimilarityScore>,
}

/// One extraction observations page: the fields the reader gathers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Page {
    /// The extraction attempt the page read.
    pub attempt: String,
    /// The attempt's clock, in Unix milliseconds, that the page echoed.
    pub now_ms: u64,
    /// The pin of the effective policy the page was read under.
    pub policy_pin: String,
    /// The pin of the facts the page was read under.
    pub facts_pin: String,
    /// The page's candidate observations, in page order.
    pub candidates: Vec<CandidateObservation>,
    /// The page's listing observations, in page order.
    pub listed: Vec<ListedObservation>,
    /// The page's prior observations, in page order.
    pub priors: Vec<PriorObservation>,
    /// The page's replay observations, in page order.
    pub replay: Vec<ReplayObservation>,
    /// The page's similarity scores, in page order.
    pub scores: Vec<SimilarityScore>,
    /// The cursor after the last served row, set only when a later row reads.
    pub next: Option<String>,
}

/// One candidate as the page observed it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CandidateObservation {
    /// The candidate's position in the request's candidates, in order.
    pub index: usize,
    /// The candidate's claim, as the engine keys it.
    pub claim: String,
    /// The identity token of the candidate's native equality key.
    pub identity_token: String,
    /// The topic token of the candidate's native equality key.
    pub topic_token: String,
    /// The value token of the candidate's native equality key.
    pub value_token: String,
    /// The slice token of the candidate's native equality key.
    pub slice_token: String,
    /// The candidate's predicate in claim grammar.
    pub predicate: String,
    /// The claim this candidate corrects, when it corrects one.
    pub corrects: Option<String>,
    /// The candidate's meet, as the engine computed it from the facts read.
    pub meet: String,
    /// Whether native derive would stamp this candidate Observed.
    pub observed: bool,
    /// How many verified distinct citations the candidate carries.
    pub evidence_count: usize,
    /// The earliest verified evidence time, in Unix milliseconds, or the
    /// candidate's own time when no verified evidence reads.
    pub first_seen_ms: u64,
    /// The latest verified evidence time, in Unix milliseconds.
    pub latest_ms: u64,
    /// How many distinct diversity buckets the candidate's evidence spans.
    pub diversity: usize,
    /// How many readable in-slice incoming references the candidate's subject carries.
    pub fan_in: u64,
    /// How many of the candidate's references are new.
    pub new_refs: u64,
    /// Whether the candidate has a stored vector.
    pub has_vector: bool,
    /// The candidate's named facet, when it names one.
    pub named_facet: Option<String>,
    /// The facet of the scope the candidate was observed in, for a separate
    /// facet comparison.
    pub scope_facet: String,
    /// The project of the scope the candidate was observed in, for a separate
    /// project comparison.
    pub scope_project: String,
    /// The facet the candidate replays under.
    pub replay_facet: String,
    /// The listed indexes this candidate may correct, in native pairs order.
    pub correctable: Vec<usize>,
    /// Whether the effective policy names the candidate predicate single-valued.
    pub single_valued: bool,
}

/// One listed claim as the page observed it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ListedObservation {
    /// The listed claim, as the engine keys it.
    pub claim: String,
    /// The subject the listing shows the claim about, as the engine keys it.
    pub subject: String,
    /// The version the page served the listed row at.
    pub version: SourceVersion,
}

/// One prior claim as the page observed it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PriorObservation {
    /// The prior claim, as the engine keys it.
    pub claim: String,
    /// The version the page served the prior's source row at.
    pub version: SourceVersion,
    /// The identity token of the prior's native equality key.
    pub identity_token: String,
    /// The topic token of the prior's native equality key.
    pub topic_token: String,
    /// The value token of the prior's native equality key.
    pub value_token: String,
    /// The prior's source, as the engine names it.
    pub source: String,
    /// The prior's standing, as the page serves it.
    pub standing: String,
    /// Whether the Dreamer may write against this prior.
    pub writable: bool,
    /// The facet of the scope the prior was observed in, for a separate
    /// facet comparison.
    pub scope_facet: String,
    /// The project of the scope the prior was observed in, for a separate
    /// project comparison.
    pub scope_project: String,
    /// The positions in the request's candidates whose scope fully equals this
    /// prior's scope, each judged under that candidate's verified meet.
    pub scope_equal_candidates: Vec<usize>,
    /// The ascending positions whose meet admits this prior without widening.
    pub non_widening_candidates: Vec<usize>,
    /// The ascending positions in the request's candidates whose native
    /// identity subject and predicate equal this prior's stored subject and
    /// predicate: the head condition a lone candidate's bound correction checks.
    pub subject_predicate_equal_candidates: Vec<usize>,
}

/// One replayed row as the page observed it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplayObservation {
    /// The position in the request's candidates that this replay row replays.
    pub index: usize,
    /// The replayed claim, as the engine keys it.
    pub claim: String,
    /// The version the page served the replayed row at.
    pub version: SourceVersion,
    /// The identity token of the replayed row's native equality key.
    pub identity_token: String,
    /// The topic token of the replayed row's native equality key.
    pub topic_token: String,
    /// The value token of the replayed row's native equality key.
    pub value_token: String,
    /// The facet of the scope the row was replayed in, for a separate facet
    /// comparison.
    pub scope_facet: String,
    /// The project of the scope the row was replayed in, for a separate
    /// project comparison.
    pub scope_project: String,
    /// Whether the replayed scope fully equals the candidate's scope under the
    /// candidate's verified meet; false is allowed, since the page judges facts
    /// only.
    pub scope_equal: bool,
}

/// One cosine similarity between two candidates.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SimilarityScore {
    /// The first candidate's position in the request's candidates.
    pub i: usize,
    /// The second candidate's position in the request's candidates.
    pub j: usize,
    /// The cosine similarity between the two candidates, or none when the
    /// engine's cosine refuses their stored vectors.
    pub cosine: Option<f64>,
}

/// One source row's version as a page served it, mirroring the engine's
/// `SourceVersion` without depending on the engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SourceVersion {
    /// The source row, as 32 lowercase hexadecimal digits.
    pub entity: String,
    /// The row's entity type code.
    pub entity_type: u8,
    /// When the vault learned the revision read.
    pub learned_at: u64,
    /// The domain-separated evidence hash of the logical body read, as
    /// `blake3:<hex>`.
    pub revision: String,
    /// For a turn, `blake3:<hex>` over every fact its text was projected
    /// from; `None` for any other row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projection: Option<String>,
}

/// Why a read stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The client refused a call; `code` and `message` are the engine's.
    Client {
        /// The verb the client refused.
        verb: &'static str,
        /// The engine's refusal code, such as `LEASE_REQUIRED` or `FORBIDDEN`.
        code: String,
        /// The engine's refusal message.
        message: String,
    },
    /// A verb's answer did not read as the reader reads it.
    Decode {
        /// The verb whose answer did not read.
        verb: &'static str,
        /// What did not read.
        message: String,
    },
    /// The facts moved under the read: a later page names another facts pin.
    StaleFacts {
        /// The first page's facts pin.
        expected: String,
        /// The later page's facts pin.
        actual: String,
    },
}

impl Error {
    /// The engine's code for a refused call, such as `LEASE_REQUIRED` or
    /// `FORBIDDEN`; `None` for an answer that did not decode or facts that
    /// moved under the read.
    #[must_use]
    pub fn code(&self) -> Option<&str> {
        match self {
            Self::Client { code, .. } => Some(code),
            Self::Decode { .. } | Self::StaleFacts { .. } => None,
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
                "{verb} answered what the extraction observations cannot read: {message}"
            ),
            Self::StaleFacts { expected, actual } => write!(
                formatter,
                "the facts moved under the read: expected {expected}, served {actual}"
            ),
        }
    }
}

impl std::error::Error for Error {}

/// Reads one extraction attempt's consolidation observations over `client`,
/// the job client of one admitted extraction attempt.
///
/// The reader pages from the first cursor to the last, carrying `attempt`,
/// `now_ms` and the caller's `candidates` on every call, and gathers
/// every page's rows into the returned [`Observations`].
///
/// # Errors
///
/// [`Error::Client`] when the client refuses a call (the attempt's lease
/// ended, the Dreamer's reach is gone, a storage error). [`Error::Decode`]
/// when an answer does not read as a page, a page echoes another attempt or
/// clock or another policy pin, or a page's cursor does not advance.
/// [`Error::StaleFacts`] when a later page names another facts pin.
pub fn read_observations(
    client: &OneironClient,
    attempt: &str,
    now_ms: u64,
    candidates: &[Value],
) -> Result<Observations, Error> {
    let mut collected = Observations {
        attempt: attempt.to_owned(),
        now_ms,
        policy_pin: String::new(),
        facts_pin: String::new(),
        candidates: Vec::new(),
        listed: Vec::new(),
        priors: Vec::new(),
        replay: Vec::new(),
        scores: Vec::new(),
    };
    let mut cursor: Option<String> = None;
    let mut first = true;
    loop {
        let page = read_page(client, attempt, now_ms, candidates, cursor.as_deref())?;
        check_echo(&page, attempt, now_ms)?;
        if first {
            collected.policy_pin = page.policy_pin;
            collected.facts_pin = page.facts_pin;
            first = false;
        } else {
            check_pins(&page, &collected)?;
        }
        collected.candidates.extend(page.candidates);
        collected.listed.extend(page.listed);
        collected.priors.extend(page.priors);
        collected.replay.extend(page.replay);
        collected.scores.extend(page.scores);
        match page.next {
            None => return Ok(collected),
            Some(next) if cursor.as_deref() == Some(next.as_str()) => {
                return Err(Error::Decode {
                    verb: OBSERVATIONS_PAGE_VERB,
                    message: "the page cursor did not advance".to_owned(),
                });
            }
            Some(next) => cursor = Some(next),
        }
    }
}

/// The scoped-read answer around a page; the narrowing receipt beside `value`
/// stays unread.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct PageEnvelope {
    /// The page the answer carries.
    value: Page,
}

/// Reads the page after `cursor` for `attempt` at `now_ms` over `candidates`.
fn read_page(
    client: &OneironClient,
    attempt: &str,
    now_ms: u64,
    candidates: &[Value],
    cursor: Option<&str>,
) -> Result<Page, Error> {
    let answer = call(
        client,
        OBSERVATIONS_PAGE_VERB,
        json!({
            "attempt": attempt,
            "now_ms": now_ms,
            "candidates": candidates,
            "cursor": cursor,
        }),
    )?;
    decode::<PageEnvelope>(OBSERVATIONS_PAGE_VERB, answer).map(|envelope| envelope.value)
}

/// Refuses a page that echoes another attempt or clock.
fn check_echo(page: &Page, attempt: &str, now_ms: u64) -> Result<(), Error> {
    if page.attempt != attempt {
        return Err(Error::Decode {
            verb: OBSERVATIONS_PAGE_VERB,
            message: format!(
                "the page echoes attempt {:?}, not {attempt:?}",
                page.attempt
            ),
        });
    }
    if page.now_ms != now_ms {
        return Err(Error::Decode {
            verb: OBSERVATIONS_PAGE_VERB,
            message: format!("the page echoes now_ms {}, not {now_ms}", page.now_ms),
        });
    }
    Ok(())
}

/// Refuses a page read under another policy pin, and reports facts that moved
/// under the read.
fn check_pins(page: &Page, collected: &Observations) -> Result<(), Error> {
    if page.policy_pin != collected.policy_pin {
        return Err(Error::Decode {
            verb: OBSERVATIONS_PAGE_VERB,
            message: "the page was read under another policy pin".to_owned(),
        });
    }
    if page.facts_pin != collected.facts_pin {
        return Err(Error::StaleFacts {
            expected: collected.facts_pin.clone(),
            actual: page.facts_pin.clone(),
        });
    }
    Ok(())
}

/// Calls `verb` with `input` over the bound client.
fn call(client: &OneironClient, verb: &'static str, input: Value) -> Result<Value, Error> {
    client
        .agent_verb(verb, input)
        .map_err(|error| Error::Client {
            verb,
            code: error.code,
            message: error.message,
        })
}

/// Reads `answer` as `T`.
fn decode<T: DeserializeOwned>(verb: &'static str, answer: Value) -> Result<T, Error> {
    serde_json::from_value(answer).map_err(|error| Error::Decode {
        verb,
        message: error.to_string(),
    })
}
