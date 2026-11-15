//! The Psych Mirror profile job (untangle 6.9i; canon ARCH-0025): one
//! profile key's three tiers in one bound step, landed as one derive
//! PsychProfile item.
//!
//! The job reads the key's ranked claims from the engine, chooses the
//! profile's sources with the pure policy of [`crate::psych_profile`] (the
//! band floor and 50 slots filled round robin by predicate), cites those
//! claims' served versions in one bound `ai.steps.submit`, and commits the
//! checked tiers with the sources' confidence. It never reads or sends a
//! claim's words: the engine renders the psych-mirror skill over the words
//! it serves, checks the reply's shape and token caps, and reads each cited
//! claim's exact words again when the profile lands.

use std::fmt;

use oneiron_remote::OneironClient;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::extraction_observations::SourceVersion;
use crate::psych_profile::{Candidate, ClaimSource, confidence, fill_slots};

/// The ranked claims of one profile key.
const SOURCES_PAGE_VERB: &str = "vault.consolidation.psych_profile.sources.page";
/// The bound generation step over the cited claims.
const STEP_SUBMIT_VERB: &str = "ai.steps.submit";
/// The commit that lands the profile.
const DERIVE_COMMIT_VERB: &str = "vault.derive.commit";

/// The local name of the one item the job commits.
const PROFILE_LOCAL: &str = "profile";

/// The profile key the attempt names, each id as 32 lowercase hexadecimal
/// digits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Input {
    /// The PERSON the profile describes.
    pub person: String,
    /// The facet its claims were born in; `None` for the vault's default.
    pub facet: Option<String>,
    /// The WORLD its claims lie in; `None` for world-free claims.
    pub world: Option<String>,
}

/// What one run did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Outcome {
    /// How many ranked claims the engine served for the key.
    pub served: usize,
    /// How many of them the profile read.
    pub chosen: usize,
    /// Whether the profile landed.
    pub landed: bool,
    /// Why the step ended with no tiers, when it did: the engine refused the
    /// model's reply (the step was paid), or an owner's erase took the step.
    /// Nothing was committed.
    pub reply_refused: Option<String>,
    /// The refusal tokens of a commit the engine refused.
    pub refusals: Vec<String>,
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
    /// The step answered no finished or failed result, such as a budget
    /// trap or a provider rest; the attempt resumes later.
    Unsettled { status: String },
}

impl Error {
    /// The engine's code for a refused call, such as `LEASE_REQUIRED` or
    /// `MODEL_UNAVAILABLE`; `None` otherwise.
    #[must_use]
    pub fn code(&self) -> Option<&str> {
        match self {
            Self::Client { code, .. } => Some(code),
            Self::Decode { .. } | Self::Unsettled { .. } => None,
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
            Self::Decode { verb, message } => {
                write!(
                    formatter,
                    "{verb} answered what the job cannot read: {message}"
                )
            }
            Self::Unsettled { status } => {
                write!(
                    formatter,
                    "{STEP_SUBMIT_VERB} answered {status}, no settled result"
                )
            }
        }
    }
}

impl std::error::Error for Error {}

/// Runs the profile job once over `client`, the job client of one admitted
/// psych profile attempt, for the key `input` names.
///
/// A key that serves no claim the profile may read lands nothing. A reply
/// the engine refused lands nothing and says why in
/// [`Outcome::reply_refused`].
///
/// # Errors
///
/// A refused page, step or commit call (`MODEL_UNAVAILABLE` when no host
/// lends the step; `FORBIDDEN` when a cited claim moved since the page), an
/// answer the job cannot read, and a step with no settled result.
pub fn run(client: &OneironClient, input: &Input) -> Result<Outcome, Error> {
    let page: PageEnvelope = decode(
        SOURCES_PAGE_VERB,
        call(
            client,
            SOURCES_PAGE_VERB,
            json!({ "person": &input.person, "facet": &input.facet, "world": &input.world }),
        )?,
    )?;
    let served = page.value.candidates;
    let mut outcome = Outcome {
        served: served.len(),
        ..Outcome::default()
    };
    let ranked: Vec<Candidate> = served
        .iter()
        .map(|candidate| Candidate {
            predicate: candidate.predicate.clone(),
            band: candidate.band,
            source: candidate.source,
        })
        .collect();
    let chosen: Vec<&ServedCandidate> = fill_slots(&ranked)
        .into_iter()
        .map(|position| &served[position])
        .collect();
    outcome.chosen = chosen.len();
    if chosen.is_empty() {
        return Ok(outcome);
    }
    let versions: Vec<&SourceVersion> = chosen.iter().map(|candidate| &candidate.version).collect();
    let receipt: Receipt = decode(
        STEP_SUBMIT_VERB,
        call(client, STEP_SUBMIT_VERB, json!({ "sources": &versions }))?,
    )?;
    let tiers = match receipt.result {
        Some(StepResult {
            status,
            json: Some(tiers),
            ..
        }) if status == "finished" => decode::<Tiers>(STEP_SUBMIT_VERB, tiers)?,
        Some(StepResult {
            status, failure, ..
        }) if status == "failed" => {
            outcome.reply_refused =
                Some(failure.map_or_else(|| status.clone(), |failure| failure.to_string()));
            return Ok(outcome);
        }
        // An owner's erase took the step's request and result: it is over
        // and never asked again, so the attempt ends as a refused one does.
        Some(StepResult { status, .. }) if status == "erased" => {
            outcome.reply_refused = Some("an owner's erase took the step".to_owned());
            return Ok(outcome);
        }
        Some(StepResult { status, .. }) => return Err(Error::Unsettled { status }),
        None => {
            return Err(Error::Unsettled {
                status: "no result".to_owned(),
            });
        }
    };
    let confidence = confidence(chosen.iter().map(|candidate| candidate.source));
    let view: CommitView = decode(
        DERIVE_COMMIT_VERB,
        call(
            client,
            DERIVE_COMMIT_VERB,
            json!({
                "items": [{
                    "kind": "psych_profile",
                    "spec": {
                        "local": PROFILE_LOCAL,
                        "person": &input.person,
                        "facet": &input.facet,
                        "world": &input.world,
                        "compact": tiers.compact,
                        "text": tiers.text,
                        "narrative": tiers.narrative,
                        "confidence": f64::from(confidence),
                        "claims": versions.iter().map(|version| &version.entity).collect::<Vec<_>>(),
                    },
                }],
                "sources": &versions,
            }),
        )?,
    )?;
    for item in view.items {
        if item.landed {
            outcome.landed = true;
        } else {
            outcome.refusals.extend(item.reasons);
        }
    }
    Ok(outcome)
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

#[derive(Deserialize)]
struct PageEnvelope {
    value: Page,
}

#[derive(Deserialize)]
struct Page {
    candidates: Vec<ServedCandidate>,
}

/// One ranked claim as the page serves it: its version, predicate, band and
/// source, and no words.
#[derive(Deserialize)]
struct ServedCandidate {
    version: SourceVersion,
    predicate: String,
    band: Option<u8>,
    source: Option<ClaimSource>,
}

#[derive(Deserialize)]
struct Receipt {
    result: Option<StepResult>,
}

#[derive(Deserialize)]
struct StepResult {
    status: String,
    #[serde(default)]
    json: Option<Value>,
    #[serde(default)]
    failure: Option<Value>,
}

/// The tiers the engine checked.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Tiers {
    compact: String,
    text: String,
    narrative: String,
}

#[derive(Deserialize)]
struct CommitView {
    items: Vec<CommitItem>,
}

#[derive(Deserialize)]
struct CommitItem {
    landed: bool,
    #[serde(default)]
    reasons: Vec<String>,
}
