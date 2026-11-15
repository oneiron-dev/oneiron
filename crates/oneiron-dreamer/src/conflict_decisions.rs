//! Builds bound extraction verdict packs and reduces their answers as pure policy.
//!
//! The engine alone renders and measures reads. Start with Whole, then supply
//! its typed layout refusal to the step function. Histories contain only
//! successful verdict results; this module makes no client calls or writes.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::extraction_observations::{Observations, SourceVersion};
use crate::extraction_routing::JudgeSet;

mod answers;
mod questions;
mod steps;

pub use answers::{read_answers, read_layout};
pub(crate) use questions::{across, prior_pins};
pub use questions::{
    correction, correction_final, correction_pages, identity_final, resolution, resolution_final,
    resolution_pages,
};
pub use steps::{correction_step, resolution_step};

/// Borrows the complete operand universe and the observations served for it.
#[derive(Debug, Clone, Copy)]
pub struct Input<'a> {
    /// Borrows candidate operands in unchanged request order.
    pub candidates: &'a [Value],
    /// Borrows the engine's served claim identifiers, listing and prior pins.
    pub observations: &'a Observations,
}

/// Borrows one routed judge set within the complete operand universe.
#[derive(Debug, Clone, Copy)]
pub struct ResolutionInput<'a> {
    /// Borrows the complete operands and their observations.
    pub input: Input<'a>,
    /// Borrows the set whose member positions select this conflict.
    pub set: &'a JudgeSet,
}

/// Names the native read a pack asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtractionRead {
    /// Asks which listed claims the operands correct.
    Correction,
    /// Asks one candidate's final listed identity choice.
    CorrectionFinal,
    /// Asks one conflict's resolution and initial identity groups.
    Resolution,
    /// Asks the resolution over differing page answers.
    ResolutionFinal,
    /// Asks one final candidate identity round.
    IdentityFinal,
}

/// Names the whole read, one engine page or one final round.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExtractionPart {
    /// Asks all entries without a page marker.
    Whole,
    /// Asks the zero-based page of the engine's rebuilt page count.
    Page {
        /// Names the zero-based page.
        page: usize,
        /// Names the engine's total page count.
        pages: usize,
    },
    /// Asks a final round, zero for resolution and one-based for identity.
    Final {
        /// Names the final round.
        round: usize,
    },
}

/// Pins one served listed or prior claim at its observed version.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedClaim {
    /// Names the claim as served lowercase hexadecimal.
    pub claim: String,
    /// Holds the source version served for that claim.
    pub version: SourceVersion,
}

/// Holds one native question's key and canonical ordered options.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackQuestion {
    /// Holds native text and decimal key parts.
    pub key: Vec<String>,
    /// Holds canonical text, literal listed identifiers or candidate aliases.
    pub options: Vec<String>,
}

/// Replays a canonical answer without replacing its actual decision trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EarlierAnswer {
    /// Names the earlier question by its pack key.
    pub key: Vec<String>,
    /// Holds a canonical option, using candidate aliases for candidate claims.
    pub answer: String,
}

/// Mirrors the engine's pack while leaving already-built operands as JSON.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtractionPack {
    /// Names the read the engine rebuilds.
    pub read: ExtractionRead,
    /// Names its whole, page or final part.
    pub part: ExtractionPart,
    /// Holds the complete, unchanged operand array.
    pub candidates: Vec<Value>,
    /// Holds listed pins in served order for correction reads.
    pub listed: Vec<PinnedClaim>,
    /// Holds the selected conflict's prior pins in native order.
    pub priors: Vec<PinnedClaim>,
    /// Holds questions in native pack order.
    pub questions: Vec<PackQuestion>,
    /// Holds initial answers followed by all earlier final rounds.
    pub earlier: Vec<EarlierAnswer>,
    /// Explicitly selects the conflict's ordered positions in candidates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub set_members: Option<Vec<usize>>,
}

/// Names one eligible pair by its positions in the unchanged arrays.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtractionCorrectionPair {
    /// Names a position in the complete candidate array.
    pub candidate: usize,
    /// Names a position in the served listed array.
    pub listed: usize,
}

/// Mirrors only the typed layout field, without measuring any rendered state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExtractionLayout {
    /// Holds correction pair entries in engine page order.
    CorrectionPages {
        /// Holds each page's ordered candidate and listed positions.
        pages: Vec<Vec<ExtractionCorrectionPair>>,
    },
    /// Holds resolution member positions in engine page order.
    ResolutionPages {
        /// Holds each page's positions in the complete candidate array.
        pages: Vec<Vec<usize>>,
    },
}

/// Holds one engine page's part and its unchanged entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page<T> {
    /// Holds the page index and engine page count.
    pub part: ExtractionPart,
    /// Holds entries in the engine's layout order.
    pub entries: Vec<T>,
}

/// Borrows one final identity round's shortlist and complete earlier answers.
#[derive(Debug, Clone, Copy)]
pub struct IdentityRound<'a> {
    /// Names the one-based final round.
    pub round: usize,
    /// Holds listed positions for correction or candidate positions for identity.
    pub shortlist: &'a [usize],
    /// Holds initial group answers followed by every earlier final round.
    pub earlier: &'a [EarlierAnswer],
}

/// Preserves the answer of a Choice question, including an actual abstention.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum DecisionAnswer {
    /// Holds the native canonical answer, never a shown label.
    Choice(String),
    /// Records that the ladder abstained.
    Abstain,
}

/// Preserves one answered question's complete ordered provenance entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionEntry {
    /// Holds the native pack key.
    pub key: Vec<String>,
    /// Holds the actual answer, including Abstain.
    pub answer: DecisionAnswer,
    /// Holds probability only for the native empty-final fallback.
    pub p: Option<f64>,
    /// Holds the engine's rung without interpreting it.
    pub rung: Option<String>,
    /// Preserves the engine's question identifier without using it for mapping.
    pub question: String,
    /// Preserves the engine's complete receipt without interpreting it.
    pub receipt: Value,
}

/// Associates validated answer entries with the pack they answered.
#[derive(Debug, Clone, PartialEq)]
pub struct AnsweredPack {
    /// Holds the exact pack asked.
    pub pack: ExtractionPack,
    /// Holds one entry per question in pack order.
    pub entries: Vec<DecisionEntry>,
}

/// Holds either the next pack to ask or the completed pure-policy result.
#[derive(Debug, Clone, PartialEq)]
pub enum Step<T> {
    /// Requests the next bound verdict without making a client call.
    Ask(ExtractionPack),
    /// Returns the completed decision and its actual provenance.
    Finished(T),
}

/// Records one operand's correction and the decisions that chose it.
#[derive(Debug, Clone, PartialEq)]
pub struct Correction {
    /// Names the operand's position in candidates.
    pub candidate: usize,
    /// Names the chosen listed claim, or none when no claim was chosen.
    pub corrects: Option<String>,
    /// Preserves initial groups and final rounds in decision order.
    pub decisions: Vec<DecisionEntry>,
}

/// Records the standing resolution of a judge set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    /// Combines the conflicting values.
    Merge,
    /// Replaces a prior with the newest value.
    Supersede,
    /// Keeps the conflicting values separately.
    Accumulate,
    /// Leaves a single read's explicit escalation standing.
    Escalate,
    /// Leaves no standing answer after absence or a paged escalation.
    NoStandingAnswer,
}

/// Records one judge set's resolution, kept position and actual decisions.
#[derive(Debug, Clone, PartialEq)]
pub struct ConflictDecision {
    /// Records the standing resolution.
    pub resolution: Resolution,
    /// Names the kept candidate position, never a newly derived identifier.
    pub identity: Option<usize>,
    /// Preserves all entries in ask order, including every actual Abstain.
    pub decisions: Vec<DecisionEntry>,
}

/// Explains why pure pack policy refused its inputs or answer history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Rejects a layout for the other read kind.
    WrongLayout,
    /// Rejects an absent or undecodable typed layout field.
    Layout(String),
    /// Rejects missing or inconsistent served positions and pins.
    Observations(String),
    /// Rejects a page, shortlist or round that cannot name this read.
    Part(String),
    /// Rejects a verdict whose entries do not match its pack.
    Answers(String),
    /// Rejects a history that does not follow the next native pack.
    History,
    /// Rejects an absent replay answer when canonical none is not offered.
    EarlierAbsence,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "extraction conflict decisions: {self:?}")
    }
}

impl std::error::Error for Error {}
