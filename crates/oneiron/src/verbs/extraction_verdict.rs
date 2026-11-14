//! The bound Extraction `ai.verdict` pack: the typed state a Dreamer extraction job sends and the engine rebuilds.
//!
//! An extraction binding reads one pack per verdict call. The job sends the pack as the
//! verdict request state, and the engine re-reads every pinned row, checks each candidate
//! operand, derives each candidate identifier with the native deterministic identifier, and
//! rebuilds the pack questions with the native builders before any model is asked. The pack
//! carries typed bounded candidate operands, listed and prior claim pins, question keys
//! with canonical options, and earlier answers for a final round. Nothing here asks a model
//! or writes a row.
//!
//! Wire forms keep the job from deriving what only the engine knows. An option that names
//! a candidate is written `candidate:<index into candidates>`; the engine maps each alias
//! to its derived identifier before it compares options. A stored claim option is the
//! claim identifier as 32 lowercase hexadecimal digits. Every other option is the native
//! canonical text. A key part is the native text, a number in decimal, or a binary part in
//! lowercase hexadecimal. Bounds and request rules are enforced by the bound handler, not
//! here: only the requested pack array lengths are bounded, with the native decision state
//! bound as the fallback where no native cardinality bound names a smaller limit. There is
//! no whole encoded pack byte cap, so native paged and final operand universes and
//! oversized row behavior stay possible.

use serde::{Deserialize, Serialize};

use crate::snapshot_read::{EvidenceRange, SourceVersion};

/// Which native read one extraction pack asks: a correction read over listed claims, its
/// final identity choice, a resolution read over conflicting candidates with its identity
/// groups, its final resolution choice, or a final identity choice over a shortlist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtractionRead {
    /// Which listed claim each candidate corrects, over whole or paged reads.
    Correction,
    /// Which shortlisted claim one corrected candidate names, in final rounds.
    CorrectionFinal,
    /// How one conflict resolves, with the identity groups a merge keeps.
    Resolution,
    /// Which resolution stands after pages read different ones.
    ResolutionFinal,
    /// Which shortlisted candidate identity a merge keeps, in final rounds.
    IdentityFinal,
}

/// Which part of a pack one read asks: the whole pack, one page of it, or one final round.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExtractionPart {
    /// The whole pack in one read.
    Whole,
    /// One page of a paged pack, with a zero-based page below the page count.
    Page {
        /// The zero-based page this read asks.
        page: usize,
        /// The page count of the paged pack.
        pages: usize,
    },
    /// One final round. A resolution final carries round zero as its sentinel, since its
    /// native question has no round number; an identity final carries its one-based round.
    Final {
        /// The final round this read asks.
        round: usize,
    },
}

/// One bound Extraction verdict pack: the read, its part, the candidate operands the job
/// proposes, the listed and prior claim pins the engine rebuilds, the questions with
/// canonical options, and the earlier answers a final round checks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtractionPack {
    /// The native read this pack asks.
    pub read: ExtractionRead,
    /// The part of the pack this read asks.
    pub part: ExtractionPart,
    /// The candidate operands this pack proposes, in order.
    pub candidates: Vec<CandidateOperand>,
    /// The listed claims the engine rebuilds, in native order.
    #[serde(default)]
    pub listed: Vec<PinnedClaim>,
    /// The prior heads the engine rebuilds, in native order.
    #[serde(default)]
    pub priors: Vec<PinnedClaim>,
    /// The pack questions with canonical options, in native order.
    pub questions: Vec<PackQuestion>,
    /// The earlier page or group answers a final round checks.
    #[serde(default)]
    pub earlier: Vec<EarlierAnswer>,
}

/// One candidate operand: the typed bounded proposal the job shows the model for one
/// extracted candidate. The subject and predicate shape are checked, the value stays a
/// proposal never written or trusted, and the relationship, topic and corrected claim are
/// proposals the native identifier build needs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateOperand {
    /// The candidate subject as 32 lowercase hexadecimal digits.
    pub subject: String,
    /// The candidate predicate in claim grammar.
    pub predicate: String,
    /// The proposed value as JSON, shown to the model and never trusted.
    pub value: serde_json::Value,
    /// The proposed relationship set, inside the attempt bound set when present.
    #[serde(default)]
    pub rel: Option<Vec<String>>,
    /// The proposed topic, canonicalised as the native build canonicalises it.
    #[serde(default)]
    pub topic: Option<serde_json::Value>,
    /// The listed claim this candidate corrects, as 32 lowercase hexadecimal digits.
    #[serde(default)]
    pub corrects: Option<String>,
    /// The source turns this candidate cites, each with its served pin.
    pub evidence: Vec<TurnEvidence>,
}

/// One source turn a candidate cites: the turn reference with the version the job read,
/// and the optional byte span the candidate quotes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TurnEvidence {
    /// The source turn as 32 lowercase hexadecimal digits.
    pub turn: String,
    /// The version the job read the turn at, rechecked at verdict time.
    pub version: SourceVersion,
    /// The quoted byte span in the served words coordinates, or the whole words when absent.
    #[serde(default)]
    pub span: Option<EvidenceRange>,
}

/// One listed or prior claim pin: the claim reference with the version the job read.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedClaim {
    /// The claim as 32 lowercase hexadecimal digits.
    pub claim: String,
    /// The version the job read the claim at, rechecked at verdict time.
    pub version: SourceVersion,
}

/// One pack question: the native key parts with the canonical options in native order.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackQuestion {
    /// The native key parts, each native text, decimal number or lowercase hexadecimal.
    pub key: Vec<String>,
    /// The canonical options in native order, with candidate aliases for derived identifiers.
    pub options: Vec<String>,
}

/// One earlier answer a final round checks: the answered question key with the answer given.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EarlierAnswer {
    /// The answered question key, as the pack questions key it.
    pub key: Vec<String>,
    /// The earlier answer, inside that question canonical options.
    pub answer: String,
}
