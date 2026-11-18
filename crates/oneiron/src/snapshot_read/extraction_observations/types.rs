//! Wire facts for a pinned, word-free extraction observations read.

use serde::{Deserialize, Serialize};

use crate::claim::ClaimSource;
use crate::snapshot_read::SourceVersion;
use crate::verbs::CandidateOperand;

/// The candidate operands and host clock of one extraction observations read.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExtractionObservationsPageRequest {
    /// The queued extraction attempt in lowercase hexadecimal.
    pub attempt: String,
    /// The host-supplied attempt clock in Unix milliseconds.
    pub now_ms: u64,
    /// The proposed candidates, named by their positions in this array.
    pub candidates: Vec<CandidateOperand>,
    /// The preceding page's cursor, absent for the first page.
    pub cursor: Option<String>,
    /// The requested row bound, capped by the effective snapshot settings.
    pub limit: Option<u32>,
}

/// One bounded page of facts, with pins covering the complete read.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionObservationsPage {
    /// The extraction attempt whose live branch was checked.
    pub attempt: String,
    /// The host clock carried by the request, unchanged.
    pub now_ms: u64,
    /// The effective extraction policy pin shared with the inputs page.
    pub policy_pin: String,
    /// The pin of the request operands, clock, policy and complete fact set.
    pub facts_pin: String,
    /// The candidate rows on this page, in operand order.
    pub candidates: Vec<CandidateObservation>,
    /// The rebuilt correction listing rows on this page, in native first-seen order.
    pub listed: Vec<ListedObservation>,
    /// The admitted prior rows on this page, in native order.
    pub priors: Vec<PriorObservation>,
    /// The unlisted provisional rows on this page, separate from priors.
    pub replay: Vec<ReplayObservation>,
    /// The candidate pair scores on this page, with no threshold applied.
    pub scores: Vec<SimilarityScore>,
    /// The next section and offset bound to the same complete fact set.
    pub next: Option<String>,
}

/// The engine's facts about one candidate operand, without its words.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateObservation {
    /// The operand's zero-based position in the request.
    pub index: usize,
    /// The engine-derived claim identifier in lowercase hexadecimal.
    pub claim: String,
    /// The equality token for the full native conflict identity.
    pub identity_token: String,
    /// The equality token for the native question key.
    pub topic_token: String,
    /// The equality token for the normalized native value key.
    pub value_token: String,
    /// The equality token for the native same-slice tuple.
    pub slice_token: String,
    /// The checked predicate, including its full suffix.
    pub predicate: String,
    /// The valid listed correction target, when the operand names one.
    pub corrects: Option<String>,
    /// The source meet of the native verified evidence set.
    pub meet: ClaimSource,
    /// Whether the derivation rule would stamp an Observed preference.
    pub observed: bool,
    /// The native verified citation count.
    pub evidence_count: usize,
    /// The earliest evidence time, with the native candidate-time fallback.
    pub first_seen_ms: u64,
    /// The latest verified evidence time in Unix milliseconds.
    pub latest_ms: u64,
    /// The native distinct speaker-or-claim set size.
    pub diversity: usize,
    /// The count of readable in-slice incoming references.
    pub fan_in: u64,
    /// The references newer than the last review or candidate clock.
    pub new_refs: u64,
    /// Whether the guarded native candidate identifier has a stored vector.
    pub has_vector: bool,
    /// The facet explicitly named by the candidate's scope, when valid.
    pub named_facet: Option<String>,
    /// The fresh scope facet used by the native attachment comparison.
    pub scope_facet: String,
    /// The fresh project stamp used by both native scope comparisons.
    pub scope_project: String,
    /// The explicit or vault-default facet used by replay comparison.
    pub replay_facet: String,
    /// The listed indexes this candidate may correct, in native pairs order.
    pub correctable: Vec<usize>,
    /// Whether the effective policy names the candidate predicate single-valued.
    pub single_valued: bool,
}

/// One rebuilt correction listing row, without predicate or value words.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListedObservation {
    /// The listed claim identifier in native first-seen order.
    pub claim: String,
    /// The subject the listing shows the claim about.
    pub subject: String,
    /// The source version read under the caller's live authority.
    pub version: SourceVersion,
}

/// One admitted prior, with equality and scope facts but no value words.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriorObservation {
    /// The stored claim identifier in native prior order.
    pub claim: String,
    /// The source version read under the caller's live authority.
    pub version: SourceVersion,
    /// The equality token for the full native conflict identity.
    pub identity_token: String,
    /// The equality token for the native question key.
    pub topic_token: String,
    /// The equality token for the native value key.
    pub value_token: String,
    /// The stored source, with the native Imported fallback when absent.
    pub source: ClaimSource,
    /// The native standing, either prior or provisional.
    pub standing: String,
    /// Whether the native exact prior write check currently passes.
    pub writable: bool,
    /// The prior's stored facet stamp.
    pub scope_facet: String,
    /// The prior's stored project stamp.
    pub scope_project: String,
    /// The operands whose fresh full scope equals this scope under their meet.
    pub scope_equal_candidates: Vec<usize>,
    /// The ascending operand positions whose meet admits this prior without widening.
    pub non_widening_candidates: Vec<usize>,
    /// The ascending operand positions whose native identity subject and
    /// predicate equal this prior's stored subject and predicate: the head
    /// condition a lone candidate's bound correction checks.
    pub subject_predicate_equal_candidates: Vec<usize>,
}

/// One reachable unlisted provisional head for a single operand's cohort.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayObservation {
    /// The operand whose subject and predicate define this cohort.
    pub index: usize,
    /// The stored head identifier, which carries no prior write right.
    pub claim: String,
    /// The source version read in this page's transaction.
    pub version: SourceVersion,
    /// The equality token for the full native conflict identity.
    pub identity_token: String,
    /// The equality token for the native question key.
    pub topic_token: String,
    /// The equality token for the native value key.
    pub value_token: String,
    /// The head's stored facet stamp.
    pub scope_facet: String,
    /// The head's stored project stamp.
    pub scope_project: String,
    /// Whether the full scopes compare equal under this operand's meet.
    pub scope_equal: bool,
}

/// The native cosine for one unordered operand pair with stored vectors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimilarityScore {
    /// The first operand's zero-based position.
    pub i: usize,
    /// The second operand's position, strictly greater than the first.
    pub j: usize,
    /// The native cosine, computed in double precision without a threshold.
    /// None when the native cosine refuses the pair's stored vectors (empty,
    /// unequal lengths, a non-finite or a zero vector): native nomination
    /// fails only when it compares that pair, so the page does not refuse.
    pub cosine: Option<f64>,
}

/// The complete ordered fact set pinned before any page is cut.
#[derive(Serialize)]
pub(super) struct ObservationFacts {
    /// Every candidate observation, in operand order.
    pub(super) candidates: Vec<CandidateObservation>,
    /// Every rebuilt listing observation, in native first-seen order.
    pub(super) listed: Vec<ListedObservation>,
    /// Every admitted prior observation, in native order.
    pub(super) priors: Vec<PriorObservation>,
    /// Every replay cohort observation, in operand and native head order.
    pub(super) replay: Vec<ReplayObservation>,
    /// Every stored-vector pair score, in lexicographic operand order.
    pub(super) scores: Vec<SimilarityScore>,
}
