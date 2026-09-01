//! BEAM scaffold and fixed scorer for EVAL-001/EVAL-002.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use crate::retrieval_trace_export;
use oneiron::{
    ContextPack, ContextPackBuilder, EmptyReason, EntityId, FieldProfile, PackFormat, PackStats,
    Signal, TimeRange, Vault, VaultConfig,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(crate) const BEAM_128K_TOKEN_BUDGET: usize = 128 * 1024;

const SCHEMA_VERSION: u32 = 2;
const BEAM_CONTEXT_PACK_FORMAT: PackFormat = PackFormat::Yaml;
const BEAM_SCORER_VERSION: &str = "beam-fixed-scorer-v1";
const BEAM_COMPARATOR_VERSION: &str = "beam-comparator-card-v1";
const COST_USD_SCALE: f64 = 1_000_000.0;
const MAX_NORMALIZABLE_COST_USD: f64 = f64::MAX / COST_USD_SCALE;
const LOW_CONFIDENCE_RETRIEVAL_LIMIT: usize = 1;
const BUILTIN_FIXTURE_JSON: &str = include_str!("../fixtures/beam_128k_smoke.fixture.json");
const BUILTIN_MANIFEST_JSON: &str = include_str!("../fixtures/beam_128k_smoke.run.json");
#[cfg(test)]
const CONTRACT_MANIFEST_JSON: &str = include_str!("../fixtures/beam_128k_contract.run.json");
#[cfg(test)]
const CONTRACT_RUN_JSONL: &str = include_str!("../fixtures/beam_128k_contract.run.jsonl");
const EVAL_CONTRACT_VERSION: &str = "oneiron-eval.contract.v1";
const JSONL_CONTRACT_SOURCE_KIND: &str = "jsonl";
const ONEIRON_CONTEXT_PACK_ARM_KIND: &str = "context_pack_http";
const VANILLA_RAG_CONTRACT_ARM_ID: &str = "vanilla-rag";
const VANILLA_RAG_CONTRACT_ARM_KIND: &str = "vanilla-rag";
const VANILLA_RAG_CONFIG_VERSION: &str = "vanilla-rag-v1";
const VANILLA_RAG_FUSION: &str = "rrf(vector,bm25f)";
const VANILLA_RAG_CHUNKING: &str = "one-run-jsonl-corpus-item-per-chunk";
const VANILLA_RAG_EMBEDDER_ID: &str = "oneiron/eval-contract@v1";
const DEFAULT_JSONL_RETRIEVAL_LIMIT: usize = 8;
const BEAM_CONTRACT_EMBEDDING_DIMENSIONS: usize = 4;
const BENCH_CONTRACT_ENTITY_TYPE: u8 = oneiron::registry::ENTITY_TYPE_TURN;

type BeamResult<T> = Result<T, BeamError>;

#[derive(Debug, thiserror::Error)]
pub(crate) enum BeamError {
    #[error("unsupported BEAM schema version {actual}; expected {expected}")]
    UnsupportedSchemaVersion { expected: u32, actual: u32 },
    #[error("invalid BEAM fixture `{fixture_id}`: {reason}")]
    InvalidFixture { fixture_id: String, reason: String },
    #[error("invalid BEAM run manifest `{run_id}`: {reason}")]
    InvalidManifest { run_id: String, reason: String },
    #[error("judge card invalid: {reason}")]
    JudgeCardInvalid { reason: String },
    #[error("invalid entity id `{id}`: {source}")]
    InvalidEntityId { id: String, source: oneiron::Error },
    #[error("fixture `{fixture_id}` does not match manifest dataset `{manifest_fixture_id}`")]
    FixtureMismatch {
        fixture_id: String,
        manifest_fixture_id: String,
    },
    #[error("manifest case `{case_id}` was not found in fixture `{fixture_id}`")]
    MissingCase { fixture_id: String, case_id: String },
    #[error("uncarded BEAM competitor row `{competitor_id}` in run manifest `{run_id}`")]
    UncardedCompetitor {
        run_id: String,
        competitor_id: String,
    },
    #[error("dataset loader is not ready: {0}")]
    DatasetNotReady(NotReadyState),
    #[error("invalid oneiron-eval run.jsonl `{path}` line {line}: {reason}")]
    InvalidRunJsonl {
        path: String,
        line: usize,
        reason: String,
    },
    #[error("run.jsonl-backed case `{case_id}` still has {pending_vectors} pending embeddings")]
    PendingEmbeddings {
        case_id: String,
        pending_vectors: usize,
    },
    #[error("vanilla-rag arm for case `{case_id}` requires a query embedding")]
    MissingQueryEmbedding { case_id: String },
    #[error(
        "vanilla-rag arm returned {actual} results for case `{case_id}`; expected at least {expected}"
    )]
    VanillaRagExpectation {
        case_id: String,
        expected: usize,
        actual: usize,
    },
    #[error(
        "deterministic arm returned {actual} results for case `{case_id}`; expected at least {expected}"
    )]
    DeterministicExpectation {
        case_id: String,
        expected: usize,
        actual: usize,
    },
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("messagepack encode error: {0}")]
    MessagePackEncode(#[from] rmp_serde::encode::Error),
    #[error("oneiron engine error: {0}")]
    Oneiron(#[from] oneiron::Error),
    #[error("budgeted deterministic context pack serialization was not UTF-8: {0}")]
    BudgetedContextPackUtf8(#[from] std::str::Utf8Error),
    #[error("temporary vault error: {0}")]
    TempVault(#[from] std::io::Error),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BeamFixture {
    schema_version: u32,
    fixture_id: String,
    description: String,
    records: Vec<FixtureRecord>,
    cases: Vec<FixtureCase>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FixtureRecord {
    id: String,
    entity_type: u8,
    occurred: FixtureTimeRange,
    learned_at: u64,
    fields: serde_json::Value,
    #[serde(default)]
    text: Vec<TextField>,
    #[serde(default)]
    embedding: Option<ContractEmbeddingState>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FixtureTimeRange {
    start: u64,
    end: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TextField {
    field: String,
    value: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FixtureCase {
    case_id: String,
    query: String,
    limit: usize,
    token_budget: usize,
    expected_min_results: usize,
    #[serde(default)]
    pending_vector_count: usize,
    #[serde(default)]
    query_embedding: Option<ContractEmbeddingState>,
    #[serde(default)]
    fixture_class: FixtureClass,
    #[serde(default)]
    temporal_search: Option<FixtureTimeRange>,
    #[serde(default)]
    temporal_evidence_ids: Vec<String>,
    #[serde(default)]
    opposing_evidence: Option<OpposingEvidence>,
    #[serde(default)]
    offline_amortized_cost: CostComponentInput,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OpposingEvidence {
    field: String,
    record_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum FixtureClass {
    #[default]
    EvidenceSupported,
    EmptyMemory,
    LowConfidence,
    AdversarialContradiction,
    TemporalStaleness,
}

impl FixtureClass {
    const fn expects_abstention(self) -> bool {
        !matches!(self, Self::EvidenceSupported)
    }

    const fn gate_label(self) -> &'static str {
        match self {
            Self::EvidenceSupported => "score_publication",
            Self::EmptyMemory => "empty_memory_abstention",
            Self::LowConfidence => "low_confidence_abstention",
            Self::AdversarialContradiction => "adversarial_contradiction_abstention",
            Self::TemporalStaleness => "temporal_staleness_abstention",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RunManifest {
    schema_version: u32,
    run_id: String,
    dataset: DatasetSource,
    case_ids: Vec<String>,
    arms: Vec<ArmKind>,
    competitors: Vec<CompetitorConfig>,
    report: ReportConfig,
    #[serde(default)]
    outputs: Option<RunOutputs>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SchemaHeader {
    schema_version: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
enum DatasetSource {
    Fixture {
        fixture_id: String,
    },
    Jsonl {
        path: PathBuf,
        #[serde(default)]
        arm_id: Option<String>,
        #[serde(default = "default_jsonl_retrieval_limit")]
        limit: usize,
        #[serde(default)]
        expected_min_results: usize,
    },
    Miracl {
        dataset: String,
    },
    MrTydi {
        dataset: String,
    },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RunOutputs {
    packs_jsonl: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ArmKind {
    Deterministic,
    VanillaRag,
    BackboneSolo,
    Agentic,
    Chat,
}

impl ArmKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Deterministic => "deterministic",
            Self::VanillaRag => "vanilla_rag",
            Self::BackboneSolo => "backbone_solo",
            Self::Agentic => "agentic",
            Self::Chat => "chat",
        }
    }

    const fn is_completed(self) -> bool {
        matches!(self, Self::Deterministic | Self::VanillaRag)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReportConfig {
    format: ReportFormat,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CompetitorConfig {
    competitor_id: String,
    arm: ArmKind,
    card: Option<CompetitorCardConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CompetitorCardConfig {
    display_name: String,
    public_parity_status: PublicParityStatus,
    judge: JudgeMetadata,
    comparator: ComparatorMetadata,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_accounting: Option<TokenAccountingDeclaration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum PublicParityStatus {
    PublicParity,
    FixtureOnly,
    NotPublicComparable,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct JudgeMetadata {
    judge_id: String,
    version: String,
    notes: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    answer_prompt: Option<AnswerPromptPin>,
    #[serde(default = "single_judge_vote")]
    vote_count: u8,
}

// Judge transport lands in oneiron-eval (EVAL 1404-1407); this crate pins the card/majority substrate.
// This module holds exactly that pinned-but-unwired substrate, so the single allowance below stands
// in for the eleven identical per-item allowances these items used to carry one by one. The
// `pub(crate)` re-export under the module keeps every `beam::` path and its reach unchanged.
#[allow(dead_code)]
mod majority_judge {
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};

    use super::{BeamError, BeamResult, JudgeMetadata, hex_lower};

    pub(crate) const JUDGE_VOTE_COUNT: usize = 3;

    #[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    pub(crate) struct AnswerPromptPin {
        pub(super) content: String,
        pub(super) sha256: String,
    }

    pub(crate) fn single_judge_vote() -> u8 {
        1
    }

    impl AnswerPromptPin {
        /// Pins the answer-generation prompt exactly as it is sent: the unmodified UTF-8 bytes are
        /// hashed with SHA-256 and stored as lowercase hexadecimal beside the verbatim content, so the
        /// card is self-contained and independently checkable. No trimming, newline normalization,
        /// whitespace canonicalization, or second interpolation happens before hashing.
        pub(crate) fn from_exact_text(content: &str) -> Self {
            let mut hasher = Sha256::new();
            hasher.update(content.as_bytes());
            Self {
                content: content.to_owned(),
                sha256: hex_lower(&hasher.finalize()),
            }
        }

        /// True only when this pin is byte-identical to the pin `content` would produce: the stored
        /// content equals `content` and the stored digest is the digest of those exact bytes.
        pub(crate) fn matches_exact_text(&self, content: &str) -> bool {
            *self == Self::from_exact_text(content)
        }
    }

    impl JudgeMetadata {
        /// Gate for the LLM-majority judge boundary: the caller must run this before its first external
        /// judge call. It never repairs the card, substitutes the runtime prompt, or hashes a prompt
        /// label; a missing pin, wrong vote count, malformed digest, or runtime/card prompt mismatch is
        /// reported as [`BeamError::JudgeCardInvalid`] and no judge call is made.
        pub(crate) fn require_majority_vote_card(
            &self,
            exact_answer_prompt: &str,
        ) -> BeamResult<()> {
            if self.judge_id.trim().is_empty() {
                return Err(BeamError::JudgeCardInvalid {
                    reason: "judge ids must not be empty".to_owned(),
                });
            }
            if self.version.trim().is_empty() {
                return Err(BeamError::JudgeCardInvalid {
                    reason: "judge versions must not be empty".to_owned(),
                });
            }
            if usize::from(self.vote_count) != JUDGE_VOTE_COUNT {
                return Err(BeamError::JudgeCardInvalid {
                    reason: format!("majority judgments require voteCount {JUDGE_VOTE_COUNT}"),
                });
            }
            let Some(pin) = self.answer_prompt.as_ref() else {
                return Err(BeamError::JudgeCardInvalid {
                    reason: "majority judgments require a pinned answerPrompt".to_owned(),
                });
            };
            if pin.content.trim().is_empty() {
                return Err(BeamError::JudgeCardInvalid {
                    reason: "pinned answerPrompt content must not be empty".to_owned(),
                });
            }
            if !pin.matches_exact_text(&pin.content) {
                return Err(BeamError::JudgeCardInvalid {
                    reason: "pinned answerPrompt sha256 does not match its content".to_owned(),
                });
            }
            if !pin.matches_exact_text(exact_answer_prompt) {
                return Err(BeamError::JudgeCardInvalid {
                    reason: "runtime answer prompt does not match the card pin".to_owned(),
                });
            }

            Ok(())
        }
    }

    #[derive(Debug)]
    pub(crate) enum MajorityVoteError<V, E> {
        CallFailures {
            attempts: [Result<V, E>; JUDGE_VOTE_COUNT],
        },
        Tie {
            votes: [V; JUDGE_VOTE_COUNT],
        },
    }

    #[derive(Debug)]
    pub(crate) struct MajorityDecision<V> {
        pub(super) verdict: V,
        pub(super) vote_count: usize,
    }

    /// Runs one logical judgment as exactly [`JUDGE_VOTE_COUNT`] independent judge calls at indices
    /// `0`, `1`, and `2`, and decides only after all three return.
    ///
    /// The caller supplies the same immutable item, candidate answer, judge instructions, judge
    /// id/version, and pinned answer-prompt declaration to every call, and never feeds an earlier vote,
    /// error, or rationale back in; those are transport obligations this layer cannot verify. What this
    /// layer does enforce is call count, index order, and fail-closed aggregation: two agreeing votes do
    /// not short-circuit the third call, a failing call does not short-circuit the remaining calls, and
    /// a provider-side retry inside one call stays that call's transport policy rather than a fourth
    /// vote. Any call failure yields [`MajorityVoteError::CallFailures`] with the three typed outcomes
    /// and no verdict; three distinct successful votes yield [`MajorityVoteError::Tie`] with no verdict.
    /// A decision therefore always carries the winning tally, `2` or `3`, never the attempted count.
    pub(crate) fn majority_of_three<V, E, F>(
        judge_call: F,
    ) -> Result<MajorityDecision<V>, MajorityVoteError<V, E>>
    where
        V: Clone + Eq,
        F: FnMut(usize) -> Result<V, E>,
    {
        // `from_fn` walks the array forward, so the call indices are 0, 1, 2 in that order, and every
        // index is called before any outcome is inspected.
        let attempts: [Result<V, E>; JUDGE_VOTE_COUNT] = std::array::from_fn(judge_call);
        let votes = match attempts {
            [Ok(first), Ok(second), Ok(third)] => [first, second, third],
            attempts => return Err(MajorityVoteError::CallFailures { attempts }),
        };

        let [first, second, third] = votes;
        if first == second && second == third {
            return Ok(MajorityDecision {
                verdict: first,
                vote_count: JUDGE_VOTE_COUNT,
            });
        }
        if first == second || first == third {
            return Ok(MajorityDecision {
                verdict: first,
                vote_count: 2,
            });
        }
        if second == third {
            return Ok(MajorityDecision {
                verdict: second,
                vote_count: 2,
            });
        }

        Err(MajorityVoteError::Tie {
            votes: [first, second, third],
        })
    }

    #[derive(Debug)]
    pub(crate) enum MajorityJudgeError<V, E> {
        Card(BeamError),
        Vote(MajorityVoteError<V, E>),
    }

    /// Composed LLM-majority judge boundary: validate the card against the runtime answer prompt first,
    /// then run the three-call majority. A rejected card invokes `judge_call` zero times, so no stale
    /// answer-prompt pin can accompany an emitted verdict.
    pub(crate) fn run_majority_judge_card<V, E, F>(
        metadata: &JudgeMetadata,
        exact_answer_prompt: &str,
        judge_call: F,
    ) -> Result<MajorityDecision<V>, MajorityJudgeError<V, E>>
    where
        V: Clone + Eq,
        F: FnMut(usize) -> Result<V, E>,
    {
        metadata
            .require_majority_vote_card(exact_answer_prompt)
            .map_err(MajorityJudgeError::Card)?;
        majority_of_three(judge_call).map_err(MajorityJudgeError::Vote)
    }
}

pub(crate) use majority_judge::*;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ComparatorMetadata {
    comparator_id: String,
    version: String,
    baseline_competitor_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum TokenAccountingSource {
    TokenizerCount,
    ProviderUsage,
    FixtureDeclaredZero,
    NotApplicable,
    CharCountEstimate,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TokenAccountingDeclaration {
    source: TokenAccountingSource,
    notes: String,
}

impl Default for TokenAccountingDeclaration {
    fn default() -> Self {
        Self {
            source: TokenAccountingSource::NotApplicable,
            notes: String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CostComponentInput {
    #[serde(default = "default_fixture_cost_source")]
    token_source: TokenAccountingSource,
    #[serde(default)]
    input_tokens: u64,
    #[serde(default)]
    output_tokens: u64,
    #[serde(default)]
    target_tokens: u64,
    #[serde(default)]
    elapsed_us: u64,
    #[serde(default)]
    cost_usd: f64,
}

impl Default for CostComponentInput {
    fn default() -> Self {
        Self {
            token_source: default_fixture_cost_source(),
            input_tokens: 0,
            output_tokens: 0,
            target_tokens: 0,
            elapsed_us: 0,
            cost_usd: 0.0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReportFormat {
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NotReadyState {
    component: String,
    reason: String,
    retryable: bool,
}

impl std::fmt::Display for NotReadyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} not ready: {}", self.component, self.reason)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BeamReport {
    schema_version: u32,
    run_id: String,
    fixture_id: String,
    fixture_description: String,
    dataset: DatasetLoadReport,
    scorer: ScorerReport,
    report_format: String,
    cases: Vec<CaseReport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct DatasetLoadReport {
    dataset_id: String,
    source_kind: String,
    records_loaded: usize,
    text_fields_indexed: usize,
    pending_vectors: usize,
}

struct LoadedDataset {
    report: DatasetLoadReport,
    fixture_id: String,
    fixture_description: String,
    cases: Vec<FixtureCase>,
    contract_records: BTreeMap<String, RunContractRecord>,
    source_id_by_entity_id: BTreeMap<String, String>,
    query_vector_by_case_id: BTreeMap<String, Vec<f32>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ContractRecordType {
    Run,
    ContextPack,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ContractDataset {
    id: String,
    revision: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ContractArm {
    id: String,
    kind: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ContractBudget {
    currency: String,
    limit: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ContractGold {
    answers: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    labels: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
struct RunContractRecord {
    contract_version: String,
    record_type: ContractRecordType,
    run_id: String,
    question_id: String,
    dataset: ContractDataset,
    arm: ContractArm,
    budget: ContractBudget,
    question: String,
    #[serde(default, alias = "queryEmbedding")]
    query_embedding: Option<ContractEmbeddingState>,
    corpus: Vec<ContractCorpusRecord>,
    #[serde(default)]
    gold: Option<ContractGold>,
}

#[derive(Debug, Clone, Deserialize)]
struct ContractCorpusRecord {
    id: String,
    text: String,
    #[serde(default)]
    metadata: Option<serde_json::Value>,
    #[serde(default)]
    embedding: Option<ContractEmbeddingState>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum ContractEmbeddingState {
    Pending {
        #[serde(rename = "status")]
        _status: ContractEmbeddingStatus,
    },
    Ready(ContractVector),
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ContractEmbeddingStatus {
    Pending,
}

#[derive(Debug, Clone, Deserialize)]
struct ContractVector {
    encoding: String,
    dimensions: usize,
    data: String,
}

#[derive(Debug, Serialize)]
struct ContextPackContractRecord {
    contract_version: &'static str,
    record_type: ContractRecordType,
    run_id: String,
    question_id: String,
    dataset: ContractDataset,
    arm: ContractArm,
    budget: ContractBudget,
    question: String,
    pack: ContractPack,
    #[serde(skip_serializing_if = "Option::is_none")]
    gold: Option<ContractGold>,
}

#[derive(Debug, Serialize)]
struct ContractPack {
    #[serde(skip_serializing_if = "Option::is_none")]
    token_count: Option<u64>,
    corpus_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    config: Option<ContractPackConfig>,
    contexts: Vec<ContractPackContext>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ContractPackConfig {
    kind: &'static str,
    version: &'static str,
    top_k: usize,
    chunking: &'static str,
    fusion: &'static str,
    signals: Vec<&'static str>,
    embedder_id: &'static str,
    vector_dimensions: usize,
    token_budget_source: &'static str,
    structure: &'static str,
}

#[derive(Debug, Serialize)]
struct ContractPackContext {
    id: String,
    text: String,
    score: f32,
    source_turn_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct CaseReport {
    case_id: String,
    query: String,
    limit: usize,
    token_budget: usize,
    expected_min_results: usize,
    fixture_class: FixtureClass,
    offline_amortized_cost: CostComponentReport,
    arms: Vec<ArmReport>,
    competitors: Vec<CompetitorReport>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ArmReport {
    arm: ArmKind,
    outcome: ArmOutcome,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(
    tag = "status",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
enum ArmOutcome {
    Completed {
        context_pack: Box<ContextPackReport>,
    },
    NotReady {
        not_ready: NotReadyState,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ContextPackReport {
    token_budget: usize,
    limit: usize,
    serialized_format: String,
    serialized_bytes: usize,
    serialized_tokens: u64,
    tokenizer_id: String,
    query_cost: CostComponentReport,
    result_count: usize,
    neighbor_count: usize,
    results: Vec<ContextEntityReport>,
    neighbors: Vec<ContextEntityReport>,
    stats: PackStatsReport,
    empty: Option<EmptyContextReport>,
    #[serde(skip)]
    temporal_result_ids: BTreeSet<String>,
    #[serde(skip)]
    budgeted_text_by_entity_id: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ScorerReport {
    scorer_id: String,
    version: String,
    comparator_version: String,
    abilities: Vec<AbilityKind>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum AbilityKind {
    RetrievalCoverage,
    BudgetDiscipline,
    Readiness,
    AbstentionGate,
    NoRegressionGate,
}

impl AbilityKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::RetrievalCoverage => "retrieval_coverage",
            Self::BudgetDiscipline => "budget_discipline",
            Self::Readiness => "readiness",
            Self::AbstentionGate => "abstention_gate",
            Self::NoRegressionGate => "no_regression_gate",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct CompetitorReport {
    competitor_id: String,
    arm: ArmKind,
    card: CompetitorCardConfig,
    costs: CostBreakdownReport,
    scoring: ScoreReport,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct CostBreakdownReport {
    query: CostComponentReport,
    offline: CostComponentReport,
    judge: CostComponentReport,
    total_cost_usd: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct CostComponentReport {
    token_source: TokenAccountingSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    tokenizer_id: Option<String>,
    input_tokens: u64,
    output_tokens: u64,
    target_tokens: u64,
    elapsed_us: u64,
    cost_usd: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ScoreReport {
    scorer_version: String,
    overall_score: Option<f32>,
    abilities: Vec<AbilityScoreReport>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct AbilityScoreReport {
    ability: AbilityKind,
    score: Option<f32>,
    passed: Option<bool>,
    detail: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ContextEntityReport {
    id: String,
    short_id: String,
    entity_type: u8,
    score: f32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct PackStatsReport {
    candidates_considered: usize,
    signals_used: Vec<String>,
    query_time_us: u64,
    entities_hydrated: usize,
    neighbors_hydrated: usize,
    cosine_ghosts_dampened: usize,
    claims_suppressed: usize,
    tokenizer_id: String,
    total_tokens: usize,
    section_tokens: Vec<PackSectionTokenReport>,
    item_tokens: Vec<PackItemTokenReport>,
    items_truncated: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    items_truncated_reasons: Vec<String>,
    items_dropped: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    items_dropped_reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct PackSectionTokenReport {
    section: String,
    tokens: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct PackItemTokenReport {
    section: String,
    id: String,
    entity_type: u8,
    tokens: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct EmptyContextReport {
    reason: String,
    total_in_scope: usize,
    hint: String,
}

trait BeamArmAdapter {
    fn kind(&self) -> ArmKind;
    fn run(
        &self,
        vault: &Vault,
        loaded: &LoadedDataset,
        case: &FixtureCase,
    ) -> BeamResult<ArmReport>;
}

trait BeamScorer {
    fn metadata(&self) -> ScorerReport;
    fn score(
        &self,
        case: &FixtureCase,
        competitor: &CompetitorConfig,
        arm: &ArmReport,
    ) -> ScoreReport;
}

struct FixedBeamScorer;

impl BeamScorer for FixedBeamScorer {
    fn metadata(&self) -> ScorerReport {
        ScorerReport {
            scorer_id: "beam-fixed-scorer".to_owned(),
            version: BEAM_SCORER_VERSION.to_owned(),
            comparator_version: BEAM_COMPARATOR_VERSION.to_owned(),
            abilities: vec![
                AbilityKind::RetrievalCoverage,
                AbilityKind::BudgetDiscipline,
                AbilityKind::Readiness,
                AbilityKind::AbstentionGate,
                AbilityKind::NoRegressionGate,
            ],
        }
    }

    fn score(
        &self,
        case: &FixtureCase,
        competitor: &CompetitorConfig,
        arm: &ArmReport,
    ) -> ScoreReport {
        let abilities = match &arm.outcome {
            ArmOutcome::Completed { context_pack } => completed_ability_scores(case, context_pack),
            ArmOutcome::NotReady { not_ready } => not_ready_ability_scores(competitor, not_ready),
        };
        let overall_score = mean_score(&abilities);

        ScoreReport {
            scorer_version: BEAM_SCORER_VERSION.to_owned(),
            overall_score,
            abilities,
        }
    }
}

struct DeterministicContextPackArm;

impl BeamArmAdapter for DeterministicContextPackArm {
    fn kind(&self) -> ArmKind {
        ArmKind::Deterministic
    }

    fn run(
        &self,
        vault: &Vault,
        _loaded: &LoadedDataset,
        case: &FixtureCase,
    ) -> BeamResult<ArmReport> {
        if case.pending_vector_count > 0 {
            return Err(BeamError::PendingEmbeddings {
                case_id: case.case_id.clone(),
                pending_vectors: case.pending_vector_count,
            });
        }

        let pack = run_deterministic_context_pack(vault, case)?;
        let report = context_pack_report(&pack, case);

        if report.result_count < case.expected_min_results {
            return Err(BeamError::DeterministicExpectation {
                case_id: case.case_id.clone(),
                expected: case.expected_min_results,
                actual: report.result_count,
            });
        }

        Ok(ArmReport {
            arm: self.kind(),
            outcome: ArmOutcome::Completed {
                context_pack: Box::new(report),
            },
        })
    }
}

struct VanillaRagArm;

impl BeamArmAdapter for VanillaRagArm {
    fn kind(&self) -> ArmKind {
        ArmKind::VanillaRag
    }

    fn run(
        &self,
        vault: &Vault,
        loaded: &LoadedDataset,
        case: &FixtureCase,
    ) -> BeamResult<ArmReport> {
        if case.pending_vector_count > 0 {
            return Err(BeamError::PendingEmbeddings {
                case_id: case.case_id.clone(),
                pending_vectors: case.pending_vector_count,
            });
        }
        let query_vector = loaded
            .query_vector_by_case_id
            .get(case.case_id.as_str())
            .ok_or_else(|| BeamError::MissingQueryEmbedding {
                case_id: case.case_id.clone(),
            })?;

        let pack = run_vanilla_rag_context_pack(vault, case, query_vector)?;
        let report = context_pack_report(&pack, case);

        if report.result_count < case.expected_min_results {
            return Err(BeamError::VanillaRagExpectation {
                case_id: case.case_id.clone(),
                expected: case.expected_min_results,
                actual: report.result_count,
            });
        }

        Ok(ArmReport {
            arm: self.kind(),
            outcome: ArmOutcome::Completed {
                context_pack: Box::new(report),
            },
        })
    }
}

struct NotReadyArm {
    kind: ArmKind,
}

impl BeamArmAdapter for NotReadyArm {
    fn kind(&self) -> ArmKind {
        self.kind
    }

    fn run(
        &self,
        _vault: &Vault,
        _loaded: &LoadedDataset,
        _case: &FixtureCase,
    ) -> BeamResult<ArmReport> {
        Ok(ArmReport {
            arm: self.kind,
            outcome: ArmOutcome::NotReady {
                not_ready: arm_not_ready(self.kind),
            },
        })
    }
}

pub(crate) fn run(args: &[String]) -> ExitCode {
    match args {
        [] => {
            print_help();
            ExitCode::SUCCESS
        }
        [sub] if sub == "smoke" => match run_builtin_smoke()
            .and_then(|report| serde_json::to_string_pretty(&report).map_err(BeamError::from))
        {
            Ok(report_json) => {
                println!("{report_json}");
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("BEAM smoke failed: {err}");
                ExitCode::FAILURE
            }
        },
        [sub, manifest_path] if sub == "run" => match run_manifest_path(Path::new(manifest_path))
            .and_then(|report| serde_json::to_string_pretty(&report).map_err(BeamError::from))
        {
            Ok(report_json) => {
                println!("{report_json}");
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("BEAM run failed: {err}");
                ExitCode::FAILURE
            }
        },
        [sub, rest @ ..] if sub == "trace-export" => retrieval_trace_export::run(rest),
        [sub] => {
            eprintln!("unknown BEAM subcommand: {sub}");
            print_help();
            ExitCode::FAILURE
        }
        other => {
            eprintln!("unknown BEAM invocation: {other:?}");
            print_help();
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    println!("{BEAM_HELP}");
}

pub(crate) fn run_builtin_smoke() -> BeamResult<BeamReport> {
    let fixture = parse_fixture_json(BUILTIN_FIXTURE_JSON)?;
    let manifest = parse_manifest_json(BUILTIN_MANIFEST_JSON)?;
    ensure_manifest_selects_128k_case(&manifest, &fixture)?;
    run_fixture_manifest(&manifest, &fixture)
}

const BEAM_HELP: &str = "usage: oneiron-bench beam <subcommand>\n\
                         \n\
                         subcommands:\n\
                           smoke    run the built-in BEAM 128K deterministic context-pack smoke fixture\n\
                                    aligned with ONEIRON-ARCH-0042\n\
                           run      run a BEAM run manifest and emit declared packs.jsonl outputs\n\
                           trace-export\n\
                                    export RetrievalTrace records to JSONL by fork hash (ONE-1311)";

pub(crate) fn run_manifest_path(path: &Path) -> BeamResult<BeamReport> {
    let manifest_json = std::fs::read_to_string(path)?;
    let mut manifest = parse_manifest_json(&manifest_json)?;
    resolve_manifest_paths(&mut manifest, path);
    run_manifest(&manifest, None)
}

fn ensure_manifest_selects_128k_case(
    manifest: &RunManifest,
    fixture: &BeamFixture,
) -> BeamResult<()> {
    let cases_by_id: BTreeMap<&str, &FixtureCase> = fixture
        .cases
        .iter()
        .map(|case| (case.case_id.as_str(), case))
        .collect();

    if manifest.case_ids.iter().any(|case_id| {
        cases_by_id
            .get(case_id.as_str())
            .is_some_and(|case| case.token_budget == BEAM_128K_TOKEN_BUDGET)
    }) {
        return Ok(());
    }

    Err(invalid_manifest(
        manifest,
        "built-in BEAM smoke manifest must select a 128K token-budget case",
    ))
}

pub(crate) fn parse_fixture_json(json: &str) -> BeamResult<BeamFixture> {
    let fixture: BeamFixture = serde_json::from_str(json)?;
    validate_fixture(&fixture)?;
    Ok(fixture)
}

pub(crate) fn parse_manifest_json(json: &str) -> BeamResult<RunManifest> {
    let header: SchemaHeader = serde_json::from_str(json)?;
    if header.schema_version != SCHEMA_VERSION {
        return Err(BeamError::UnsupportedSchemaVersion {
            expected: SCHEMA_VERSION,
            actual: header.schema_version,
        });
    }
    let manifest: RunManifest = serde_json::from_str(json)?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

pub(crate) fn run_fixture_manifest(
    manifest: &RunManifest,
    fixture: &BeamFixture,
) -> BeamResult<BeamReport> {
    run_manifest(manifest, Some(fixture))
}

fn run_manifest(manifest: &RunManifest, fixture: Option<&BeamFixture>) -> BeamResult<BeamReport> {
    validate_manifest(manifest)?;
    if let (DatasetSource::Fixture { .. }, Some(fixture)) = (&manifest.dataset, fixture) {
        validate_manifest_fixture_cases(manifest, fixture)?;
    }
    validate_manifest_paths(manifest)?;

    if matches!(manifest.dataset, DatasetSource::Jsonl { .. }) {
        return run_jsonl_manifest_isolated(manifest);
    }

    let tempdir = tempfile::tempdir()?;
    let vault = Vault::open(tempdir.path(), beam_vault_config())?;
    let loaded = load_dataset(&vault, manifest, fixture)?;
    let (cases, pack_rows) = run_loaded_cases(&vault, manifest, &loaded)?;
    let scorer = FixedBeamScorer;
    let report_format = report_format_label(manifest.report.format).to_owned();

    if let Some(outputs) = &manifest.outputs {
        write_contract_pack_rows(&outputs.packs_jsonl, &pack_rows)?;
    }

    Ok(BeamReport {
        schema_version: SCHEMA_VERSION,
        run_id: manifest.run_id.clone(),
        fixture_id: loaded.fixture_id,
        fixture_description: loaded.fixture_description,
        dataset: loaded.report,
        scorer: scorer.metadata(),
        report_format,
        cases,
    })
}

fn run_jsonl_manifest_isolated(manifest: &RunManifest) -> BeamResult<BeamReport> {
    let scorer = FixedBeamScorer;
    let report_format = report_format_label(manifest.report.format).to_owned();
    let mut dataset_report: Option<DatasetLoadReport> = None;
    let mut fixture_id: Option<String> = None;
    let mut fixture_description: Option<String> = None;
    let mut cases = Vec::with_capacity(manifest.case_ids.len());
    let mut pack_rows = Vec::new();

    for case_id in &manifest.case_ids {
        let tempdir = tempfile::tempdir()?;
        let vault = Vault::open(tempdir.path(), beam_vault_config())?;
        let mut single_case_manifest = manifest.clone();
        single_case_manifest.case_ids = vec![case_id.clone()];
        let loaded = load_dataset(&vault, &single_case_manifest, None)?;

        match &mut dataset_report {
            Some(report) => {
                if report.dataset_id != loaded.report.dataset_id {
                    return Err(invalid_manifest(
                        manifest,
                        "jsonl selected cases must resolve to one dataset id",
                    ));
                }
                report.records_loaded += loaded.report.records_loaded;
                report.text_fields_indexed += loaded.report.text_fields_indexed;
                report.pending_vectors += loaded.report.pending_vectors;
            }
            None => {
                dataset_report = Some(loaded.report.clone());
                fixture_id = Some(loaded.fixture_id.clone());
                fixture_description = Some(loaded.fixture_description.clone());
            }
        }

        let (mut case_reports, mut rows) =
            run_loaded_cases(&vault, &single_case_manifest, &loaded)?;
        cases.append(&mut case_reports);
        pack_rows.append(&mut rows);
    }

    if let Some(outputs) = &manifest.outputs {
        write_contract_pack_rows(&outputs.packs_jsonl, &pack_rows)?;
    }

    Ok(BeamReport {
        schema_version: SCHEMA_VERSION,
        run_id: manifest.run_id.clone(),
        fixture_id: fixture_id.unwrap_or_else(|| "jsonl".to_owned()),
        fixture_description: fixture_description
            .unwrap_or_else(|| "oneiron-eval run.jsonl".to_owned()),
        dataset: dataset_report.expect("validated manifest has at least one case"),
        scorer: scorer.metadata(),
        report_format,
        cases,
    })
}

fn run_loaded_cases(
    vault: &Vault,
    manifest: &RunManifest,
    loaded: &LoadedDataset,
) -> BeamResult<(Vec<CaseReport>, Vec<ContextPackContractRecord>)> {
    let scorer = FixedBeamScorer;
    let cases_by_id: BTreeMap<&str, &FixtureCase> = loaded
        .cases
        .iter()
        .map(|case| (case.case_id.as_str(), case))
        .collect();

    let mut cases = Vec::with_capacity(manifest.case_ids.len());
    let mut pack_rows = Vec::new();
    for case_id in &manifest.case_ids {
        let case = cases_by_id
            .get(case_id.as_str())
            .ok_or_else(|| BeamError::MissingCase {
                fixture_id: loaded.fixture_id.clone(),
                case_id: case_id.clone(),
            })?;
        let mut arms = Vec::with_capacity(manifest.competitors.len());
        let mut competitors = Vec::with_capacity(manifest.competitors.len());
        for competitor in &manifest.competitors {
            let card = competitor
                .card
                .as_ref()
                .ok_or_else(|| BeamError::UncardedCompetitor {
                    run_id: manifest.run_id.clone(),
                    competitor_id: competitor.competitor_id.clone(),
                })?;
            let arm_report = adapter_for(competitor.arm).run(vault, loaded, case)?;
            if let Some(row) =
                contract_context_pack_record(manifest, loaded, case, competitor, &arm_report)?
            {
                pack_rows.push(row);
            }
            let scoring = scorer.score(case, competitor, &arm_report);
            arms.push(arm_report);
            let costs = cost_breakdown(case, arms.last().expect("arm just pushed"));
            competitors.push(CompetitorReport {
                competitor_id: competitor.competitor_id.clone(),
                arm: competitor.arm,
                card: card.clone(),
                costs,
                scoring,
            });
        }
        cases.push(CaseReport {
            case_id: case.case_id.clone(),
            query: case.query.clone(),
            limit: case.limit,
            token_budget: case.token_budget,
            expected_min_results: case.expected_min_results,
            fixture_class: case.fixture_class,
            offline_amortized_cost: cost_component_from_input(&case.offline_amortized_cost),
            arms,
            competitors,
        });
    }

    Ok((cases, pack_rows))
}

fn validate_fixture(fixture: &BeamFixture) -> BeamResult<()> {
    if fixture.schema_version != SCHEMA_VERSION {
        return Err(BeamError::UnsupportedSchemaVersion {
            expected: SCHEMA_VERSION,
            actual: fixture.schema_version,
        });
    }
    if fixture.cases.is_empty() {
        return Err(invalid_fixture(
            fixture,
            "fixture must contain at least one case",
        ));
    }
    if fixture.records.is_empty()
        && !fixture
            .cases
            .iter()
            .all(|case| case.fixture_class == FixtureClass::EmptyMemory)
    {
        return Err(invalid_fixture(
            fixture,
            "fixtures without records must use empty_memory abstention cases only",
        ));
    }

    let mut record_ids = BTreeSet::new();
    let mut records_by_id = BTreeMap::new();
    for record in &fixture.records {
        EntityId::from_hex(&record.id).map_err(|source| BeamError::InvalidEntityId {
            id: record.id.clone(),
            source,
        })?;
        if !record_ids.insert(record.id.as_str()) {
            return Err(invalid_fixture(fixture, "record ids must be unique"));
        }
        if record.occurred.start > record.occurred.end {
            return Err(invalid_fixture(
                fixture,
                "record occurred.start must be <= occurred.end",
            ));
        }
        let field_object = record
            .fields
            .as_object()
            .ok_or_else(|| invalid_fixture(fixture, "record fields must be a JSON object"))?;
        if record.text.iter().any(|field| field.field.is_empty()) {
            return Err(invalid_fixture(
                fixture,
                "text field names must not be empty",
            ));
        }
        if record
            .text
            .iter()
            .any(|field| !field_object.contains_key(field.field.as_str()))
        {
            return Err(invalid_fixture(
                fixture,
                "text fields must reference keys present in record.fields",
            ));
        }
        records_by_id.insert(record.id.as_str(), record);
    }

    let mut case_ids = BTreeSet::new();
    for case in &fixture.cases {
        if !case_ids.insert(case.case_id.as_str()) {
            return Err(invalid_fixture(fixture, "case ids must be unique"));
        }
        if case.query.trim().is_empty() {
            return Err(invalid_fixture(fixture, "case query must not be empty"));
        }
        if case.limit == 0 && case.fixture_class != FixtureClass::LowConfidence {
            return Err(invalid_fixture(fixture, "case limit must be positive"));
        }
        if case.fixture_class == FixtureClass::LowConfidence && case.limit != 0 {
            return Err(invalid_fixture(
                fixture,
                "low_confidence cases must set limit to 0",
            ));
        }
        if case.token_budget == 0 {
            return Err(invalid_fixture(
                fixture,
                "case token budget must be positive",
            ));
        }
        validate_cost_component("case offlineAmortizedCost", &case.offline_amortized_cost)
            .map_err(|reason| invalid_fixture(fixture, reason))?;
        if case.fixture_class.expects_abstention() && case.expected_min_results != 0 {
            return Err(invalid_fixture(
                fixture,
                "abstention fixture cases must set expected_min_results to 0",
            ));
        }
        if case.fixture_class == FixtureClass::EmptyMemory && !fixture.records.is_empty() {
            return Err(invalid_fixture(
                fixture,
                "empty_memory cases must not include fixture records",
            ));
        }
        if let Some(temporal_search) = &case.temporal_search
            && temporal_search.start > temporal_search.end
        {
            return Err(invalid_fixture(
                fixture,
                "case temporalSearch.start must be <= temporalSearch.end",
            ));
        }
        if case.fixture_class == FixtureClass::TemporalStaleness && case.temporal_search.is_none() {
            return Err(invalid_fixture(
                fixture,
                "temporal_staleness cases must declare temporalSearch",
            ));
        }
        if case.fixture_class == FixtureClass::TemporalStaleness {
            if case.temporal_evidence_ids.is_empty() {
                return Err(invalid_fixture(
                    fixture,
                    "temporal_staleness cases must declare temporalEvidenceIds",
                ));
            }
            let temporal_search = case
                .temporal_search
                .as_ref()
                .expect("temporal_staleness temporalSearch checked above");
            validate_temporal_evidence_ids(
                fixture,
                &records_by_id,
                temporal_search,
                &case.temporal_evidence_ids,
            )?;
            if case.temporal_evidence_ids.len() > case.limit {
                return Err(invalid_fixture(
                    fixture,
                    "temporalEvidenceIds count must be <= limit",
                ));
            }
        } else {
            if case.temporal_search.is_some() {
                return Err(invalid_fixture(
                    fixture,
                    "temporalSearch is only valid for temporal_staleness cases",
                ));
            }
            if !case.temporal_evidence_ids.is_empty() {
                return Err(invalid_fixture(
                    fixture,
                    "temporalEvidenceIds are only valid for temporal_staleness cases",
                ));
            }
        }
        if case.fixture_class == FixtureClass::AdversarialContradiction {
            let opposing_evidence = case.opposing_evidence.as_ref().ok_or_else(|| {
                invalid_fixture(
                    fixture,
                    "adversarial_contradiction cases must declare opposingEvidence",
                )
            })?;
            validate_opposing_evidence(fixture, &records_by_id, opposing_evidence)?;
            if opposing_evidence.record_ids.len() > case.limit {
                return Err(invalid_fixture(
                    fixture,
                    "opposingEvidence.recordIds count must be <= limit",
                ));
            }
        } else if case.opposing_evidence.is_some() {
            return Err(invalid_fixture(
                fixture,
                "opposingEvidence is only valid for adversarial_contradiction cases",
            ));
        }
        if case.expected_min_results > case.limit {
            return Err(invalid_fixture(
                fixture,
                "expected_min_results must be <= limit",
            ));
        }
    }

    Ok(())
}

fn validate_temporal_evidence_ids(
    fixture: &BeamFixture,
    records_by_id: &BTreeMap<&str, &FixtureRecord>,
    temporal_search: &FixtureTimeRange,
    temporal_evidence_ids: &[String],
) -> BeamResult<()> {
    let mut ids = BTreeSet::new();
    for id in temporal_evidence_ids {
        if !ids.insert(id.as_str()) {
            return Err(invalid_fixture(
                fixture,
                "temporalEvidenceIds must be unique",
            ));
        }
        let record = records_by_id.get(id.as_str()).ok_or_else(|| {
            invalid_fixture(
                fixture,
                "temporalEvidenceIds must reference fixture records",
            )
        })?;
        if record.occurred.end < temporal_search.start
            || record.occurred.start > temporal_search.end
        {
            return Err(invalid_fixture(
                fixture,
                "temporalEvidenceIds must reference records inside temporalSearch",
            ));
        }
    }

    Ok(())
}

fn validate_opposing_evidence(
    fixture: &BeamFixture,
    records_by_id: &BTreeMap<&str, &FixtureRecord>,
    opposing_evidence: &OpposingEvidence,
) -> BeamResult<()> {
    if opposing_evidence.field.trim().is_empty() {
        return Err(invalid_fixture(
            fixture,
            "opposingEvidence.field must not be empty",
        ));
    }
    if opposing_evidence.record_ids.len() < 2 {
        return Err(invalid_fixture(
            fixture,
            "opposingEvidence must reference at least two records",
        ));
    }

    let mut ids = BTreeSet::new();
    let mut values = BTreeSet::new();
    for id in &opposing_evidence.record_ids {
        if !ids.insert(id.as_str()) {
            return Err(invalid_fixture(
                fixture,
                "opposingEvidence.recordIds must be unique",
            ));
        }
        let record = records_by_id.get(id.as_str()).ok_or_else(|| {
            invalid_fixture(
                fixture,
                "opposingEvidence.recordIds must reference fixture records",
            )
        })?;
        let field_value = record
            .fields
            .as_object()
            .and_then(|fields| fields.get(opposing_evidence.field.as_str()))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                invalid_fixture(
                    fixture,
                    "opposingEvidence.field must reference string values on all records",
                )
            })?;
        values.insert(field_value);
    }

    if values.len() < 2 {
        return Err(invalid_fixture(
            fixture,
            "opposingEvidence must reference records with distinct field values",
        ));
    }

    Ok(())
}

fn validate_manifest(manifest: &RunManifest) -> BeamResult<()> {
    if manifest.schema_version != SCHEMA_VERSION {
        return Err(BeamError::UnsupportedSchemaVersion {
            expected: SCHEMA_VERSION,
            actual: manifest.schema_version,
        });
    }
    if manifest.case_ids.is_empty() {
        return Err(invalid_manifest(
            manifest,
            "manifest must request at least one case",
        ));
    }
    if manifest.arms.is_empty() {
        return Err(invalid_manifest(
            manifest,
            "manifest must request at least one arm",
        ));
    }
    if manifest.competitors.is_empty() {
        return Err(invalid_manifest(
            manifest,
            "manifest must declare at least one competitor row",
        ));
    }
    validate_manifest_dataset(manifest)?;

    let mut case_ids = BTreeSet::new();
    for case_id in &manifest.case_ids {
        if case_id.trim().is_empty() {
            return Err(invalid_manifest(manifest, "case ids must not be empty"));
        }
        if !case_ids.insert(case_id.as_str()) {
            return Err(invalid_manifest(
                manifest,
                "manifest case ids must be unique",
            ));
        }
    }

    let mut arms = BTreeSet::new();
    for arm in &manifest.arms {
        if !arms.insert(arm.as_str()) {
            return Err(invalid_manifest(manifest, "manifest arms must be unique"));
        }
    }

    let mut competitor_ids = BTreeSet::new();
    let mut competitor_arms = Vec::with_capacity(manifest.competitors.len());
    for competitor in &manifest.competitors {
        if competitor.competitor_id.trim().is_empty() {
            return Err(invalid_manifest(
                manifest,
                "competitor ids must not be empty",
            ));
        }
        if !competitor_ids.insert(competitor.competitor_id.as_str()) {
            return Err(invalid_manifest(manifest, "competitor ids must be unique"));
        }
        if competitor.card.is_none() {
            return Err(BeamError::UncardedCompetitor {
                run_id: manifest.run_id.clone(),
                competitor_id: competitor.competitor_id.clone(),
            });
        }
        if let Some(card) = &competitor.card {
            validate_competitor_card(manifest, competitor.arm, card)?;
        }
        competitor_arms.push(competitor.arm);
    }
    for competitor in &manifest.competitors {
        if let Some(card) = &competitor.card
            && !competitor_ids.contains(card.comparator.baseline_competitor_id.as_str())
        {
            return Err(invalid_manifest(
                manifest,
                "competitor card baseline ids must reference a declared competitor",
            ));
        }
    }
    if competitor_arms != manifest.arms {
        return Err(invalid_manifest(
            manifest,
            "competitor row arms must match manifest arms in order",
        ));
    }

    Ok(())
}

fn validate_manifest_dataset(manifest: &RunManifest) -> BeamResult<()> {
    if let DatasetSource::Jsonl {
        limit,
        expected_min_results,
        ..
    } = &manifest.dataset
    {
        if *limit == 0 {
            return Err(invalid_manifest(
                manifest,
                "jsonl dataset sources must set limit > 0",
            ));
        }
        if expected_min_results > limit {
            return Err(invalid_manifest(
                manifest,
                "jsonl dataset expectedMinResults must be <= limit",
            ));
        }
    }

    Ok(())
}

fn validate_manifest_paths(manifest: &RunManifest) -> BeamResult<()> {
    let DatasetSource::Jsonl { path, .. } = &manifest.dataset else {
        return Ok(());
    };
    let Some(outputs) = &manifest.outputs else {
        return Ok(());
    };

    let input = canonical_path_for_overlap(path)?;
    let output = canonical_path_for_overlap(&outputs.packs_jsonl)?;
    if input == output {
        return Err(invalid_manifest(
            manifest,
            "outputs.packsJsonl must not resolve to the input run.jsonl path",
        ));
    }

    Ok(())
}

fn canonical_path_for_overlap(path: &Path) -> std::io::Result<PathBuf> {
    match path.canonicalize() {
        Ok(path) => Ok(path),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let parent = parent.canonicalize()?;
            Ok(path
                .file_name()
                .map_or(parent.clone(), |file_name| parent.join(file_name)))
        }
        Err(err) => Err(err),
    }
}

fn validate_manifest_fixture_cases(
    manifest: &RunManifest,
    fixture: &BeamFixture,
) -> BeamResult<()> {
    let cases_by_id: BTreeMap<&str, &FixtureCase> = fixture
        .cases
        .iter()
        .map(|case| (case.case_id.as_str(), case))
        .collect();

    for case_id in &manifest.case_ids {
        if !cases_by_id.contains_key(case_id.as_str()) {
            return Err(BeamError::MissingCase {
                fixture_id: fixture.fixture_id.clone(),
                case_id: case_id.clone(),
            });
        }
    }

    Ok(())
}

fn validate_competitor_card(
    manifest: &RunManifest,
    arm: ArmKind,
    card: &CompetitorCardConfig,
) -> BeamResult<()> {
    if matches!(manifest.dataset, DatasetSource::Fixture { .. })
        && card.public_parity_status == PublicParityStatus::PublicParity
    {
        return Err(invalid_manifest(
            manifest,
            "fixture-backed BEAM manifests cannot claim public parity",
        ));
    }
    if card.display_name.trim().is_empty() {
        return Err(invalid_manifest(
            manifest,
            "competitor card display names must not be empty",
        ));
    }
    if card.judge.judge_id.trim().is_empty() {
        return Err(invalid_manifest(
            manifest,
            "competitor card judge ids must not be empty",
        ));
    }
    if card.judge.version.trim().is_empty() {
        return Err(invalid_manifest(
            manifest,
            "competitor card judge versions must not be empty",
        ));
    }
    // EVAL-01 defines exactly two carded judge modes: the single-vote fixed scorer, whose answer
    // prompt pin stays optional, and the LLM majority vote, which must disclose the pin regardless
    // of which call path later consumes the card.
    if usize::from(card.judge.vote_count) == JUDGE_VOTE_COUNT {
        let Some(pin) = card.judge.answer_prompt.as_ref() else {
            return Err(invalid_manifest(
                manifest,
                "majority-vote competitor cards must pin the answer prompt",
            ));
        };
        if pin.content.trim().is_empty() {
            return Err(invalid_manifest(
                manifest,
                "competitor card answer prompt pins must not be empty",
            ));
        }
        if !pin.matches_exact_text(&pin.content) {
            return Err(invalid_manifest(
                manifest,
                "competitor card answer prompt sha256 must match the pinned content",
            ));
        }
    } else if usize::from(card.judge.vote_count) != usize::from(single_judge_vote()) {
        return Err(invalid_manifest(
            manifest,
            format!("competitor card judge vote counts must be 1 or {JUDGE_VOTE_COUNT}"),
        ));
    }
    let token_accounting = card.token_accounting.as_ref();
    if token_accounting
        .is_some_and(|accounting| accounting.source == TokenAccountingSource::CharCountEstimate)
    {
        return Err(invalid_manifest(
            manifest,
            "model-scored competitor rows must not use char_count_estimate token accounting",
        ));
    }
    if arm.is_completed() {
        match token_accounting {
            Some(accounting) if accounting.source == TokenAccountingSource::TokenizerCount => {}
            Some(_) => {
                return Err(invalid_manifest(
                    manifest,
                    "completed competitor rows must declare tokenizer_count tokenAccounting",
                ));
            }
            None => {
                return Err(invalid_manifest(
                    manifest,
                    "completed competitor rows must declare tokenAccounting",
                ));
            }
        }
    }
    if card.comparator.comparator_id.trim().is_empty() {
        return Err(invalid_manifest(
            manifest,
            "competitor card comparator ids must not be empty",
        ));
    }
    if card.comparator.version != BEAM_COMPARATOR_VERSION {
        return Err(invalid_manifest(
            manifest,
            format!("competitor card comparator version must be {BEAM_COMPARATOR_VERSION}"),
        ));
    }
    if card.comparator.baseline_competitor_id.trim().is_empty() {
        return Err(invalid_manifest(
            manifest,
            "competitor card baseline competitor ids must not be empty",
        ));
    }

    Ok(())
}

fn load_dataset(
    vault: &Vault,
    manifest: &RunManifest,
    fixture: Option<&BeamFixture>,
) -> BeamResult<LoadedDataset> {
    match &manifest.dataset {
        DatasetSource::Fixture { fixture_id } => {
            let Some(fixture) = fixture else {
                return Err(invalid_manifest(
                    manifest,
                    "fixture-backed manifests require a fixture document",
                ));
            };
            if fixture_id != &fixture.fixture_id {
                return Err(BeamError::FixtureMismatch {
                    fixture_id: fixture.fixture_id.clone(),
                    manifest_fixture_id: fixture_id.clone(),
                });
            }
            load_fixture_dataset(vault, fixture)
        }
        DatasetSource::Jsonl {
            path,
            arm_id,
            limit,
            expected_min_results,
        } => load_run_jsonl_dataset(
            vault,
            manifest,
            path,
            arm_id.as_deref(),
            *limit,
            *expected_min_results,
        ),
        source => Err(BeamError::DatasetNotReady(dataset_not_ready(source))),
    }
}

fn load_fixture_dataset(vault: &Vault, fixture: &BeamFixture) -> BeamResult<LoadedDataset> {
    let mut batch = vault.batch();
    let mut text_fields_indexed = 0;
    for record in &fixture.records {
        let id = EntityId::from_hex(&record.id).map_err(|source| BeamError::InvalidEntityId {
            id: record.id.clone(),
            source,
        })?;
        let payload = rmp_serde::to_vec_named(&record.fields)?;
        batch = batch.put(
            &id,
            record.entity_type,
            TimeRange {
                start: record.occurred.start,
                end: record.occurred.end,
            },
            record.learned_at,
            &payload,
        );
        if !record.text.is_empty() {
            let fields: Vec<(&str, &str)> = record
                .text
                .iter()
                .map(|field| (field.field.as_str(), field.value.as_str()))
                .collect();
            text_fields_indexed += fields.len();
            batch = batch.text(&id, &fields);
        }
        if let Some(embedding) = &record.embedding {
            let vector = decode_fixture_vector(fixture, "record embedding", embedding)?;
            batch = batch.vector(&id, &vector);
        }
    }
    batch.commit()?;

    let mut query_vector_by_case_id = BTreeMap::new();
    for case in &fixture.cases {
        if let Some(embedding) = &case.query_embedding {
            let vector = decode_fixture_vector(fixture, "case queryEmbedding", embedding)?;
            query_vector_by_case_id.insert(case.case_id.clone(), vector);
        }
    }

    Ok(LoadedDataset {
        report: DatasetLoadReport {
            dataset_id: fixture.fixture_id.clone(),
            source_kind: "fixture".to_owned(),
            records_loaded: fixture.records.len(),
            text_fields_indexed,
            pending_vectors: 0,
        },
        fixture_id: fixture.fixture_id.clone(),
        fixture_description: fixture.description.clone(),
        cases: fixture.cases.clone(),
        contract_records: BTreeMap::new(),
        source_id_by_entity_id: BTreeMap::new(),
        query_vector_by_case_id,
    })
}

fn load_run_jsonl_dataset(
    vault: &Vault,
    manifest: &RunManifest,
    path: &Path,
    arm_id: Option<&str>,
    limit: usize,
    expected_min_results: usize,
) -> BeamResult<LoadedDataset> {
    let records = read_run_jsonl_records(path)?;
    let selected: BTreeSet<&str> = manifest.case_ids.iter().map(String::as_str).collect();
    let mut contract_records = BTreeMap::new();
    let mut source_id_by_entity_id = BTreeMap::new();
    let mut query_vector_by_case_id = BTreeMap::new();
    let mut seen_corpus = BTreeSet::new();
    let mut cases = Vec::with_capacity(manifest.case_ids.len());
    let mut case_seen = BTreeSet::new();
    let mut batch = vault.batch();
    let mut dataset_id: Option<String> = None;
    let mut dataset_revision: Option<String> = None;
    let mut records_loaded = 0;
    let mut text_fields_indexed = 0;
    let mut pending_vectors_total = 0;

    for entry in records {
        let line = entry.line;
        let record = entry.record;
        if !selected.contains(record.question_id.as_str()) {
            continue;
        }
        if let Some(arm_id) = arm_id
            && record.arm.id != arm_id
        {
            continue;
        }
        if record.run_id != manifest.run_id {
            return Err(invalid_run_jsonl(
                path,
                line,
                format!(
                    "selected record run_id `{}` does not match manifest runId `{}`",
                    record.run_id, manifest.run_id
                ),
            ));
        }
        if record.arm.kind != ONEIRON_CONTEXT_PACK_ARM_KIND {
            return Err(invalid_run_jsonl(
                path,
                line,
                format!(
                    "selected record arm.kind `{}` is not supported by this engine path; expected `{ONEIRON_CONTEXT_PACK_ARM_KIND}`",
                    record.arm.kind
                ),
            ));
        }
        if record.budget.currency != "tokens" {
            return Err(invalid_run_jsonl(
                path,
                line,
                format!(
                    "selected record budget.currency `{}` is not supported by this engine path; expected `tokens`",
                    record.budget.currency
                ),
            ));
        }
        match (&dataset_id, &dataset_revision) {
            (None, None) => {
                dataset_id = Some(record.dataset.id.clone());
                dataset_revision = Some(record.dataset.revision.clone());
            }
            (Some(id), Some(revision))
                if id == &record.dataset.id && revision == &record.dataset.revision => {}
            _ => {
                return Err(invalid_run_jsonl(
                    path,
                    line,
                    "selected records must share one dataset id and revision",
                ));
            }
        }
        if contract_records.contains_key(record.question_id.as_str()) {
            let arm_detail = arm_id.map_or_else(
                || " without dataset.armId".to_owned(),
                |id| format!(" for armId `{id}`"),
            );
            return Err(invalid_run_jsonl(
                path,
                line,
                format!(
                    "multiple selected run records found for question_id `{}`{arm_detail}; set dataset.armId to disambiguate",
                    record.question_id
                ),
            ));
        }

        let mut pending_for_case = 0;
        match &record.query_embedding {
            Some(ContractEmbeddingState::Ready(vector)) => {
                let vector = decode_contract_vector(path, line, vector)?;
                query_vector_by_case_id.insert(record.question_id.clone(), vector);
            }
            Some(ContractEmbeddingState::Pending { .. }) => {
                pending_for_case += 1;
                pending_vectors_total += 1;
            }
            None => {}
        }
        for item in &record.corpus {
            let entity_id = contract_corpus_entity_id(&record, item)?;
            let entity_hex = entity_id.to_hex();
            source_id_by_entity_id.insert(entity_hex.clone(), item.id.clone());
            if !seen_corpus.insert((record.question_id.clone(), item.id.clone())) {
                continue;
            }
            let fields = contract_corpus_fields(item);
            let payload = rmp_serde::to_vec_named(&fields)?;
            batch = batch
                .put(
                    &entity_id,
                    BENCH_CONTRACT_ENTITY_TYPE,
                    TimeRange { start: 1, end: 1 },
                    1,
                    &payload,
                )
                .text(&entity_id, &[("txt", item.text.as_str())]);
            text_fields_indexed += 1;
            records_loaded += 1;

            match &item.embedding {
                Some(ContractEmbeddingState::Ready(vector)) => {
                    let vector = decode_contract_vector(path, line, vector)?;
                    batch = batch.vector(&entity_id, &vector);
                }
                Some(ContractEmbeddingState::Pending { .. }) => {
                    pending_for_case += 1;
                    pending_vectors_total += 1;
                }
                None => {}
            }
        }

        if case_seen.insert(record.question_id.clone()) {
            cases.push(FixtureCase {
                case_id: record.question_id.clone(),
                query: record.question.clone(),
                limit,
                token_budget: record.budget.limit,
                expected_min_results,
                pending_vector_count: pending_for_case,
                query_embedding: None,
                fixture_class: FixtureClass::EvidenceSupported,
                temporal_search: None,
                temporal_evidence_ids: Vec::new(),
                opposing_evidence: None,
                offline_amortized_cost: CostComponentInput::default(),
            });
        }
        contract_records.insert(record.question_id.clone(), record);
    }

    batch.commit()?;

    for case_id in &manifest.case_ids {
        if !case_seen.contains(case_id.as_str()) {
            return Err(BeamError::MissingCase {
                fixture_id: dataset_id
                    .as_deref()
                    .map_or_else(|| path.display().to_string(), str::to_owned),
                case_id: case_id.clone(),
            });
        }
    }

    let dataset_id = dataset_id.unwrap_or_else(|| path.display().to_string());
    let dataset_revision = dataset_revision.unwrap_or_else(|| "unknown".to_owned());
    Ok(LoadedDataset {
        report: DatasetLoadReport {
            dataset_id: dataset_id.clone(),
            source_kind: JSONL_CONTRACT_SOURCE_KIND.to_owned(),
            records_loaded,
            text_fields_indexed,
            pending_vectors: pending_vectors_total,
        },
        fixture_id: dataset_id.clone(),
        fixture_description: format!("oneiron-eval run.jsonl {dataset_id}@{dataset_revision}"),
        cases,
        contract_records,
        source_id_by_entity_id,
        query_vector_by_case_id,
    })
}

fn resolve_manifest_paths(manifest: &mut RunManifest, manifest_path: &Path) {
    let Some(base) = manifest_path.parent() else {
        return;
    };
    if let DatasetSource::Jsonl { path, .. } = &mut manifest.dataset
        && path.is_relative()
    {
        *path = base.join(&path);
    }
    if let Some(outputs) = &mut manifest.outputs
        && outputs.packs_jsonl.is_relative()
    {
        outputs.packs_jsonl = base.join(&outputs.packs_jsonl);
    }
}

#[derive(Debug)]
struct RunJsonlEntry {
    line: usize,
    record: RunContractRecord,
}

fn read_run_jsonl_records(path: &Path) -> BeamResult<Vec<RunJsonlEntry>> {
    let file = File::open(path)?;
    let mut records = Vec::new();
    for (index, line) in BufReader::new(file).lines().enumerate() {
        let line_number = index + 1;
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let record: RunContractRecord = serde_json::from_str(&line)
            .map_err(|source| invalid_run_jsonl(path, line_number, source.to_string()))?;
        validate_run_contract_record_at(path, line_number, &record)?;
        records.push(RunJsonlEntry {
            line: line_number,
            record,
        });
    }
    if records.is_empty() {
        return Err(invalid_run_jsonl(
            path,
            0,
            "run.jsonl must contain at least one record",
        ));
    }
    Ok(records)
}

fn validate_run_contract_record_at(
    path: &Path,
    line: usize,
    record: &RunContractRecord,
) -> BeamResult<()> {
    if record.contract_version != EVAL_CONTRACT_VERSION {
        return Err(invalid_run_jsonl(
            path,
            line,
            format!(
                "contract_version must be `{EVAL_CONTRACT_VERSION}`, got `{}`",
                record.contract_version
            ),
        ));
    }
    if !matches!(record.record_type, ContractRecordType::Run) {
        return Err(invalid_run_jsonl(path, line, "record_type must be `run`"));
    }
    if record.run_id.trim().is_empty() {
        return Err(invalid_run_jsonl(path, line, "run_id must not be empty"));
    }
    if record.question_id.trim().is_empty() {
        return Err(invalid_run_jsonl(
            path,
            line,
            "question_id must not be empty",
        ));
    }
    if record.dataset.id.trim().is_empty() || record.dataset.revision.trim().is_empty() {
        return Err(invalid_run_jsonl(
            path,
            line,
            "dataset.id and dataset.revision must not be empty",
        ));
    }
    if record.arm.id.trim().is_empty() || record.arm.kind.trim().is_empty() {
        return Err(invalid_run_jsonl(
            path,
            line,
            "arm.id and arm.kind must not be empty",
        ));
    }
    if record.budget.currency.trim().is_empty() || record.budget.limit == 0 {
        return Err(invalid_run_jsonl(
            path,
            line,
            "budget.currency must not be empty and budget.limit must be > 0",
        ));
    }
    if record.question.trim().is_empty() {
        return Err(invalid_run_jsonl(path, line, "question must not be empty"));
    }
    if record.corpus.is_empty() {
        return Err(invalid_run_jsonl(path, line, "corpus must not be empty"));
    }
    let mut corpus_ids = BTreeSet::new();
    for item in &record.corpus {
        if item.id.trim().is_empty() || item.text.trim().is_empty() {
            return Err(invalid_run_jsonl(
                path,
                line,
                "corpus items must have non-empty id and text",
            ));
        }
        if !corpus_ids.insert(item.id.as_str()) {
            return Err(invalid_run_jsonl(
                path,
                line,
                "corpus item ids must be unique per run record",
            ));
        }
    }
    Ok(())
}

fn contract_corpus_entity_id(
    record: &RunContractRecord,
    item: &ContractCorpusRecord,
) -> BeamResult<EntityId> {
    let mut hasher = Sha256::new();
    hash_str(&mut hasher, EVAL_CONTRACT_VERSION);
    hash_str(&mut hasher, &record.run_id);
    hash_str(&mut hasher, &record.question_id);
    hash_str(&mut hasher, &item.id);
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    EntityId::from_bytes(bytes).map_err(|source| BeamError::InvalidEntityId {
        id: item.id.clone(),
        source,
    })
}

fn contract_corpus_fields(item: &ContractCorpusRecord) -> serde_json::Value {
    let mut fields = serde_json::Map::new();
    fields.insert(
        "txt".to_owned(),
        serde_json::Value::String(item.text.clone()),
    );
    fields.insert(
        "source_id".to_owned(),
        serde_json::Value::String(item.id.clone()),
    );
    if let Some(metadata) = &item.metadata {
        fields.insert("metadata".to_owned(), metadata.clone());
    }
    serde_json::Value::Object(fields)
}

fn decode_contract_vector(
    path: &Path,
    line: usize,
    vector: &ContractVector,
) -> BeamResult<Vec<f32>> {
    decode_contract_vector_value(vector).map_err(|reason| invalid_run_jsonl(path, line, reason))
}

fn decode_fixture_vector(
    fixture: &BeamFixture,
    owner: &str,
    embedding: &ContractEmbeddingState,
) -> BeamResult<Vec<f32>> {
    let ContractEmbeddingState::Ready(vector) = embedding else {
        return Err(invalid_fixture(
            fixture,
            format!("{owner} must be ready before fixture ingest"),
        ));
    };

    decode_contract_vector_value(vector)
        .map_err(|reason| invalid_fixture(fixture, format!("{owner} {reason}")))
}

fn decode_contract_vector_value(vector: &ContractVector) -> Result<Vec<f32>, String> {
    if vector.encoding != "f32-le-base64" {
        return Err(format!(
            "vector encoding must be f32-le-base64, got `{}`",
            vector.encoding
        ));
    }
    if vector.dimensions != BEAM_CONTRACT_EMBEDDING_DIMENSIONS {
        return Err(format!(
            "vector dimensions must be {BEAM_CONTRACT_EMBEDDING_DIMENSIONS} for this engine path, got {}",
            vector.dimensions
        ));
    }
    let bytes = decode_base64_standard(&vector.data)?;
    let expected_bytes = vector
        .dimensions
        .checked_mul(4)
        .ok_or_else(|| "vector dimensions overflow byte-size calculation".to_owned())?;
    if bytes.len() != expected_bytes {
        return Err(format!(
            "vector data decoded to {} bytes, expected {expected_bytes}",
            bytes.len()
        ));
    }
    Ok(bytes
        .chunks_exact(4)
        .map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect())
}

fn contract_context_pack_record(
    manifest: &RunManifest,
    loaded: &LoadedDataset,
    case: &FixtureCase,
    competitor: &CompetitorConfig,
    arm_report: &ArmReport,
) -> BeamResult<Option<ContextPackContractRecord>> {
    if manifest.outputs.is_none() || !competitor.arm.is_completed() {
        return Ok(None);
    }
    let ArmOutcome::Completed { context_pack } = &arm_report.outcome else {
        return Ok(None);
    };
    let Some(record) = loaded.contract_records.get(case.case_id.as_str()) else {
        return Ok(None);
    };

    let mut contexts =
        Vec::with_capacity(context_pack.results.len() + context_pack.neighbors.len());
    for entity in context_pack
        .results
        .iter()
        .chain(context_pack.neighbors.iter())
    {
        let source_id = loaded
            .source_id_by_entity_id
            .get(entity.id.as_str())
            .cloned()
            .unwrap_or_else(|| entity.id.clone());
        let Some(text) = context_pack
            .budgeted_text_by_entity_id
            .get(entity.id.as_str())
            .cloned()
        else {
            return Err(invalid_manifest(
                manifest,
                format!(
                    "serialized context-pack output did not include budgeted txt for entity `{}`",
                    entity.id
                ),
            ));
        };
        contexts.push(ContractPackContext {
            id: source_id.clone(),
            text,
            score: entity.score,
            source_turn_ids: vec![source_id],
        });
    }

    Ok(Some(ContextPackContractRecord {
        contract_version: EVAL_CONTRACT_VERSION,
        record_type: ContractRecordType::ContextPack,
        run_id: record.run_id.clone(),
        question_id: record.question_id.clone(),
        dataset: record.dataset.clone(),
        arm: contract_output_arm(record, competitor.arm),
        budget: record.budget.clone(),
        question: record.question.clone(),
        pack: ContractPack {
            token_count: Some(context_pack.serialized_tokens),
            corpus_digest: contract_corpus_digest(record),
            config: contract_pack_config(competitor.arm, case),
            contexts,
        },
        gold: record.gold.clone(),
    }))
}

fn contract_output_arm(record: &RunContractRecord, arm: ArmKind) -> ContractArm {
    match arm {
        ArmKind::Deterministic => record.arm.clone(),
        ArmKind::VanillaRag => ContractArm {
            id: VANILLA_RAG_CONTRACT_ARM_ID.to_owned(),
            kind: VANILLA_RAG_CONTRACT_ARM_KIND.to_owned(),
        },
        ArmKind::BackboneSolo | ArmKind::Agentic | ArmKind::Chat => record.arm.clone(),
    }
}

fn contract_pack_config(arm: ArmKind, case: &FixtureCase) -> Option<ContractPackConfig> {
    match arm {
        ArmKind::VanillaRag => Some(ContractPackConfig {
            kind: VANILLA_RAG_CONTRACT_ARM_KIND,
            version: VANILLA_RAG_CONFIG_VERSION,
            top_k: case.limit,
            chunking: VANILLA_RAG_CHUNKING,
            fusion: VANILLA_RAG_FUSION,
            signals: vec!["vector", "bm25f"],
            embedder_id: VANILLA_RAG_EMBEDDER_ID,
            vector_dimensions: BEAM_CONTRACT_EMBEDDING_DIMENSIONS,
            token_budget_source: "run_record.budget.limit",
            structure: "flat_l0_no_claims_no_ppr_no_graph",
        }),
        ArmKind::Deterministic | ArmKind::BackboneSolo | ArmKind::Agentic | ArmKind::Chat => None,
    }
}

fn write_contract_pack_rows(path: &Path, rows: &[ContextPackContractRecord]) -> BeamResult<()> {
    let mut file = File::create(path)?;
    for row in rows {
        serde_json::to_writer(&mut file, row)?;
        file.write_all(b"\n")?;
    }
    Ok(())
}

fn contract_corpus_digest(record: &RunContractRecord) -> String {
    let mut hasher = Sha256::new();
    hash_str(&mut hasher, EVAL_CONTRACT_VERSION);
    hash_str(&mut hasher, &record.dataset.id);
    hash_str(&mut hasher, &record.dataset.revision);
    hash_str(&mut hasher, &record.question_id);
    for item in &record.corpus {
        hash_str(&mut hasher, &item.id);
        hash_str(&mut hasher, &item.text);
    }
    format!("sha256:{}", hex_lower(&hasher.finalize()))
}

fn hash_str(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value.as_bytes());
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn decode_base64_standard(input: &str) -> Result<Vec<u8>, String> {
    let bytes: Vec<u8> = input
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    if !bytes.len().is_multiple_of(4) {
        return Err("base64 vector data length must be a multiple of 4".to_owned());
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let chunk_count = bytes.len() / 4;
    for (chunk_index, chunk) in bytes.chunks_exact(4).enumerate() {
        let mut vals = [0_u8; 4];
        let mut padding = 0;
        for (index, byte) in chunk.iter().copied().enumerate() {
            if byte == b'=' {
                vals[index] = 0;
                padding += 1;
            } else if padding > 0 {
                return Err("base64 vector data has non-padding after padding".to_owned());
            } else {
                vals[index] = base64_value(byte)
                    .ok_or_else(|| "base64 vector data contains an invalid character".to_owned())?;
            }
        }
        if padding > 2 || (padding > 0 && chunk_index + 1 != chunk_count) {
            return Err("base64 vector data has invalid padding".to_owned());
        }
        out.push((vals[0] << 2) | (vals[1] >> 4));
        if padding < 2 {
            out.push((vals[1] << 4) | (vals[2] >> 2));
        }
        if padding == 0 {
            out.push((vals[2] << 6) | vals[3]);
        }
    }
    Ok(out)
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn adapter_for(kind: ArmKind) -> Box<dyn BeamArmAdapter> {
    match kind {
        ArmKind::Deterministic => Box::new(DeterministicContextPackArm),
        ArmKind::VanillaRag => Box::new(VanillaRagArm),
        ArmKind::BackboneSolo | ArmKind::Agentic | ArmKind::Chat => Box::new(NotReadyArm { kind }),
    }
}

fn configured_context_pack_builder<'a>(
    vault: &'a Vault,
    case: &FixtureCase,
) -> ContextPackBuilder<'a> {
    let text_search_limit = if case.fixture_class == FixtureClass::LowConfidence && case.limit == 0
    {
        LOW_CONFIDENCE_RETRIEVAL_LIMIT
    } else {
        case.limit
    };
    let builder = vault
        .context_pack()
        .search_text(&case.query, text_search_limit)
        .field_profile(FieldProfile::Standard)
        .format(BEAM_CONTEXT_PACK_FORMAT)
        .merge_neighbors(false)
        .include_stats(true)
        .token_budget(case.token_budget);

    match (case.fixture_class, &case.temporal_search) {
        (FixtureClass::TemporalStaleness, Some(range)) => builder
            .search_temporal(range.start, range.end, case.limit)
            .limit(case.limit),
        (FixtureClass::LowConfidence, _) => builder.limit(case.limit),
        _ => builder,
    }
}

struct BudgetedContextPack {
    raw: ContextPack,
    serialized: Vec<u8>,
    serialized_tokens: u64,
    serialized_stats: PackStats,
    serialized_elapsed_us: u64,
    serialized_ids: SerializedContextPackIds,
    temporal_result_ids: BTreeSet<String>,
}

fn run_deterministic_context_pack(
    vault: &Vault,
    case: &FixtureCase,
) -> BeamResult<BudgetedContextPack> {
    run_budgeted_context_pack(|| configured_context_pack_builder(vault, case), vault, case)
}

fn run_vanilla_rag_context_pack(
    vault: &Vault,
    case: &FixtureCase,
    query_vector: &[f32],
) -> BeamResult<BudgetedContextPack> {
    run_budgeted_context_pack(
        || configured_vanilla_rag_context_pack_builder(vault, case, query_vector),
        vault,
        case,
    )
}

fn configured_vanilla_rag_context_pack_builder<'a>(
    vault: &'a Vault,
    case: &FixtureCase,
    query_vector: &'a [f32],
) -> ContextPackBuilder<'a> {
    let retrieval_limit = if case.fixture_class == FixtureClass::LowConfidence && case.limit == 0 {
        LOW_CONFIDENCE_RETRIEVAL_LIMIT
    } else {
        case.limit
    };

    vault
        .context_pack()
        .search_text(&case.query, retrieval_limit)
        .search_vector(query_vector, retrieval_limit)
        .field_profile(FieldProfile::Standard)
        .format(BEAM_CONTEXT_PACK_FORMAT)
        .merge_neighbors(false)
        .include_stats(true)
        .token_budget(case.token_budget)
        .limit(case.limit)
}

#[derive(Default)]
struct SerializedContextPackIds {
    results: HashSet<String>,
    neighbors: HashSet<String>,
    text_by_id: BTreeMap<String, String>,
}

#[derive(Clone, Copy)]
enum SerializedContextPackSection {
    Results,
    Neighbors,
}

struct ActiveSerializedContextPackSection {
    section: SerializedContextPackSection,
    section_indent: usize,
    group_indent: Option<usize>,
    row_indent: Option<usize>,
    row_id: Option<String>,
}

fn run_budgeted_context_pack<'a, F>(
    build_context_pack: F,
    vault: &Vault,
    case: &FixtureCase,
) -> BeamResult<BudgetedContextPack>
where
    F: Fn() -> ContextPackBuilder<'a>,
{
    let pack = build_context_pack().run()?;
    let serialized_start = Instant::now();
    let serialized_with_stats = build_context_pack().run_serialized_with_stats()?.value;
    let serialized_elapsed_us = serialized_start.elapsed().as_micros() as u64;
    let serialized = serialized_with_stats.bytes;
    let serialized_text = std::str::from_utf8(&serialized)?;
    let serialized_tokens = serialized_with_stats.stats.tokens.total_tokens as u64;
    let serialized_ids = serialized_context_pack_ids(serialized_text);
    let temporal_result_ids = temporal_result_ids(vault, case)?;

    Ok(BudgetedContextPack {
        raw: pack,
        serialized,
        serialized_tokens,
        serialized_stats: serialized_with_stats.stats,
        serialized_elapsed_us,
        serialized_ids,
        temporal_result_ids,
    })
}

fn temporal_result_ids(vault: &Vault, case: &FixtureCase) -> BeamResult<BTreeSet<String>> {
    if case.fixture_class != FixtureClass::TemporalStaleness {
        return Ok(BTreeSet::new());
    }
    let Some(range) = &case.temporal_search else {
        return Ok(BTreeSet::new());
    };
    let results = vault
        .query()
        .search_temporal(range.start, range.end, case.limit)
        .limit(case.limit)
        .run()?;

    Ok(results
        .into_iter()
        .map(|entity| entity.id.to_hex())
        .collect())
}

fn context_pack_report(pack: &BudgetedContextPack, case: &FixtureCase) -> ContextPackReport {
    let results = context_entity_reports_for_ids(&pack.raw.results, &pack.serialized_ids.results);
    let neighbors =
        context_entity_reports_for_ids(&pack.raw.neighbors, &pack.serialized_ids.neighbors);
    let budgeted_text_by_entity_id =
        budgeted_text_by_entity_id(&pack.raw, &pack.serialized_ids.text_by_id);
    let result_count = results.len();
    let neighbor_count = neighbors.len();
    let stats = &pack.serialized_stats;
    let items_truncated = stats.items_truncated.count;
    let items_dropped = stats.items_dropped.count;
    let items_truncated_reasons =
        accounting_reasons(items_truncated, stats.items_truncated.reason.as_str());
    let items_dropped_reasons =
        accounting_reasons(items_dropped, stats.items_dropped.reason.as_str());

    ContextPackReport {
        token_budget: case.token_budget,
        limit: case.limit,
        serialized_format: pack_format_label(BEAM_CONTEXT_PACK_FORMAT).to_owned(),
        serialized_bytes: pack.serialized.len(),
        serialized_tokens: pack.serialized_tokens,
        tokenizer_id: stats.tokens.tokenizer_id.clone(),
        query_cost: query_cost_report(case, pack),
        result_count,
        neighbor_count,
        results,
        neighbors,
        stats: PackStatsReport {
            candidates_considered: stats.candidates_considered,
            signals_used: stats
                .signals_used
                .iter()
                .copied()
                .map(signal_label)
                .map(str::to_owned)
                .collect(),
            query_time_us: stats.query_time_us,
            entities_hydrated: result_count,
            neighbors_hydrated: neighbor_count,
            cosine_ghosts_dampened: stats.cosine_ghosts_dampened,
            claims_suppressed: stats.claims_suppressed,
            tokenizer_id: stats.tokens.tokenizer_id.clone(),
            total_tokens: stats.tokens.total_tokens,
            section_tokens: stats
                .tokens
                .sections
                .iter()
                .map(|section| PackSectionTokenReport {
                    section: section.section.clone(),
                    tokens: section.tokens,
                })
                .collect(),
            item_tokens: stats
                .tokens
                .items
                .iter()
                .map(|item| PackItemTokenReport {
                    section: item.section.clone(),
                    id: item.id.clone(),
                    entity_type: item.entity_type,
                    tokens: item.tokens,
                })
                .collect(),
            items_truncated,
            items_truncated_reasons,
            items_dropped,
            items_dropped_reasons,
        },
        empty: pack.raw.empty.as_ref().map(|empty| EmptyContextReport {
            reason: empty_reason_label(empty.reason).to_owned(),
            total_in_scope: empty.total_in_scope,
            hint: empty.hint.clone(),
        }),
        temporal_result_ids: pack.temporal_result_ids.clone(),
        budgeted_text_by_entity_id,
    }
}

fn cost_breakdown(case: &FixtureCase, arm: &ArmReport) -> CostBreakdownReport {
    let query = match &arm.outcome {
        ArmOutcome::Completed { context_pack } => context_pack.query_cost.clone(),
        ArmOutcome::NotReady { .. } => not_applicable_cost(),
    };
    let offline = cost_component_from_input(&case.offline_amortized_cost);
    let judge = fixed_scorer_judge_cost();
    let total_cost_usd = normalized_cost_usd(query.cost_usd + offline.cost_usd + judge.cost_usd);

    CostBreakdownReport {
        query,
        offline,
        judge,
        total_cost_usd,
    }
}

fn query_cost_report(case: &FixtureCase, pack: &BudgetedContextPack) -> CostComponentReport {
    CostComponentReport {
        token_source: TokenAccountingSource::TokenizerCount,
        tokenizer_id: Some(pack.serialized_stats.tokens.tokenizer_id.clone()),
        input_tokens: oneiron::count_context_pack_tokens(&case.query) as u64,
        output_tokens: pack.serialized_tokens,
        target_tokens: case.token_budget as u64,
        elapsed_us: pack.serialized_elapsed_us,
        cost_usd: 0.0,
    }
}

fn fixed_scorer_judge_cost() -> CostComponentReport {
    CostComponentReport {
        token_source: TokenAccountingSource::FixtureDeclaredZero,
        tokenizer_id: None,
        input_tokens: 0,
        output_tokens: 0,
        target_tokens: 0,
        elapsed_us: 0,
        cost_usd: 0.0,
    }
}

fn cost_component_from_input(input: &CostComponentInput) -> CostComponentReport {
    CostComponentReport {
        token_source: input.token_source,
        tokenizer_id: None,
        input_tokens: input.input_tokens,
        output_tokens: input.output_tokens,
        target_tokens: input.target_tokens,
        elapsed_us: input.elapsed_us,
        cost_usd: normalized_cost_usd(input.cost_usd),
    }
}

fn not_applicable_cost() -> CostComponentReport {
    CostComponentReport {
        token_source: TokenAccountingSource::NotApplicable,
        tokenizer_id: None,
        input_tokens: 0,
        output_tokens: 0,
        target_tokens: 0,
        elapsed_us: 0,
        cost_usd: 0.0,
    }
}

fn validate_cost_component(owner: &str, input: &CostComponentInput) -> Result<(), String> {
    if input.token_source == TokenAccountingSource::CharCountEstimate {
        return Err(format!(
            "{owner} must not use char_count_estimate token accounting"
        ));
    }
    if !input.cost_usd.is_finite() || input.cost_usd < 0.0 {
        return Err(format!("{owner}.costUsd must be non-negative and finite"));
    }
    if input.cost_usd > MAX_NORMALIZABLE_COST_USD {
        return Err(format!("{owner}.costUsd is too large to normalize safely"));
    }
    if matches!(
        input.token_source,
        TokenAccountingSource::FixtureDeclaredZero | TokenAccountingSource::NotApplicable
    ) && !cost_component_metrics_are_zero(input)
    {
        return Err(format!(
            "{owner} with {:?} token accounting must declare zero tokens, elapsed time, and cost",
            input.token_source
        ));
    }
    Ok(())
}

fn cost_component_metrics_are_zero(input: &CostComponentInput) -> bool {
    input.input_tokens == 0
        && input.output_tokens == 0
        && input.target_tokens == 0
        && input.elapsed_us == 0
        && input.cost_usd == 0.0
}

fn normalized_cost_usd(cost: f64) -> f64 {
    if cost > MAX_NORMALIZABLE_COST_USD {
        cost
    } else {
        (cost * COST_USD_SCALE).round() / COST_USD_SCALE
    }
}

fn default_fixture_cost_source() -> TokenAccountingSource {
    TokenAccountingSource::FixtureDeclaredZero
}

const fn default_jsonl_retrieval_limit() -> usize {
    DEFAULT_JSONL_RETRIEVAL_LIMIT
}

fn accounting_reasons(count: usize, reason: &str) -> Vec<String> {
    if count == 0 {
        Vec::new()
    } else {
        vec![reason.to_owned()]
    }
}

fn completed_ability_scores(
    case: &FixtureCase,
    context_pack: &ContextPackReport,
) -> Vec<AbilityScoreReport> {
    if case.fixture_class.expects_abstention() {
        return abstention_ability_scores(case, context_pack);
    }

    let coverage = if case.expected_min_results == 0 {
        1.0
    } else {
        (context_pack.result_count as f32 / case.expected_min_results as f32).min(1.0)
    };
    let budget_passed =
        context_pack.stats.items_dropped == 0 && context_pack.stats.items_truncated == 0;
    let budget_score = if budget_passed { 1.0 } else { 0.0 };
    let budget_detail = budget_discipline_detail(case, context_pack);

    vec![
        AbilityScoreReport {
            ability: AbilityKind::RetrievalCoverage,
            score: Some(coverage),
            passed: Some(coverage >= 1.0),
            detail: format!(
                "{} serialized results for expected minimum {}",
                context_pack.result_count, case.expected_min_results
            ),
        },
        AbilityScoreReport {
            ability: AbilityKind::BudgetDiscipline,
            score: Some(budget_score),
            passed: Some(budget_passed),
            detail: budget_detail,
        },
        AbilityScoreReport {
            ability: AbilityKind::Readiness,
            score: Some(1.0),
            passed: Some(true),
            detail: "arm completed".to_owned(),
        },
    ]
}

fn abstention_ability_scores(
    case: &FixtureCase,
    context_pack: &ContextPackReport,
) -> Vec<AbilityScoreReport> {
    let (gate_passed, gate_detail) = abstention_gate_status(case, context_pack);

    vec![
        AbilityScoreReport {
            ability: AbilityKind::AbstentionGate,
            score: None,
            passed: Some(gate_passed),
            detail: format!("{}: {gate_detail}", case.fixture_class.gate_label()),
        },
        AbilityScoreReport {
            ability: AbilityKind::NoRegressionGate,
            score: None,
            passed: Some(true),
            detail: "numeric score suppressed before publication".to_owned(),
        },
        AbilityScoreReport {
            ability: AbilityKind::Readiness,
            score: None,
            passed: Some(true),
            detail: "arm completed and abstained by fixture safety gate".to_owned(),
        },
    ]
}

fn abstention_gate_status(case: &FixtureCase, context_pack: &ContextPackReport) -> (bool, String) {
    match case.fixture_class {
        FixtureClass::EvidenceSupported => (
            false,
            "evidence_supported cases must use scored BEAM abilities".to_owned(),
        ),
        FixtureClass::EmptyMemory => {
            let Some(empty) = context_pack.empty.as_ref() else {
                return (
                    false,
                    format!(
                        "empty vault had {} serialized results but no empty report",
                        context_pack.result_count
                    ),
                );
            };
            let passed = context_pack.result_count == 0
                && empty.total_in_scope == 0
                && empty.reason == "no_data";
            (
                passed,
                format!(
                    "empty vault had {} serialized results, {} in-scope records, and empty reason={}",
                    context_pack.result_count, empty.total_in_scope, empty.reason
                ),
            )
        }
        FixtureClass::LowConfidence => {
            let (empty_reason, total_in_scope) =
                context_pack.empty.as_ref().map_or(("none", 0), |empty| {
                    (empty.reason.as_str(), empty.total_in_scope)
                });
            let passed = context_pack.result_count == 0
                && empty_reason == "below_threshold"
                && total_in_scope > 0;
            (
                passed,
                format!(
                    "low-confidence query produced {} serialized results with {total_in_scope} in-scope records and empty reason={empty_reason}",
                    context_pack.result_count,
                ),
            )
        }
        FixtureClass::AdversarialContradiction => {
            let surfaced = context_pack_result_ids(context_pack);
            let required_ids = case
                .opposing_evidence
                .as_ref()
                .map(|evidence| evidence.record_ids.as_slice())
                .unwrap_or_default();
            let matched = required_ids
                .iter()
                .filter(|id| surfaced.contains(id.as_str()))
                .count();
            let passed = !required_ids.is_empty() && matched == required_ids.len();
            (
                passed,
                format!(
                    "contradictory fixture evidence surfaced {matched}/{} required opposing records",
                    required_ids.len()
                ),
            )
        }
        FixtureClass::TemporalStaleness => {
            let surfaced = context_pack_result_ids(context_pack);
            let used_temporal_signal = context_pack
                .stats
                .signals_used
                .iter()
                .any(|signal| signal == "temporal");
            let matched = case
                .temporal_evidence_ids
                .iter()
                .filter(|id| {
                    surfaced.contains(id.as_str())
                        && context_pack.temporal_result_ids.contains(id.as_str())
                })
                .count();
            let passed = !case.temporal_evidence_ids.is_empty()
                && used_temporal_signal
                && matched == case.temporal_evidence_ids.len();
            (
                passed,
                format!(
                    "staleness fixture surfaced {matched}/{} required temporal records with temporal signal={used_temporal_signal}",
                    case.temporal_evidence_ids.len()
                ),
            )
        }
    }
}

fn context_pack_result_ids(context_pack: &ContextPackReport) -> BTreeSet<&str> {
    context_pack
        .results
        .iter()
        .map(|entity| entity.id.as_str())
        .collect()
}

fn budget_discipline_detail(case: &FixtureCase, context_pack: &ContextPackReport) -> String {
    format!(
        "{} serialized items dropped [{}], {} truncated [{}] under {} token budget ({} bytes emitted)",
        context_pack.stats.items_dropped,
        accounting_reason_detail(&context_pack.stats.items_dropped_reasons),
        context_pack.stats.items_truncated,
        accounting_reason_detail(&context_pack.stats.items_truncated_reasons),
        case.token_budget,
        context_pack.serialized_bytes
    )
}

fn accounting_reason_detail(reasons: &[String]) -> String {
    if reasons.is_empty() {
        "none".to_owned()
    } else {
        reasons.join(", ")
    }
}

fn not_ready_ability_scores(
    competitor: &CompetitorConfig,
    not_ready: &NotReadyState,
) -> Vec<AbilityScoreReport> {
    [
        AbilityKind::RetrievalCoverage,
        AbilityKind::BudgetDiscipline,
        AbilityKind::Readiness,
    ]
    .into_iter()
    .map(|ability| AbilityScoreReport {
        ability,
        score: None,
        passed: None,
        detail: format!(
            "{} could not be scored for {}: {}",
            competitor.competitor_id,
            ability.as_str(),
            not_ready.reason
        ),
    })
    .collect()
}

fn mean_score(abilities: &[AbilityScoreReport]) -> Option<f32> {
    let (total, count) = abilities
        .iter()
        .filter_map(|ability| ability.score)
        .fold((0.0_f32, 0_usize), |(total, count), score| {
            (total + score, count + 1)
        });
    if count == 0 {
        None
    } else {
        Some(total / count as f32)
    }
}

fn context_entity_reports_for_ids(
    entities: &[oneiron::ContextEntity],
    serialized_ids: &HashSet<String>,
) -> Vec<ContextEntityReport> {
    entities
        .iter()
        .filter(|entity| serialized_ids.contains(&serialized_context_entity_id(entity)))
        .map(context_entity_report)
        .collect()
}

fn context_entity_report(entity: &oneiron::ContextEntity) -> ContextEntityReport {
    ContextEntityReport {
        id: entity.id.to_hex(),
        short_id: entity.short_id.clone(),
        entity_type: entity.entity_type,
        score: entity.score,
    }
}

fn serialized_context_pack_ids(serialized: &str) -> SerializedContextPackIds {
    let mut ids = SerializedContextPackIds::default();
    let mut active_section: Option<ActiveSerializedContextPackSection> = None;

    for line in serialized.lines() {
        let trimmed_start = line.trim_start();
        let trimmed = trimmed_start.trim_end();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = line.len() - trimmed_start.len();

        if indent == 0 {
            active_section = match trimmed {
                "results:" => Some(ActiveSerializedContextPackSection {
                    section: SerializedContextPackSection::Results,
                    section_indent: indent,
                    group_indent: None,
                    row_indent: None,
                    row_id: None,
                }),
                "neighbors:" => Some(ActiveSerializedContextPackSection {
                    section: SerializedContextPackSection::Neighbors,
                    section_indent: indent,
                    group_indent: None,
                    row_indent: None,
                    row_id: None,
                }),
                _ => None,
            };
            continue;
        }

        let Some(section) = active_section.as_mut() else {
            continue;
        };
        if indent <= section.section_indent {
            active_section = None;
            continue;
        }
        if section
            .group_indent
            .is_some_and(|group_indent| indent <= group_indent)
        {
            section.group_indent = None;
            section.row_indent = None;
            section.row_id = None;
        }

        if indent == section.section_indent + 2
            && trimmed.ends_with(':')
            && !trimmed.starts_with("- ")
        {
            section.group_indent = Some(indent);
            section.row_indent = None;
            section.row_id = None;
            continue;
        }

        let expected_row_indent = section
            .group_indent
            .map_or(section.section_indent + 2, |group_indent| group_indent + 2);

        if indent == expected_row_indent
            && let Some(raw_id) = trimmed.strip_prefix("- id: ")
        {
            let id = generated_yaml_scalar(raw_id);
            match section.section {
                SerializedContextPackSection::Results => {
                    ids.results.insert(id.clone());
                }
                SerializedContextPackSection::Neighbors => {
                    ids.neighbors.insert(id.clone());
                }
            }
            section.row_indent = Some(indent);
            section.row_id = Some(id);
            continue;
        }

        if let (Some(row_indent), Some(row_id)) = (section.row_indent, section.row_id.as_ref())
            && indent > row_indent
            && let Some(raw_text) = trimmed.strip_prefix("txt: ")
        {
            ids.text_by_id
                .insert(row_id.clone(), generated_yaml_scalar(raw_text));
        }
    }

    ids
}

fn budgeted_text_by_entity_id(
    pack: &ContextPack,
    text_by_serialized_id: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    pack.results
        .iter()
        .chain(pack.neighbors.iter())
        .filter_map(|entity| {
            let serialized_id = serialized_context_entity_id(entity);
            text_by_serialized_id
                .get(&serialized_id)
                .map(|text| (entity.id.to_hex(), text.clone()))
        })
        .collect()
}

fn generated_yaml_scalar(raw: &str) -> String {
    let trimmed = raw.trim();
    trimmed
        .strip_prefix('"')
        .and_then(|quoted| quoted.strip_suffix('"'))
        .unwrap_or(trimmed)
        .replace("\\\"", "\"")
        .replace("\\\\", "\\")
}

fn serialized_context_entity_id(entity: &oneiron::ContextEntity) -> String {
    let short_id = if entity.short_id.is_empty() {
        entity.id.to_hex()
    } else {
        entity.short_id.clone()
    };
    format!("{}:{:02x}", short_id, entity.content_hash)
}

fn arm_not_ready(kind: ArmKind) -> NotReadyState {
    NotReadyState {
        component: format!("{} arm", kind.as_str()),
        reason: "adapter intentionally not implemented in EVAL-001 scaffold".to_owned(),
        retryable: false,
    }
}

fn dataset_not_ready(source: &DatasetSource) -> NotReadyState {
    NotReadyState {
        component: "dataset loader".to_owned(),
        reason: format!(
            "{} datasets are declared in the schema but not implemented in EVAL-001",
            dataset_source_description(source)
        ),
        retryable: false,
    }
}

fn beam_vault_config() -> VaultConfig {
    let mut cfg = VaultConfig::device();
    cfg.map_size = 32 * 1024 * 1024;
    cfg.dimensions = BEAM_CONTRACT_EMBEDDING_DIMENSIONS;
    cfg.embedding_model = Some("oneiron/eval-contract@v1".to_owned());
    cfg.max_readers = 16;
    cfg
}

fn invalid_fixture(fixture: &BeamFixture, reason: impl Into<String>) -> BeamError {
    BeamError::InvalidFixture {
        fixture_id: fixture.fixture_id.clone(),
        reason: reason.into(),
    }
}

fn invalid_manifest(manifest: &RunManifest, reason: impl Into<String>) -> BeamError {
    BeamError::InvalidManifest {
        run_id: manifest.run_id.clone(),
        reason: reason.into(),
    }
}

fn invalid_run_jsonl(path: &Path, line: usize, reason: impl Into<String>) -> BeamError {
    BeamError::InvalidRunJsonl {
        path: path.display().to_string(),
        line,
        reason: reason.into(),
    }
}

fn dataset_source_description(source: &DatasetSource) -> String {
    match source {
        DatasetSource::Fixture { fixture_id } => format!("fixture `{fixture_id}`"),
        DatasetSource::Jsonl { path, .. } => format!("jsonl `{}`", path.display()),
        DatasetSource::Miracl { dataset } => format!("miracl `{dataset}`"),
        DatasetSource::MrTydi { dataset } => format!("mr_tydi `{dataset}`"),
    }
}

fn report_format_label(format: ReportFormat) -> &'static str {
    match format {
        ReportFormat::Json => "json",
    }
}

fn pack_format_label(format: PackFormat) -> &'static str {
    match format {
        PackFormat::Json => "json",
        PackFormat::Yaml => "yaml",
        PackFormat::Toon => "toon",
        PackFormat::Markdown => "markdown",
        PackFormat::Plaintext => "plaintext",
        _ => "unknown",
    }
}

fn signal_label(signal: Signal) -> &'static str {
    match signal {
        Signal::Vector => "vector",
        Signal::Text => "text",
        Signal::Phonetic => "phonetic",
        Signal::Temporal => "temporal",
        Signal::Ppr => "ppr",
        _ => "unknown",
    }
}

fn empty_reason_label(reason: EmptyReason) -> &'static str {
    match reason {
        EmptyReason::FilterMatchedNone => "filter_matched_none",
        EmptyReason::NoData => "no_data",
        EmptyReason::AllActivated => "all_activated",
        EmptyReason::BelowThreshold => "below_threshold",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oneiron::context_pack::{PackItemAccounting, PackStats};

    #[test]
    fn parse_fixture_and_manifest_accepts_beam_128k_smoke_schema() {
        let fixture = parse_fixture_json(BUILTIN_FIXTURE_JSON).expect("fixture parses");
        let manifest = parse_manifest_json(BUILTIN_MANIFEST_JSON).expect("manifest parses");

        assert_eq!(fixture.schema_version, SCHEMA_VERSION);
        assert_eq!(manifest.schema_version, SCHEMA_VERSION);
        assert_eq!(fixture.fixture_id, "beam-128k-smoke");
        assert_eq!(fixture.cases[0].token_budget, BEAM_128K_TOKEN_BUDGET);
        ensure_manifest_selects_128k_case(&manifest, &fixture)
            .expect("manifest selects the 128K smoke case");
        assert_eq!(
            manifest.arms,
            vec![
                ArmKind::Deterministic,
                ArmKind::VanillaRag,
                ArmKind::BackboneSolo,
                ArmKind::Agentic,
                ArmKind::Chat
            ]
        );
    }

    #[test]
    fn fixture_validation_requires_fields_object() {
        let mut fixture_json: serde_json::Value =
            serde_json::from_str(BUILTIN_FIXTURE_JSON).expect("fixture JSON");
        fixture_json["records"][0]["fields"] = serde_json::json!(["body"]);
        let err = parse_fixture_json(&fixture_json.to_string())
            .expect_err("fixture fields must be object");

        assert!(
            err.to_string()
                .contains("record fields must be a JSON object")
        );
    }

    #[test]
    fn fixture_validation_rejects_missing_fields() {
        let mut fixture_json: serde_json::Value =
            serde_json::from_str(BUILTIN_FIXTURE_JSON).expect("fixture JSON");
        fixture_json["records"][0]
            .as_object_mut()
            .expect("record object")
            .remove("fields");
        let err =
            parse_fixture_json(&fixture_json.to_string()).expect_err("record fields are required");

        assert!(err.to_string().contains("missing field `fields`"));
    }

    #[test]
    fn fixture_validation_rejects_text_field_missing_from_fields() {
        let mut fixture_json: serde_json::Value =
            serde_json::from_str(BUILTIN_FIXTURE_JSON).expect("fixture JSON");
        fixture_json["records"][0]["text"][0]["field"] = serde_json::json!("missing");
        let err = parse_fixture_json(&fixture_json.to_string())
            .expect_err("text field must reference stored field");

        assert!(
            err.to_string()
                .contains("text fields must reference keys present in record.fields")
        );
    }

    #[test]
    fn manifest_validation_rejects_duplicate_arms() {
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(BUILTIN_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["arms"] = serde_json::json!(["deterministic", "deterministic"]);
        let err = parse_manifest_json(&manifest_json.to_string())
            .expect_err("duplicate arms must be rejected");

        assert!(err.to_string().contains("manifest arms must be unique"));
    }

    #[test]
    fn manifest_schema_version_rejects_legacy_v1_before_required_competitors() {
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(BUILTIN_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["schemaVersion"] = serde_json::json!(1);
        manifest_json
            .as_object_mut()
            .expect("manifest object")
            .remove("competitors");
        let err = parse_manifest_json(&manifest_json.to_string())
            .expect_err("legacy v1 manifests must be rejected by schema version first");

        assert!(matches!(
            &err,
            BeamError::UnsupportedSchemaVersion {
                expected: SCHEMA_VERSION,
                actual: 1
            }
        ));
        assert!(!err.to_string().contains("missing field `competitors`"));
    }

    #[test]
    fn manifest_validation_rejects_uncarded_competitor_rows() {
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(BUILTIN_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["competitors"][0]
            .as_object_mut()
            .expect("competitor object")
            .remove("card");
        let err = parse_manifest_json(&manifest_json.to_string())
            .expect_err("uncarded competitors must be rejected");

        assert!(
            err.to_string()
                .contains("uncarded BEAM competitor row `deterministic-context-pack`")
        );
    }

    #[test]
    fn manifest_validation_requires_competitor_rows_to_match_arms() {
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(BUILTIN_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["competitors"][0]["arm"] = serde_json::json!("chat");
        let err = parse_manifest_json(&manifest_json.to_string())
            .expect_err("competitor rows must match arms");

        assert!(
            err.to_string()
                .contains("competitor row arms must match manifest arms in order")
        );
    }

    #[test]
    fn manifest_validation_rejects_public_parity_for_fixture_dataset() {
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(BUILTIN_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["competitors"][0]["card"]["publicParityStatus"] =
            serde_json::json!("public_parity");
        let err = parse_manifest_json(&manifest_json.to_string())
            .expect_err("fixture-backed manifests must not claim public parity");

        assert!(
            err.to_string()
                .contains("fixture-backed BEAM manifests cannot claim public parity")
        );
    }

    #[test]
    fn run_fixture_manifest_validates_manifest_before_loading_dataset() {
        let fixture = parse_fixture_json(BUILTIN_FIXTURE_JSON).expect("fixture parses");
        let mut manifest = parse_manifest_json(BUILTIN_MANIFEST_JSON).expect("manifest parses");
        manifest.schema_version = 1;
        manifest.dataset = DatasetSource::Miracl {
            dataset: "should-not-load".to_owned(),
        };

        let err = run_fixture_manifest(&manifest, &fixture)
            .expect_err("manifest validation must run before dataset loading");

        assert!(matches!(
            err,
            BeamError::UnsupportedSchemaVersion {
                expected: SCHEMA_VERSION,
                actual: 1
            }
        ));
    }

    #[test]
    fn run_fixture_manifest_validates_case_ids_before_loading_dataset() {
        let mut fixture = parse_fixture_json(BUILTIN_FIXTURE_JSON).expect("fixture parses");
        let mut manifest = parse_manifest_json(BUILTIN_MANIFEST_JSON).expect("manifest parses");
        fixture.records[0].id = "not-a-hex-entity-id".to_owned();
        manifest.case_ids = vec!["missing_case".to_owned()];

        let err = run_fixture_manifest(&manifest, &fixture)
            .expect_err("case-id validation must run before dataset loading");

        assert!(matches!(
            err,
            BeamError::MissingCase {
                fixture_id,
                case_id
            } if fixture_id == "beam-128k-smoke" && case_id == "missing_case"
        ));
    }

    #[test]
    fn deterministic_arm_exercises_serialized_128k_budget_path() {
        let fixture = parse_fixture_json(BUILTIN_FIXTURE_JSON).expect("fixture parses");
        let manifest = parse_manifest_json(BUILTIN_MANIFEST_JSON).expect("manifest parses");
        let tempdir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(tempdir.path(), beam_vault_config()).expect("vault opens");
        load_dataset(&vault, &manifest, Some(&fixture)).expect("fixture loads");

        let pack =
            run_deterministic_context_pack(&vault, &fixture.cases[0]).expect("deterministic run");
        let serialized_text =
            std::str::from_utf8(&pack.serialized).expect("serialized context pack is UTF-8");

        assert_eq!(fixture.cases[0].token_budget, BEAM_128K_TOKEN_BUDGET);
        assert!(pack.raw.results.len() >= fixture.cases[0].expected_min_results);
        assert!(!pack.serialized.is_empty());
        assert!(serialized_text.contains("results:"));
        assert!(serialized_text.contains(
            "txt: BEAM deterministic context pack 128K smoke target for evaluation scaffolding."
        ));
        assert!(serialized_text.contains("lvl: benchmark-smoke"));
        assert!(serialized_text.contains("at: beam-smoke-t1"));
        assert!(
            pack.serialized_ids
                .results
                .iter()
                .any(|id| id.starts_with("sm"))
        );
    }

    #[test]
    fn serialized_context_pack_ids_ignore_nested_yaml_id_fields() {
        let serialized = r#"
results:
  memory:
    - id: result:01
      txt: Budgeted result text
      title: kept
      nested:
        - id: dropped-result:02
neighbors:
  memory:
    - id: neighbor:03
      txt: "Budgeted neighbor text"
      nested:
        - id: dropped-neighbor:04
"#;

        let ids = serialized_context_pack_ids(serialized);

        assert_eq!(ids.results, HashSet::from(["result:01".to_owned()]));
        assert_eq!(ids.neighbors, HashSet::from(["neighbor:03".to_owned()]));
        assert_eq!(
            ids.text_by_id.get("result:01").map(String::as_str),
            Some("Budgeted result text")
        );
        assert_eq!(
            ids.text_by_id.get("neighbor:03").map(String::as_str),
            Some("Budgeted neighbor text")
        );
    }

    #[test]
    fn deterministic_arm_reports_budgeted_pack_when_token_budget_drops_rows() {
        let mut fixture = parse_fixture_json(BUILTIN_FIXTURE_JSON).expect("fixture parses");
        let manifest = parse_manifest_json(BUILTIN_MANIFEST_JSON).expect("manifest parses");
        for (offset, id) in [
            "30303030303030303030303030303030",
            "40404040404040404040404040404040",
            "50505050505050505050505050505050",
        ]
        .into_iter()
        .enumerate()
        {
            let mut record = fixture.records[0].clone();
            record.id = id.to_owned();
            record.occurred.start = 3 + offset as u64;
            record.occurred.end = 3 + offset as u64;
            record.learned_at = 3 + offset as u64;
            fixture.records.push(record);
        }
        fixture.cases[0].token_budget = 1;
        fixture.cases[0].expected_min_results = 0;
        let tempdir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(tempdir.path(), beam_vault_config()).expect("vault opens");
        let loaded = load_dataset(&vault, &manifest, Some(&fixture)).expect("fixture loads");
        let raw_pack = configured_context_pack_builder(&vault, &fixture.cases[0])
            .run()
            .expect("raw context pack");

        let arm = DeterministicContextPackArm
            .run(&vault, &loaded, &fixture.cases[0])
            .expect("deterministic arm reports");
        let ArmOutcome::Completed { context_pack } = arm.outcome else {
            panic!("deterministic arm should complete");
        };

        assert_eq!(context_pack.serialized_format, "yaml");
        assert!(raw_pack.results.len() > context_pack.result_count);
        assert!(context_pack.stats.items_dropped > 0);
    }

    #[test]
    fn budget_discipline_uses_accounting_not_serialized_byte_count() {
        let case = FixtureCase {
            case_id: "budget-accounting-regression".to_owned(),
            query: "budget accounting".to_owned(),
            limit: 1,
            token_budget: 8,
            expected_min_results: 1,
            pending_vector_count: 0,
            query_embedding: None,
            fixture_class: FixtureClass::EvidenceSupported,
            temporal_search: None,
            temporal_evidence_ids: Vec::new(),
            opposing_evidence: None,
            offline_amortized_cost: CostComponentInput::default(),
        };
        let mut context_pack = ContextPackReport {
            token_budget: case.token_budget,
            limit: case.limit,
            serialized_format: "yaml".to_owned(),
            serialized_bytes: 24,
            serialized_tokens: 6,
            tokenizer_id: oneiron::DEFAULT_CONTEXT_PACK_TOKENIZER_ID.to_owned(),
            query_cost: CostComponentReport {
                token_source: TokenAccountingSource::TokenizerCount,
                tokenizer_id: Some(oneiron::DEFAULT_CONTEXT_PACK_TOKENIZER_ID.to_owned()),
                input_tokens: 2,
                output_tokens: 6,
                target_tokens: case.token_budget as u64,
                elapsed_us: 10,
                cost_usd: 0.0,
            },
            result_count: 1,
            neighbor_count: 0,
            results: Vec::new(),
            neighbors: Vec::new(),
            stats: empty_pack_stats_report(),
            empty: None,
            temporal_result_ids: BTreeSet::new(),
            budgeted_text_by_entity_id: BTreeMap::new(),
        };

        let scores = completed_ability_scores(&case, &context_pack);
        let budget = budget_score(&scores);
        assert_eq!(
            budget.passed,
            Some(true),
            "bytes can exceed token budget units when no serializer accounting loss occurred"
        );
        assert_eq!(budget.score, Some(1.0));

        context_pack.serialized_bytes = 4;
        context_pack.stats.items_dropped = 1;
        context_pack.stats.items_dropped_reasons = vec!["token_budget".to_owned()];

        let scores = completed_ability_scores(&case, &context_pack);
        let budget = budget_score(&scores);
        assert_eq!(
            budget.passed,
            Some(false),
            "small byte output must not pass when serialization accounting dropped content"
        );
        assert_eq!(budget.score, Some(0.0));
        assert!(budget.detail.contains("token_budget"));
    }

    #[test]
    fn deterministic_arm_runs_beam_128k_fixture_end_to_end() {
        let report = run_builtin_smoke().expect("BEAM smoke report");
        let deterministic = find_arm(&report, ArmKind::Deterministic);

        let ArmOutcome::Completed { context_pack } = &deterministic.outcome else {
            panic!("deterministic arm should complete");
        };
        assert_eq!(context_pack.token_budget, BEAM_128K_TOKEN_BUDGET);
        assert!(context_pack.result_count >= 1);
        assert!(
            context_pack
                .results
                .iter()
                .any(|entity| { entity.id == "10101010101010101010101010101010" })
        );
    }

    #[test]
    fn vanilla_rag_arm_runs_beam_128k_fixture_end_to_end() {
        let report = run_builtin_smoke().expect("BEAM smoke report");
        let vanilla = find_arm(&report, ArmKind::VanillaRag);

        let ArmOutcome::Completed { context_pack } = &vanilla.outcome else {
            panic!("vanilla-rag arm should complete");
        };

        assert_eq!(context_pack.token_budget, BEAM_128K_TOKEN_BUDGET);
        assert!(context_pack.result_count >= 1);
        assert!(
            context_pack
                .stats
                .signals_used
                .iter()
                .any(|signal| signal == "vector")
        );
        assert!(
            context_pack
                .stats
                .signals_used
                .iter()
                .any(|signal| signal == "text")
        );
        assert!(
            context_pack
                .results
                .iter()
                .any(|entity| { entity.id == "10101010101010101010101010101010" })
        );
    }

    #[test]
    fn vanilla_rag_and_deterministic_share_real_token_budget() {
        let report = run_builtin_smoke().expect("BEAM smoke report");
        let deterministic = completed_context_pack(&report, ArmKind::Deterministic);
        let vanilla = completed_context_pack(&report, ArmKind::VanillaRag);

        assert_eq!(deterministic.token_budget, vanilla.token_budget);
        assert_eq!(
            deterministic.query_cost.target_tokens,
            vanilla.query_cost.target_tokens
        );
        assert_eq!(deterministic.tokenizer_id, vanilla.tokenizer_id);
        assert_eq!(deterministic.stats.tokenizer_id, vanilla.stats.tokenizer_id);
        assert!(deterministic.serialized_tokens <= deterministic.token_budget as u64);
        assert!(vanilla.serialized_tokens <= vanilla.token_budget as u64);
        assert_eq!(
            vanilla.query_cost.token_source,
            TokenAccountingSource::TokenizerCount
        );
    }

    #[test]
    fn report_records_real_query_tokens_target_tokens_and_cost_boundaries() {
        let report = run_builtin_smoke().expect("BEAM smoke report");
        let report_json = serde_json::to_value(&report).expect("report serializes");
        let deterministic = find_arm(&report, ArmKind::Deterministic);
        let ArmOutcome::Completed { context_pack } = &deterministic.outcome else {
            panic!("deterministic arm should complete");
        };
        let competitors = report_json["cases"][0]["competitors"]
            .as_array()
            .expect("competitors array");
        let deterministic_competitor = competitors
            .iter()
            .find(|competitor| competitor["competitorId"] == "deterministic-context-pack")
            .expect("deterministic competitor");

        assert_eq!(
            context_pack.query_cost.input_tokens,
            oneiron::count_context_pack_tokens("BEAM deterministic context pack") as u64
        );
        assert_eq!(
            context_pack.query_cost.tokenizer_id.as_deref(),
            Some(oneiron::DEFAULT_CONTEXT_PACK_TOKENIZER_ID)
        );
        assert_eq!(
            context_pack.query_cost.output_tokens,
            context_pack.serialized_tokens
        );
        assert_eq!(
            context_pack.query_cost.target_tokens,
            BEAM_128K_TOKEN_BUDGET as u64
        );
        assert_eq!(
            deterministic_competitor["costs"]["query"]["tokenSource"],
            "tokenizer_count"
        );
        assert_eq!(
            deterministic_competitor["costs"]["query"]["elapsedUs"],
            context_pack.query_cost.elapsed_us
        );
        assert_eq!(
            deterministic_competitor["costs"]["offline"]["tokenSource"],
            "fixture_declared_zero"
        );
        assert_eq!(
            deterministic_competitor["costs"]["judge"]["tokenSource"],
            "fixture_declared_zero"
        );
        assert_eq!(deterministic_competitor["costs"]["totalCostUsd"], 0.0);
        assert!(
            deterministic_competitor["costs"]["query"]["elapsedUs"]
                .as_u64()
                .expect("elapsedUs is u64")
                > 0
        );
    }

    #[test]
    fn query_cost_elapsed_uses_serialized_pass_only() {
        let case = FixtureCase {
            case_id: "elapsed_boundary".to_owned(),
            query: "BEAM deterministic context pack".to_owned(),
            limit: 1,
            token_budget: 128,
            expected_min_results: 0,
            pending_vector_count: 0,
            query_embedding: None,
            fixture_class: FixtureClass::EvidenceSupported,
            temporal_search: None,
            temporal_evidence_ids: Vec::new(),
            opposing_evidence: None,
            offline_amortized_cost: CostComponentInput::default(),
        };
        let pack = BudgetedContextPack {
            raw: ContextPack {
                results: Vec::new(),
                neighbors: Vec::new(),
                stats: PackStats {
                    candidates_considered: 0,
                    signals_used: Vec::new(),
                    query_time_us: 11,
                    entities_hydrated: 0,
                    neighbors_hydrated: 0,
                    cosine_ghosts_dampened: 0,
                    claims_suppressed: 0,
                    tokens: oneiron::PackTokenStats::default(),
                    items_truncated: PackItemAccounting::item_budget(),
                    items_dropped: PackItemAccounting::token_budget(),
                },
                empty: None,
            },
            serialized: Vec::new(),
            serialized_tokens: 7,
            serialized_stats: PackStats {
                candidates_considered: 0,
                signals_used: Vec::new(),
                query_time_us: 11,
                entities_hydrated: 0,
                neighbors_hydrated: 0,
                cosine_ghosts_dampened: 0,
                claims_suppressed: 0,
                tokens: oneiron::PackTokenStats {
                    tokenizer_id: oneiron::DEFAULT_CONTEXT_PACK_TOKENIZER_ID.to_owned(),
                    total_tokens: 7,
                    sections: Vec::new(),
                    items: Vec::new(),
                },
                items_truncated: PackItemAccounting::item_budget(),
                items_dropped: PackItemAccounting::token_budget(),
            },
            serialized_elapsed_us: 13,
            serialized_ids: SerializedContextPackIds::default(),
            temporal_result_ids: BTreeSet::new(),
        };

        let report = query_cost_report(&case, &pack);

        assert_eq!(report.elapsed_us, 13);
    }

    #[test]
    fn report_arm_outcome_payload_uses_camel_case_fields() {
        let report = run_builtin_smoke().expect("BEAM smoke report");
        let report_json = serde_json::to_value(&report).expect("report serializes");
        let arms = report_json["cases"][0]["arms"]
            .as_array()
            .expect("arms array");
        let deterministic = arms
            .iter()
            .find(|arm| arm["arm"] == "deterministic")
            .expect("deterministic arm");
        let agentic = arms
            .iter()
            .find(|arm| arm["arm"] == "agentic")
            .expect("agentic arm");

        assert!(deterministic["outcome"].get("contextPack").is_some());
        assert!(deterministic["outcome"].get("context_pack").is_none());
        assert!(agentic["outcome"].get("notReady").is_some());
        assert!(agentic["outcome"].get("not_ready").is_none());
    }

    #[test]
    fn report_records_scorer_version_and_public_parity_status() {
        let report = run_builtin_smoke().expect("BEAM smoke report");
        let report_json = serde_json::to_value(&report).expect("report serializes");
        let competitors = report_json["cases"][0]["competitors"]
            .as_array()
            .expect("competitors array");
        let deterministic = competitors
            .iter()
            .find(|competitor| competitor["competitorId"] == "deterministic-context-pack")
            .expect("deterministic competitor");

        assert_eq!(report_json["scorer"]["version"], BEAM_SCORER_VERSION);
        assert_eq!(deterministic["card"]["publicParityStatus"], "fixture_only");
        assert_eq!(
            deterministic["scoring"]["scorerVersion"],
            BEAM_SCORER_VERSION
        );
        assert!(
            deterministic["scoring"]["abilities"]
                .as_array()
                .expect("abilities array")
                .iter()
                .any(|ability| ability["ability"] == "retrieval_coverage")
        );
    }

    #[test]
    fn manifest_rejects_char_count_token_estimates_for_scored_rows() {
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(BUILTIN_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["competitors"][0]["card"]["tokenAccounting"]["source"] =
            serde_json::json!("char_count_estimate");
        let err = parse_manifest_json(&manifest_json.to_string())
            .expect_err("char-count token estimates must be rejected");

        assert!(
            err.to_string()
                .contains("model-scored competitor rows must not use char_count_estimate")
        );
    }

    #[test]
    fn manifest_requires_token_accounting_for_completed_rows() {
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(BUILTIN_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["competitors"][0]["card"]
            .as_object_mut()
            .expect("card object")
            .remove("tokenAccounting");
        let err = parse_manifest_json(&manifest_json.to_string())
            .expect_err("completed rows must declare token accounting");

        assert!(
            err.to_string()
                .contains("completed competitor rows must declare tokenAccounting")
        );
    }

    #[test]
    fn manifest_rejects_non_tokenizer_accounting_for_deterministic_rows() {
        for source in ["provider_usage", "fixture_declared_zero", "not_applicable"] {
            let mut manifest_json: serde_json::Value =
                serde_json::from_str(BUILTIN_MANIFEST_JSON).expect("manifest JSON");
            manifest_json["competitors"][0]["card"]["tokenAccounting"]["source"] =
                serde_json::json!(source);
            let err = parse_manifest_json(&manifest_json.to_string())
                .expect_err("deterministic rows must use tokenizer_count accounting");

            assert!(
                err.to_string()
                    .contains("completed competitor rows must declare tokenizer_count")
            );
        }
    }

    #[test]
    fn majority_of_three() {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum Verdict {
            Keep,
            Discard,
            Revise,
        }

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum JudgeCallFailed {
            Timeout,
            Refusal,
        }

        for votes in [
            [Verdict::Keep, Verdict::Keep, Verdict::Discard],
            [Verdict::Keep, Verdict::Discard, Verdict::Keep],
            [Verdict::Discard, Verdict::Keep, Verdict::Keep],
        ] {
            let mut calls = Vec::new();
            let decision = super::majority_of_three::<Verdict, JudgeCallFailed, _>(|index| {
                calls.push(index);
                Ok(votes[index])
            })
            .expect("two agreeing votes decide the judgment");

            assert_eq!(calls, vec![0, 1, 2]);
            assert_eq!(decision.verdict, Verdict::Keep);
            assert_eq!(decision.vote_count, 2);
        }

        let mut calls = Vec::new();
        let decision = super::majority_of_three::<Verdict, JudgeCallFailed, _>(|index| {
            calls.push(index);
            Ok(Verdict::Keep)
        })
        .expect("unanimous votes decide the judgment");

        // The first two votes already agree; the third call still happens and the tally is the
        // winning verdict's, not the number of attempted calls.
        assert_eq!(calls, vec![0, 1, 2]);
        assert_eq!(decision.verdict, Verdict::Keep);
        assert_eq!(decision.vote_count, JUDGE_VOTE_COUNT);

        let mut calls = Vec::new();
        let error = super::majority_of_three::<Verdict, JudgeCallFailed, _>(|index| {
            calls.push(index);
            Ok([Verdict::Keep, Verdict::Discard, Verdict::Revise][index])
        })
        .expect_err("three distinct verdicts cannot reach a majority");

        assert_eq!(calls, vec![0, 1, 2]);
        match error {
            MajorityVoteError::Tie { votes } => {
                assert_eq!(votes, [Verdict::Keep, Verdict::Discard, Verdict::Revise]);
            }
            MajorityVoteError::CallFailures { attempts } => {
                panic!("expected a typed tie, got call failures {attempts:?}")
            }
        }

        let mut calls = Vec::new();
        let error = super::majority_of_three::<Verdict, JudgeCallFailed, _>(|index| {
            calls.push(index);
            if index == 1 {
                Err(JudgeCallFailed::Refusal)
            } else {
                Ok(Verdict::Keep)
            }
        })
        .expect_err("a failed call emits no verdict");

        assert_eq!(calls, vec![0, 1, 2]);
        match error {
            MajorityVoteError::CallFailures { attempts } => {
                assert_eq!(attempts[0], Ok(Verdict::Keep));
                assert_eq!(attempts[1], Err(JudgeCallFailed::Refusal));
                assert_eq!(attempts[2], Ok(Verdict::Keep));
            }
            MajorityVoteError::Tie { votes } => {
                panic!("expected typed call failures, got a tie {votes:?}")
            }
        }

        let mut calls = Vec::new();
        let error = super::majority_of_three::<Verdict, JudgeCallFailed, _>(|index| {
            calls.push(index);
            match index {
                0 => Err(JudgeCallFailed::Timeout),
                1 => Ok(Verdict::Discard),
                _ => Err(JudgeCallFailed::Refusal),
            }
        })
        .expect_err("multiple failed calls emit no verdict");

        assert_eq!(calls, vec![0, 1, 2]);
        match error {
            MajorityVoteError::CallFailures { attempts } => {
                assert_eq!(attempts[0], Err(JudgeCallFailed::Timeout));
                assert_eq!(attempts[1], Ok(Verdict::Discard));
                assert_eq!(attempts[2], Err(JudgeCallFailed::Refusal));
            }
            MajorityVoteError::Tie { votes } => {
                panic!("expected typed call failures, got a tie {votes:?}")
            }
        }

        // A failure at index 0 does not short-circuit: indices 1 and 2 still run, their real
        // outcomes are carried back, and their agreement is not promoted to a verdict.
        let mut calls = Vec::new();
        let error = super::majority_of_three::<Verdict, JudgeCallFailed, _>(|index| {
            calls.push(index);
            if index == 0 {
                Err(JudgeCallFailed::Timeout)
            } else {
                Ok(Verdict::Keep)
            }
        })
        .expect_err("a failed first call emits no verdict");

        assert_eq!(calls, vec![0, 1, 2]);
        match error {
            MajorityVoteError::CallFailures { attempts } => {
                assert_eq!(attempts[0], Err(JudgeCallFailed::Timeout));
                assert_eq!(attempts[1], Ok(Verdict::Keep));
                assert_eq!(attempts[2], Ok(Verdict::Keep));
            }
            MajorityVoteError::Tie { votes } => {
                panic!("expected typed call failures, got a tie {votes:?}")
            }
        }
    }

    #[test]
    fn answer_prompt_pinned_on_card() {
        fn majority_card(prompt: &str) -> JudgeMetadata {
            JudgeMetadata {
                judge_id: "beam-llm-judge".to_owned(),
                version: "v1".to_owned(),
                notes: "Three-vote LLM judgment; answer prompt pinned.".to_owned(),
                answer_prompt: Some(AnswerPromptPin::from_exact_text(prompt)),
                vote_count: 3,
            }
        }

        fn assert_card_rejected(card: &JudgeMetadata, prompt: &str) {
            let mut calls = 0_usize;
            let error = run_majority_judge_card::<&str, &str, _>(card, prompt, |_| {
                calls += 1;
                Ok("keep")
            })
            .expect_err("an invalid majority card is rejected before any judge call");

            assert_eq!(calls, 0);
            match error {
                MajorityJudgeError::Card(BeamError::JudgeCardInvalid { .. }) => {}
                other => panic!("expected a typed card rejection, got {other:?}"),
            }
        }

        let prompt = "Answer the question.\n\n  Cite each claim as [id].\n";
        let card = majority_card(prompt);
        let mut hasher = Sha256::new();
        hasher.update(prompt.as_bytes());
        let expected_digest = hex_lower(&hasher.finalize());

        let card_json = serde_json::to_value(&card).expect("judge metadata serializes");
        assert_eq!(card_json["voteCount"], 3);
        assert_eq!(card_json["answerPrompt"]["content"], prompt);
        assert_eq!(card_json["answerPrompt"]["sha256"], expected_digest);

        let restored: JudgeMetadata =
            serde_json::from_value(card_json).expect("judge metadata round-trips");
        assert_eq!(restored, card);

        let mut calls = Vec::new();
        let decision = run_majority_judge_card::<&str, &str, _>(&card, prompt, |index| {
            calls.push(index);
            Ok("keep")
        })
        .expect("the pinned prompt admits the judgment");

        assert_eq!(calls, vec![0, 1, 2]);
        assert_eq!(decision.verdict, "keep");
        assert_eq!(decision.vote_count, JUDGE_VOTE_COUNT);

        // One byte of drift is a different answer prompt.
        assert_card_rejected(&card, &format!("{prompt} "));

        let mut empty_pin = card.clone();
        empty_pin.answer_prompt = Some(AnswerPromptPin::from_exact_text(""));
        assert_card_rejected(&empty_pin, "");

        let mut malformed_digest = card.clone();
        malformed_digest.answer_prompt = Some(AnswerPromptPin {
            content: prompt.to_owned(),
            sha256: "not-a-sha256-digest".to_owned(),
        });
        assert_card_rejected(&malformed_digest, prompt);

        let mut wrong_digest = card.clone();
        wrong_digest.answer_prompt = Some(AnswerPromptPin {
            content: prompt.to_owned(),
            sha256: AnswerPromptPin::from_exact_text("another prompt").sha256,
        });
        assert_card_rejected(&wrong_digest, prompt);

        let mut missing_pin = card.clone();
        missing_pin.answer_prompt = None;
        assert_card_rejected(&missing_pin, prompt);

        for vote_count in [0_u8, 1, 2, 4] {
            let mut wrong_votes = card.clone();
            wrong_votes.vote_count = vote_count;
            assert_card_rejected(&wrong_votes, prompt);
        }

        // Existing fixed-scorer fixture cards stay non-LLM, single-vote cards.
        let manifest = parse_manifest_json(BUILTIN_MANIFEST_JSON).expect("manifest parses");
        let competitor = &manifest.competitors[0];
        let fixture_card = competitor.card.as_ref().expect("carded competitor");
        assert_eq!(fixture_card.judge.answer_prompt, None);
        assert_eq!(fixture_card.judge.vote_count, single_judge_vote());

        // The generic gate rejects vote-count-three cards without a valid pin even though
        // `run_majority_judge_card` is never invoked for them.
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(BUILTIN_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["competitors"][0]["card"]["judge"]["voteCount"] = serde_json::json!(3);
        let err = parse_manifest_json(&manifest_json.to_string())
            .expect_err("three-vote cards must pin the answer prompt");
        assert!(matches!(err, BeamError::InvalidManifest { .. }));

        manifest_json["competitors"][0]["card"]["judge"]["answerPrompt"] = serde_json::json!({
            "content": prompt,
            "sha256": "not-a-sha256-digest"
        });
        let err = parse_manifest_json(&manifest_json.to_string())
            .expect_err("three-vote cards must pin a well-formed digest");
        assert!(matches!(err, BeamError::InvalidManifest { .. }));

        manifest_json["competitors"][0]["card"]["judge"]["answerPrompt"] = serde_json::json!({
            "content": prompt,
            "sha256": expected_digest
        });
        parse_manifest_json(&manifest_json.to_string())
            .expect("a three-vote card with a valid pin is accepted");

        for vote_count in [0, 2, 4] {
            manifest_json["competitors"][0]["card"]["judge"]["voteCount"] =
                serde_json::json!(vote_count);
            let err = parse_manifest_json(&manifest_json.to_string())
                .expect_err("only single-vote and majority-vote cards are accepted");
            assert!(matches!(err, BeamError::InvalidManifest { .. }));
        }
    }

    #[test]
    fn dial481_confound_regression() {
        // The judge identity, version, and instructions are held fixed across both cards; only the
        // answer-generation prompt moves, which is the confound this regression pins down.
        fn majority_card(prompt: &str) -> JudgeMetadata {
            JudgeMetadata {
                judge_id: "beam-llm-judge".to_owned(),
                version: "v1".to_owned(),
                notes: "Score only grounded claims; ignore style.".to_owned(),
                answer_prompt: Some(AnswerPromptPin::from_exact_text(prompt)),
                vote_count: 3,
            }
        }

        let item = "beam_128k_context_pack_smoke";
        let candidate = "Enterprise renewals drove the revenue increase.";
        let prompt_a = "Answer strictly from the retrieved context.\n";
        let prompt_b = "Answer from the retrieved context, then add a summary.\n";

        let card_a = majority_card(prompt_a);
        let card_b = majority_card(prompt_b);
        let json_a = serde_json::to_value(&card_a).expect("card A serializes");
        let json_b = serde_json::to_value(&card_b).expect("card B serializes");

        assert_ne!(card_a.answer_prompt, card_b.answer_prompt);
        assert_ne!(json_a, json_b);
        assert_eq!(card_a.judge_id, card_b.judge_id);
        assert_eq!(card_a.version, card_b.version);
        assert_eq!(card_a.notes, card_b.notes);

        let mut calls = Vec::new();
        let error = run_majority_judge_card::<&str, &str, _>(&card_a, prompt_b, |index| {
            calls.push((index, item, candidate));
            Ok("keep")
        })
        .expect_err("a card pinned to prompt A cannot judge a prompt B generation");

        // No comparison or scored result can be emitted behind a stale answer-prompt pin.
        assert!(calls.is_empty());
        match error {
            MajorityJudgeError::Card(BeamError::JudgeCardInvalid { .. }) => {}
            other => panic!("expected a typed card rejection, got {other:?}"),
        }

        // The stale card is not repaired in place; it still pins prompt A and stays ineligible.
        let pin_a = AnswerPromptPin::from_exact_text(prompt_a);
        assert_eq!(card_a.answer_prompt, Some(pin_a));
        assert!(card_a.require_majority_vote_card(prompt_b).is_err());
        assert!(card_a.require_majority_vote_card(prompt_a).is_ok());

        // Eligibility returns only by rebuilding the card from prompt B.
        let mut calls = Vec::new();
        let decision = run_majority_judge_card::<&str, &str, _>(&card_b, prompt_b, |index| {
            calls.push((index, item, candidate));
            Ok("keep")
        })
        .expect("the rebuilt card admits the judgment");

        assert_eq!(calls.len(), JUDGE_VOTE_COUNT);
        assert_eq!(calls[0], (0, item, candidate));
        assert_eq!(calls[1], (1, item, candidate));
        assert_eq!(calls[2], (2, item, candidate));
        assert_eq!(decision.verdict, "keep");
        assert_eq!(decision.vote_count, JUDGE_VOTE_COUNT);
    }

    #[test]
    fn fixture_rejects_char_count_offline_amortized_cost_accounting() {
        let mut fixture_json: serde_json::Value =
            serde_json::from_str(BUILTIN_FIXTURE_JSON).expect("fixture JSON");
        fixture_json["cases"][0]["offlineAmortizedCost"]["tokenSource"] =
            serde_json::json!("char_count_estimate");
        let err = parse_fixture_json(&fixture_json.to_string())
            .expect_err("char-count offline cost token estimates must be rejected");

        assert!(
            err.to_string()
                .contains("case offlineAmortizedCost must not use char_count_estimate")
        );
    }

    #[test]
    fn fixture_rejects_nonzero_metrics_for_zero_offline_cost_sources() {
        for source in ["fixture_declared_zero", "not_applicable"] {
            let mut fixture_json: serde_json::Value =
                serde_json::from_str(BUILTIN_FIXTURE_JSON).expect("fixture JSON");
            fixture_json["cases"][0]["offlineAmortizedCost"]["tokenSource"] =
                serde_json::json!(source);
            fixture_json["cases"][0]["offlineAmortizedCost"]["inputTokens"] = serde_json::json!(1);
            let err = parse_fixture_json(&fixture_json.to_string())
                .expect_err("zero-source offline costs must have zero metrics");

            assert!(
                err.to_string()
                    .contains("must declare zero tokens, elapsed time, and cost")
            );
        }
    }

    #[test]
    fn fixture_rejects_costs_too_large_to_normalize() {
        let mut fixture_json: serde_json::Value =
            serde_json::from_str(BUILTIN_FIXTURE_JSON).expect("fixture JSON");
        fixture_json["cases"][0]["offlineAmortizedCost"]["tokenSource"] =
            serde_json::json!("provider_usage");
        fixture_json["cases"][0]["offlineAmortizedCost"]["costUsd"] = serde_json::json!(f64::MAX);
        let err = parse_fixture_json(&fixture_json.to_string())
            .expect_err("overflowing normalization boundary must be rejected");

        assert!(
            err.to_string()
                .contains("case offlineAmortizedCost.costUsd is too large to normalize safely")
        );
    }

    #[test]
    fn not_ready_scores_are_unmeasured_and_do_not_publish_zero_overall() {
        let report = run_builtin_smoke().expect("BEAM smoke report");
        let report_json = serde_json::to_value(&report).expect("report serializes");
        let competitors = report_json["cases"][0]["competitors"]
            .as_array()
            .expect("competitors array");
        let deterministic = competitors
            .iter()
            .find(|competitor| competitor["competitorId"] == "deterministic-context-pack")
            .expect("deterministic competitor");

        assert!(deterministic["scoring"]["overallScore"].as_f64().is_some());

        for competitor_id in ["backbone-solo", "agentic-adapter", "chat-adapter"] {
            let competitor = competitors
                .iter()
                .find(|competitor| competitor["competitorId"] == competitor_id)
                .expect("not-ready competitor");
            assert!(competitor["scoring"]["overallScore"].is_null());

            let abilities = competitor["scoring"]["abilities"]
                .as_array()
                .expect("abilities array");
            assert_eq!(abilities.len(), 3);
            for ability in abilities {
                assert!(ability["score"].is_null());
                assert!(ability["passed"].is_null());
                assert!(
                    ability["detail"]
                        .as_str()
                        .expect("detail string")
                        .contains("could not be scored")
                );
            }
        }
    }

    #[test]
    fn empty_memory_fixture_abstains_before_score_publication() {
        let fixture = eval004_fixture(
            "eval004-empty-memory",
            "What did the empty vault remember about Project Borealis?",
            FixtureClass::EmptyMemory,
            Vec::new(),
        );
        let manifest = manifest_for_fixture_case(&fixture, "eval004-empty-memory");
        let report = run_fixture_manifest(&manifest, &fixture).expect("empty fixture runs");
        let report_json = serde_json::to_value(&report).expect("report serializes");
        let deterministic = deterministic_competitor_json(&report_json);

        assert_abstention_gate_passed(deterministic, "empty_memory_abstention");
    }

    #[test]
    fn contradictory_evidence_fixture_abstains_without_regressing_to_score() {
        let fixture = eval004_fixture(
            "eval004-contradiction",
            "What is the Atlas launch date?",
            FixtureClass::AdversarialContradiction,
            vec![
                eval004_record_json(
                    "30303030303030303030303030303030",
                    10,
                    "Atlas launch date is March 1.",
                ),
                eval004_record_json(
                    "40404040404040404040404040404040",
                    11,
                    "Atlas launch date is April 1.",
                ),
            ],
        );
        let manifest = manifest_for_fixture_case(&fixture, "eval004-contradiction");
        let report = run_fixture_manifest(&manifest, &fixture).expect("contradiction fixture runs");
        let report_json = serde_json::to_value(&report).expect("report serializes");
        let deterministic = deterministic_competitor_json(&report_json);

        assert_abstention_gate_passed(deterministic, "adversarial_contradiction_abstention");
    }

    #[test]
    fn temporal_staleness_fixture_abstains_without_regressing_to_score() {
        let fixture = eval004_fixture(
            "eval004-temporal-staleness",
            "What is the current Nimbus pricing?",
            FixtureClass::TemporalStaleness,
            vec![eval004_record_json(
                "50505050505050505050505050505050",
                10_000,
                "Old Nimbus pricing was 10 credits before the current plan changed.",
            )],
        );
        let manifest = manifest_for_fixture_case(&fixture, "eval004-temporal-staleness");
        let report = run_fixture_manifest(&manifest, &fixture).expect("staleness fixture runs");
        let report_json = serde_json::to_value(&report).expect("report serializes");
        let deterministic = deterministic_competitor_json(&report_json);

        assert_abstention_gate_passed(deterministic, "temporal_staleness_abstention");
    }

    #[test]
    fn low_confidence_fixture_abstains_via_below_threshold_context_pack() {
        let fixture = eval004_fixture(
            "eval004-low-confidence",
            "What is the Atlas launch date?",
            FixtureClass::LowConfidence,
            vec![eval004_record_json(
                "30303030303030303030303030303030",
                10,
                "Atlas launch date is March 1.",
            )],
        );
        let manifest = manifest_for_fixture_case(&fixture, "eval004-low-confidence");
        let report =
            run_fixture_manifest(&manifest, &fixture).expect("low-confidence fixture runs");

        for kind in [ArmKind::Deterministic, ArmKind::VanillaRag] {
            let arm = find_arm(&report, kind);
            let ArmOutcome::Completed { context_pack } = &arm.outcome else {
                panic!("{} arm should complete", kind.as_str());
            };
            let empty = context_pack.empty.as_ref().unwrap_or_else(|| {
                panic!("{} arm should report below-threshold empty", kind.as_str())
            });

            assert_eq!(context_pack.limit, 0);
            assert_eq!(context_pack.result_count, 0);
            assert_eq!(empty.reason, "below_threshold");
            assert!(
                empty.total_in_scope > 0,
                "{} arm should count in-scope low-confidence candidates",
                kind.as_str()
            );
        }

        let report_json = serde_json::to_value(&report).expect("report serializes");
        let deterministic = deterministic_competitor_json(&report_json);
        assert_abstention_gate_passed(deterministic, "low_confidence_abstention");
        let vanilla = vanilla_rag_competitor_json(&report_json);
        assert_abstention_gate_passed(vanilla, "low_confidence_abstention");
    }

    #[test]
    fn empty_memory_fixture_rejects_nonempty_vault() {
        let mut fixture_json: serde_json::Value =
            serde_json::from_str(BUILTIN_FIXTURE_JSON).expect("fixture JSON");
        fixture_json["cases"][0]["expectedMinResults"] = serde_json::json!(0);
        fixture_json["cases"][0]["fixtureClass"] = serde_json::json!("empty_memory");

        let err = parse_fixture_json(&fixture_json.to_string())
            .expect_err("empty_memory cases must not carry records");

        assert!(
            err.to_string()
                .contains("empty_memory cases must not include fixture records")
        );
    }

    #[test]
    fn contradiction_fixture_requires_distinct_opposing_values() {
        let mut fixture_json: serde_json::Value =
            serde_json::from_str(BUILTIN_FIXTURE_JSON).expect("fixture JSON");
        fixture_json["fixtureId"] = serde_json::json!("eval004-consistent-not-contradiction");
        fixture_json["records"] = serde_json::json!([
            eval004_record_json(
                "30303030303030303030303030303030",
                10,
                "Atlas launch date is March 1.",
            ),
            eval004_record_json(
                "40404040404040404040404040404040",
                11,
                "Atlas launch date is March 1.",
            ),
        ]);
        fixture_json["cases"][0]["caseId"] =
            serde_json::json!("eval004-consistent-not-contradiction");
        fixture_json["cases"][0]["query"] = serde_json::json!("What is the Atlas launch date?");
        fixture_json["cases"][0]["expectedMinResults"] = serde_json::json!(0);
        fixture_json["cases"][0]["fixtureClass"] = serde_json::json!("adversarial_contradiction");
        fixture_json["cases"][0]["opposingEvidence"] = serde_json::json!({
            "field": "txt",
            "recordIds": [
                "30303030303030303030303030303030",
                "40404040404040404040404040404040",
            ],
        });

        let err = parse_fixture_json(&fixture_json.to_string())
            .expect_err("consistent records must not validate as contradiction");

        assert!(
            err.to_string()
                .contains("opposingEvidence must reference records with distinct field values")
        );
    }

    #[test]
    fn temporal_staleness_fixture_requires_evidence_inside_temporal_search() {
        let mut fixture_json: serde_json::Value =
            serde_json::from_str(BUILTIN_FIXTURE_JSON).expect("fixture JSON");
        fixture_json["fixtureId"] = serde_json::json!("eval004-temporal-out-of-range");
        fixture_json["records"] = serde_json::json!([eval004_record_json(
            "50505050505050505050505050505050",
            10,
            "Old Nimbus pricing was 10 credits.",
        )]);
        fixture_json["cases"][0]["caseId"] = serde_json::json!("eval004-temporal-out-of-range");
        fixture_json["cases"][0]["query"] = serde_json::json!("Nimbus pricing");
        fixture_json["cases"][0]["expectedMinResults"] = serde_json::json!(0);
        fixture_json["cases"][0]["fixtureClass"] = serde_json::json!("temporal_staleness");
        fixture_json["cases"][0]["temporalSearch"] = serde_json::json!({
            "start": 0,
            "end": 1,
        });
        fixture_json["cases"][0]["temporalEvidenceIds"] =
            serde_json::json!(["50505050505050505050505050505050"]);

        let err = parse_fixture_json(&fixture_json.to_string())
            .expect_err("temporal evidence must be inside the temporal search range");

        assert!(
            err.to_string()
                .contains("temporalEvidenceIds must reference records inside temporalSearch")
        );
    }

    #[test]
    fn fixture_rejects_temporal_search_on_non_temporal_cases() {
        let mut fixture_json: serde_json::Value =
            serde_json::from_str(BUILTIN_FIXTURE_JSON).expect("fixture JSON");
        fixture_json["cases"][0]["temporalSearch"] = serde_json::json!({
            "start": 0,
            "end": 1,
        });

        let err = parse_fixture_json(&fixture_json.to_string())
            .expect_err("non-temporal cases must not carry temporalSearch");

        assert!(
            err.to_string()
                .contains("temporalSearch is only valid for temporal_staleness cases")
        );
    }

    #[test]
    fn low_confidence_fixture_requires_zero_publication_limit() {
        let mut fixture_json: serde_json::Value =
            serde_json::from_str(BUILTIN_FIXTURE_JSON).expect("fixture JSON");
        fixture_json["cases"][0]["expectedMinResults"] = serde_json::json!(0);
        fixture_json["cases"][0]["fixtureClass"] = serde_json::json!("low_confidence");
        fixture_json["cases"][0]["limit"] = serde_json::json!(1);

        let err = parse_fixture_json(&fixture_json.to_string())
            .expect_err("low-confidence fixtures must publish zero results");

        assert!(
            err.to_string()
                .contains("low_confidence cases must set limit to 0")
        );
    }

    #[test]
    fn contradiction_fixture_rejects_more_required_evidence_than_limit() {
        let mut fixture_json: serde_json::Value =
            serde_json::from_str(BUILTIN_FIXTURE_JSON).expect("fixture JSON");
        fixture_json["fixtureId"] = serde_json::json!("eval004-contradiction-over-limit");
        fixture_json["records"] = serde_json::json!([
            eval004_record_json(
                "30303030303030303030303030303030",
                10,
                "Atlas launch date is March 1.",
            ),
            eval004_record_json(
                "40404040404040404040404040404040",
                11,
                "Atlas launch date is April 1.",
            ),
        ]);
        fixture_json["cases"][0]["caseId"] = serde_json::json!("eval004-contradiction-over-limit");
        fixture_json["cases"][0]["query"] = serde_json::json!("What is the Atlas launch date?");
        fixture_json["cases"][0]["limit"] = serde_json::json!(1);
        fixture_json["cases"][0]["expectedMinResults"] = serde_json::json!(0);
        fixture_json["cases"][0]["fixtureClass"] = serde_json::json!("adversarial_contradiction");
        fixture_json["cases"][0]["opposingEvidence"] = serde_json::json!({
            "field": "txt",
            "recordIds": [
                "30303030303030303030303030303030",
                "40404040404040404040404040404040",
            ],
        });

        let err = parse_fixture_json(&fixture_json.to_string())
            .expect_err("required opposing evidence must fit within limit");

        assert!(
            err.to_string()
                .contains("opposingEvidence.recordIds count must be <= limit")
        );
    }

    #[test]
    fn temporal_fixture_rejects_more_required_evidence_than_limit() {
        let mut fixture_json: serde_json::Value =
            serde_json::from_str(BUILTIN_FIXTURE_JSON).expect("fixture JSON");
        fixture_json["fixtureId"] = serde_json::json!("eval004-temporal-over-limit");
        fixture_json["records"] = serde_json::json!([
            eval004_record_json(
                "50505050505050505050505050505050",
                1,
                "Old Nimbus pricing was 10 credits.",
            ),
            eval004_record_json(
                "60606060606060606060606060606060",
                1,
                "Old Nimbus pricing was 12 credits.",
            ),
        ]);
        fixture_json["cases"][0]["caseId"] = serde_json::json!("eval004-temporal-over-limit");
        fixture_json["cases"][0]["query"] = serde_json::json!("Nimbus pricing");
        fixture_json["cases"][0]["limit"] = serde_json::json!(1);
        fixture_json["cases"][0]["expectedMinResults"] = serde_json::json!(0);
        fixture_json["cases"][0]["fixtureClass"] = serde_json::json!("temporal_staleness");
        fixture_json["cases"][0]["temporalSearch"] = serde_json::json!({
            "start": 0,
            "end": 1,
        });
        fixture_json["cases"][0]["temporalEvidenceIds"] = serde_json::json!([
            "50505050505050505050505050505050",
            "60606060606060606060606060606060",
        ]);

        let err = parse_fixture_json(&fixture_json.to_string())
            .expect_err("required temporal evidence must fit within limit");

        assert!(
            err.to_string()
                .contains("temporalEvidenceIds count must be <= limit")
        );
    }

    #[test]
    fn empty_memory_gate_requires_explicit_no_data_empty_report() {
        let mut context_pack = minimal_context_pack_report(0, &[], None);
        let case = gate_case(FixtureClass::EmptyMemory);

        let (passed, detail) = abstention_gate_status(&case, &context_pack);
        assert!(!passed);
        assert!(detail.contains("no empty report"));

        context_pack.empty = Some(EmptyContextReport {
            reason: "filter_matched_none".to_owned(),
            total_in_scope: 0,
            hint: "query matched no records".to_owned(),
        });
        let (passed, detail) = abstention_gate_status(&case, &context_pack);
        assert!(!passed);
        assert!(detail.contains("filter_matched_none"));

        context_pack.empty = Some(EmptyContextReport {
            reason: "no_data".to_owned(),
            total_in_scope: 1,
            hint: "records were in scope".to_owned(),
        });
        let (passed, _detail) = abstention_gate_status(&case, &context_pack);
        assert!(!passed);

        context_pack.empty = Some(EmptyContextReport {
            reason: "no_data".to_owned(),
            total_in_scope: 0,
            hint: "empty vault".to_owned(),
        });
        let (passed, _detail) = abstention_gate_status(&case, &context_pack);
        assert!(passed);
    }

    #[test]
    fn low_confidence_gate_requires_below_threshold_empty_reason() {
        let case = gate_case(FixtureClass::LowConfidence);
        let mut context_pack = minimal_context_pack_report(
            0,
            &[],
            Some(EmptyContextReport {
                reason: "no_data".to_owned(),
                total_in_scope: 0,
                hint: "no records".to_owned(),
            }),
        );

        let (passed, detail) = abstention_gate_status(&case, &context_pack);
        assert!(!passed);
        assert!(detail.contains("empty reason=no_data"));

        context_pack.empty = Some(EmptyContextReport {
            reason: "below_threshold".to_owned(),
            total_in_scope: 0,
            hint: "out-of-scope fixture".to_owned(),
        });
        let (passed, detail) = abstention_gate_status(&case, &context_pack);
        assert!(!passed);
        assert!(detail.contains("0 in-scope records"));

        context_pack.empty = Some(EmptyContextReport {
            reason: "below_threshold".to_owned(),
            total_in_scope: 1,
            hint: "below confidence threshold".to_owned(),
        });
        let (passed, detail) = abstention_gate_status(&case, &context_pack);
        assert!(passed);
        assert!(detail.contains("1 in-scope records"));
        assert!(detail.contains("empty reason=below_threshold"));
    }

    #[test]
    fn contradiction_gate_requires_declared_opposing_result_ids() {
        let case = gate_case(FixtureClass::AdversarialContradiction);
        let context_pack = minimal_context_pack_report_with_result_ids(
            &["30303030303030303030303030303030"],
            &[],
            None,
        );

        let (passed, detail) = abstention_gate_status(&case, &context_pack);
        assert!(!passed);
        assert!(detail.contains("1/2 required opposing records"));

        let context_pack = minimal_context_pack_report_with_result_ids(
            &[
                "30303030303030303030303030303030",
                "40404040404040404040404040404040",
            ],
            &[],
            None,
        );
        let (passed, detail) = abstention_gate_status(&case, &context_pack);
        assert!(passed);
        assert!(detail.contains("2/2 required opposing records"));
    }

    #[test]
    fn temporal_staleness_gate_requires_declared_temporal_result_ids() {
        let case = gate_case(FixtureClass::TemporalStaleness);
        let context_pack = minimal_context_pack_report_with_result_ids(
            &["60606060606060606060606060606060"],
            &["temporal"],
            None,
        );

        let (passed, detail) = abstention_gate_status(&case, &context_pack);
        assert!(!passed);
        assert!(detail.contains("0/1 required temporal records"));

        let context_pack = minimal_context_pack_report_with_result_ids(
            &["50505050505050505050505050505050"],
            &[],
            None,
        );
        let context_pack = minimal_context_pack_report_with_temporal_result_ids(
            context_pack,
            &["50505050505050505050505050505050"],
        );
        let (passed, detail) = abstention_gate_status(&case, &context_pack);
        assert!(!passed);
        assert!(detail.contains("temporal signal=false"));

        let context_pack = minimal_context_pack_report_with_result_ids(
            &["50505050505050505050505050505050"],
            &["temporal"],
            None,
        );
        let context_pack = minimal_context_pack_report_with_temporal_result_ids(
            context_pack,
            &["50505050505050505050505050505050"],
        );
        let (passed, detail) = abstention_gate_status(&case, &context_pack);
        assert!(passed);
        assert!(detail.contains("1/1 required temporal records"));
        assert!(detail.contains("temporal signal=true"));
    }

    #[test]
    fn temporal_staleness_gate_rejects_text_only_expected_result() {
        let case = gate_case(FixtureClass::TemporalStaleness);
        let context_pack = minimal_context_pack_report_with_result_ids(
            &["50505050505050505050505050505050"],
            &["temporal"],
            None,
        );
        let (passed, detail) = abstention_gate_status(&case, &context_pack);
        assert!(!passed);
        assert!(detail.contains("0/1 required temporal records"));
    }

    #[test]
    fn low_confidence_gate_suppresses_score_publication() {
        let case = FixtureCase {
            case_id: "eval004-low-confidence".to_owned(),
            query: "unsupported low confidence query".to_owned(),
            limit: 0,
            token_budget: 128,
            expected_min_results: 0,
            pending_vector_count: 0,
            query_embedding: None,
            fixture_class: FixtureClass::LowConfidence,
            temporal_search: None,
            temporal_evidence_ids: Vec::new(),
            opposing_evidence: None,
            offline_amortized_cost: CostComponentInput::default(),
        };
        let context_pack = ContextPackReport {
            token_budget: case.token_budget,
            limit: case.limit,
            serialized_format: "yaml".to_owned(),
            serialized_bytes: 0,
            serialized_tokens: 0,
            tokenizer_id: oneiron::DEFAULT_CONTEXT_PACK_TOKENIZER_ID.to_owned(),
            query_cost: CostComponentReport {
                token_source: TokenAccountingSource::TokenizerCount,
                tokenizer_id: Some(oneiron::DEFAULT_CONTEXT_PACK_TOKENIZER_ID.to_owned()),
                input_tokens: 4,
                output_tokens: 0,
                target_tokens: case.token_budget as u64,
                elapsed_us: 1,
                cost_usd: 0.0,
            },
            result_count: 0,
            neighbor_count: 0,
            results: Vec::new(),
            neighbors: Vec::new(),
            stats: empty_pack_stats_report(),
            empty: Some(EmptyContextReport {
                reason: "below_threshold".to_owned(),
                total_in_scope: 1,
                hint: "fixture confidence was below publication threshold".to_owned(),
            }),
            temporal_result_ids: BTreeSet::new(),
            budgeted_text_by_entity_id: BTreeMap::new(),
        };

        let score = FixedBeamScorer.score(
            &case,
            &eval004_deterministic_competitor(),
            &ArmReport {
                arm: ArmKind::Deterministic,
                outcome: ArmOutcome::Completed {
                    context_pack: Box::new(context_pack),
                },
            },
        );

        assert!(score.overall_score.is_none());
        assert!(
            score
                .abilities
                .iter()
                .all(|ability| ability.score.is_none())
        );
        assert_eq!(
            score
                .abilities
                .iter()
                .find(|ability| ability.ability == AbilityKind::AbstentionGate)
                .expect("abstention gate ability")
                .passed,
            Some(true)
        );
    }

    #[test]
    fn built_in_128k_guard_checks_manifest_selected_cases() {
        let mut fixture = parse_fixture_json(BUILTIN_FIXTURE_JSON).expect("fixture parses");
        let mut manifest = parse_manifest_json(BUILTIN_MANIFEST_JSON).expect("manifest parses");
        fixture.cases.push(FixtureCase {
            case_id: "beam_small_budget_smoke".to_owned(),
            query: "BEAM deterministic context pack".to_owned(),
            limit: 5,
            token_budget: 4096,
            expected_min_results: 1,
            pending_vector_count: 0,
            query_embedding: None,
            fixture_class: FixtureClass::EvidenceSupported,
            temporal_search: None,
            temporal_evidence_ids: Vec::new(),
            opposing_evidence: None,
            offline_amortized_cost: CostComponentInput::default(),
        });
        manifest.case_ids = vec!["beam_small_budget_smoke".to_owned()];

        let err = ensure_manifest_selects_128k_case(&manifest, &fixture)
            .expect_err("manifest must select a 128K case");
        assert!(
            err.to_string()
                .contains("built-in BEAM smoke manifest must select a 128K token-budget case")
        );
    }

    #[test]
    fn beam_help_references_arch_0042() {
        assert!(BEAM_HELP.contains("ONEIRON-ARCH-0042"));
    }

    #[test]
    fn not_ready_arms_return_explicit_not_ready_states() {
        let report = run_builtin_smoke().expect("BEAM smoke report");
        for kind in [ArmKind::BackboneSolo, ArmKind::Agentic, ArmKind::Chat] {
            let arm = find_arm(&report, kind);
            let ArmOutcome::NotReady { not_ready } = &arm.outcome else {
                panic!("{} arm should be not-ready", kind.as_str());
            };
            assert_eq!(
                not_ready.reason,
                "adapter intentionally not implemented in EVAL-001 scaffold"
            );
        }
    }

    #[test]
    fn jsonl_contract_manifest_emits_packs_with_bucket_labels() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let run_jsonl_path = tempdir.path().join("run.jsonl");
        let packs_jsonl_path = tempdir.path().join("packs.jsonl");
        std::fs::write(&run_jsonl_path, CONTRACT_RUN_JSONL).expect("write run.jsonl");
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(CONTRACT_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["dataset"]["path"] = serde_json::json!(run_jsonl_path);
        manifest_json["outputs"]["packsJsonl"] = serde_json::json!(packs_jsonl_path);
        let manifest =
            parse_manifest_json(&manifest_json.to_string()).expect("contract manifest parses");

        let report = run_manifest(&manifest, None).expect("contract run succeeds");
        let packs_jsonl = std::fs::read_to_string(&packs_jsonl_path).expect("packs.jsonl exists");
        let rows: Vec<serde_json::Value> = packs_jsonl
            .lines()
            .map(|line| serde_json::from_str(line).expect("pack row JSON"))
            .collect();
        let deterministic = rows
            .iter()
            .find(|row| row["arm"]["kind"] == ONEIRON_CONTEXT_PACK_ARM_KIND)
            .expect("deterministic context-pack row");
        let vanilla = rows
            .iter()
            .find(|row| row["arm"]["kind"] == VANILLA_RAG_CONTRACT_ARM_KIND)
            .expect("vanilla-rag row");

        assert_eq!(report.dataset.source_kind, "jsonl");
        assert_eq!(report.dataset.pending_vectors, 0);
        assert_eq!(rows.len(), 2);
        assert_eq!(deterministic["contract_version"], EVAL_CONTRACT_VERSION);
        assert_eq!(deterministic["record_type"], "context_pack");
        assert_eq!(deterministic["arm"]["id"], "oneiron");
        assert_eq!(deterministic["arm"]["kind"], ONEIRON_CONTEXT_PACK_ARM_KIND);
        assert_eq!(
            deterministic["gold"]["labels"]["ability"],
            "information_extraction"
        );
        assert_eq!(
            deterministic["gold"]["labels"]["wedge_bucket"],
            "needle_short"
        );
        assert!(
            deterministic["pack"]["contexts"]
                .as_array()
                .expect("contexts array")
                .iter()
                .any(|context| context["id"] == "turn-1"
                    && context["text"]
                        .as_str()
                        .expect("context text")
                        .contains("contract launch code is tulip"))
        );
        assert_eq!(vanilla["arm"]["id"], VANILLA_RAG_CONTRACT_ARM_ID);
        assert_eq!(vanilla["arm"]["kind"], VANILLA_RAG_CONTRACT_ARM_KIND);
        assert_eq!(
            vanilla["pack"]["config"]["kind"],
            VANILLA_RAG_CONTRACT_ARM_KIND
        );
        assert_eq!(vanilla["pack"]["config"]["topK"], 5);
        assert_eq!(
            vanilla["pack"]["config"]["fusion"],
            serde_json::json!(VANILLA_RAG_FUSION)
        );
        assert_eq!(
            deterministic["pack"]["corpusDigest"], vanilla["pack"]["corpusDigest"],
            "purity gate: comparator rows must share the exact same ingested corpus"
        );
        assert!(
            vanilla["pack"]["contexts"]
                .as_array()
                .expect("contexts array")
                .iter()
                .any(|context| context["id"] == "turn-1")
        );
    }

    #[test]
    fn jsonl_arm_id_selects_oneiron_row_when_question_has_two_arms() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let run_jsonl_path = tempdir.path().join("run.jsonl");
        let packs_jsonl_path = tempdir.path().join("packs.jsonl");
        let mut ours: serde_json::Value =
            serde_json::from_str(CONTRACT_RUN_JSONL.trim()).expect("contract row JSON");
        ours["arm"]["id"] = serde_json::json!("oneiron");
        ours["arm"]["kind"] = serde_json::json!(ONEIRON_CONTEXT_PACK_ARM_KIND);
        let mut l0 = ours.clone();
        l0["arm"]["id"] = serde_json::json!("longmemeval_l0");
        l0["arm"]["kind"] = serde_json::json!("baseline_jsonl");
        l0["gold"]["labels"]["wedge_bucket"] = serde_json::json!("wrong_arm_bucket");
        std::fs::write(&run_jsonl_path, format!("{l0}\n{ours}\n")).expect("write run.jsonl");
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(CONTRACT_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["dataset"]["path"] = serde_json::json!(run_jsonl_path);
        manifest_json["dataset"]["armId"] = serde_json::json!("oneiron");
        manifest_json["outputs"]["packsJsonl"] = serde_json::json!(packs_jsonl_path);
        let manifest =
            parse_manifest_json(&manifest_json.to_string()).expect("contract manifest parses");

        run_manifest(&manifest, None).expect("contract run succeeds");
        let packs_jsonl = std::fs::read_to_string(&packs_jsonl_path).expect("packs.jsonl exists");
        let rows: Vec<serde_json::Value> = packs_jsonl
            .lines()
            .map(|line| serde_json::from_str(line).expect("pack row JSON"))
            .collect();
        let deterministic = rows
            .iter()
            .find(|row| row["arm"]["kind"] == ONEIRON_CONTEXT_PACK_ARM_KIND)
            .expect("deterministic context-pack row");
        let vanilla = rows
            .iter()
            .find(|row| row["arm"]["kind"] == VANILLA_RAG_CONTRACT_ARM_KIND)
            .expect("vanilla-rag row");

        assert_eq!(rows.len(), 2);
        assert_eq!(deterministic["arm"]["id"], "oneiron");
        assert_eq!(deterministic["arm"]["kind"], ONEIRON_CONTEXT_PACK_ARM_KIND);
        assert_eq!(
            deterministic["gold"]["labels"]["wedge_bucket"],
            "needle_short"
        );
        assert_eq!(vanilla["arm"]["id"], VANILLA_RAG_CONTRACT_ARM_ID);
        assert_eq!(vanilla["gold"]["labels"]["wedge_bucket"], "needle_short");
    }

    #[test]
    fn purity_gate_keeps_gold_unreachable_from_arm_assembly() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let run_jsonl_path = tempdir.path().join("run.jsonl");
        let packs_jsonl_path = tempdir.path().join("packs.jsonl");
        let secret = "PURE_RECALL_GOLD_ONLY";
        let mut row: serde_json::Value =
            serde_json::from_str(CONTRACT_RUN_JSONL.trim()).expect("contract row JSON");
        row["question_id"] = serde_json::json!("purity_gate_gold_unreachable");
        row["question"] = serde_json::json!("What does the purity probe note say?");
        row["corpus"] = serde_json::json!([
            {
                "id": "visible-turn",
                "text": "The purity probe note says the visible answer is amber.",
                "metadata": {"case": "purity"},
                "embedding": {
                    "encoding": "f32-le-base64",
                    "dimensions": 4,
                    "data": "AACAPwAAAAAAAAAAAAAAAA=="
                }
            }
        ]);
        row["gold"]["answers"] = serde_json::json!([secret]);
        std::fs::write(&run_jsonl_path, format!("{row}\n")).expect("write run.jsonl");

        let mut manifest_json: serde_json::Value =
            serde_json::from_str(CONTRACT_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["dataset"]["path"] = serde_json::json!(run_jsonl_path);
        manifest_json["caseIds"] = serde_json::json!(["purity_gate_gold_unreachable"]);
        manifest_json["outputs"]["packsJsonl"] = serde_json::json!(packs_jsonl_path);
        let manifest =
            parse_manifest_json(&manifest_json.to_string()).expect("contract manifest parses");

        run_manifest(&manifest, None).expect("purity run succeeds");
        let packs_jsonl = std::fs::read_to_string(&packs_jsonl_path).expect("packs.jsonl exists");
        let rows: Vec<serde_json::Value> = packs_jsonl
            .lines()
            .map(|line| serde_json::from_str(line).expect("pack row JSON"))
            .collect();
        let deterministic = rows
            .iter()
            .find(|row| row["arm"]["kind"] == ONEIRON_CONTEXT_PACK_ARM_KIND)
            .expect("deterministic context-pack row");
        let vanilla = rows
            .iter()
            .find(|row| row["arm"]["kind"] == VANILLA_RAG_CONTRACT_ARM_KIND)
            .expect("vanilla-rag row");

        assert_eq!(rows.len(), 2);
        assert_eq!(
            deterministic["pack"]["corpusDigest"],
            vanilla["pack"]["corpusDigest"]
        );
        for row in rows {
            assert_eq!(row["gold"]["answers"][0], secret);
            let contexts = row["pack"]["contexts"].as_array().expect("contexts array");
            assert!(contexts.iter().any(|context| {
                context["text"]
                    .as_str()
                    .expect("context text")
                    .contains("visible answer is amber")
            }));
            assert!(contexts.iter().all(|context| {
                !context["text"]
                    .as_str()
                    .expect("context text")
                    .contains(secret)
            }));
        }
    }

    #[test]
    fn duplicate_jsonl_question_without_arm_id_fails_typed() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let run_jsonl_path = tempdir.path().join("run.jsonl");
        let mut first: serde_json::Value =
            serde_json::from_str(CONTRACT_RUN_JSONL.trim()).expect("contract row JSON");
        first["arm"]["id"] = serde_json::json!("oneiron");
        let mut second = first.clone();
        second["arm"]["id"] = serde_json::json!("oneiron-shadow");
        std::fs::write(&run_jsonl_path, format!("{first}\n{second}\n")).expect("write run.jsonl");
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(CONTRACT_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["dataset"]["path"] = serde_json::json!(run_jsonl_path);
        manifest_json["dataset"]
            .as_object_mut()
            .expect("dataset object")
            .remove("armId");
        let manifest =
            parse_manifest_json(&manifest_json.to_string()).expect("contract manifest parses");

        let err = run_manifest(&manifest, None).expect_err("duplicate question must fail");

        assert!(
            matches!(
                &err,
                BeamError::InvalidRunJsonl {
                    line: 2,
                    reason,
                    ..
                } if reason.contains("multiple selected run records")
                    && reason.contains("set dataset.armId")
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn non_context_pack_jsonl_arm_kind_fails_typed() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let run_jsonl_path = tempdir.path().join("run.jsonl");
        let mut row: serde_json::Value =
            serde_json::from_str(CONTRACT_RUN_JSONL.trim()).expect("contract row JSON");
        row["arm"]["id"] = serde_json::json!("longmemeval_l0");
        row["arm"]["kind"] = serde_json::json!("baseline_jsonl");
        std::fs::write(&run_jsonl_path, format!("{row}\n")).expect("write run.jsonl");
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(CONTRACT_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["dataset"]["path"] = serde_json::json!(run_jsonl_path);
        manifest_json["dataset"]["armId"] = serde_json::json!("longmemeval_l0");
        let manifest =
            parse_manifest_json(&manifest_json.to_string()).expect("contract manifest parses");

        let err = run_manifest(&manifest, None).expect_err("non-context-pack arm must fail");

        assert!(
            matches!(
                &err,
                BeamError::InvalidRunJsonl {
                    line: 1,
                    reason,
                    ..
                } if reason.contains("arm.kind `baseline_jsonl`")
                    && reason.contains(ONEIRON_CONTEXT_PACK_ARM_KIND)
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn jsonl_expected_min_results_must_not_exceed_limit() {
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(CONTRACT_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["dataset"]["limit"] = serde_json::json!(1);
        manifest_json["dataset"]["expectedMinResults"] = serde_json::json!(2);

        let err = parse_manifest_json(&manifest_json.to_string())
            .expect_err("expectedMinResults > limit is invalid");

        assert!(matches!(
            err,
            BeamError::InvalidManifest { reason, .. }
                if reason.contains("expectedMinResults must be <= limit")
        ));
    }

    #[test]
    fn jsonl_ready_embedding_dimensions_must_match_engine_config() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let run_jsonl_path = tempdir.path().join("run.jsonl");
        let mut row: serde_json::Value =
            serde_json::from_str(CONTRACT_RUN_JSONL.trim()).expect("contract row JSON");
        row["corpus"][0]["embedding"] = serde_json::json!({
            "encoding": "f32-le-base64",
            "dimensions": 3,
            "data": "AAAAAAAAAAAAAAAA"
        });
        std::fs::write(&run_jsonl_path, format!("{row}\n")).expect("write run.jsonl");
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(CONTRACT_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["dataset"]["path"] = serde_json::json!(run_jsonl_path);
        let manifest =
            parse_manifest_json(&manifest_json.to_string()).expect("contract manifest parses");

        let err = run_manifest(&manifest, None).expect_err("non-4D vector must fail typed");

        assert!(
            matches!(
                &err,
                BeamError::InvalidRunJsonl {
                    line: 1,
                    reason,
                    ..
                } if reason.contains("vector dimensions must be 4")
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn jsonl_budget_currency_must_be_tokens() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let run_jsonl_path = tempdir.path().join("run.jsonl");
        let mut row: serde_json::Value =
            serde_json::from_str(CONTRACT_RUN_JSONL.trim()).expect("contract row JSON");
        row["budget"]["currency"] = serde_json::json!("usd");
        std::fs::write(&run_jsonl_path, format!("{row}\n")).expect("write run.jsonl");
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(CONTRACT_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["dataset"]["path"] = serde_json::json!(run_jsonl_path);
        let manifest =
            parse_manifest_json(&manifest_json.to_string()).expect("contract manifest parses");

        let err = run_manifest(&manifest, None).expect_err("non-token budget must fail typed");

        assert!(
            matches!(
                &err,
                BeamError::InvalidRunJsonl {
                    line: 1,
                    reason,
                    ..
                } if reason.contains("budget.currency `usd`")
                    && reason.contains("expected `tokens`")
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn jsonl_cases_are_loaded_into_isolated_vaults() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let run_jsonl_path = tempdir.path().join("run.jsonl");
        let packs_jsonl_path = tempdir.path().join("packs.jsonl");
        let mut first: serde_json::Value =
            serde_json::from_str(CONTRACT_RUN_JSONL.trim()).expect("contract row JSON");
        first["question_id"] = serde_json::json!("case_a");
        first["question"] = serde_json::json!("shared keyword answer");
        first["corpus"] = serde_json::json!([
            {
                "id": "a-turn",
                "text": "shared keyword alpha answer only in case A",
                "metadata": {"case": "a"}
            }
        ]);
        let mut second = first.clone();
        second["question_id"] = serde_json::json!("case_b");
        second["corpus"] = serde_json::json!([
            {
                "id": "b-turn",
                "text": "shared keyword beta answer only in case B",
                "metadata": {"case": "b"}
            }
        ]);
        std::fs::write(&run_jsonl_path, format!("{first}\n{second}\n")).expect("write run.jsonl");
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(CONTRACT_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["dataset"]["path"] = serde_json::json!(run_jsonl_path);
        manifest_json["dataset"]["limit"] = serde_json::json!(5);
        manifest_json["caseIds"] = serde_json::json!(["case_a", "case_b"]);
        manifest_json["outputs"]["packsJsonl"] = serde_json::json!(packs_jsonl_path);
        let manifest =
            parse_manifest_json(&manifest_json.to_string()).expect("contract manifest parses");

        let report = run_manifest(&manifest, None).expect("contract run succeeds");
        let packs_jsonl = std::fs::read_to_string(&packs_jsonl_path).expect("packs.jsonl exists");
        let rows: Vec<serde_json::Value> = packs_jsonl
            .lines()
            .map(|line| serde_json::from_str(line).expect("pack row JSON"))
            .collect();

        assert_eq!(report.dataset.records_loaded, 2);
        assert_eq!(rows.len(), 4);
        for row in rows {
            let expected_prefix = if row["question_id"] == "case_a" {
                "a-"
            } else {
                assert_eq!(row["question_id"], "case_b");
                "b-"
            };
            let contexts = row["pack"]["contexts"].as_array().expect("contexts array");
            assert!(!contexts.is_empty());
            assert!(contexts.iter().all(|context| {
                context["id"]
                    .as_str()
                    .expect("context id")
                    .starts_with(expected_prefix)
            }));
        }
    }

    #[test]
    fn jsonl_outputs_must_not_overwrite_input_run_jsonl() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let run_jsonl_path = tempdir.path().join("run.jsonl");
        std::fs::write(&run_jsonl_path, CONTRACT_RUN_JSONL).expect("write run.jsonl");
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(CONTRACT_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["dataset"]["path"] = serde_json::json!(&run_jsonl_path);
        manifest_json["outputs"]["packsJsonl"] = serde_json::json!(run_jsonl_path);
        let manifest =
            parse_manifest_json(&manifest_json.to_string()).expect("contract manifest parses");

        let err = run_manifest(&manifest, None).expect_err("same output/input path must fail");

        assert!(matches!(
            err,
            BeamError::InvalidManifest { reason, .. }
                if reason.contains("must not resolve to the input run.jsonl path")
        ));
    }

    #[test]
    fn contract_pack_rows_use_budgeted_serialized_text() {
        let manifest = parse_manifest_json(CONTRACT_MANIFEST_JSON).expect("manifest parses");
        let record: RunContractRecord =
            serde_json::from_str(CONTRACT_RUN_JSONL.trim()).expect("contract row JSON");
        let entity_id = "10101010101010101010101010101010";
        let case = FixtureCase {
            case_id: record.question_id.clone(),
            query: record.question.clone(),
            limit: 1,
            token_budget: 128,
            expected_min_results: 1,
            pending_vector_count: 0,
            query_embedding: None,
            fixture_class: FixtureClass::EvidenceSupported,
            temporal_search: None,
            temporal_evidence_ids: Vec::new(),
            opposing_evidence: None,
            offline_amortized_cost: CostComponentInput::default(),
        };
        let loaded = LoadedDataset {
            report: DatasetLoadReport {
                dataset_id: "dataset".to_owned(),
                source_kind: JSONL_CONTRACT_SOURCE_KIND.to_owned(),
                records_loaded: 1,
                text_fields_indexed: 1,
                pending_vectors: 0,
            },
            fixture_id: "dataset".to_owned(),
            fixture_description: "dataset".to_owned(),
            cases: vec![case.clone()],
            contract_records: BTreeMap::from([(case.case_id.clone(), record)]),
            source_id_by_entity_id: BTreeMap::from([(entity_id.to_owned(), "turn-1".to_owned())]),
            query_vector_by_case_id: BTreeMap::new(),
        };
        let mut budgeted_text_by_entity_id = BTreeMap::new();
        budgeted_text_by_entity_id.insert(entity_id.to_owned(), "budgeted emitted txt".to_owned());
        let context_pack = ContextPackReport {
            token_budget: case.token_budget,
            limit: case.limit,
            serialized_format: "yaml".to_owned(),
            serialized_bytes: 64,
            serialized_tokens: 7,
            tokenizer_id: oneiron::DEFAULT_CONTEXT_PACK_TOKENIZER_ID.to_owned(),
            query_cost: CostComponentReport {
                token_source: TokenAccountingSource::TokenizerCount,
                tokenizer_id: Some(oneiron::DEFAULT_CONTEXT_PACK_TOKENIZER_ID.to_owned()),
                input_tokens: 1,
                output_tokens: 7,
                target_tokens: case.token_budget as u64,
                elapsed_us: 1,
                cost_usd: 0.0,
            },
            result_count: 1,
            neighbor_count: 0,
            results: vec![ContextEntityReport {
                id: entity_id.to_owned(),
                short_id: "sm1".to_owned(),
                entity_type: BENCH_CONTRACT_ENTITY_TYPE,
                score: 1.0,
            }],
            neighbors: Vec::new(),
            stats: empty_pack_stats_report(),
            empty: None,
            temporal_result_ids: BTreeSet::new(),
            budgeted_text_by_entity_id,
        };
        let arm_report = ArmReport {
            arm: ArmKind::Deterministic,
            outcome: ArmOutcome::Completed {
                context_pack: Box::new(context_pack),
            },
        };

        let row = contract_context_pack_record(
            &manifest,
            &loaded,
            &case,
            &manifest.competitors[0],
            &arm_report,
        )
        .expect("row generation succeeds")
        .expect("row emitted");

        assert_eq!(row.pack.contexts[0].id, "turn-1");
        assert_eq!(row.pack.contexts[0].text, "budgeted emitted txt");
    }

    #[test]
    fn pending_jsonl_embeddings_fail_deterministic_arm_typed() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let run_jsonl_path = tempdir.path().join("run.jsonl");
        let packs_jsonl_path = tempdir.path().join("packs.jsonl");
        let mut row: serde_json::Value =
            serde_json::from_str(CONTRACT_RUN_JSONL.trim()).expect("contract row JSON");
        row["corpus"][0]["embedding"] = serde_json::json!({"status": "pending"});
        std::fs::write(&run_jsonl_path, format!("{row}\n")).expect("write run.jsonl");
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(CONTRACT_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["dataset"]["path"] = serde_json::json!(run_jsonl_path);
        manifest_json["outputs"]["packsJsonl"] = serde_json::json!(packs_jsonl_path);
        let manifest =
            parse_manifest_json(&manifest_json.to_string()).expect("contract manifest parses");

        let err = run_manifest(&manifest, None).expect_err("pending embeddings fail typed");

        assert!(matches!(
            err,
            BeamError::PendingEmbeddings {
                case_id,
                pending_vectors: 1,
            } if case_id == "beam_128k_contract_context_pack_smoke"
        ));
    }

    #[test]
    fn non_wired_dataset_sources_still_return_dataset_not_ready() {
        let fixture = parse_fixture_json(BUILTIN_FIXTURE_JSON).expect("fixture parses");
        let mut manifest = parse_manifest_json(BUILTIN_MANIFEST_JSON).expect("manifest parses");
        manifest.dataset = DatasetSource::Miracl {
            dataset: "miracl-dev-smoke".to_owned(),
        };

        let err = run_fixture_manifest(&manifest, &fixture).expect_err("MIRACL remains unwired");

        assert!(
            matches!(err, BeamError::DatasetNotReady(state) if state.component == "dataset loader")
        );
    }

    fn find_arm(report: &BeamReport, kind: ArmKind) -> &ArmReport {
        report.cases[0]
            .arms
            .iter()
            .find(|arm| arm.arm == kind)
            .expect("arm report exists")
    }

    fn completed_context_pack(report: &BeamReport, kind: ArmKind) -> &ContextPackReport {
        let arm = find_arm(report, kind);
        let ArmOutcome::Completed { context_pack } = &arm.outcome else {
            panic!("{} arm should complete", kind.as_str());
        };
        context_pack
    }

    fn eval004_fixture(
        case_id: &str,
        query: &str,
        fixture_class: FixtureClass,
        records: Vec<serde_json::Value>,
    ) -> BeamFixture {
        let mut fixture_json: serde_json::Value =
            serde_json::from_str(BUILTIN_FIXTURE_JSON).expect("fixture JSON");
        fixture_json["fixtureId"] = serde_json::json!(case_id);
        fixture_json["description"] = serde_json::json!("EVAL-004 abstention gate fixture.");
        fixture_json["records"] = serde_json::Value::Array(records);
        fixture_json["cases"][0]["caseId"] = serde_json::json!(case_id);
        fixture_json["cases"][0]["query"] = serde_json::json!(query);
        fixture_json["cases"][0]["limit"] =
            serde_json::json!(if fixture_class == FixtureClass::LowConfidence {
                0
            } else {
                5
            });
        fixture_json["cases"][0]["tokenBudget"] = serde_json::json!(4096);
        fixture_json["cases"][0]["expectedMinResults"] = serde_json::json!(0);
        fixture_json["cases"][0]["fixtureClass"] =
            serde_json::to_value(fixture_class).expect("fixture class serializes");
        let record_ids: Vec<String> = fixture_json["records"]
            .as_array()
            .expect("records array")
            .iter()
            .map(|record| record["id"].as_str().expect("record id").to_owned())
            .collect();
        if fixture_class == FixtureClass::TemporalStaleness {
            // The window sits far from t=0 on purpose: ONE-1890 seeds the
            // system AGENT_DEF rows at the pinned timestamp 0, and a window
            // touching 0 sweeps those seeds into temporal scope, crowding the
            // case's record out of the leg's limit.
            fixture_json["cases"][0]["temporalSearch"] = serde_json::json!({
                "start": 9_999,
                "end": 10_000
            });
            fixture_json["cases"][0]["temporalEvidenceIds"] = serde_json::json!(record_ids);
        } else {
            fixture_json["cases"][0]
                .as_object_mut()
                .expect("case object")
                .remove("temporalSearch");
            fixture_json["cases"][0]
                .as_object_mut()
                .expect("case object")
                .remove("temporalEvidenceIds");
        }
        if fixture_class == FixtureClass::AdversarialContradiction {
            fixture_json["cases"][0]["opposingEvidence"] = serde_json::json!({
                "field": "txt",
                "recordIds": record_ids,
            });
        } else {
            fixture_json["cases"][0]
                .as_object_mut()
                .expect("case object")
                .remove("opposingEvidence");
        }

        parse_fixture_json(&fixture_json.to_string()).expect("EVAL-004 fixture parses")
    }

    fn eval004_record_json(id: &str, timestamp: u64, text: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "entityType": 8,
            "occurred": {
                "start": timestamp,
                "end": timestamp
            },
            "learnedAt": timestamp,
            "fields": {
                "txt": text,
                "lvl": "eval004",
                "at": format!("eval004-t{timestamp}")
            },
            "text": [
                {
                    "field": "txt",
                    "value": text
                }
            ]
        })
    }

    fn manifest_for_fixture_case(fixture: &BeamFixture, case_id: &str) -> RunManifest {
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(BUILTIN_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["runId"] = serde_json::json!(case_id);
        manifest_json["dataset"]["fixtureId"] = serde_json::json!(fixture.fixture_id.as_str());
        manifest_json["caseIds"] = serde_json::json!([case_id]);

        parse_manifest_json(&manifest_json.to_string()).expect("EVAL-004 manifest parses")
    }

    fn eval004_deterministic_competitor() -> CompetitorConfig {
        let manifest = parse_manifest_json(BUILTIN_MANIFEST_JSON).expect("manifest parses");
        manifest
            .competitors
            .into_iter()
            .find(|competitor| competitor.arm == ArmKind::Deterministic)
            .expect("deterministic competitor")
    }

    fn deterministic_competitor_json(report_json: &serde_json::Value) -> &serde_json::Value {
        report_json["cases"][0]["competitors"]
            .as_array()
            .expect("competitors array")
            .iter()
            .find(|competitor| competitor["competitorId"] == "deterministic-context-pack")
            .expect("deterministic competitor")
    }

    fn vanilla_rag_competitor_json(report_json: &serde_json::Value) -> &serde_json::Value {
        report_json["cases"][0]["competitors"]
            .as_array()
            .expect("competitors array")
            .iter()
            .find(|competitor| competitor["competitorId"] == "vanilla-rag")
            .expect("vanilla-rag competitor")
    }

    fn assert_abstention_gate_passed(competitor: &serde_json::Value, expected_gate: &str) {
        assert!(competitor["scoring"]["overallScore"].is_null());
        let abilities = competitor["scoring"]["abilities"]
            .as_array()
            .expect("abilities array");
        assert!(abilities.iter().all(|ability| ability["score"].is_null()));
        assert!(abilities.iter().any(|ability| {
            ability["ability"] == "abstention_gate"
                && ability["passed"] == true
                && ability["detail"]
                    .as_str()
                    .expect("detail string")
                    .contains(expected_gate)
        }));
        assert!(abilities.iter().any(|ability| {
            ability["ability"] == "no_regression_gate" && ability["passed"] == true
        }));
    }

    fn gate_case(fixture_class: FixtureClass) -> FixtureCase {
        FixtureCase {
            case_id: format!("eval004-{}", fixture_class.gate_label()),
            query: "fixture gate query".to_owned(),
            limit: if fixture_class == FixtureClass::LowConfidence {
                0
            } else {
                5
            },
            token_budget: 128,
            expected_min_results: 0,
            pending_vector_count: 0,
            query_embedding: None,
            fixture_class,
            temporal_search: (fixture_class == FixtureClass::TemporalStaleness)
                .then_some(FixtureTimeRange { start: 0, end: 1 }),
            temporal_evidence_ids: if fixture_class == FixtureClass::TemporalStaleness {
                vec!["50505050505050505050505050505050".to_owned()]
            } else {
                Vec::new()
            },
            opposing_evidence: (fixture_class == FixtureClass::AdversarialContradiction).then(
                || OpposingEvidence {
                    field: "txt".to_owned(),
                    record_ids: vec![
                        "30303030303030303030303030303030".to_owned(),
                        "40404040404040404040404040404040".to_owned(),
                    ],
                },
            ),
            offline_amortized_cost: CostComponentInput::default(),
        }
    }

    fn budget_score(scores: &[AbilityScoreReport]) -> &AbilityScoreReport {
        scores
            .iter()
            .find(|score| score.ability == AbilityKind::BudgetDiscipline)
            .expect("budget discipline score exists")
    }

    fn minimal_context_pack_report(
        result_count: usize,
        signals_used: &[&str],
        empty: Option<EmptyContextReport>,
    ) -> ContextPackReport {
        assert_eq!(
            result_count, 0,
            "use minimal_context_pack_report_with_result_ids for non-empty reports"
        );
        minimal_context_pack_report_with_result_ids(&[], signals_used, empty)
    }

    fn minimal_context_pack_report_with_result_ids(
        result_ids: &[&str],
        signals_used: &[&str],
        empty: Option<EmptyContextReport>,
    ) -> ContextPackReport {
        let mut stats = empty_pack_stats_report();
        stats.signals_used = signals_used
            .iter()
            .map(|signal| (*signal).to_owned())
            .collect();
        let results: Vec<ContextEntityReport> = result_ids
            .iter()
            .enumerate()
            .map(|(idx, id)| ContextEntityReport {
                id: (*id).to_owned(),
                short_id: format!("g{idx}"),
                entity_type: 8,
                score: 1.0,
            })
            .collect();

        ContextPackReport {
            token_budget: 128,
            limit: result_ids.len().max(1),
            serialized_format: "yaml".to_owned(),
            serialized_bytes: 0,
            serialized_tokens: 0,
            tokenizer_id: oneiron::DEFAULT_CONTEXT_PACK_TOKENIZER_ID.to_owned(),
            query_cost: CostComponentReport {
                token_source: TokenAccountingSource::TokenizerCount,
                tokenizer_id: Some(oneiron::DEFAULT_CONTEXT_PACK_TOKENIZER_ID.to_owned()),
                input_tokens: 0,
                output_tokens: 0,
                target_tokens: 128,
                elapsed_us: 0,
                cost_usd: 0.0,
            },
            result_count: results.len(),
            neighbor_count: 0,
            results,
            neighbors: Vec::new(),
            stats,
            empty,
            temporal_result_ids: BTreeSet::new(),
            budgeted_text_by_entity_id: BTreeMap::new(),
        }
    }

    fn minimal_context_pack_report_with_temporal_result_ids(
        mut context_pack: ContextPackReport,
        temporal_result_ids: &[&str],
    ) -> ContextPackReport {
        context_pack.temporal_result_ids = temporal_result_ids
            .iter()
            .map(|id| (*id).to_owned())
            .collect();
        context_pack
    }

    fn empty_pack_stats_report() -> PackStatsReport {
        PackStatsReport {
            candidates_considered: 0,
            signals_used: Vec::new(),
            query_time_us: 0,
            entities_hydrated: 0,
            neighbors_hydrated: 0,
            cosine_ghosts_dampened: 0,
            claims_suppressed: 0,
            tokenizer_id: oneiron::DEFAULT_CONTEXT_PACK_TOKENIZER_ID.to_owned(),
            total_tokens: 0,
            section_tokens: Vec::new(),
            item_tokens: Vec::new(),
            items_truncated: 0,
            items_truncated_reasons: Vec::new(),
            items_dropped: 0,
            items_dropped_reasons: Vec::new(),
        }
    }
}
