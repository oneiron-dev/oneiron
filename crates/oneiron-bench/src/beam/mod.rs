//! BEAM scaffold and fixed scorer for EVAL-001/EVAL-002.

use oneiron::PackFormat;

use self::report_model::NotReadyState;

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

mod arms;
mod community;
mod judge;
mod load;
mod model;
mod ppr_vad;
mod report;
mod report_model;
mod runner;
mod scorer;
#[cfg(test)]
mod tests_community_eval004;
#[cfg(test)]
mod tests_gates;
#[cfg(test)]
mod tests_jsonl_contract;
#[cfg(test)]
mod tests_judge_cost;
#[cfg(test)]
mod tests_ppr_vad;
#[cfg(test)]
mod tests_smoke_manifest;
mod util;
mod validate;

pub(crate) use self::arms::run;
#[cfg(test)]
pub(crate) use self::judge::{
    AnswerPromptPin, JUDGE_VOTE_COUNT, MajorityJudgeError, MajorityVoteError, majority_of_three,
    run_majority_judge_card, single_judge_vote,
};
#[cfg(test)]
pub(crate) use self::model::{ArmKind, BeamFixture, FixtureCase, JudgeMetadata, RunManifest};
#[cfg(test)]
pub(crate) use self::report_model::BeamReport;
#[cfg(test)]
pub(crate) use self::runner::{
    parse_fixture_json, parse_manifest_json, run_builtin_smoke, run_fixture_manifest,
    run_manifest_path,
};

#[cfg(test)]
use self::tests_community_eval004::{CONTRACT_MANIFEST_JSON, CONTRACT_RUN_JSONL};
#[cfg(test)]
use self::{
    arms::*, community::*, load::*, model::*, ppr_vad::*, report::*, report_model::*, runner::*,
    scorer::*, util::*,
};
