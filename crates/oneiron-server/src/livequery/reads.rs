//! The eight existing WS read verbs call the engine facade, without write aliases.
use oneiron::memory::{ClaimListFilter, Effort, Memory, MemoryError, NeighborOpts, RecallScope};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::AppError;

pub(super) fn read_method(method: &str) -> bool {
    matches!(
        method,
        "recall"
            | "queryBm25"
            | "neighbors"
            | "hydrate"
            | "pendingWrites"
            | "receipts"
            | "claimList"
            | "claimHistory"
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Limit {
    limit: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Query {
    query: String,
    limit: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Hydrate {
    refs: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Neighbors {
    entity_ref: String,
    opts: NeighborOpts,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct History {
    claim_ref: String,
}

// These two request shapes and defaults are the released HTTP facade contract.
#[derive(Deserialize)]
struct Recall {
    query: String,
    #[serde(default)]
    effort: Option<Effort>,
    #[serde(default)]
    scope: Option<RecallScope>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    format: Option<String>,
}

#[derive(Deserialize)]
struct Receipts {
    #[serde(default)]
    limit: Option<usize>,
}

pub(super) enum Read {
    Hydrate(Vec<String>),
    Query(String, usize),
    Neighbors(String, NeighborOpts),
    PendingWrites(usize),
    Receipts(usize),
    ClaimList(ClaimListFilter),
    ClaimHistory(String),
    Recall {
        query: String,
        effort: Effort,
        scope: RecallScope,
        limit: usize,
        format: Option<String>,
    },
}

impl Read {
    pub(super) fn parse(method: &str, value: Value) -> Result<Self, AppError> {
        Ok(match method {
            "hydrate" => {
                let p: Hydrate = params(value)?;
                Self::Hydrate(p.refs)
            }
            "queryBm25" => {
                let p: Query = params(value)?;
                Self::Query(p.query, p.limit)
            }
            "neighbors" => {
                let p: Neighbors = params(value)?;
                Self::Neighbors(p.entity_ref, p.opts)
            }
            "pendingWrites" => {
                let p: Limit = params(value)?;
                Self::PendingWrites(p.limit)
            }
            "receipts" => {
                let p: Receipts = params(value)?;
                Self::Receipts(facade_limit(p.limit, 100)?)
            }
            "claimList" => Self::ClaimList(params(value)?),
            "claimHistory" => {
                let p: History = params(value)?;
                Self::ClaimHistory(p.claim_ref)
            }
            "recall" => {
                let p: Recall = params(value)?;
                Self::Recall {
                    query: p.query,
                    effort: p.effort.unwrap_or(Effort::Standard),
                    scope: p.scope.unwrap_or_default(),
                    limit: facade_limit(p.limit, 10)?,
                    format: p.format,
                }
            }
            _ => return Err(AppError::bad_request("unknown read RPC", Some("method"))),
        })
    }

    pub(super) fn run(self, memory: &Memory<'_>) -> Result<Value, AppError> {
        match self {
            Self::Hydrate(refs) => result(memory.hydrate(&refs)),
            Self::Query(query, limit) => result(memory.query_bm25(&query, limit)),
            Self::Neighbors(entity_ref, opts) => result(memory.neighbors(&entity_ref, &opts)),
            Self::PendingWrites(limit) => result(memory.pending_writes(limit)),
            Self::Receipts(limit) => result(memory.receipts(limit)),
            Self::ClaimList(filter) => result(memory.claim_list(&filter)),
            Self::ClaimHistory(claim_ref) => result(memory.claim_history(&claim_ref)),
            Self::Recall {
                query,
                effort,
                scope,
                limit,
                format,
            } => result(memory.recall(&query, effort, &scope, limit, format.as_deref(), None)),
        }
    }
}

fn params<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, AppError> {
    serde_json::from_value(value).map_err(|_| AppError::invalid_params())
}

fn result<T: Serialize>(value: Result<T, MemoryError>) -> Result<Value, AppError> {
    serde_json::to_value(value?)
        .map_err(|_| AppError::internal_server_error("facade serialization failed"))
}

pub(super) fn facade_limit(requested: Option<usize>, default: usize) -> Result<usize, AppError> {
    let limit = requested.unwrap_or(default);
    if limit == 0 || limit > crate::api::CORE_MAX_LIST_LIMIT {
        return Err(AppError::new(
            oneiron::memory::MEMORY_CODE_BAD_REQUEST,
            format!(
                "limit must be between 1 and {}",
                crate::api::CORE_MAX_LIST_LIMIT
            ),
            ["Request a smaller page and paginate."],
        ));
    }
    Ok(limit)
}
