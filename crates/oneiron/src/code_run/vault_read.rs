//! One Rust vault-read contract whose behavior does not change with deployment
//! topology (ONE-1433).
//!
//! The same typed call reaches the same accepted vault-read operation through
//! an in-process adapter ([`InProcessVaultReadAdapter`]), a transport-injected
//! adapter ([`WireTransportVaultReadAdapter`]), or the cloud placeholder
//! ([`CloudVaultReadAdapter`]). The contract is engine-side Rust: no HTTP, MCP,
//! async, or cloud dependency enters this crate, and no TypeScript ships here.
//!
//! The v1 inventory is CLOSED at eight methods — five structured reads mapped
//! 1:1 onto the accepted `/v1/core` operations, plus three M8-reserved runtime
//! peers whose generated wrappers return [`VaultReadError::RuntimeUnavailable`]
//! before any validation, backend, or transport work. Method enum values, wire
//! ops, request/response union arms, trait methods, and
//! [`VAULT_READ_METHOD_MAP`] are generated from ONE declaration
//! (`vault_read_contract!`), so a new method is a wire-contract change that
//! adds exactly one row.
//!
//! Request DTOs copy the accepted route serde exactly (canonical spellings plus
//! every accepted alias) and are pinned by hand-written golden vectors.
//! Response DTOs are local engine-canonical records constructible ENTIRELY from
//! [`ScopedRead`] and public [`ContextPack`] fields: this module imports no
//! `facade`/`memory` DTO type (`EntityView`, `MemoryPack`, `Memory::recall`),
//! and never performs a naked-vault read or a second unscoped existence check
//! after `ScopedRead` answers absence. Scope denial and absence are therefore
//! the SAME typed outcome: `Engine { engine_code: "NOT_FOUND", .. }`.

use std::collections::BTreeMap;
use std::io::Cursor;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::claim::{ScopedRead, ScopedReadActorKey};
use crate::companion::companion_value_to_json;
use crate::context_pack::{
    ContextEntity, ContextPack, ContextPackBuilder, ContextPackRetrievalBudget,
    DEFAULT_MAX_NEIGHBORS, EmptyContext, EmptyReason, FieldProfile, MAX_CONTEXT_NEIGHBORS,
    MAX_EDGE_HOP, PackItemAccounting, PackItemAccountingReason, PackStats, PackTokenStats,
    TokenAllocation,
};
use crate::deletion::{
    HydratedShortIdDeletion, MemoryTimeline, MemoryTimelineRecord, MemoryTimelineRecordState,
};
use crate::edge::EdgeInfo;
use crate::entity_id::{EntityId, parse_presentation_id};
use crate::pipeline::{ScoredEntity, Signal};
use crate::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_FACET, ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN,
};
use crate::vault::{HydratedShortId, Vault};

/// Result of every vault-read operation.
pub type VaultReadResult<T> = std::result::Result<T, VaultReadError>;

/// Maximum refs accepted by one batch short-id hydrate call. Copied from the
/// accepted route's `CORE_MAX_BATCH_ENTITIES`.
pub const VAULT_READ_MAX_BATCH_REFS: usize = 256;

/// Stable engine code for accepted-route absence. A missing target and a
/// clamp-denied target normalize to this one code by design.
const NOT_FOUND_ENGINE_CODE: &str = "NOT_FOUND";

/// Stable engine code for an engine-side failure, copied from the accepted API
/// error vocabulary.
const INTERNAL_ENGINE_CODE: &str = "INTERNAL_SERVER_ERROR";

// ─── Contract declaration ────────────────────────────────────────────────────

/// The one declarative contract table.
///
/// Every generated surface — [`VaultReadMethod`], [`VaultReadWireOp`],
/// [`VaultReadRequest`], [`VaultReadResponse`], [`VAULT_READ_METHOD_MAP`], and
/// the [`VaultReadClient`] trait methods — comes from the single invocation
/// below. A trait method cannot exist without its method/wire-op row, and the
/// mapping table is never hand-copied.
macro_rules! vault_read_contract {
    (
        $(
            $method:ident => {
                variant: $variant:ident,
                wire: $wire_variant:ident = $wire:literal,
                availability: $availability:ident,
                request: $request:ty,
                response: $response:ty,
                doc: $doc:literal,
            }
        )+
    ) => {
        /// Closed inventory of v1 vault-read methods.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum VaultReadMethod {
            $(
                #[doc = $doc]
                $variant,
            )+
        }

        impl VaultReadMethod {
            /// Number of rows in the closed contract.
            pub const COUNT: usize = [$(Self::$variant,)+].len();

            /// Every method, in contract-declaration order.
            pub const ALL: [Self; Self::COUNT] = [$(Self::$variant,)+];

            /// The one stable wire operation this method maps onto.
            #[must_use]
            pub const fn wire_op(self) -> VaultReadWireOp {
                match self {
                    $(Self::$variant => VaultReadWireOp::$wire_variant,)+
                }
            }

            /// Whether this method executes a structured read or is deferred to
            /// the M8 runtime.
            #[must_use]
            pub const fn availability(self) -> VaultReadAvailability {
                match self {
                    $(Self::$variant => VaultReadAvailability::$availability,)+
                }
            }
        }

        /// Stable wire operation names. These strings are the contract; no
        /// legacy route alias may enter this enum.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub enum VaultReadWireOp {
            $(
                #[doc = $doc]
                #[serde(rename = $wire)]
                $wire_variant,
            )+
        }

        impl VaultReadWireOp {
            /// The pinned wire string for this operation.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$wire_variant => $wire,)+
                }
            }

            /// The one method this operation belongs to.
            #[must_use]
            pub const fn method(self) -> VaultReadMethod {
                match self {
                    $(Self::$wire_variant => VaultReadMethod::$variant,)+
                }
            }
        }

        /// Generated method → wire-op → availability table.
        pub const VAULT_READ_METHOD_MAP: [VaultReadMethodMapping; VaultReadMethod::COUNT] = [
            $(
                VaultReadMethodMapping {
                    method: VaultReadMethod::$variant,
                    wire_op: VaultReadWireOp::$wire_variant,
                    availability: VaultReadAvailability::$availability,
                },
            )+
        ];

        /// Operation-tagged request union. The tag is the stable wire op.
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        #[serde(tag = "op", content = "request")]
        pub enum VaultReadRequest {
            $(
                #[doc = $doc]
                #[serde(rename = $wire)]
                $variant($request),
            )+
        }

        impl VaultReadRequest {
            /// The method this request arm belongs to.
            #[must_use]
            pub const fn method(&self) -> VaultReadMethod {
                match self {
                    $(Self::$variant(_) => VaultReadMethod::$variant,)+
                }
            }

            /// The wire op this request arm serializes under.
            #[must_use]
            pub const fn wire_op(&self) -> VaultReadWireOp {
                self.method().wire_op()
            }

            /// The canonical transport body for this arm: the INNER request
            /// DTO, serialized once.
            ///
            /// The operation travels beside the body as the `op` argument of
            /// [`WireTransport::round_trip`], so the body must never re-wrap it
            /// in this type's `{"op", "request"}` tagged envelope. Generated
            /// from the contract table, so a new row cannot forget it.
            pub(crate) fn canonical_body(&self) -> serde_json::Result<Vec<u8>> {
                match self {
                    $(Self::$variant(request) => serde_json::to_vec(request),)+
                }
            }
        }

        /// Operation-tagged response union. The tag proves operation identity:
        /// a structurally compatible payload from the wrong operation still
        /// fails.
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        #[serde(tag = "op", content = "response")]
        pub enum VaultReadResponse {
            $(
                #[doc = $doc]
                #[serde(rename = $wire)]
                $variant($response),
            )+
        }

        impl VaultReadResponse {
            /// The method this response arm belongs to.
            #[must_use]
            pub const fn method(&self) -> VaultReadMethod {
                match self {
                    $(Self::$variant(_) => VaultReadMethod::$variant,)+
                }
            }

            /// The wire op this response arm serializes under.
            #[must_use]
            pub const fn wire_op(&self) -> VaultReadWireOp {
                self.method().wire_op()
            }
        }

        /// The ONE Rust client contract.
        ///
        /// Sealed on purpose: hosts inject transport behavior through
        /// [`WireTransport`], they do not create a fourth client that could skip
        /// accepted validation or redefine parity. Every method is a generated
        /// wrapper around one validated dispatch path.
        #[allow(
            private_bounds,
            reason = "sealed contract: `Backend` is unnameable outside this module on purpose"
        )]
        pub trait VaultReadClient: sealed::Backend {
            $(
                #[doc = $doc]
                fn $method(&self, request: $request) -> VaultReadResult<$response> {
                    let response =
                        validate_and_dispatch(self, VaultReadRequest::$variant(request))?;
                    match response {
                        VaultReadResponse::$variant(response) => Ok(response),
                        other => Err(response_arm_mismatch(
                            VaultReadMethod::$variant,
                            other.wire_op(),
                        )),
                    }
                }
            )+
        }
    };
}

vault_read_contract! {
    query => {
        variant: Query,
        wire: CoreQuery = "core.query",
        availability: StructuredRead,
        request: CoreQueryRequest,
        response: CoreQueryResponse,
        doc: "Accepted `POST /v1/core/query` retrieval through the actor's scoped read lane.",
    }
    context_pack => {
        variant: ContextPack,
        wire: CoreContextPack = "core.context_pack",
        availability: StructuredRead,
        request: CoreContextPackRequest,
        response: CoreContextPackResponse,
        doc: "Accepted `POST /v1/core/context-pack` assembly, re-clamped by the scoped read.",
    }
    hydrate => {
        variant: Hydrate,
        wire: CoreHydrate = "core.hydrate",
        availability: StructuredRead,
        request: CoreHydrateRequest,
        response: CoreHydrateResponse,
        doc: "Accepted `POST /v1/core/hydrate` short-reference hydration.",
    }
    hydrate_many => {
        variant: HydrateMany,
        wire: CoreBatchShortIdHydrate = "core.batch_short_id_hydrate",
        availability: StructuredRead,
        request: CoreBatchShortIdHydrateRequest,
        response: CoreBatchShortIdHydrateResponse,
        doc: "Accepted `POST /v1/core/batch/shortId/hydrate` batch hydration.",
    }
    memory_timeline => {
        variant: MemoryTimeline,
        wire: CoreMemoryTimeline = "core.memory_timeline",
        availability: StructuredRead,
        request: CoreMemoryTimelineRequest,
        response: CoreMemoryTimelineResponse,
        doc: "Accepted `GET /v1/core/memory/{id}/timeline` supersession timeline.",
    }
    ask => {
        variant: Ask,
        wire: RuntimeAsk = "runtime.ask",
        availability: RuntimeDeferred,
        request: AskRequest,
        response: AskResponse,
        doc: "M8-reserved runtime ask. Always `RuntimeUnavailable` in this contract version.",
    }
    code_search => {
        variant: CodeSearch,
        wire: RuntimeCodeSearch = "runtime.code_search",
        availability: RuntimeDeferred,
        request: CodeSearchRequest,
        response: CodeSearchResponse,
        doc: "M8-reserved runtime code search. Always `RuntimeUnavailable` in this version.",
    }
    code_execute => {
        variant: CodeExecute,
        wire: RuntimeCodeExecute = "runtime.code_execute",
        availability: RuntimeDeferred,
        request: CodeExecuteRequest,
        response: CodeExecuteResponse,
        doc: "M8-reserved runtime code execution. Always `RuntimeUnavailable` in this version.",
    }
}

/// Whether a contract row executes here or waits for the M8 runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultReadAvailability {
    /// Structured read backed by an accepted `/v1/core` operation.
    StructuredRead,
    /// Runtime peer reserved for M8; every adapter reports it unavailable.
    RuntimeDeferred,
}

/// One generated row of [`VAULT_READ_METHOD_MAP`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultReadMethodMapping {
    /// Rust-side method identity.
    pub method: VaultReadMethod,
    /// Stable wire operation the method maps onto.
    pub wire_op: VaultReadWireOp,
    /// Whether the row executes here or is M8-deferred.
    pub availability: VaultReadAvailability,
}

// ─── Error taxonomy ──────────────────────────────────────────────────────────

/// Which adapter produced an [`VaultReadError::Unimplemented`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultReadAdapterKind {
    /// Embedded host adapter bound to a scoped read lane.
    InProcess,
    /// Transport-injected adapter used by HTTP or MCP daemons.
    WireTransport,
    /// Cloud placeholder exposing the identical Rust surface.
    Cloud,
}

/// The one comparable typed failure taxonomy shared by every adapter.
///
/// Parity is structured-fields-only: compare `InvalidRequest` by
/// `{ method, field }` and `Engine` by `{ method, engine_code }`. Free-text
/// `reason`/`message` never gates parity.
///
/// This type deliberately does NOT embed [`crate::Error`]: the crate error
/// bridges to it with `#[from]`, and embedding would make the type recursive
/// and non-serializable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VaultReadError {
    /// The request failed the accepted route's own validation.
    #[error("invalid vault-read request for {method:?}: {field}: {reason}")]
    InvalidRequest {
        /// Method whose accepted validation rejected the request.
        method: VaultReadMethod,
        /// Accepted route field name that failed.
        field: String,
        /// Human-readable reason. Never compared for parity.
        reason: String,
    },
    /// The injected transport failed to complete a round trip.
    #[error("vault-read transport failed for {method:?}: {message}")]
    Transport {
        /// Method whose round trip failed.
        method: VaultReadMethod,
        /// Human-readable transport detail. Never compared for parity.
        message: String,
    },
    /// The response envelope or its operation tag violated the contract.
    #[error("vault-read protocol mismatch for {method:?}: {message}")]
    ProtocolMismatch {
        /// Method whose response failed contract decoding.
        method: VaultReadMethod,
        /// Human-readable protocol detail. Never compared for parity.
        message: String,
    },
    /// An M8-reserved runtime peer was called before the runtime exists.
    #[error("vault-read runtime unavailable for {method:?}")]
    RuntimeUnavailable {
        /// Runtime peer that is not available.
        method: VaultReadMethod,
    },
    /// The adapter exposes the method but cannot execute it yet.
    #[error("vault-read method {method:?} is unimplemented by {adapter:?}")]
    Unimplemented {
        /// Adapter that has no implementation for the method.
        adapter: VaultReadAdapterKind,
        /// Method that is unimplemented on that adapter.
        method: VaultReadMethod,
    },
    /// The engine refused or failed the accepted operation.
    #[error("vault-read engine failure for {method:?} ({engine_code}): {message}")]
    Engine {
        /// Method whose engine execution failed.
        method: VaultReadMethod,
        /// Stable code copied from the accepted API error vocabulary.
        engine_code: String,
        /// Human-readable engine detail. Never compared for parity.
        message: String,
    },
}

fn invalid_request(method: VaultReadMethod, field: &str, reason: &str) -> VaultReadError {
    VaultReadError::InvalidRequest {
        method,
        field: field.to_owned(),
        reason: reason.to_owned(),
    }
}

/// Accepted-route absence. A missing row and a clamp-denied row normalize here
/// identically; the adapter never distinguishes why the route answered absence.
fn engine_absent(method: VaultReadMethod, field: &str) -> VaultReadError {
    VaultReadError::Engine {
        method,
        engine_code: NOT_FOUND_ENGINE_CODE.to_owned(),
        message: format!("{field} was not found"),
    }
}

fn engine_failure(method: VaultReadMethod, error: &crate::Error) -> VaultReadError {
    VaultReadError::Engine {
        method,
        engine_code: INTERNAL_ENGINE_CODE.to_owned(),
        message: error.to_string(),
    }
}

fn engine_corruption(method: VaultReadMethod, detail: &str) -> VaultReadError {
    VaultReadError::Engine {
        method,
        engine_code: INTERNAL_ENGINE_CODE.to_owned(),
        message: detail.to_owned(),
    }
}

fn response_arm_mismatch(method: VaultReadMethod, received: VaultReadWireOp) -> VaultReadError {
    VaultReadError::ProtocolMismatch {
        method,
        message: format!(
            "expected response op {}, received {}",
            method.wire_op().as_str(),
            received.as_str()
        ),
    }
}

// ─── Wire DTOs ───────────────────────────────────────────────────────────────

/// Accepted default page limit, copied from the accepted route's
/// `default_limit()`.
const fn default_limit() -> usize {
    10
}

/// Read projection requested by the accepted routes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum View {
    /// Compact projection used by list/search results.
    Summary,
    /// Identity-only projection; the v1 rule omits the body.
    Standard,
    /// Full projection including the decoded body.
    Full,
}

/// Count precision requested by callers and reported in response metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CountMode {
    /// Skip count work and report `total = 0`.
    None,
    /// Report a non-exact search estimate.
    Estimate,
    /// Requested exact count; search responses collapse it to `Estimate`.
    Exact,
}

impl CountMode {
    const fn default_estimate() -> Self {
        Self::Estimate
    }

    /// Accepted collapse: search responses never report exact counts.
    #[must_use]
    pub const fn for_search_response(self) -> Self {
        match self {
            Self::None => Self::None,
            Self::Estimate | Self::Exact => Self::Estimate,
        }
    }
}

/// Accepted over-fetch recipe. `Exact` is collapsed before this call.
const fn search_fetch_limit(count_mode: CountMode, page_limit: usize) -> usize {
    match count_mode {
        CountMode::None => page_limit,
        CountMode::Estimate => page_limit.saturating_add(1),
        CountMode::Exact => {
            panic!("count mode collapses to none/estimate before fetch-limit resolution")
        }
    }
}

/// Accepted `search_meta` total: `None` reports zero, `Estimate` reports the
/// admitted over-fetch count.
const fn search_total(count_mode: CountMode, admitted: usize) -> u64 {
    match count_mode {
        CountMode::None => 0,
        CountMode::Estimate => admitted as u64,
        CountMode::Exact => panic!("count mode collapses to none/estimate before meta resolution"),
    }
}

/// Entity record constructible from `ScopedRead::get_entity_parts`.
///
/// `body` is the one view-controlled field in v1: `Standard` omits it, while
/// `Summary` and `Full` carry the public MessagePack → JSON projection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoreEntityRecord {
    /// Full `EntityId` as lowercase hex.
    pub id: String,
    /// Numeric entity type byte.
    pub entity_type: u8,
    /// Entity learned-at timestamp in Unix seconds.
    pub learned_at: u64,
    /// Retrieval score, when the record came from a ranked read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f32>,
    /// Decoded entity body, when the view includes it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<Value>,
}

/// Accepted `POST /v1/core/query` request body.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoreQueryRequest {
    /// Optional BM25 text query.
    #[serde(default)]
    pub query: Option<String>,
    /// Optional vector query.
    #[serde(default, rename = "query_vector", alias = "queryVector")]
    pub query_vector: Option<Vec<f32>>,
    /// Maximum result count.
    #[serde(default = "default_limit")]
    pub limit: usize,
    /// Projection view. Defaults to `Summary`.
    #[serde(default)]
    pub view: Option<View>,
    /// Count precision. Defaults to `Estimate`.
    #[serde(
        default = "CountMode::default_estimate",
        rename = "countMode",
        alias = "count_mode"
    )]
    pub count_mode: CountMode,
}

/// Count metadata reported by [`CoreQueryResponse`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreQueryMeta {
    /// Reported total under the collapsed count mode.
    pub total: u64,
    /// Collapsed count mode actually applied.
    #[serde(rename = "countMode")]
    pub count_mode: CountMode,
}

/// Query response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoreQueryResponse {
    /// Projected page of admitted entities.
    pub items: Vec<CoreEntityRecord>,
    /// Reserved cursor field; this contract version never paginates.
    #[serde(rename = "nextCursor", skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    /// Count metadata.
    pub meta: CoreQueryMeta,
}

/// Engine-executable context-pack subset of the accepted route.
///
/// The daemon-only session, companion, disclosure, policy, time, and projection
/// controls are outside this engine contract.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoreContextPackRequest {
    /// Optional BM25 text seed.
    #[serde(default)]
    pub query: Option<String>,
    /// Optional vector seed.
    #[serde(default, rename = "query_vector", alias = "queryVector")]
    pub query_vector: Option<Vec<f32>>,
    /// Maximum primary candidates to retrieve.
    #[serde(default = "default_limit")]
    pub limit: usize,
    /// Nested depth controls; populated fields win over their top-level twins.
    #[serde(default)]
    pub depth: Option<ContextPackDepthControls>,
    /// Top-level edge expansion depth (compatibility twin).
    #[serde(default, rename = "edge_hop", alias = "edgeHop")]
    pub edge_hop: Option<u32>,
    /// Top-level neighbor cap (compatibility twin).
    #[serde(default, rename = "max_neighbors", alias = "maxNeighbors")]
    pub max_neighbors: Option<usize>,
    /// Retrieval and serialization budget controls.
    #[serde(default)]
    pub budget: Option<ContextPackBudgetControls>,
}

impl CoreContextPackRequest {
    /// Accepted-route resolution: a populated nested `depth` field wins over
    /// its top-level compatibility twin; an absent nested field falls back.
    #[must_use]
    pub fn resolved_depth(&self) -> ContextPackDepthControls {
        ContextPackDepthControls {
            edge_hop: self
                .depth
                .as_ref()
                .and_then(|d| d.edge_hop)
                .or(self.edge_hop),
            max_neighbors: self
                .depth
                .as_ref()
                .and_then(|d| d.max_neighbors)
                .or(self.max_neighbors),
        }
    }

    /// Accepted field name reported when the resolved `edge_hop` is rejected.
    const fn edge_hop_field(&self) -> &'static str {
        match &self.depth {
            Some(depth) if depth.edge_hop.is_some() => "depth.edge_hop",
            _ => "edge_hop",
        }
    }

    /// Accepted field name reported when the resolved `max_neighbors` is
    /// rejected.
    const fn max_neighbors_field(&self) -> &'static str {
        match &self.depth {
            Some(depth) if depth.max_neighbors.is_some() => "depth.max_neighbors",
            _ => "max_neighbors",
        }
    }
}

/// Nested edge-expansion depth controls.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextPackDepthControls {
    /// Edge expansion depth for neighbor hydration.
    #[serde(default, rename = "edge_hop", alias = "edgeHop")]
    pub edge_hop: Option<u32>,
    /// Maximum neighbors to hydrate during edge expansion.
    #[serde(default, rename = "max_neighbors", alias = "maxNeighbors")]
    pub max_neighbors: Option<usize>,
}

/// Per-kind retrieval item budgets applied before final truncation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextPackRetrievalBudgetControls {
    /// CLAIM item budget.
    #[serde(default)]
    pub claims: Option<usize>,
    /// TURN item budget.
    #[serde(default)]
    pub turns: Option<usize>,
    /// SUMMARY item budget.
    #[serde(default)]
    pub summaries: Option<usize>,
    /// FACET item budget.
    #[serde(default)]
    pub facets: Option<usize>,
    /// Remaining-kind item budget.
    #[serde(default)]
    pub other: Option<usize>,
    /// Edge-walk neighbor selection cap.
    #[serde(default, rename = "selected_edges", alias = "selectedEdges")]
    pub selected_edges: Option<usize>,
}

/// Token and item budget controls.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextPackBudgetControls {
    /// Serialized token budget.
    #[serde(default, rename = "token_budget", alias = "tokenBudget")]
    pub token_budget: Option<usize>,
    /// Per-item token cap; `0` disables it.
    #[serde(default, rename = "max_item_tokens", alias = "maxItemTokens")]
    pub max_item_tokens: Option<usize>,
    /// Maximum field characters before truncation.
    #[serde(default, rename = "max_field_chars", alias = "maxFieldChars")]
    pub max_field_chars: Option<usize>,
    /// Per-kind retrieval item budgets.
    #[serde(default)]
    pub retrieval: Option<ContextPackRetrievalBudgetControls>,
}

/// Local serialization of every public `ContextEntity` field.
///
/// `fields` is a `BTreeMap` rather than the engine's `HashMap` so the
/// serialized bytes are deterministic: adapter parity is byte-comparable, which
/// a randomly-seeded hash order cannot be.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoreContextPackEntityRecord {
    /// Hex entity id.
    pub id: String,
    /// Short id allocated by the vault, or hex fallback.
    pub short_id: String,
    /// One-byte content hash.
    pub content_hash: u8,
    /// Numeric entity type byte.
    pub entity_type: u8,
    /// Retrieval score.
    pub score: f32,
    /// Hydrated fields when the pack hydrated them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<BTreeMap<String, Value>>,
    /// Hydrated edges when the pack included them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edges: Option<Vec<CoreContextPackEdgeRecord>>,
    /// Stored vector when the pack included it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vector: Option<Vec<f32>>,
}

/// Local serialization of one hydrated context edge.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoreContextPackEdgeRecord {
    /// `EdgeKind`'s pinned storage discriminant.
    pub kind: u8,
    /// Hex target entity id.
    pub target: String,
    /// Target short id when the target is present in the same pack.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_short_id: Option<String>,
    /// Edge weight.
    pub weight: f32,
    /// Edge creation timestamp in Unix seconds.
    pub created_at: u64,
    /// Optional edge VAD payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vad: Option<CoreContextPackVad>,
    /// Optional cached edge provenance flags.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<CoreContextPackEdgeProvenance>,
}

/// Local VAD triple.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CoreContextPackVad {
    /// Valence component.
    pub valence: f32,
    /// Arousal component.
    pub arousal: f32,
    /// Dominance component.
    pub dominance: f32,
}

/// Local edge provenance flags, using their pinned `repr(u8)` discriminants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreContextPackEdgeProvenance {
    /// `EdgeConfirmationStatus` discriminant.
    pub confirmation_status: u8,
    /// `EdgeActorClass` discriminant.
    pub actor_class: u8,
}

/// Closed local mirror of the engine's retrieval `Signal`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreContextPackSignal {
    /// Vector similarity channel.
    Vector,
    /// BM25 text channel.
    Text,
    /// Phonetic channel.
    Phonetic,
    /// Temporal channel.
    Temporal,
    /// Personalized PageRank channel.
    Ppr,
    /// Hypothetical-document expansion channel.
    Hyde,
}

/// Local token accounting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreContextPackTokenStats {
    /// Stable tokenizer identifier used for every count here.
    pub tokenizer_id: String,
    /// Exact token count of the serialized pack.
    pub total_tokens: usize,
    /// Per-section row-token accounting.
    pub sections: Vec<CoreContextPackSectionTokenStats>,
    /// Per-item row-token accounting.
    pub items: Vec<CoreContextPackItemTokenStats>,
}

/// Local per-section token accounting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreContextPackSectionTokenStats {
    /// Logical section name.
    pub section: String,
    /// Row-level token count for this section.
    pub tokens: usize,
}

/// Local per-item token accounting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreContextPackItemTokenStats {
    /// Logical section containing this item.
    pub section: String,
    /// Serialized short reference for the item.
    pub id: String,
    /// Entity type byte used for the serialized row group.
    pub entity_type: u8,
    /// Row-level token count for this item.
    pub tokens: usize,
}

/// Why items were truncated or dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreContextPackAccountingReason {
    /// Per-kind item budget.
    ItemBudget,
    /// Token budget.
    TokenBudget,
}

/// Local item accounting record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreContextPackAccounting {
    /// Number of items affected.
    pub count: usize,
    /// Accounting reason.
    pub reason: CoreContextPackAccountingReason,
}

/// Local mirror of the public pack stats.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreContextPackStats {
    /// Candidates considered by retrieval.
    pub candidates_considered: usize,
    /// Retrieval signals used.
    pub signals_used: Vec<CoreContextPackSignal>,
    /// Query time in microseconds.
    pub query_time_us: u64,
    /// Entities hydrated for the results section.
    pub entities_hydrated: usize,
    /// Entities hydrated for the neighbors section.
    pub neighbors_hydrated: usize,
    /// Cosine-ghost candidates dampened.
    pub cosine_ghosts_dampened: usize,
    /// CLAIM records suppressed by the read-path gates.
    pub claims_suppressed: usize,
    /// Token accounting.
    pub tokens: CoreContextPackTokenStats,
    /// Items truncated.
    pub items_truncated: CoreContextPackAccounting,
    /// Items dropped.
    pub items_dropped: CoreContextPackAccounting,
}

/// Why an otherwise successful pack surfaced no entities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreContextPackEmptyReason {
    /// Read-path filters matched nothing.
    FilterMatchedNone,
    /// Nothing in scope to retrieve.
    NoData,
    /// Every candidate was already activated.
    AllActivated,
    /// Every candidate scored below threshold.
    BelowThreshold,
}

/// Structured empty-context record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreContextPackEmpty {
    /// Machine-readable reason.
    pub reason: CoreContextPackEmptyReason,
    /// Candidate count in scope.
    pub total_in_scope: usize,
    /// Human-readable hint.
    pub hint: String,
}

/// Field-for-field local projection of the public `ContextPack`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoreContextPackProjection {
    /// Primary results.
    pub results: Vec<CoreContextPackEntityRecord>,
    /// Edge-walk neighbors.
    pub neighbors: Vec<CoreContextPackEntityRecord>,
    /// Pack statistics.
    pub stats: CoreContextPackStats,
    /// Empty-context record when the pack surfaced nothing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub empty: Option<CoreContextPackEmpty>,
}

/// Context-pack response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CoreContextPackResponse(pub CoreContextPackProjection);

/// Accepted `POST /v1/core/hydrate` request body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreHydrateRequest {
    /// Canonical short reference in `shortId:contentHashHex` form.
    #[serde(default, rename = "ref", alias = "short_ref", alias = "shortRef")]
    pub reference: Option<String>,
    /// Short id without the content hash.
    #[serde(default, rename = "short_id", alias = "shortId")]
    pub short_id: Option<String>,
    /// Two-hex-digit content hash.
    #[serde(default, rename = "content_hash", alias = "contentHash")]
    pub content_hash: Option<String>,
    /// Projection view for live entities. Defaults to `Full`.
    #[serde(default)]
    pub view: Option<View>,
}

/// Hydrate outcome for a resolved short ref.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreHydrateStatus {
    /// Resolved to a live entity payload.
    Live,
    /// Resolved to a deleted shell or dangling short-id row.
    Deleted,
}

/// Hydrate response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoreHydrateResponse {
    /// Hydrate state for the resolved short ref.
    pub status: CoreHydrateStatus,
    /// Requested short id without content hash.
    #[serde(rename = "short_id")]
    pub short_id: String,
    /// Requested content hash as two lowercase hex digits.
    #[serde(rename = "content_hash")]
    pub content_hash: String,
    /// Hex entity id the short ref resolved to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Numeric entity type byte.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_type: Option<u8>,
    /// Deletion metadata for deleted shells and dangling rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deletion: Option<HydratedShortIdDeletion>,
    /// Projected entity record for live entities.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item: Option<CoreEntityRecord>,
}

/// Accepted `POST /v1/core/batch/shortId/hydrate` request body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreBatchShortIdHydrateRequest {
    /// Canonical short references in `shortId:contentHashHex` form.
    #[serde(
        default,
        rename = "refs",
        alias = "short_refs",
        alias = "shortRefs",
        alias = "short_ids",
        alias = "shortIds"
    )]
    pub refs: Vec<String>,
    /// Projection view for live entities. Defaults to `Full`.
    #[serde(default)]
    pub view: Option<View>,
}

/// Per-item batch hydrate outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreShortIdHydrateOutcome {
    /// Resolved to a live entity.
    Live,
    /// Resolved to a deleted shell or dangling row.
    Deleted,
    /// The caller's ref did not parse.
    MalformedShortId,
    /// The accepted route answered absence.
    NotFound,
}

/// One batch hydrate item.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoreBatchShortIdHydrateItem {
    /// Caller-echoed input ref.
    #[serde(rename = "ref")]
    pub reference: String,
    /// Outcome for this ref.
    pub outcome: CoreShortIdHydrateOutcome,
    /// Hydrate result for `Live`/`Deleted` outcomes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<CoreHydrateResponse>,
}

/// Batch hydrate response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoreBatchShortIdHydrateResponse {
    /// Per-input results, in caller order.
    pub results: Vec<CoreBatchShortIdHydrateItem>,
}

/// Canonical transport body for the accepted
/// `GET /v1/core/memory/{id}/timeline` route.
///
/// An HTTP `WireTransport` places `id` in the route path and `view` in the
/// query while still carrying this canonical JSON body at the `round_trip`
/// seam.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreMemoryTimelineRequest {
    /// Hex entity id whose supersession chain is requested.
    pub id: String,
    /// Accepted for wire fidelity. Deliberately ignored in v1: the engine
    /// timeline record carries no `item` projection to view.
    #[serde(default)]
    pub view: Option<View>,
}

/// One projected timeline record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreMemoryTimelineRecord {
    /// Hex entity id of this record.
    pub id: String,
    /// Renderer-facing lifecycle state.
    pub state: MemoryTimelineRecordState,
    /// Numeric entity type byte, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_type: Option<u8>,
    /// Occurrence start timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub occurred_start: Option<u64>,
    /// Occurrence end timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub occurred_end: Option<u64>,
    /// Learned-at timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub learned_at: Option<u64>,
    /// Stored body size in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_bytes: Option<usize>,
    /// Deletion metadata for deletion shells.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deletion: Option<HydratedShortIdDeletion>,
    /// Hex ids this record supersedes, already clamped.
    pub supersedes: Vec<String>,
    /// Hex ids that supersede this record, already clamped.
    pub superseded_by: Vec<String>,
}

/// Timeline response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreMemoryTimelineResponse {
    /// Hex anchor entity id.
    #[serde(rename = "anchor_id")]
    pub anchor_id: String,
    /// Ordered timeline records.
    pub records: Vec<CoreMemoryTimelineRecord>,
}

/// M8-reserved ask request payload. Opaque on purpose.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AskRequest(pub Value);

/// M8-reserved ask response payload. Opaque on purpose.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AskResponse(pub Value);

/// M8-reserved code-search request payload. Opaque on purpose.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CodeSearchRequest(pub Value);

/// M8-reserved code-search response payload. Opaque on purpose.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CodeSearchResponse(pub Value);

/// M8-reserved code-execute request payload. Opaque on purpose.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CodeExecuteRequest(pub Value);

/// M8-reserved code-execute response payload. Opaque on purpose.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CodeExecuteResponse(pub Value);

// ─── Accepted request validation ─────────────────────────────────────────────

fn non_empty_query(query: Option<&str>) -> Option<&str> {
    query.map(str::trim).filter(|query| !query.is_empty())
}

fn validate_query_seeds(
    method: VaultReadMethod,
    query: Option<&str>,
    vector: Option<&[f32]>,
) -> VaultReadResult<()> {
    if non_empty_query(query).is_none() && vector.is_none() {
        return Err(invalid_request(
            method,
            "query",
            "query or query_vector is required",
        ));
    }
    if vector.is_some_and(|vector| vector.iter().any(|value| !value.is_finite())) {
        return Err(invalid_request(
            method,
            "query_vector",
            "query_vector values must be finite",
        ));
    }
    Ok(())
}

fn validate_context_pack_request(request: &CoreContextPackRequest) -> VaultReadResult<()> {
    const METHOD: VaultReadMethod = VaultReadMethod::ContextPack;

    validate_query_seeds(
        METHOD,
        request.query.as_deref(),
        request.query_vector.as_deref(),
    )?;
    let depth = request.resolved_depth();
    if depth.edge_hop.is_some_and(|hop| hop > MAX_EDGE_HOP) {
        return Err(invalid_request(
            METHOD,
            request.edge_hop_field(),
            &format!("edge_hop must be less than or equal to {MAX_EDGE_HOP}"),
        ));
    }
    if depth
        .max_neighbors
        .is_some_and(|neighbors| neighbors > MAX_CONTEXT_NEIGHBORS)
    {
        return Err(invalid_request(
            METHOD,
            request.max_neighbors_field(),
            &format!("max_neighbors must be less than or equal to {MAX_CONTEXT_NEIGHBORS}"),
        ));
    }
    if request
        .budget
        .as_ref()
        .and_then(|budget| budget.retrieval.as_ref())
        .and_then(|retrieval| retrieval.selected_edges)
        .is_some_and(|edges| edges > MAX_CONTEXT_NEIGHBORS)
    {
        return Err(invalid_request(
            METHOD,
            "budget.retrieval.selected_edges",
            &format!("selected_edges must be less than or equal to {MAX_CONTEXT_NEIGHBORS}"),
        ));
    }
    Ok(())
}

fn validate_batch_request(request: &CoreBatchShortIdHydrateRequest) -> VaultReadResult<()> {
    const METHOD: VaultReadMethod = VaultReadMethod::HydrateMany;

    if request.refs.is_empty() {
        return Err(invalid_request(METHOD, "refs", "refs must not be empty"));
    }
    if request.refs.len() > VAULT_READ_MAX_BATCH_REFS {
        return Err(invalid_request(
            METHOD,
            "refs",
            &format!("refs must contain at most {VAULT_READ_MAX_BATCH_REFS} entries"),
        ));
    }
    Ok(())
}

fn parse_timeline_anchor(request: &CoreMemoryTimelineRequest) -> VaultReadResult<EntityId> {
    EntityId::from_hex(&request.id).map_err(|_| {
        invalid_request(
            VaultReadMethod::MemoryTimeline,
            "id",
            "id must be a hex entity id",
        )
    })
}

fn parse_short_ref_parts(
    method: VaultReadMethod,
    short_id: &str,
    content_hash: &str,
) -> VaultReadResult<(String, u8)> {
    if parse_presentation_id(short_id).is_err() {
        return Err(invalid_request(
            method,
            "short_id",
            "short_id must be at least two lowercase letters followed by decimal digits",
        ));
    }
    if content_hash.len() != 2 || !content_hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid_request(
            method,
            "content_hash",
            "content_hash must be exactly two hex digits",
        ));
    }
    let content_hash = u8::from_str_radix(content_hash, 16)
        .map_err(|_| invalid_request(method, "content_hash", "content_hash must be hex"))?;
    Ok((short_id.to_owned(), content_hash))
}

fn parse_short_ref(method: VaultReadMethod, reference: &str) -> VaultReadResult<(String, u8)> {
    let Some((short_id, content_hash)) = reference.split_once(':') else {
        return Err(invalid_request(
            method,
            "ref",
            "ref must be in shortId:contentHashHex form",
        ));
    };
    parse_short_ref_parts(method, short_id, content_hash)
}

fn parse_short_ref_request(request: &CoreHydrateRequest) -> VaultReadResult<(String, u8)> {
    const METHOD: VaultReadMethod = VaultReadMethod::Hydrate;

    if let Some(reference) = request.reference.as_deref() {
        return parse_short_ref(METHOD, reference);
    }
    let Some(short_id) = request.short_id.as_deref() else {
        return Err(invalid_request(
            METHOD,
            "ref",
            "ref or short_id/content_hash is required",
        ));
    };
    let Some(content_hash) = request.content_hash.as_deref() else {
        return Err(invalid_request(
            METHOD,
            "content_hash",
            "ref or short_id/content_hash is required",
        ));
    };
    parse_short_ref_parts(METHOD, short_id, content_hash)
}

/// The one validation door. It mirrors accepted route semantics only; no
/// client-only rule is added here.
fn validate_request(
    request: VaultReadRequest,
) -> VaultReadResult<sealed::ValidatedVaultReadRequest> {
    match &request {
        VaultReadRequest::Query(query) => validate_query_seeds(
            VaultReadMethod::Query,
            query.query.as_deref(),
            query.query_vector.as_deref(),
        )?,
        VaultReadRequest::ContextPack(pack) => validate_context_pack_request(pack)?,
        VaultReadRequest::Hydrate(hydrate) => {
            parse_short_ref_request(hydrate)?;
        }
        VaultReadRequest::HydrateMany(batch) => validate_batch_request(batch)?,
        VaultReadRequest::MemoryTimeline(timeline) => {
            parse_timeline_anchor(timeline)?;
        }
        VaultReadRequest::Ask(_)
        | VaultReadRequest::CodeSearch(_)
        | VaultReadRequest::CodeExecute(_) => {}
    }
    Ok(sealed::ValidatedVaultReadRequest(request))
}

// ─── One validated dispatch path ─────────────────────────────────────────────

pub(crate) mod sealed {
    use super::{VaultReadRequest, VaultReadResponse, VaultReadResult};

    /// A request that has already passed the accepted-route validation door.
    /// Backends can only ever receive one of these.
    #[derive(Debug)]
    pub(crate) struct ValidatedVaultReadRequest(pub(super) VaultReadRequest);

    impl ValidatedVaultReadRequest {
        pub(super) fn into_inner(self) -> VaultReadRequest {
            self.0
        }
    }

    /// The sealed adapter seam. Implemented only by this module's three
    /// adapters; hosts inject behavior through `WireTransport` instead.
    pub(crate) trait Backend: Send + Sync {
        fn dispatch_validated(
            &self,
            request: ValidatedVaultReadRequest,
        ) -> VaultReadResult<VaultReadResponse>;
    }
}

/// Validation runs once, before any adapter code. Runtime peers stop here,
/// before validation, backend, or transport work.
fn validate_and_dispatch<B>(
    backend: &B,
    request: VaultReadRequest,
) -> VaultReadResult<VaultReadResponse>
where
    B: sealed::Backend + ?Sized,
{
    let method = request.method();
    if matches!(
        method.availability(),
        VaultReadAvailability::RuntimeDeferred
    ) {
        return Err(VaultReadError::RuntimeUnavailable { method });
    }
    let validated = validate_request(request)?;
    backend.dispatch_validated(validated)
}

impl<T: sealed::Backend + ?Sized> VaultReadClient for T {}

// ─── Projection helpers ──────────────────────────────────────────────────────

/// Decodes already-clamped entity bytes into the public JSON projection.
fn decode_scoped_body(method: VaultReadMethod, body: &[u8]) -> VaultReadResult<Value> {
    let mut cursor = Cursor::new(body);
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| engine_corruption(method, "entity body is not valid MessagePack"))?;
    if cursor.position() != body.len() as u64 {
        return Err(engine_corruption(
            method,
            "trailing bytes after entity body",
        ));
    }
    Ok(companion_value_to_json(&value))
}

fn entity_record_from_parts(
    method: VaultReadMethod,
    id: &EntityId,
    entity_type: u8,
    learned_at: u64,
    score: Option<f32>,
    body: &[u8],
    view: View,
) -> VaultReadResult<CoreEntityRecord> {
    let body = match view {
        View::Standard => None,
        View::Summary | View::Full => Some(decode_scoped_body(method, body)?),
    };
    Ok(CoreEntityRecord {
        id: id.to_hex(),
        entity_type,
        learned_at,
        score,
        body,
    })
}

fn project_signal(signal: Signal) -> CoreContextPackSignal {
    match signal {
        Signal::Vector => CoreContextPackSignal::Vector,
        Signal::Text => CoreContextPackSignal::Text,
        Signal::Phonetic => CoreContextPackSignal::Phonetic,
        Signal::Temporal => CoreContextPackSignal::Temporal,
        Signal::Ppr => CoreContextPackSignal::Ppr,
        Signal::Hyde => CoreContextPackSignal::Hyde,
    }
}

fn project_accounting(accounting: PackItemAccounting) -> CoreContextPackAccounting {
    CoreContextPackAccounting {
        count: accounting.count,
        reason: match accounting.reason {
            PackItemAccountingReason::ItemBudget => CoreContextPackAccountingReason::ItemBudget,
            PackItemAccountingReason::TokenBudget => CoreContextPackAccountingReason::TokenBudget,
        },
    }
}

fn project_token_stats(tokens: &PackTokenStats) -> CoreContextPackTokenStats {
    CoreContextPackTokenStats {
        tokenizer_id: tokens.tokenizer_id.clone(),
        total_tokens: tokens.total_tokens,
        sections: tokens
            .sections
            .iter()
            .map(|section| CoreContextPackSectionTokenStats {
                section: section.section.clone(),
                tokens: section.tokens,
            })
            .collect(),
        items: tokens
            .items
            .iter()
            .map(|item| CoreContextPackItemTokenStats {
                section: item.section.clone(),
                id: item.id.clone(),
                entity_type: item.entity_type,
                tokens: item.tokens,
            })
            .collect(),
    }
}

fn project_pack_stats(stats: &PackStats) -> CoreContextPackStats {
    CoreContextPackStats {
        candidates_considered: stats.candidates_considered,
        signals_used: stats
            .signals_used
            .iter()
            .copied()
            .map(project_signal)
            .collect(),
        query_time_us: stats.query_time_us,
        entities_hydrated: stats.entities_hydrated,
        neighbors_hydrated: stats.neighbors_hydrated,
        cosine_ghosts_dampened: stats.cosine_ghosts_dampened,
        claims_suppressed: stats.claims_suppressed,
        tokens: project_token_stats(&stats.tokens),
        items_truncated: project_accounting(stats.items_truncated),
        items_dropped: project_accounting(stats.items_dropped),
    }
}

fn project_context_edge(edge: &EdgeInfo) -> CoreContextPackEdgeRecord {
    CoreContextPackEdgeRecord {
        kind: edge.kind as u8,
        target: edge.target.to_hex(),
        target_short_id: edge.target_short_id.clone(),
        weight: edge.weight,
        created_at: edge.created_at,
        vad: edge.vad.map(|vad| CoreContextPackVad {
            valence: vad.valence,
            arousal: vad.arousal,
            dominance: vad.dominance,
        }),
        provenance: edge.provenance.map(|flags| CoreContextPackEdgeProvenance {
            confirmation_status: flags.confirmation_status as u8,
            actor_class: flags.actor_class as u8,
        }),
    }
}

fn project_context_entity(entity: &ContextEntity) -> CoreContextPackEntityRecord {
    CoreContextPackEntityRecord {
        id: entity.id.to_hex(),
        short_id: entity.short_id.clone(),
        content_hash: entity.content_hash,
        entity_type: entity.entity_type,
        score: entity.score,
        fields: entity.fields.as_ref().map(|fields| {
            fields
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect()
        }),
        edges: entity
            .edges
            .as_ref()
            .map(|edges| edges.iter().map(project_context_edge).collect()),
        vector: entity.vector.clone(),
    }
}

fn project_empty_context(empty: &EmptyContext) -> CoreContextPackEmpty {
    CoreContextPackEmpty {
        reason: match empty.reason {
            EmptyReason::FilterMatchedNone => CoreContextPackEmptyReason::FilterMatchedNone,
            EmptyReason::NoData => CoreContextPackEmptyReason::NoData,
            EmptyReason::AllActivated => CoreContextPackEmptyReason::AllActivated,
            EmptyReason::BelowThreshold => CoreContextPackEmptyReason::BelowThreshold,
        },
        total_in_scope: empty.total_in_scope,
        hint: empty.hint.clone(),
    }
}

/// Consumes the already-filtered pack and copies every public field into the
/// local serializable projection. No facade helper is involved.
fn project_context_pack(pack: &ContextPack) -> CoreContextPackProjection {
    CoreContextPackProjection {
        results: pack.results.iter().map(project_context_entity).collect(),
        neighbors: pack.neighbors.iter().map(project_context_entity).collect(),
        stats: project_pack_stats(&pack.stats),
        empty: pack.empty.as_ref().map(project_empty_context),
    }
}

fn project_timeline_record(record: &MemoryTimelineRecord) -> CoreMemoryTimelineRecord {
    CoreMemoryTimelineRecord {
        id: record.id.to_hex(),
        state: record.state,
        entity_type: record.entity_type,
        occurred_start: record.occurred_start,
        occurred_end: record.occurred_end,
        learned_at: record.learned_at,
        body_bytes: record.body_bytes,
        deletion: record.deletion.clone(),
        supersedes: record.supersedes.iter().map(EntityId::to_hex).collect(),
        superseded_by: record.superseded_by.iter().map(EntityId::to_hex).collect(),
    }
}

fn project_memory_timeline(timeline: &MemoryTimeline) -> CoreMemoryTimelineResponse {
    CoreMemoryTimelineResponse {
        anchor_id: timeline.anchor.to_hex(),
        records: timeline
            .records
            .iter()
            .map(project_timeline_record)
            .collect(),
    }
}

/// Accepted timeline absence predicate: no records at all, or exactly one
/// `Missing` record.
fn timeline_is_absent(timeline: &MemoryTimeline) -> bool {
    timeline.records.is_empty()
        || matches!(
            timeline.records.as_slice(),
            [record] if record.state == MemoryTimelineRecordState::Missing
        )
}

/// Narrow batch absence conversion: only accepted-route absence becomes a
/// per-item `NotFound`. Every other failure aborts the whole batch call.
fn batch_item_from_result(
    reference: String,
    result: VaultReadResult<CoreHydrateResponse>,
) -> VaultReadResult<CoreBatchShortIdHydrateItem> {
    match result {
        Ok(response) => {
            let outcome = match response.status {
                CoreHydrateStatus::Live => CoreShortIdHydrateOutcome::Live,
                CoreHydrateStatus::Deleted => CoreShortIdHydrateOutcome::Deleted,
            };
            Ok(CoreBatchShortIdHydrateItem {
                reference,
                outcome,
                result: Some(response),
            })
        }
        Err(VaultReadError::Engine { engine_code, .. }) if engine_code == NOT_FOUND_ENGINE_CODE => {
            Ok(CoreBatchShortIdHydrateItem {
                reference,
                outcome: CoreShortIdHydrateOutcome::NotFound,
                result: None,
            })
        }
        Err(other) => Err(other),
    }
}

// ─── In-process adapter ──────────────────────────────────────────────────────

/// Embedded-host adapter. It stores a [`ScopedRead`], never a naked vault
/// convenience client: proximity to `Vault` is never authority.
pub struct InProcessVaultReadAdapter<'v> {
    scoped_read: ScopedRead<'v>,
}

impl<'v> InProcessVaultReadAdapter<'v> {
    /// The ONLY constructor: an actor key is mandatory, so no unkeyed bulk read
    /// handle can be built from this type.
    #[must_use]
    pub fn new(vault: &'v Vault, actor_key: ScopedReadActorKey) -> Self {
        Self {
            scoped_read: vault.scoped_read(actor_key),
        }
    }

    fn run_query(
        &self,
        query: Option<&str>,
        vector: Option<&[f32]>,
        limit: usize,
    ) -> VaultReadResult<Vec<ScoredEntity>> {
        let results = match (query, vector) {
            (Some(query), Some(vector)) => self.scoped_read.search(query, vector, limit),
            (Some(query), None) => self.scoped_read.search_text(query, limit),
            (None, Some(vector)) => self.scoped_read.search_vector(vector, limit),
            (None, None) => Ok(Vec::new()),
        };
        results.map_err(|error| engine_failure(VaultReadMethod::Query, &error))
    }

    fn query_op(&self, request: &CoreQueryRequest) -> VaultReadResult<CoreQueryResponse> {
        const METHOD: VaultReadMethod = VaultReadMethod::Query;

        let view = request.view.unwrap_or(View::Summary);
        let count_mode = request.count_mode.for_search_response();
        let fetch_limit = search_fetch_limit(count_mode, request.limit);
        let admitted = self.run_query(
            non_empty_query(request.query.as_deref()),
            request.query_vector.as_deref(),
            fetch_limit,
        )?;
        let total = admitted.len();
        let mut items = Vec::with_capacity(total.min(request.limit));
        for result in admitted {
            if items.len() >= request.limit {
                break;
            }
            let parts = self
                .scoped_read
                .get_entity_parts(&result.id)
                .map_err(|error| engine_failure(METHOD, &error))?;
            let Some((entity_type, learned_at, body)) = parts else {
                continue;
            };
            items.push(entity_record_from_parts(
                METHOD,
                &result.id,
                entity_type,
                learned_at,
                Some(result.score),
                &body,
                view,
            )?);
        }
        Ok(CoreQueryResponse {
            items,
            next_cursor: None,
            meta: CoreQueryMeta {
                total: search_total(count_mode, total),
                count_mode,
            },
        })
    }

    fn context_pack_op(
        &self,
        request: &CoreContextPackRequest,
    ) -> VaultReadResult<CoreContextPackResponse> {
        const METHOD: VaultReadMethod = VaultReadMethod::ContextPack;

        let query = non_empty_query(request.query.as_deref());
        let vector = request.query_vector.as_deref();
        let depth = request.resolved_depth();
        let edge_hop = depth.edge_hop.unwrap_or(0);
        let max_neighbors = depth.max_neighbors.unwrap_or(DEFAULT_MAX_NEIGHBORS);
        let candidate_limit = self
            .scoped_read
            .search_candidate_limit(request.limit, query.is_some(), vector.is_some())
            .map_err(|error| engine_failure(METHOD, &error))?;
        let mut builder = self
            .scoped_read
            .vault()
            .context_pack()
            .limit(candidate_limit)
            .hydrate(true)
            .include_edges(false)
            .include_vectors(false)
            .edge_hop(edge_hop)
            .max_neighbors(max_neighbors)
            .field_profile(FieldProfile::Standard);
        if let Some(query) = query {
            builder = builder.search_text(query, candidate_limit);
        }
        if let Some(vector) = vector {
            builder = builder.search_vector(vector, candidate_limit);
        }
        let (builder, response_budget) = apply_budget_controls(
            builder,
            request.budget.as_ref(),
            candidate_limit,
            request.limit,
            max_neighbors,
        );

        // UNFINALIZED on purpose (ONE-1433 X1): the assembly registers only a
        // PROVISIONAL retrieval-run row here and publishes nothing until every
        // filter below has run. Finalizing first — what `run()` does — would
        // commit the PRE-filter result ids, score components and trace
        // candidacy of entities this actor may not see into the durable
        // telemetry ledger, where `Vault::retrieval_runs` publishes them. This
        // mirrors the accepted route's `run_context_pack_builder`.
        let mut pack = builder
            .run_unfinalized_with_telemetry()
            .map_err(|error| engine_failure(METHOD, &error))?;
        // Re-clamp immediately: the builder was entered through the accepted
        // door, and nothing leaves this method unfiltered. A failed filter
        // discards the provisional row before the error returns, so a refused
        // read leaves no residue behind it.
        self.scoped_read
            .filter_context_pack(&mut pack.value)
            .map_err(|error| {
                pack.discard_telemetry();
                engine_failure(METHOD, &error)
            })?;
        // The widened budget only ever fed retrieval, so the answered pack is
        // bound by the UNWIDENED response budget after filtering, exactly like
        // the accepted route's `apply_context_pack_response_limits`.
        apply_context_pack_response_retrieval_budget(&mut pack.value, response_budget);
        pack.value.results.truncate(request.limit);
        pack.value.neighbors.truncate(max_neighbors);
        scrub_context_pack_visible_stats(&mut pack.value);
        // Publish LAST, off the post-filter, post-truncate pack: the durable
        // run row then carries exactly the ids this actor received, so a
        // denied entity is as absent from telemetry as it is from the
        // response. Finalize failure still fails the read, as it did through
        // `run()`.
        let pack = pack
            .finish_post_filter()
            .map_err(|error| engine_failure(METHOD, &error))?;
        Ok(CoreContextPackResponse(project_context_pack(&pack.value)))
    }

    /// Hydrates ONE short ref for `method` — the CALLING method, which is the
    /// identity every error this helper mints must carry. A batch item is
    /// served by the same code as a single hydrate, but an error that aborts
    /// the batch is an error of `HydrateMany`, so the identity is a parameter
    /// rather than a constant pinned to the single-ref method.
    fn hydrate_ref(
        &self,
        method: VaultReadMethod,
        short_id: String,
        content_hash: u8,
        view: View,
    ) -> VaultReadResult<CoreHydrateResponse> {
        let hydrated = self
            .scoped_read
            .hydrate_short_id(&short_id, content_hash)
            .map_err(|error| engine_failure(method, &error))?;
        // A missing row and a clamp-denied claim are the SAME answer here. The
        // adapter never probes the naked vault to tell them apart.
        let Some(HydratedShortId {
            id,
            entity_type,
            learned_at,
            deletion,
            body,
        }) = hydrated
        else {
            return Err(engine_absent(method, "short_id"));
        };
        let content_hash = format!("{content_hash:02x}");
        let Some(body) = body else {
            return Ok(CoreHydrateResponse {
                status: CoreHydrateStatus::Deleted,
                short_id,
                content_hash,
                id: Some(id.to_hex()),
                entity_type: (entity_type != 0).then_some(entity_type),
                deletion,
                item: None,
            });
        };
        let item =
            entity_record_from_parts(method, &id, entity_type, learned_at, None, &body, view)?;
        Ok(CoreHydrateResponse {
            status: CoreHydrateStatus::Live,
            short_id,
            content_hash,
            id: Some(id.to_hex()),
            entity_type: Some(entity_type),
            deletion: None,
            item: Some(item),
        })
    }

    fn hydrate_op(&self, request: &CoreHydrateRequest) -> VaultReadResult<CoreHydrateResponse> {
        let (short_id, content_hash) = parse_short_ref_request(request)?;
        self.hydrate_ref(
            VaultReadMethod::Hydrate,
            short_id,
            content_hash,
            request.view.unwrap_or(View::Full),
        )
    }

    fn hydrate_batch_item(
        &self,
        reference: &str,
        view: View,
    ) -> VaultReadResult<CoreBatchShortIdHydrateItem> {
        const METHOD: VaultReadMethod = VaultReadMethod::HydrateMany;

        let Ok((short_id, content_hash)) = parse_short_ref(METHOD, reference) else {
            return Ok(CoreBatchShortIdHydrateItem {
                reference: reference.to_owned(),
                outcome: CoreShortIdHydrateOutcome::MalformedShortId,
                result: None,
            });
        };
        batch_item_from_result(
            reference.to_owned(),
            self.hydrate_ref(METHOD, short_id, content_hash, view),
        )
    }

    fn hydrate_many_op(
        &self,
        request: &CoreBatchShortIdHydrateRequest,
    ) -> VaultReadResult<CoreBatchShortIdHydrateResponse> {
        let view = request.view.unwrap_or(View::Full);
        let mut results = Vec::with_capacity(request.refs.len());
        for reference in &request.refs {
            results.push(self.hydrate_batch_item(reference, view)?);
        }
        Ok(CoreBatchShortIdHydrateResponse { results })
    }

    fn memory_timeline_op(
        &self,
        request: &CoreMemoryTimelineRequest,
    ) -> VaultReadResult<CoreMemoryTimelineResponse> {
        const METHOD: VaultReadMethod = VaultReadMethod::MemoryTimeline;

        let anchor = parse_timeline_anchor(request)?;
        let timeline = self
            .scoped_read
            .memory_timeline(&anchor)
            .map_err(|error| engine_failure(METHOD, &error))?;
        if timeline_is_absent(&timeline) {
            return Err(engine_absent(METHOD, "entity"));
        }
        Ok(project_memory_timeline(&timeline))
    }
}

/// Mirrors the accepted route's budget application: the WIDENED internal
/// retrieval budget goes on the builder so it survives scoped-read clamping,
/// and the UNWIDENED response budget is returned to bind the answered pack.
fn apply_budget_controls<'a>(
    mut builder: ContextPackBuilder<'a>,
    budget: Option<&ContextPackBudgetControls>,
    candidate_limit: usize,
    result_limit: usize,
    default_selected_edges: usize,
) -> (ContextPackBuilder<'a>, ContextPackRetrievalBudget) {
    if let Some(controls) = budget {
        if let Some(max_item_tokens) = controls.max_item_tokens
            && max_item_tokens > 0
        {
            builder = builder.max_item_tokens(max_item_tokens);
        }
        if let Some(token_budget) = controls.token_budget {
            builder = builder.token_budget(token_budget);
        }
        if let Some(max_field_chars) = controls.max_field_chars {
            builder = builder.max_field_chars(max_field_chars);
        }
    }
    let retrieval = budget.and_then(|controls| controls.retrieval.as_ref());
    let response_budget = resolve_retrieval_budget(retrieval, result_limit, default_selected_edges);
    let builder =
        builder.retrieval_budget(widen_retrieval_budget(response_budget, candidate_limit));
    (builder, response_budget)
}

/// Accepted per-kind response budget, copied from the accepted route's
/// `apply_context_pack_response_retrieval_budget`: each retrieval kind keeps at
/// most its own unwidened item budget, in pack order.
fn apply_context_pack_response_retrieval_budget(
    pack: &mut ContextPack,
    budget: ContextPackRetrievalBudget,
) {
    let mut claims = 0_usize;
    let mut turns = 0_usize;
    let mut summaries = 0_usize;
    let mut facets = 0_usize;
    let mut other = 0_usize;
    pack.results.retain(|entity| {
        let (count, limit) = match entity.entity_type {
            ENTITY_TYPE_CLAIM => (&mut claims, budget.claims),
            ENTITY_TYPE_TURN => (&mut turns, budget.turns),
            ENTITY_TYPE_SUMMARY => (&mut summaries, budget.summaries),
            ENTITY_TYPE_FACET => (&mut facets, budget.facets),
            _ => (&mut other, budget.other),
        };
        if *count >= limit {
            return false;
        }
        *count += 1;
        true
    });
}

/// Accepted visible-stat scrub, copied from the accepted route's
/// `scrub_context_pack_visible_stats`: the counters a caller can see describe
/// the pack it actually received, never the wider internal retrieval.
fn scrub_context_pack_visible_stats(pack: &mut ContextPack) {
    pack.stats.candidates_considered = pack.results.len();
    pack.stats.entities_hydrated = pack.results.len();
    pack.stats.neighbors_hydrated = pack.neighbors.len();

    if pack.results.is_empty() && pack.neighbors.is_empty() {
        if let Some(empty) = pack.empty.as_mut() {
            empty.total_in_scope = 0;
        } else {
            pack.empty = Some(EmptyContext {
                reason: EmptyReason::FilterMatchedNone,
                total_in_scope: 0,
                hint: "Try removing filters or widening the world, type, or time scope".to_owned(),
            });
        }
    } else {
        pack.empty = None;
    }
}

fn resolve_retrieval_budget(
    retrieval: Option<&ContextPackRetrievalBudgetControls>,
    result_limit: usize,
    default_selected_edges: usize,
) -> ContextPackRetrievalBudget {
    let selected_edges = retrieval
        .and_then(|retrieval| retrieval.selected_edges)
        .unwrap_or(default_selected_edges);
    let mut budget = ContextPackRetrievalBudget::from_limit(
        result_limit,
        TokenAllocation::default(),
        selected_edges,
    );
    if let Some(retrieval) = retrieval {
        budget.claims = retrieval.claims.unwrap_or(budget.claims);
        budget.turns = retrieval.turns.unwrap_or(budget.turns);
        budget.summaries = retrieval.summaries.unwrap_or(budget.summaries);
        budget.facets = retrieval.facets.unwrap_or(budget.facets);
        budget.other = retrieval.other.unwrap_or(budget.other);
    }
    budget
}

fn widen_retrieval_budget(
    budget: ContextPackRetrievalBudget,
    candidate_limit: usize,
) -> ContextPackRetrievalBudget {
    let widen = |bucket: usize| {
        if bucket == 0 {
            0
        } else {
            bucket.max(candidate_limit)
        }
    };
    ContextPackRetrievalBudget::new(
        widen(budget.claims),
        widen(budget.turns),
        widen(budget.summaries),
        widen(budget.facets),
        widen(budget.other),
        budget.selected_edges,
    )
}

impl sealed::Backend for InProcessVaultReadAdapter<'_> {
    fn dispatch_validated(
        &self,
        request: sealed::ValidatedVaultReadRequest,
    ) -> VaultReadResult<VaultReadResponse> {
        match request.into_inner() {
            VaultReadRequest::Query(request) => {
                self.query_op(&request).map(VaultReadResponse::Query)
            }
            VaultReadRequest::ContextPack(request) => self
                .context_pack_op(&request)
                .map(VaultReadResponse::ContextPack),
            VaultReadRequest::Hydrate(request) => {
                self.hydrate_op(&request).map(VaultReadResponse::Hydrate)
            }
            VaultReadRequest::HydrateMany(request) => self
                .hydrate_many_op(&request)
                .map(VaultReadResponse::HydrateMany),
            VaultReadRequest::MemoryTimeline(request) => self
                .memory_timeline_op(&request)
                .map(VaultReadResponse::MemoryTimeline),
            // Unreachable through the generated wrappers, which refuse runtime
            // peers before validation; kept total and identical anyway.
            runtime => Err(VaultReadError::RuntimeUnavailable {
                method: runtime.method(),
            }),
        }
    }
}

// ─── Wire transport adapter ──────────────────────────────────────────────────

/// Host-injected transport seam. HTTP and MCP daemons implement this later; no
/// URL, socket, authentication, retry, or timeout code lives in this crate.
///
/// Authentication and actor binding belong to the transport's construction
/// context, never to guest-authored request fields.
pub trait WireTransport: Send + Sync {
    /// Sends one canonical request body for `op` and returns the response
    /// bytes, which must be a `{"ok": ...}` or `{"err": ...}` envelope.
    fn round_trip(&self, op: VaultReadWireOp, request_json: &[u8]) -> VaultReadResult<Vec<u8>>;
}

/// Transport-injected adapter used by HTTP or MCP daemons.
pub struct WireTransportVaultReadAdapter {
    transport: Arc<dyn WireTransport>,
}

impl WireTransportVaultReadAdapter {
    /// Binds the adapter to one injected transport.
    #[must_use]
    pub fn new(transport: Arc<dyn WireTransport>) -> Self {
        Self { transport }
    }
}

fn protocol_mismatch(method: VaultReadMethod, message: String) -> VaultReadError {
    VaultReadError::ProtocolMismatch { method, message }
}

/// Decodes the wire envelope. The key set must be EXACTLY `{ "ok" }` or exactly
/// `{ "err" }`; both keys, neither key, or any extra key is a protocol
/// mismatch before arm deserialization. A bare operation DTO is therefore
/// rejected too.
fn decode_wire_envelope(
    method: VaultReadMethod,
    op: VaultReadWireOp,
    bytes: &[u8],
) -> VaultReadResult<VaultReadResponse> {
    let envelope: serde_json::Map<String, Value> =
        serde_json::from_slice(bytes).map_err(|error| {
            protocol_mismatch(method, format!("response is not a JSON object: {error}"))
        })?;
    let has_ok = envelope.contains_key("ok");
    let has_err = envelope.contains_key("err");
    if envelope.len() != 1 || !(has_ok || has_err) {
        return Err(protocol_mismatch(
            method,
            format!(
                "response envelope must carry exactly one of \"ok\" or \"err\"; got {} key(s)",
                envelope.len()
            ),
        ));
    }
    if let Some(error) = envelope.get("err") {
        // Forwarded untranslated: the daemon's semantic variant is the answer.
        let error: VaultReadError = serde_json::from_value(error.clone()).map_err(|error| {
            protocol_mismatch(method, format!("err arm is not a VaultReadError: {error}"))
        })?;
        return Err(error);
    }
    let Some(ok) = envelope.get("ok") else {
        return Err(protocol_mismatch(method, "missing ok arm".to_owned()));
    };
    let response: VaultReadResponse = serde_json::from_value(ok.clone()).map_err(|error| {
        protocol_mismatch(method, format!("ok arm is not a tagged response: {error}"))
    })?;
    if response.wire_op() != op {
        return Err(response_arm_mismatch(method, response.wire_op()));
    }
    Ok(response)
}

impl sealed::Backend for WireTransportVaultReadAdapter {
    fn dispatch_validated(
        &self,
        request: sealed::ValidatedVaultReadRequest,
    ) -> VaultReadResult<VaultReadResponse> {
        let request = request.into_inner();
        let method = request.method();
        let op = request.wire_op();
        // The op is carried beside the body, so the body is the canonical
        // inner request DTO — never the tagged `{"op", "request"}` envelope.
        let body = request.canonical_body().map_err(|error| {
            protocol_mismatch(method, format!("request serialization failed: {error}"))
        })?;
        let bytes = self.transport.round_trip(op, &body)?;
        decode_wire_envelope(method, op, &bytes)
    }
}

// ─── Cloud adapter ───────────────────────────────────────────────────────────

/// Cloud placeholder exposing the identical Rust surface while cloud execution
/// remains unimplemented.
#[derive(Debug, Default, Clone, Copy)]
pub struct CloudVaultReadAdapter;

impl sealed::Backend for CloudVaultReadAdapter {
    fn dispatch_validated(
        &self,
        request: sealed::ValidatedVaultReadRequest,
    ) -> VaultReadResult<VaultReadResponse> {
        // Runtime peers never arrive here: their absence is runtime-wide, not
        // cloud-specific, so the shared wrapper answers them first.
        Err(VaultReadError::Unimplemented {
            adapter: VaultReadAdapterKind::Cloud,
            method: request.into_inner().method(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use rmpv::Value as MsgpackValue;
    use serde_json::json;

    use crate::claim::ClaimSubject;
    use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource};
    use crate::registry::ENTITY_TYPE_PERSON;
    use crate::store::{RetrievalAction, RetrievalRunRecord};
    use crate::temporal::TimeRange;
    use crate::test_util::{
        embedding_test_config, entity, open_test_vault_with, put_policy_manifest_bytes,
    };

    // ── Test doubles ────────────────────────────────────────────────────────

    /// Backend that records every dispatched request and answers with a canned
    /// response for the requested method.
    #[derive(Default)]
    struct RecordingBackend {
        dispatched: Mutex<Vec<VaultReadRequest>>,
    }

    impl RecordingBackend {
        fn calls(&self) -> usize {
            self.dispatched
                .lock()
                .expect("recording backend lock")
                .len()
        }

        fn last(&self) -> Option<VaultReadRequest> {
            self.dispatched
                .lock()
                .expect("recording backend lock")
                .last()
                .cloned()
        }
    }

    impl sealed::Backend for RecordingBackend {
        fn dispatch_validated(
            &self,
            request: sealed::ValidatedVaultReadRequest,
        ) -> VaultReadResult<VaultReadResponse> {
            let request = request.into_inner();
            let method = request.method();
            self.dispatched
                .lock()
                .expect("recording backend lock")
                .push(request);
            Ok(canned_response(method))
        }
    }

    /// Transport that records the ops it was asked for and replays one scripted
    /// reply.
    struct ScriptedTransport {
        ops: Mutex<Vec<VaultReadWireOp>>,
        reply: Vec<u8>,
    }

    impl ScriptedTransport {
        fn new(reply: Vec<u8>) -> Arc<Self> {
            Arc::new(Self {
                ops: Mutex::new(Vec::new()),
                reply,
            })
        }

        fn ops(&self) -> Vec<VaultReadWireOp> {
            self.ops.lock().expect("transport lock").clone()
        }
    }

    impl WireTransport for ScriptedTransport {
        fn round_trip(
            &self,
            op: VaultReadWireOp,
            _request_json: &[u8],
        ) -> VaultReadResult<Vec<u8>> {
            self.ops.lock().expect("transport lock").push(op);
            Ok(self.reply.clone())
        }
    }

    /// Transport that records the exact canonical body bytes it was handed,
    /// beside the op they were sent under.
    struct BodyRecordingTransport {
        bodies: Mutex<Vec<(VaultReadWireOp, Vec<u8>)>>,
        reply: Vec<u8>,
    }

    impl BodyRecordingTransport {
        fn new(reply: Vec<u8>) -> Arc<Self> {
            Arc::new(Self {
                bodies: Mutex::new(Vec::new()),
                reply,
            })
        }

        fn bodies(&self) -> Vec<(VaultReadWireOp, Vec<u8>)> {
            self.bodies.lock().expect("transport lock").clone()
        }
    }

    impl WireTransport for BodyRecordingTransport {
        fn round_trip(&self, op: VaultReadWireOp, request_json: &[u8]) -> VaultReadResult<Vec<u8>> {
            self.bodies
                .lock()
                .expect("transport lock")
                .push((op, request_json.to_vec()));
            Ok(self.reply.clone())
        }
    }

    fn wire_adapter(reply: Value) -> (Arc<ScriptedTransport>, WireTransportVaultReadAdapter) {
        let transport =
            ScriptedTransport::new(serde_json::to_vec(&reply).expect("scripted reply serializes"));
        let adapter = WireTransportVaultReadAdapter::new(transport.clone());
        (transport, adapter)
    }

    fn empty_projection() -> CoreContextPackProjection {
        CoreContextPackProjection {
            results: Vec::new(),
            neighbors: Vec::new(),
            stats: CoreContextPackStats {
                candidates_considered: 0,
                signals_used: Vec::new(),
                query_time_us: 0,
                entities_hydrated: 0,
                neighbors_hydrated: 0,
                cosine_ghosts_dampened: 0,
                claims_suppressed: 0,
                tokens: CoreContextPackTokenStats {
                    tokenizer_id: String::new(),
                    total_tokens: 0,
                    sections: Vec::new(),
                    items: Vec::new(),
                },
                items_truncated: CoreContextPackAccounting {
                    count: 0,
                    reason: CoreContextPackAccountingReason::ItemBudget,
                },
                items_dropped: CoreContextPackAccounting {
                    count: 0,
                    reason: CoreContextPackAccountingReason::TokenBudget,
                },
            },
            empty: None,
        }
    }

    fn canned_response(method: VaultReadMethod) -> VaultReadResponse {
        match method {
            VaultReadMethod::Query => VaultReadResponse::Query(CoreQueryResponse {
                items: Vec::new(),
                next_cursor: None,
                meta: CoreQueryMeta {
                    total: 0,
                    count_mode: CountMode::Estimate,
                },
            }),
            VaultReadMethod::ContextPack => {
                VaultReadResponse::ContextPack(CoreContextPackResponse(empty_projection()))
            }
            VaultReadMethod::Hydrate => VaultReadResponse::Hydrate(hydrate_response()),
            VaultReadMethod::HydrateMany => {
                VaultReadResponse::HydrateMany(CoreBatchShortIdHydrateResponse {
                    results: Vec::new(),
                })
            }
            VaultReadMethod::MemoryTimeline => {
                VaultReadResponse::MemoryTimeline(CoreMemoryTimelineResponse {
                    anchor_id: String::new(),
                    records: Vec::new(),
                })
            }
            VaultReadMethod::Ask => VaultReadResponse::Ask(AskResponse(Value::Null)),
            VaultReadMethod::CodeSearch => {
                VaultReadResponse::CodeSearch(CodeSearchResponse(Value::Null))
            }
            VaultReadMethod::CodeExecute => {
                VaultReadResponse::CodeExecute(CodeExecuteResponse(Value::Null))
            }
        }
    }

    fn hydrate_response() -> CoreHydrateResponse {
        CoreHydrateResponse {
            status: CoreHydrateStatus::Live,
            short_id: "cl1".to_owned(),
            content_hash: "a7".to_owned(),
            id: Some("0123456789abcdef0123456789abcdef".to_owned()),
            entity_type: Some(0),
            deletion: None,
            item: None,
        }
    }

    fn query_request(query: &str) -> CoreQueryRequest {
        CoreQueryRequest {
            query: Some(query.to_owned()),
            query_vector: None,
            limit: default_limit(),
            view: None,
            count_mode: CountMode::default_estimate(),
        }
    }

    fn context_pack_request() -> CoreContextPackRequest {
        CoreContextPackRequest {
            query: None,
            query_vector: None,
            limit: default_limit(),
            depth: None,
            edge_hop: None,
            max_neighbors: None,
            budget: None,
        }
    }

    fn hydrate_request(reference: &str) -> CoreHydrateRequest {
        CoreHydrateRequest {
            reference: Some(reference.to_owned()),
            short_id: None,
            content_hash: None,
            view: None,
        }
    }

    fn msgpack_body(text: &str) -> Vec<u8> {
        let value = MsgpackValue::Map(vec![(MsgpackValue::from("txt"), MsgpackValue::from(text))]);
        let mut encoded = Vec::new();
        rmpv::encode::write_value(&mut encoded, &value).expect("body encodes");
        encoded
    }

    // ── 1. Contract table ───────────────────────────────────────────────────

    #[test]
    fn contract_table_is_bijective() {
        assert_eq!(VaultReadMethod::ALL.len(), VAULT_READ_METHOD_MAP.len());
        assert_eq!(VaultReadMethod::COUNT, 8);

        for method in VaultReadMethod::ALL {
            let rows = VAULT_READ_METHOD_MAP
                .iter()
                .filter(|row| row.method == method)
                .count();
            assert_eq!(rows, 1, "{method:?} must own exactly one contract row");
        }

        let mut ops: Vec<&str> = VAULT_READ_METHOD_MAP
            .iter()
            .map(|row| row.wire_op.as_str())
            .collect();
        ops.sort_unstable();
        ops.dedup();
        assert_eq!(ops.len(), VaultReadMethod::COUNT, "wire ops must be unique");

        for row in VAULT_READ_METHOD_MAP {
            assert_eq!(row.method.wire_op(), row.wire_op);
            assert_eq!(row.wire_op.method(), row.method);
            assert_eq!(row.method.availability(), row.availability);
        }

        let structured = VAULT_READ_METHOD_MAP
            .iter()
            .filter(|row| row.availability == VaultReadAvailability::StructuredRead)
            .count();
        let deferred = VAULT_READ_METHOD_MAP
            .iter()
            .filter(|row| row.availability == VaultReadAvailability::RuntimeDeferred)
            .count();
        assert_eq!(structured, 5);
        assert_eq!(deferred, 3);
    }

    // ── 2. Wire names ───────────────────────────────────────────────────────

    #[test]
    fn wire_names_are_pinned() {
        let pinned = [
            (VaultReadMethod::Query, "core.query"),
            (VaultReadMethod::ContextPack, "core.context_pack"),
            (VaultReadMethod::Hydrate, "core.hydrate"),
            (VaultReadMethod::HydrateMany, "core.batch_short_id_hydrate"),
            (VaultReadMethod::MemoryTimeline, "core.memory_timeline"),
            (VaultReadMethod::Ask, "runtime.ask"),
            (VaultReadMethod::CodeSearch, "runtime.code_search"),
            (VaultReadMethod::CodeExecute, "runtime.code_execute"),
        ];
        assert_eq!(pinned.len(), VaultReadMethod::COUNT);
        for (method, wire) in pinned {
            assert_eq!(method.wire_op().as_str(), wire);
            assert_eq!(
                serde_json::to_string(&method.wire_op()).expect("wire op serializes"),
                format!("\"{wire}\"")
            );
            assert!(
                !wire.contains("/api/") && !wire.contains('-') && !wire.contains('/'),
                "{wire} must not be a route alias"
            );
        }
    }

    // ── 3. Accepted validation runs before adapters ─────────────────────────

    #[test]
    fn missing_query_seeds_reject_before_backend() {
        let backend = RecordingBackend::default();
        let error = backend
            .query(CoreQueryRequest {
                query: Some("   ".to_owned()),
                query_vector: None,
                limit: default_limit(),
                view: None,
                count_mode: CountMode::Estimate,
            })
            .expect_err("blank seeds are rejected");
        assert_eq!(
            error,
            invalid_request(
                VaultReadMethod::Query,
                "query",
                "query or query_vector is required"
            )
        );
        assert_eq!(backend.calls(), 0);

        let error = backend
            .context_pack(context_pack_request())
            .expect_err("seedless context pack is rejected");
        assert!(matches!(
            error,
            VaultReadError::InvalidRequest { method, ref field, .. }
                if method == VaultReadMethod::ContextPack && field == "query"
        ));
        assert_eq!(backend.calls(), 0);
    }

    #[test]
    fn non_finite_vector_rejects_before_backend() {
        let backend = RecordingBackend::default();
        let mut request = query_request("blue hallway");
        request.query_vector = Some(vec![0.25, f32::NAN]);
        let error = backend.query(request).expect_err("non-finite vector");
        assert!(matches!(
            error,
            VaultReadError::InvalidRequest { method, ref field, .. }
                if method == VaultReadMethod::Query && field == "query_vector"
        ));
        assert_eq!(backend.calls(), 0);
    }

    #[test]
    fn invalid_hydrate_ref_and_parts_reject_before_backend() {
        let backend = RecordingBackend::default();
        let error = backend
            .hydrate(hydrate_request("no-colon"))
            .expect_err("malformed ref");
        assert!(matches!(
            error,
            VaultReadError::InvalidRequest { method, ref field, .. }
                if method == VaultReadMethod::Hydrate && field == "ref"
        ));

        let error = backend
            .hydrate(CoreHydrateRequest {
                reference: None,
                short_id: Some("cl1".to_owned()),
                content_hash: None,
                view: None,
            })
            .expect_err("short_id without content hash");
        assert!(matches!(
            error,
            VaultReadError::InvalidRequest { ref field, .. } if field == "content_hash"
        ));

        let error = backend
            .hydrate(CoreHydrateRequest {
                reference: None,
                short_id: Some("cl1".to_owned()),
                content_hash: Some("zz".to_owned()),
                view: None,
            })
            .expect_err("non-hex content hash");
        assert!(matches!(
            error,
            VaultReadError::InvalidRequest { ref field, .. } if field == "content_hash"
        ));
        assert_eq!(backend.calls(), 0);
    }

    #[test]
    fn empty_and_oversized_batch_reject_before_backend() {
        let backend = RecordingBackend::default();
        let error = backend
            .hydrate_many(CoreBatchShortIdHydrateRequest {
                refs: Vec::new(),
                view: None,
            })
            .expect_err("empty batch");
        assert!(matches!(
            error,
            VaultReadError::InvalidRequest { method, ref field, .. }
                if method == VaultReadMethod::HydrateMany && field == "refs"
        ));

        let refs = vec!["cl1:a7".to_owned(); VAULT_READ_MAX_BATCH_REFS + 1];
        let error = backend
            .hydrate_many(CoreBatchShortIdHydrateRequest { refs, view: None })
            .expect_err("oversized batch");
        assert!(matches!(
            error,
            VaultReadError::InvalidRequest { ref field, .. } if field == "refs"
        ));
        assert_eq!(backend.calls(), 0);
    }

    #[test]
    fn vector_only_context_pack_reaches_backend() {
        let backend = RecordingBackend::default();
        let mut request = context_pack_request();
        request.query_vector = Some(vec![0.25, 0.75]);
        backend
            .context_pack(request)
            .expect("vector-only context pack is accepted");
        assert_eq!(backend.calls(), 1);
        assert!(matches!(
            backend.last(),
            Some(VaultReadRequest::ContextPack(_))
        ));
    }

    #[test]
    fn nested_context_pack_depth_overrides_top_level() {
        let mut request = context_pack_request();
        request.query = Some("blue hallway".to_owned());
        request.edge_hop = Some(1);
        request.max_neighbors = Some(7);
        request.depth = Some(ContextPackDepthControls {
            edge_hop: Some(3),
            max_neighbors: None,
        });
        let depth = request.resolved_depth();
        assert_eq!(depth.edge_hop, Some(3), "nested depth wins");
        assert_eq!(depth.max_neighbors, Some(7), "absent nested field inherits");
        assert_eq!(request.edge_hop_field(), "depth.edge_hop");
        assert_eq!(request.max_neighbors_field(), "max_neighbors");

        request.depth = Some(ContextPackDepthControls {
            edge_hop: Some(MAX_EDGE_HOP + 1),
            max_neighbors: None,
        });
        let backend = RecordingBackend::default();
        let error = backend
            .context_pack(request)
            .expect_err("resolved depth is validated");
        assert!(matches!(
            error,
            VaultReadError::InvalidRequest { ref field, .. } if field == "depth.edge_hop"
        ));
        assert_eq!(backend.calls(), 0);
    }

    #[test]
    fn absent_nested_depth_inherits_top_level() {
        let mut request = context_pack_request();
        request.edge_hop = Some(2);
        request.max_neighbors = Some(11);
        request.depth = None;
        let depth = request.resolved_depth();
        assert_eq!(depth.edge_hop, Some(2));
        assert_eq!(depth.max_neighbors, Some(11));
        assert_eq!(request.edge_hop_field(), "edge_hop");
        assert_eq!(request.max_neighbors_field(), "max_neighbors");
    }

    #[test]
    fn recording_transport_sees_no_call_for_rejected_requests() {
        let (transport, adapter) = wire_adapter(json!({ "ok": null }));
        adapter
            .hydrate(hydrate_request("nope"))
            .expect_err("malformed ref rejected before transport");
        adapter
            .hydrate_many(CoreBatchShortIdHydrateRequest {
                refs: Vec::new(),
                view: None,
            })
            .expect_err("empty batch rejected before transport");
        adapter
            .memory_timeline(CoreMemoryTimelineRequest {
                id: "not-hex".to_owned(),
                view: None,
            })
            .expect_err("bad anchor rejected before transport");
        assert!(transport.ops().is_empty());
    }

    #[test]
    fn zero_limit_query_reaches_backend() {
        let backend = RecordingBackend::default();
        let mut request = query_request("blue hallway");
        request.limit = 0;
        backend.query(request).expect("zero limit is accepted");
        assert_eq!(backend.calls(), 1);
    }

    // ── 4. Response arm is operation-bound and exclusive ─────────────────────

    #[test]
    fn wrong_op_ok_envelope_is_protocol_mismatch() {
        let wrong_arm = VaultReadResponse::Hydrate(hydrate_response());
        let (transport, adapter) = wire_adapter(json!({ "ok": wrong_arm }));
        let error = adapter
            .query(query_request("blue hallway"))
            .expect_err("wrong op arm");
        assert!(matches!(
            error,
            VaultReadError::ProtocolMismatch { method, .. } if method == VaultReadMethod::Query
        ));
        assert_eq!(transport.ops(), vec![VaultReadWireOp::CoreQuery]);
    }

    #[test]
    fn bare_response_dto_is_protocol_mismatch() {
        let bare = CoreBatchShortIdHydrateResponse {
            results: Vec::new(),
        };
        let (_transport, adapter) = wire_adapter(serde_json::to_value(bare).expect("bare dto"));
        let error = adapter
            .hydrate_many(CoreBatchShortIdHydrateRequest {
                refs: vec!["cl1:a7".to_owned()],
                view: None,
            })
            .expect_err("bare dto is rejected");
        assert!(matches!(error, VaultReadError::ProtocolMismatch { .. }));
    }

    #[test]
    fn envelope_with_ok_and_err_is_protocol_mismatch() {
        let arm = VaultReadResponse::Query(CoreQueryResponse {
            items: Vec::new(),
            next_cursor: None,
            meta: CoreQueryMeta {
                total: 0,
                count_mode: CountMode::Estimate,
            },
        });
        let error = VaultReadError::RuntimeUnavailable {
            method: VaultReadMethod::Query,
        };
        let (_transport, adapter) = wire_adapter(json!({ "ok": arm, "err": error }));
        let error = adapter
            .query(query_request("blue hallway"))
            .expect_err("both keys");
        assert!(matches!(error, VaultReadError::ProtocolMismatch { .. }));
    }

    #[test]
    fn envelope_without_ok_or_err_is_protocol_mismatch() {
        let (_transport, adapter) = wire_adapter(json!({}));
        let error = adapter
            .query(query_request("blue hallway"))
            .expect_err("neither key");
        assert!(matches!(error, VaultReadError::ProtocolMismatch { .. }));
    }

    #[test]
    fn envelope_with_extra_key_is_protocol_mismatch() {
        let arm = VaultReadResponse::Query(CoreQueryResponse {
            items: Vec::new(),
            next_cursor: None,
            meta: CoreQueryMeta {
                total: 0,
                count_mode: CountMode::Estimate,
            },
        });
        let (_transport, adapter) = wire_adapter(json!({ "ok": arm, "trace": "extra" }));
        let error = adapter
            .query(query_request("blue hallway"))
            .expect_err("extra key");
        assert!(matches!(error, VaultReadError::ProtocolMismatch { .. }));
    }

    #[test]
    fn err_envelope_forwards_error_untranslated() {
        let forwarded = VaultReadError::Engine {
            method: VaultReadMethod::Hydrate,
            engine_code: NOT_FOUND_ENGINE_CODE.to_owned(),
            message: "short_id was not found".to_owned(),
        };
        let (_transport, adapter) = wire_adapter(json!({ "err": forwarded.clone() }));
        let error = adapter
            .hydrate(hydrate_request("cl1:a7"))
            .expect_err("err arm");
        assert_eq!(error, forwarded);
    }

    /// The op travels beside the body as `round_trip`'s own argument, so the
    /// body is the BARE canonical request DTO, serialized once. Re-wrapping it
    /// in this crate's `{"op", "request"}` tagged envelope would double-tag
    /// every request and no accepted host would decode it.
    #[test]
    fn wire_request_body_is_the_inner_dto_not_the_tagged_envelope() {
        let anchor = entity(0x5A);
        let reply = VaultReadResponse::MemoryTimeline(CoreMemoryTimelineResponse {
            anchor_id: anchor.to_hex(),
            records: Vec::new(),
        });
        let transport = BodyRecordingTransport::new(
            serde_json::to_vec(&json!({ "ok": reply })).expect("scripted reply serializes"),
        );
        let adapter = WireTransportVaultReadAdapter::new(transport.clone());
        let request = CoreMemoryTimelineRequest {
            id: anchor.to_hex(),
            view: Some(View::Summary),
        };

        adapter
            .memory_timeline(request.clone())
            .expect("timeline round trip");

        let bodies = transport.bodies();
        assert_eq!(bodies.len(), 1);
        let (op, body) = &bodies[0];
        assert_eq!(*op, VaultReadWireOp::CoreMemoryTimeline);
        assert_eq!(
            body,
            &serde_json::to_vec(&request).expect("canonical body serializes"),
            "the transport body is the inner DTO, byte-for-byte"
        );

        let decoded: serde_json::Map<String, Value> =
            serde_json::from_slice(body).expect("the body is a JSON object");
        assert!(
            !decoded.contains_key("op") && !decoded.contains_key("request"),
            "the body must not carry the tagged envelope keys"
        );
        assert!(
            decoded.len() == 2 && decoded.contains_key("id") && decoded.contains_key("view"),
            "the pinned canonical timeline body is exactly {{id, view}}"
        );
        assert!(
            serde_json::from_slice::<VaultReadRequest>(body).is_err(),
            "a bare canonical DTO never decodes as the tagged request envelope"
        );
    }

    // ── 5. Runtime peers never reach a backend ──────────────────────────────

    #[test]
    fn runtime_peers_never_reach_a_backend() {
        let backend = RecordingBackend::default();
        let (transport, adapter) = wire_adapter(json!({ "ok": null }));

        for (method, in_process, wire) in [
            (
                VaultReadMethod::Ask,
                backend.ask(AskRequest(json!({ "prompt": "hi" }))).err(),
                adapter.ask(AskRequest(json!({ "prompt": "hi" }))).err(),
            ),
            (
                VaultReadMethod::CodeSearch,
                backend.code_search(CodeSearchRequest(Value::Null)).err(),
                adapter.code_search(CodeSearchRequest(Value::Null)).err(),
            ),
            (
                VaultReadMethod::CodeExecute,
                backend.code_execute(CodeExecuteRequest(Value::Null)).err(),
                adapter.code_execute(CodeExecuteRequest(Value::Null)).err(),
            ),
        ] {
            let expected = VaultReadError::RuntimeUnavailable { method };
            assert_eq!(in_process, Some(expected.clone()));
            assert_eq!(wire, Some(expected));
        }
        assert_eq!(backend.calls(), 0);
        assert!(transport.ops().is_empty());
    }

    // ── 6. Cloud is total over the surface ──────────────────────────────────

    #[test]
    fn cloud_adapter_is_total_over_the_surface() {
        let cloud = CloudVaultReadAdapter;
        let unimplemented = |method| VaultReadError::Unimplemented {
            adapter: VaultReadAdapterKind::Cloud,
            method,
        };

        assert_eq!(
            cloud.query(query_request("blue hallway")).unwrap_err(),
            unimplemented(VaultReadMethod::Query)
        );
        let mut pack = context_pack_request();
        pack.query_vector = Some(vec![0.25, 0.75]);
        assert_eq!(
            cloud.context_pack(pack).unwrap_err(),
            unimplemented(VaultReadMethod::ContextPack)
        );
        assert_eq!(
            cloud.hydrate(hydrate_request("cl1:a7")).unwrap_err(),
            unimplemented(VaultReadMethod::Hydrate)
        );
        assert_eq!(
            cloud
                .hydrate_many(CoreBatchShortIdHydrateRequest {
                    refs: vec!["cl1:a7".to_owned()],
                    view: None,
                })
                .unwrap_err(),
            unimplemented(VaultReadMethod::HydrateMany)
        );
        assert_eq!(
            cloud
                .memory_timeline(CoreMemoryTimelineRequest {
                    id: entity(0x59).to_hex(),
                    view: None,
                })
                .unwrap_err(),
            unimplemented(VaultReadMethod::MemoryTimeline)
        );

        assert_eq!(
            cloud.ask(AskRequest(Value::Null)).unwrap_err(),
            VaultReadError::RuntimeUnavailable {
                method: VaultReadMethod::Ask
            }
        );
        assert_eq!(
            cloud
                .code_search(CodeSearchRequest(Value::Null))
                .unwrap_err(),
            VaultReadError::RuntimeUnavailable {
                method: VaultReadMethod::CodeSearch
            }
        );
        assert_eq!(
            cloud
                .code_execute(CodeExecuteRequest(Value::Null))
                .unwrap_err(),
            VaultReadError::RuntimeUnavailable {
                method: VaultReadMethod::CodeExecute
            }
        );
    }

    // ── 7-10. Pinned accepted recipes ───────────────────────────────────────

    #[test]
    fn exact_collapses_to_estimate() {
        assert_eq!(CountMode::Exact.for_search_response(), CountMode::Estimate);
        assert_eq!(
            CountMode::Estimate.for_search_response(),
            CountMode::Estimate
        );
        assert_eq!(CountMode::None.for_search_response(), CountMode::None);

        assert_eq!(search_fetch_limit(CountMode::Estimate, 7), 8);
        assert_eq!(search_fetch_limit(CountMode::None, 25), 25);
        assert_eq!(
            search_fetch_limit(CountMode::Estimate, usize::MAX),
            usize::MAX
        );

        assert_eq!(search_total(CountMode::Estimate, 8), 8);
        assert_eq!(search_total(CountMode::None, 25), 0);
    }

    #[test]
    fn single_missing_record_is_not_found() {
        let anchor = entity(0x51);
        let record = |state| MemoryTimelineRecord {
            id: anchor,
            state,
            entity_type: Some(0),
            occurred_start: None,
            occurred_end: None,
            learned_at: None,
            body_bytes: None,
            deletion: None,
            supersedes: Vec::new(),
            superseded_by: Vec::new(),
        };

        assert!(timeline_is_absent(&MemoryTimeline {
            anchor,
            records: Vec::new(),
        }));
        assert!(timeline_is_absent(&MemoryTimeline {
            anchor,
            records: vec![record(MemoryTimelineRecordState::Missing)],
        }));
        assert!(!timeline_is_absent(&MemoryTimeline {
            anchor,
            records: vec![record(MemoryTimelineRecordState::Live)],
        }));
        assert!(!timeline_is_absent(&MemoryTimeline {
            anchor,
            records: vec![
                record(MemoryTimelineRecordState::Missing),
                record(MemoryTimelineRecordState::Live),
            ],
        }));
    }

    #[test]
    fn standard_view_omits_body() {
        let id = entity(0x52);
        let body = msgpack_body("blue hallway door");
        let record = |view| {
            entity_record_from_parts(
                VaultReadMethod::Query,
                &id,
                0,
                1_780_000_000,
                Some(0.75),
                &body,
                view,
            )
            .expect("record projects")
        };

        let standard = record(View::Standard);
        assert_eq!(standard.id, id.to_hex());
        assert_eq!(standard.entity_type, 0);
        assert_eq!(standard.learned_at, 1_780_000_000);
        assert_eq!(standard.score, Some(0.75));
        assert_eq!(standard.body, None);

        for view in [View::Summary, View::Full] {
            let projected = record(view);
            assert_eq!(projected.id, standard.id);
            assert_eq!(projected.entity_type, standard.entity_type);
            assert_eq!(projected.learned_at, standard.learned_at);
            assert_eq!(projected.score, standard.score);
            assert_eq!(
                projected.body,
                Some(json!({ "txt": "blue hallway door" })),
                "{view:?} carries the public MessagePack projection"
            );
        }

        let mut trailing = body.clone();
        trailing.push(0xC0);
        let error = entity_record_from_parts(
            VaultReadMethod::Hydrate,
            &id,
            0,
            1,
            None,
            &trailing,
            View::Full,
        )
        .expect_err("trailing bytes are corruption");
        assert!(matches!(
            error,
            VaultReadError::Engine { ref engine_code, .. } if engine_code == INTERNAL_ENGINE_CODE
        ));
    }

    #[test]
    fn batch_absence_conversion_is_narrow() {
        let absent = batch_item_from_result(
            "cl9:a7".to_owned(),
            Err(engine_absent(VaultReadMethod::Hydrate, "short_id")),
        )
        .expect("absence converts to a per-item outcome");
        assert_eq!(absent.reference, "cl9:a7");
        assert_eq!(absent.outcome, CoreShortIdHydrateOutcome::NotFound);
        assert_eq!(absent.result, None);

        let live =
            batch_item_from_result("cl1:a7".to_owned(), Ok(hydrate_response())).expect("live item");
        assert_eq!(live.outcome, CoreShortIdHydrateOutcome::Live);
        assert!(live.result.is_some());

        let engine = VaultReadError::Engine {
            method: VaultReadMethod::Hydrate,
            engine_code: INTERNAL_ENGINE_CODE.to_owned(),
            message: "corrupted index".to_owned(),
        };
        assert_eq!(
            batch_item_from_result("cl2:a7".to_owned(), Err(engine.clone())).unwrap_err(),
            engine,
            "a non-NOT_FOUND engine error aborts the batch"
        );

        let transport = VaultReadError::Transport {
            method: VaultReadMethod::Hydrate,
            message: "socket closed".to_owned(),
        };
        assert_eq!(
            batch_item_from_result("cl3:a7".to_owned(), Err(transport.clone())).unwrap_err(),
            transport
        );
    }

    // ── Scoped-grant denial reads as absence ────────────────────────────────

    /// `world_ref` is the grant's world scope spelling: a world id hex, or the
    /// literal `"base"` for base reality.
    fn scoped_grant_manifest(actor_ref: &str, world_ref: &str) -> Vec<u8> {
        let grant = MsgpackValue::Map(vec![
            (
                MsgpackValue::from("actor_ref"),
                MsgpackValue::from(actor_ref),
            ),
            (
                MsgpackValue::from("effector"),
                MsgpackValue::from("core:read"),
            ),
            (
                MsgpackValue::from("scope"),
                MsgpackValue::Map(vec![(
                    MsgpackValue::from("world_ref"),
                    MsgpackValue::from(world_ref),
                )]),
            ),
            (
                MsgpackValue::from("receipt_required"),
                MsgpackValue::Boolean(false),
            ),
        ]);
        let manifest = MsgpackValue::Map(vec![
            (
                MsgpackValue::from("schema_version"),
                MsgpackValue::from("1.1"),
            ),
            (
                MsgpackValue::from("pack_id"),
                MsgpackValue::from("vault-read-test"),
            ),
            (MsgpackValue::from("pack_version"), MsgpackValue::from("1")),
            (
                MsgpackValue::from("min_engine_version"),
                MsgpackValue::from("0.0.0"),
            ),
            (
                MsgpackValue::from("defaults"),
                MsgpackValue::Map(Vec::new()),
            ),
            (MsgpackValue::from("rules"), MsgpackValue::Array(Vec::new())),
            (
                MsgpackValue::from("actor_ceilings"),
                MsgpackValue::Array(Vec::new()),
            ),
            (
                MsgpackValue::from("scoped_grants"),
                MsgpackValue::Array(vec![grant]),
            ),
        ]);
        let mut data = Vec::new();
        rmpv::encode::write_value(&mut data, &manifest).expect("manifest encodes");
        data
    }

    fn short_ref(vault: &Vault, id: &EntityId) -> String {
        let rtxn = vault.store.env.read_txn().expect("read txn");
        let raw = vault
            .store
            .short_ids_reverse
            .get(&rtxn, id.as_bytes())
            .expect("short id row read")
            .expect("entity has a short id row");
        let (short_id, content_hash) =
            crate::batch::parse_short_id_value(&raw).expect("short id row parses");
        format!("{short_id}:{content_hash:02x}")
    }

    /// Seeds one admitted claim, one grant-denied claim, and the `core:read`
    /// scoped-grant manifest that separates them.
    fn seed_scoped_grant_vault(vault: &Vault) -> (EntityId, String, String) {
        let subject = entity(0x53);
        let admitted_world = entity(0x54);
        let denied_world = entity(0x55);
        let admitted_id = entity(0x56);
        let denied_id = entity(0x57);
        let occurred = TimeRange {
            start: 1_780_000_000,
            end: 1_780_000_000,
        };

        vault
            .put_entity(&subject, ENTITY_TYPE_PERSON, occurred, occurred.start, b"x")
            .expect("subject entity");
        let claim = |world: EntityId, text: &str| {
            let mut body = ClaimBody::new(
                "profile.note",
                ClaimSubject::Entity(subject),
                MsgpackValue::from(text),
                1.0,
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Active,
            );
            body.world = Some(world);
            body.source = Some(ClaimSource::UserStated);
            body
        };
        vault
            .put_claim(
                &admitted_id,
                &claim(admitted_world, "admitted note"),
                occurred,
                occurred.start,
            )
            .expect("admitted claim");
        vault
            .put_claim(
                &denied_id,
                &claim(denied_world, "denied note"),
                occurred,
                occurred.start,
            )
            .expect("denied claim");
        let refs = (short_ref(vault, &admitted_id), short_ref(vault, &denied_id));
        put_policy_manifest_bytes(
            vault,
            entity(0x58),
            &scoped_grant_manifest("reader", &admitted_world.to_hex()),
        )
        .expect("policy manifest");
        (denied_id, refs.0, refs.1)
    }

    /// A claim the actor's `core:read` grant does not admit is INDISTINGUISHABLE
    /// from a claim that is not there: the same `Engine { NOT_FOUND }`, the same
    /// per-item batch outcome, and no leaked id or body.
    #[test]
    fn scoped_grant_denial_reads_as_absence() {
        let (_dir, vault) = open_test_vault_with(embedding_test_config());
        let (denied_id, admitted_ref, denied_ref) = seed_scoped_grant_vault(&vault);
        let adapter = InProcessVaultReadAdapter::new(
            &vault,
            ScopedReadActorKey::new("reader").expect("actor key"),
        );
        let missing_ref = "cl4096:ff";

        let denied = adapter
            .hydrate(hydrate_request(&denied_ref))
            .expect_err("denied claim reads as absence");
        let missing = adapter
            .hydrate(hydrate_request(missing_ref))
            .expect_err("missing ref reads as absence");
        assert_eq!(denied, missing);
        assert_eq!(
            denied,
            engine_absent(VaultReadMethod::Hydrate, "short_id"),
            "denied and missing normalize to the same accepted absence"
        );

        adapter
            .hydrate(hydrate_request(&admitted_ref))
            .expect("admitted claim hydrates");

        let batch = adapter
            .hydrate_many(CoreBatchShortIdHydrateRequest {
                refs: vec![
                    admitted_ref.clone(),
                    denied_ref.clone(),
                    missing_ref.to_owned(),
                ],
                view: None,
            })
            .expect("batch hydrate");
        assert_eq!(batch.results.len(), 3);
        assert_eq!(batch.results[0].outcome, CoreShortIdHydrateOutcome::Live);
        assert_eq!(
            batch.results[1].outcome,
            CoreShortIdHydrateOutcome::NotFound
        );
        assert_eq!(batch.results[1].result, None);
        assert_eq!(
            batch.results[2].outcome,
            CoreShortIdHydrateOutcome::NotFound
        );
        assert_eq!(batch.results[2].result, None);
        assert_eq!(batch.results[1].reference, denied_ref);

        let serialized = serde_json::to_string(&batch).expect("batch serializes");
        assert!(
            !serialized.contains(&denied_id.to_hex()),
            "a denied entity id never appears in a response"
        );
        assert!(
            !serialized.contains("denied note"),
            "denied body bytes never appear in a response"
        );
    }

    // ── Response retrieval budget binds the answered pack ───────────────────

    /// Seeds one subject plus three admitted, vector-searchable CLAIMs and
    /// returns how many claims are in the vault.
    fn seed_retrieval_budget_vault(vault: &Vault) -> usize {
        let subject = entity(0x5B);
        let occurred = TimeRange {
            start: 1_780_000_000,
            end: 1_780_000_000,
        };
        vault
            .put_entity(
                &subject,
                ENTITY_TYPE_PERSON,
                occurred,
                occurred.start,
                b"subject",
            )
            .expect("subject entity");

        // Distinct predicates and vectors: three independent live CLAIM heads,
        // all close to the seed vector.
        let seeds = [
            (0x5C_u8, [1.0_f32, 0.0, 0.0, 0.0], "profile.note_alpha"),
            (0x5D, [0.95, 0.05, 0.0, 0.0], "profile.note_bravo"),
            (0x5E, [0.9, 0.1, 0.0, 0.0], "profile.note_charlie"),
        ];
        let seeded = seeds.len();
        for (seed, vector, predicate) in seeds {
            let id = entity(seed);
            let mut body = ClaimBody::new(
                predicate,
                ClaimSubject::Entity(subject),
                MsgpackValue::from("budget note"),
                1.0,
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Active,
            );
            body.source = Some(ClaimSource::UserStated);
            vault
                .put_claim(&id, &body, occurred, occurred.start)
                .expect("admitted claim");
            vault
                .batch()
                .vector(&id, &vector)
                .commit()
                .expect("claim vector");
        }
        seeded
    }

    /// The response retrieval budget is the UNWIDENED one and it binds the
    /// ANSWERED pack: the widened copy exists only so scoped-read clamping
    /// cannot starve retrieval. `retrieval.claims = 1` therefore returns at
    /// most one CLAIM, and the visible stats describe the delivered pack.
    #[test]
    fn response_retrieval_budget_caps_claims_after_filtering() {
        let (_dir, vault) = open_test_vault_with(embedding_test_config());
        let seeded_claims = seed_retrieval_budget_vault(&vault);
        let adapter = InProcessVaultReadAdapter::new(
            &vault,
            ScopedReadActorKey::new("reader").expect("actor key"),
        );
        let request = |claims: Option<usize>| CoreContextPackRequest {
            query: None,
            query_vector: Some(vec![1.0, 0.0, 0.0, 0.0]),
            limit: 10,
            depth: None,
            edge_hop: None,
            max_neighbors: None,
            budget: claims.map(|claims| ContextPackBudgetControls {
                retrieval: Some(ContextPackRetrievalBudgetControls {
                    claims: Some(claims),
                    ..ContextPackRetrievalBudgetControls::default()
                }),
                ..ContextPackBudgetControls::default()
            }),
        };
        let claims_in = |response: &CoreContextPackResponse| {
            response
                .0
                .results
                .iter()
                .filter(|record| record.entity_type == ENTITY_TYPE_CLAIM)
                .count()
        };

        let unbudgeted = adapter
            .context_pack(request(None))
            .expect("unbudgeted context pack");
        assert!(
            claims_in(&unbudgeted) > 1,
            "the fixture's {seeded_claims} admitted claims surface without a per-kind budget"
        );

        let budgeted = adapter
            .context_pack(request(Some(1)))
            .expect("budgeted context pack");
        assert_eq!(
            claims_in(&budgeted),
            1,
            "retrieval.claims = 1 binds the answered pack, not just retrieval"
        );
        let results = budgeted.0.results.len();
        let neighbors = budgeted.0.neighbors.len();
        assert_eq!(
            budgeted.0.stats.candidates_considered, results,
            "visible stats describe the pack the caller received"
        );
        assert_eq!(budgeted.0.stats.entities_hydrated, results);
        assert_eq!(budgeted.0.stats.neighbors_hydrated, neighbors);
    }

    // ── Durable pack telemetry carries only actor-visible ids ───────────────

    /// Seeds one BASE-reality claim the `core:read` grant admits and one
    /// world-scoped claim it denies, both vector-searchable, so a context-pack
    /// assembly surfaces BOTH before the scoped filter runs. Returns
    /// `(admitted_id, denied_id)`.
    fn seed_scoped_pack_vault(vault: &Vault) -> (EntityId, EntityId) {
        let subject = entity(0x60);
        let denied_world = entity(0x61);
        let admitted_id = entity(0x62);
        let denied_id = entity(0x63);
        let occurred = TimeRange {
            start: 1_780_000_000,
            end: 1_780_000_000,
        };
        vault
            .put_entity(&subject, ENTITY_TYPE_PERSON, occurred, occurred.start, b"x")
            .expect("subject entity");

        let claim = |predicate: &str, world: Option<EntityId>, text: &str| {
            let mut body = ClaimBody::new(
                predicate,
                ClaimSubject::Entity(subject),
                MsgpackValue::from(text),
                1.0,
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Active,
            );
            body.world = world;
            body.source = Some(ClaimSource::UserStated);
            body
        };
        let seeds = [
            (
                admitted_id,
                claim("profile.note_admitted", None, "admitted note"),
                [1.0_f32, 0.0, 0.0, 0.0],
            ),
            (
                denied_id,
                claim(
                    "profile.note_denied",
                    Some(denied_world),
                    "denied world pack note",
                ),
                [0.95, 0.05, 0.0, 0.0],
            ),
        ];
        for (id, body, vector) in seeds {
            vault
                .put_claim(&id, &body, occurred, occurred.start)
                .expect("seeded claim");
            vault
                .batch()
                .vector(&id, &vector)
                .commit()
                .expect("claim vector");
        }

        // The grant names BASE reality: the base claim is readable by `reader`
        // and the world-scoped one is not.
        let manifest = scoped_grant_manifest("reader", "base");
        put_policy_manifest_bytes(vault, entity(0x64), &manifest).expect("policy manifest");
        (admitted_id, denied_id)
    }

    fn vector_pack_request() -> CoreContextPackRequest {
        CoreContextPackRequest {
            query: None,
            query_vector: Some(vec![1.0, 0.0, 0.0, 0.0]),
            limit: 10,
            depth: None,
            edge_hop: None,
            max_neighbors: None,
            budget: None,
        }
    }

    fn published_context_pack_run(vault: &Vault) -> RetrievalRunRecord {
        let runs = vault.retrieval_runs(64).expect("published retrieval runs");
        let mut published: Vec<RetrievalRunRecord> = runs
            .into_iter()
            .filter(|record| record.action == RetrievalAction::ContextPack)
            .collect();
        assert_eq!(
            published.len(),
            1,
            "one assembly publishes exactly one context-pack run row"
        );
        published.remove(0)
    }

    /// The DURABLE retrieval-run row a context pack publishes carries EXACTLY
    /// the ids this actor received. The scoped filter runs before the
    /// finalize, so an entity the actor may not see is as absent from the
    /// telemetry ledger as it is from the response — denied-equals-absent
    /// across the operation's effects, not only its answer.
    #[test]
    fn context_pack_run_row_publishes_only_actor_visible_ids() {
        // Same seed, no actor clamp: the naked builder this method enters
        // surfaces BOTH claims, so a finalize taken before the filter would
        // publish the denied id. That is the leak this ordering closes.
        let (_leak_dir, leak_vault) = open_test_vault_with(embedding_test_config());
        let (_, leaked_id) = seed_scoped_pack_vault(&leak_vault);
        let unfiltered = leak_vault
            .context_pack()
            .limit(10)
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
            .run()
            .expect("unfiltered pack");
        let leaked = unfiltered
            .results
            .iter()
            .any(|entity| entity.id == leaked_id);
        assert!(
            leaked,
            "the fixture is leak-prone: retrieval surfaces the denied claim pre-filter"
        );

        let (_dir, vault) = open_test_vault_with(embedding_test_config());
        let (admitted_id, denied_id) = seed_scoped_pack_vault(&vault);
        let adapter = InProcessVaultReadAdapter::new(
            &vault,
            ScopedReadActorKey::new("reader").expect("actor key"),
        );

        let request = vector_pack_request();
        let response = adapter.context_pack(request).expect("context pack");
        let results = &response.0.results;
        let returned: Vec<String> = results.iter().map(|record| record.id.clone()).collect();
        assert_eq!(
            returned,
            vec![admitted_id.to_hex()],
            "only the admitted claim is answered"
        );
        assert!(
            response.0.stats.claims_suppressed >= 1,
            "the scoped filter removed the denied claim from the assembled pack"
        );

        let denied_bytes = *denied_id.as_bytes();
        let run = published_context_pack_run(&vault);
        let published_row = vault.retrieval_run(run.run_id).expect("run row read");
        assert!(
            published_row.is_some(),
            "the row is PUBLISHED, not left provisional"
        );
        assert!(
            !run.result_ids.contains(&denied_bytes),
            "a denied id never reaches the durable result ids"
        );
        assert!(
            run.score_breakdown
                .iter()
                .all(|entry| entry.result_id != denied_bytes),
            "a denied id never reaches the durable score breakdown"
        );
        // The engine path never enables trace capture, so no trace is expected
        // here; if one is ever captured the same absence rule binds it and the
        // fork index that republishes it.
        if let Some(trace) = run.trace.as_ref() {
            assert!(
                trace
                    .final_stage
                    .candidates
                    .iter()
                    .all(|entry| entry.result_id != denied_bytes),
                "a denied id never reaches the durable trace candidates"
            );
            if let Some(forked) = vault
                .retrieval_trace_by_fork_hash(trace.fork_hash)
                .expect("trace fork lookup")
            {
                assert!(
                    forked
                        .final_stage
                        .candidates
                        .iter()
                        .all(|entry| entry.result_id != denied_bytes),
                    "the trace fork index answers no denied id either"
                );
            }
        }

        let row_ids: Vec<String> = run
            .result_ids
            .iter()
            .map(|bytes| EntityId::from_bytes(*bytes).expect("run id").to_hex())
            .collect();
        assert_eq!(
            row_ids, returned,
            "the published ids are exactly the post-filter, post-truncate results"
        );
    }

    /// When the filter removes EVERYTHING the row still publishes — with no
    /// ids and the answered pack's empty reason — and the caller-visible empty
    /// context is byte-for-byte what it was before the finalize moved.
    #[test]
    fn fully_filtered_context_pack_publishes_an_empty_run_row() {
        let (_dir, vault) = open_test_vault_with(embedding_test_config());
        let (admitted_id, denied_id) = seed_scoped_pack_vault(&vault);
        // No grant names this actor, so a `core:read` grant exists that never
        // admits it: EVERY claim is denied.
        let adapter = InProcessVaultReadAdapter::new(
            &vault,
            ScopedReadActorKey::new("outsider").expect("actor key"),
        );

        let request = vector_pack_request();
        let response = adapter.context_pack(request).expect("context pack");
        assert!(response.0.results.is_empty());
        assert!(response.0.neighbors.is_empty());
        let empty = response
            .0
            .empty
            .expect("an all-filtered pack reports an empty context");
        // The caller-visible empty context is the scoped filter's own, exactly
        // as it was before the finalize moved behind it.
        let reason = CoreContextPackEmptyReason::FilterMatchedNone;
        let hint = "scoped_read returned no actor-readable entities";
        assert_eq!(empty.reason, reason);
        assert_eq!(empty.total_in_scope, 0);
        assert_eq!(empty.hint, hint);
        assert_eq!(response.0.stats.candidates_considered, 0);
        assert_eq!(response.0.stats.entities_hydrated, 0);
        assert_eq!(response.0.stats.neighbors_hydrated, 0);

        let run = published_context_pack_run(&vault);
        assert!(
            run.result_ids.is_empty(),
            "no id survived the filter, so none is published"
        );
        assert!(run.score_breakdown.is_empty());
        assert_eq!(
            run.empty_reason.as_deref(),
            Some("FilterMatchedNone"),
            "the published reason is read off the post-filter pack"
        );
        for id in [admitted_id, denied_id] {
            assert!(!run.result_ids.contains(id.as_bytes()));
        }
    }

    // ── Batch hydrate errors carry the BATCH method identity ────────────────

    /// A single-item failure that ABORTS the batch is an error of
    /// `HydrateMany`, not of `Hydrate`: the same helper serves both doors, so
    /// the identity travels as an argument. The single-ref door is unchanged.
    #[test]
    fn batch_aborting_error_carries_the_batch_method() {
        let (_dir, vault) = open_test_vault_with(embedding_test_config());
        let corrupt = entity(0x66);
        let occurred = TimeRange {
            start: 1_780_000_000,
            end: 1_780_000_000,
        };
        // A stored body whose first MessagePack value does not consume the
        // whole payload: projection rejects it as corruption, which is a
        // non-NOT_FOUND engine error and therefore batch-aborting.
        vault
            .put_entity(
                &corrupt,
                ENTITY_TYPE_PERSON,
                occurred,
                occurred.start,
                b"corrupt body",
            )
            .expect("entity with an undecodable body");
        let reference = short_ref(&vault, &corrupt);
        let adapter = InProcessVaultReadAdapter::new(
            &vault,
            ScopedReadActorKey::new("reader").expect("actor key"),
        );

        let single = adapter
            .hydrate(hydrate_request(&reference))
            .expect_err("single hydrate reports corruption");
        assert!(
            matches!(
                &single,
                VaultReadError::Engine { method, engine_code, .. }
                    if *method == VaultReadMethod::Hydrate && engine_code == INTERNAL_ENGINE_CODE
            ),
            "the single-ref door still answers with Hydrate identity: {single:?}"
        );

        let batch = adapter
            .hydrate_many(CoreBatchShortIdHydrateRequest {
                refs: vec![reference],
                view: None,
            })
            .expect_err("a non-NOT_FOUND item error aborts the batch");
        assert!(
            matches!(
                &batch,
                VaultReadError::Engine { method, engine_code, .. }
                    if *method == VaultReadMethod::HydrateMany
                        && engine_code == INTERNAL_ENGINE_CODE
            ),
            "the aborting error carries the BATCH method identity: {batch:?}"
        );
    }
}
