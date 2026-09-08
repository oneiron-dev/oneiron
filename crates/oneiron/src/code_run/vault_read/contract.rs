//! The one declarative contract table and every surface the macro generates from it.

use serde::{Deserialize, Serialize};

use super::context_pack::{CoreContextPackRequest, CoreContextPackResponse};
use super::dispatch::validate_and_dispatch;
use super::error::{VaultReadResult, response_arm_mismatch};
use super::sealed;
use super::types::{
    AskRequest, AskResponse, CodeExecuteRequest, CodeExecuteResponse, CodeSearchRequest,
    CodeSearchResponse, CoreBatchShortIdHydrateRequest, CoreBatchShortIdHydrateResponse,
    CoreHydrateRequest, CoreHydrateResponse, CoreMemoryTimelineRequest, CoreMemoryTimelineResponse,
    CoreQueryRequest, CoreQueryResponse,
};

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
