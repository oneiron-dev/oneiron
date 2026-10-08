//! The vault-read contract table and the method vocabulary generated from it.
//!
//! The table is the single row inventory of v1 vault-read methods. This crate generates
//! the method / wire-op vocabulary from it; `oneiron` feeds the same rows to its own
//! generator for the request / response carriers and the sealed `VaultReadClient`
//! trait, so a client method still cannot exist without its method / wire-op row and
//! the table is never hand-copied.

use serde::{Deserialize, Serialize};

use super::context_pack::CoreContextPackRequest;
use super::types::{
    AskRequest, CodeExecuteRequest, CodeSearchRequest, CoreBatchShortIdHydrateRequest,
    CoreHydrateRequest, CoreMemoryTimelineRequest, CoreQueryRequest,
};

/// The one declarative contract table, handed to a generator macro.
///
/// Engine seam: `oneiron`'s vault-read module invokes this with its carrier generator.
/// Rows name the request and response types by their bare names; each generator
/// resolves them in its own module.
#[doc(hidden)]
#[macro_export]
macro_rules! vault_read_contract_rows {
    ($generator:ident) => {
        $generator! {
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
    };
}

/// Generates the method vocabulary from the table rows.
macro_rules! vault_read_contract_vocabulary {
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

            /// The tool-first name, generated from the same SDK method row.
            pub const fn tool_name(self) -> &'static str {
                match self { $(Self::$variant => concat!("memory.", stringify!($method)),)+ }
            }

            /// The native request schema. Inline definitions keep it valid when
            /// nested inside an endpoint envelope with its own schema resource.
            pub fn request_schema(self) -> serde_json::Value {
                match self { $(Self::$variant => request_schema::<$request>(),)+ }
            }

            /// The engine's execution contract, including typed runtime refusal.
            pub const fn description(self) -> &'static str {
                match self { $(Self::$variant => $doc,)+ }
            }

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

        /// Engine-owned memory tool rows. No gateway-owned name census exists.
        pub const MEMORY_VERBS: [&str; VaultReadMethod::COUNT] = [
            $(concat!("memory.", stringify!($method)),)+
        ];

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

    };
}

vault_read_contract_rows!(vault_read_contract_vocabulary);

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

/// Which adapter produced an [`VaultReadError::Unimplemented`](super::VaultReadError::Unimplemented).
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

/// The inline JSON schema of one request type. Public because `oneiron` builds the
/// endpoint schemas from it.
pub fn request_schema<T: schemars::JsonSchema>() -> serde_json::Value {
    let mut settings = schemars::r#gen::SchemaSettings::default();
    settings.inline_subschemas = true;
    let mut schema = settings.into_generator().into_root_schema_for::<T>();
    schema.meta_schema = None;
    match serde_json::to_value(schema) {
        Ok(value) => value,
        Err(_) => serde_json::Value::Bool(false),
    }
}
