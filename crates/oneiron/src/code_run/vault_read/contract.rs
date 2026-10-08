//! The vault-read request / response carriers and the sealed client, generated from the
//! contract table in `oneiron-contracts` (the same rows that generate the method
//! vocabulary there).

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

pub use oneiron_contracts::code_run::vault_read::{
    MEMORY_VERBS, VAULT_READ_METHOD_MAP, VaultReadAdapterKind, VaultReadAvailability,
    VaultReadMethod, VaultReadMethodMapping, VaultReadWireOp,
};

/// Generates the carriers and the sealed client from the contract table rows.
///
/// Every surface here — [`VaultReadRequest`], [`VaultReadResponse`] and the
/// [`VaultReadClient`] trait methods — comes from the one row inventory that also
/// generates [`VaultReadMethod`], [`VaultReadWireOp`] and [`VAULT_READ_METHOD_MAP`].
macro_rules! vault_read_contract_carriers {
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
        /// [`WireTransport`](super::WireTransport), they do not create a fourth client that could skip
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

oneiron_contracts::vault_read_contract_rows!(vault_read_contract_carriers);
