//! One typed verb table for embedded SDK, HTTP, WS and language bindings.
//! Session-handle and host-callback operations remain host-only. Wire callers
//! cannot supply a session, composer, execution sink, or budget lease.

use super::*;
use crate::calendar::{CalendarEventView, CalendarReadRequest, CalendarSearchRequest};
pub use crate::code_run::vault_read::{
    CoreContextPackRequest, CoreContextPackResponse, CoreQueryRequest, CoreQueryResponse,
};
use serde::{Deserialize, Serialize};

mod builders;
mod dispatch;
mod domains;
mod dto;
mod expression;
mod validate;
mod verbs;
pub use domains::*;
pub use expression::*;
#[cfg(test)]
mod tests;
pub use builders::{ContextPackBuilder, QueryBuilder};
pub use dto::*;

/// Minimum credential scope required by a facade operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FacadeScope {
    /// A read-only operation.
    Read,
    /// An operation that can change durable state.
    Write,
}

/// A single host-call boundary. Implementations must not split one request
/// into several transport calls or accept caller-supplied actor authority.
pub trait FacadeTransport {
    /// Dispatches one verb with its engine request body.
    fn call(&self, verb: FacadeVerb, body: serde_json::Value) -> MemoryResult<serde_json::Value>;
}

/// Typed SDK over any facade transport. Methods come from the verb table.
pub struct FacadeClient<T>(pub T);

pub(super) fn encode<T: Serialize>(value: &T) -> MemoryResult<serde_json::Value> {
    serde_json::to_value(value).map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_INTERNAL,
            "facade serialization failed",
            &["Retry the operation."],
        )
    })
}

pub(super) fn decode<T: serde::de::DeserializeOwned>(body: serde_json::Value) -> MemoryResult<T> {
    serde_json::from_value(body).map_err(|_| {
        MemoryError::bad_request_with(
            "invalid JSON request body",
            &["Send a JSON body matching this verb's documented input."],
        )
    })
}

macro_rules! facade_verb_table {
    ($($variant:ident => {
        method: $method:ident, wire: $wire:literal, sdk: $sdk:literal, scope: $scope:ident,
        request: $request:ty, response: $response:ty, doc: $doc:literal,
    })+) => {
        /// Every wire-projectable Memory operation.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub enum FacadeVerb { $(#[doc = $doc] #[serde(rename = $wire)] $variant,)+ }
        impl FacadeVerb {
            /// Number of operations in the table.
            pub const COUNT: usize = [$(Self::$variant,)+].len();
            /// Declaration order is the SDK and wire census order.
            pub const ALL: [Self; Self::COUNT] = [$(Self::$variant,)+];
            /// HTTP route names, generated rather than copied into a binding.
            pub const WIRE_NAMES: [&'static str; Self::COUNT] = [$($wire,)+];
            /// Stable HTTP operation name.
            #[must_use]
            pub const fn wire_name(self) -> &'static str { match self { $(Self::$variant => $wire,)+ } }
            /// Language binding method name.
            #[must_use]
            pub const fn sdk_name(self) -> &'static str { match self { $(Self::$variant => $sdk,)+ } }
            /// Minimum caller scope.
            #[must_use]
            pub const fn scope(self) -> FacadeScope { match self { $(Self::$variant => FacadeScope::$scope,)+ } }
            /// Description used by SDK search.
            #[must_use]
            pub const fn doc(self) -> &'static str { match self { $(Self::$variant => $doc,)+ } }
            /// Engine request DTO name used in generated SDK documentation.
            #[must_use]
            pub const fn request_type(self) -> &'static str { match self { $(Self::$variant => stringify!($request),)+ } }
            /// Engine response DTO name used in generated SDK documentation.
            #[must_use]
            pub const fn response_type(self) -> &'static str { match self { $(Self::$variant => stringify!($response),)+ } }
            /// Parses the stable HTTP name.
            #[must_use]
            pub fn parse_wire(name: &str) -> Option<Self> { match name { $($wire => Some(Self::$variant),)+ _ => None } }
            /// Parses the language binding name.
            #[must_use]
            pub fn parse_sdk(name: &str) -> Option<Self> { match name { $($sdk => Some(Self::$variant),)+ _ => None } }
            /// Decodes a typed call before dispatch, without side effects.
            pub fn request(self, body: serde_json::Value) -> MemoryResult<FacadeRequest> {
                let request = match self { $(Self::$variant => FacadeRequest::$variant(decode::<$request>(body)?),)+ };
                request.validate()?;
                Ok(request)
            }
        }
        /// Typed instruction for one engine operation.
        #[derive(Debug, Clone, Serialize, Deserialize)]
        #[serde(tag = "verb", content = "body")]
        pub enum FacadeRequest { $(#[doc = $doc] #[serde(rename = $wire)] $variant($request),)+ }
        impl FacadeRequest {
            /// Operation carried by this request.
            #[must_use]
            pub const fn verb(&self) -> FacadeVerb { match self { $(Self::$variant(_) => FacadeVerb::$variant,)+ } }
            /// Runs against the actor already bound to Memory.
            pub fn run(self, memory: &Memory<'_>) -> MemoryResult<FacadeResponse> {
                self.validate()?;
                match self { $(Self::$variant(body) => Ok(FacadeResponse::$variant(dispatch::$method(memory, body)?)),)+ }
            }
            /// Request body without the internal typed envelope.
            pub fn body(&self) -> MemoryResult<serde_json::Value> {
                match self { $(Self::$variant(body) => encode(body),)+ }
            }
        }
        /// Typed operation result. Wires send its body, not this envelope.
        #[derive(Debug, Clone, Serialize, Deserialize)]
        #[serde(tag = "verb", content = "body")]
        pub enum FacadeResponse { $(#[doc = $doc] #[serde(rename = $wire)] $variant($response),)+ }
        impl FacadeResponse {
            /// Response body without the typed envelope.
            pub fn body(&self) -> MemoryResult<serde_json::Value> {
                match self { $(Self::$variant(body) => encode(body),)+ }
            }
        }
        impl<T: FacadeTransport> FacadeClient<T> {
            $(#[doc = $doc]
            pub fn $method(&self, request: &$request) -> MemoryResult<$response> {
                let body = self.0.call(FacadeVerb::$variant, encode(request)?)?;
                serde_json::from_value(body).map_err(|_| MemoryError::new(
                    MEMORY_CODE_INTERNAL, "facade response type mismatch", &["Check the host SDK contract."],
                ))
            })+
        }
    };
}

include!("table.rs");

/// Executes one table row. Every projection uses this dispatch.
pub fn dispatch_facade_verb(
    memory: &Memory<'_>,
    verb: FacadeVerb,
    body: serde_json::Value,
) -> MemoryResult<serde_json::Value> {
    verb.request(body)?.run(memory)?.body()
}

impl FacadeTransport for Memory<'_> {
    fn call(&self, verb: FacadeVerb, body: serde_json::Value) -> MemoryResult<serde_json::Value> {
        dispatch_facade_verb(self, verb, body)
    }
}
impl<T: FacadeTransport + ?Sized> FacadeTransport for &T {
    fn call(&self, verb: FacadeVerb, body: serde_json::Value) -> MemoryResult<serde_json::Value> {
        (**self).call(verb, body)
    }
}
