//! Federation scope vocabulary and codecs: six-axis scopes and their MessagePack form, the
//! pact direction scopes, selector kinds and the shared map/entity-ref helpers. Grants,
//! membership and every door that admits a federated write stay in `oneiron::federation`,
//! which re-exports these. Helpers that were crate-private there are public here so those
//! doors can call them across the crate line; they encode and decode values only.

pub mod codec;
pub mod pact_scope;
pub mod scope;
pub mod scope_codec;
pub mod selector_kind;

pub use self::pact_scope::{
    Ceiling, FEDERATION_PACT_SCOPE_SCHEMA_VERSION, FederationDirectionScope, FederationPactScope,
    Position, SelectorRange, decode_federation_direction_scope_value, decode_federation_pact_scope,
    decode_federation_pact_scope_value, encode_federation_pact_scope,
    federation_direction_scope_value, federation_pact_scope_value, selector_range_of,
};
pub use self::scope::{Scope, ScopeAtom, ScopeAxis, ScopeId, Sensitivity, SensitivityCeiling};
