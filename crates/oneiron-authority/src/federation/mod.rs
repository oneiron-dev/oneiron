//! Federation scope vocabulary and codecs: six-axis scopes and their MessagePack form, the
//! pact direction scopes, selector kinds and the shared map/entity-ref helpers. Grants,
//! membership and every door that admits a federated write stay in `oneiron::federation`,
//! which re-exports these. Helpers that were crate-private there are public here so those
//! doors can call them across the crate line; they encode and decode values only.

pub mod codec;
pub mod git_push;
pub mod pact_scope;
pub mod repo_scope;
pub mod scope;
pub mod scope_codec;
pub mod selector_kind;
pub mod verb_classes;
pub mod wallet_ref;
pub mod working_view_bounds;

pub use self::git_push::{
    FederationGrantKind, GIT_PUSH_VERB, GRANT_KIND_GIT_PUSH, GitPushBounds, GitPushRepo,
};
pub use self::pact_scope::{
    Ceiling, FEDERATION_PACT_SCOPE_SCHEMA_VERSION, FederationDirectionScope, FederationPactScope,
    Position, SelectorRange, decode_federation_direction_scope_value, decode_federation_pact_scope,
    decode_federation_pact_scope_value, encode_federation_pact_scope,
    federation_direction_scope_value, federation_pact_scope_value, selector_range_of,
};
pub use self::repo_scope::{
    REPO_EDIT_VERB, REPO_READ_VERB, RepoAccessBounds, RepoAccessIntent, RepoAccessRefusal,
    RepoTarget,
};
pub use self::scope::{Scope, ScopeAtom, ScopeAxis, ScopeId, Sensitivity, SensitivityCeiling};
pub use self::verb_classes::{
    KEY_VERB_CLASSES, decode_verb_classes_value, verb_class_name_is_valid, verb_classes_value,
};
pub use self::wallet_ref::{KEY_WALLET_REF, decode_wallet_ref_value, wallet_ref_value};
pub use self::working_view_bounds::{
    KEY_WORKING_VIEW_BOUNDS, WorkingViewEditBounds, decode_working_view_bounds_value,
    working_view_bounds_value,
};
pub use oneiron_contracts::wallet::WalletRef;
