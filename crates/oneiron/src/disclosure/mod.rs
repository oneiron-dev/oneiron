//! Interlocutor-scoped disclosure clamp substrate (OF-365 ILD-2).
//!
//! Owner alone receives TOP. With any non-owner present, every assembly
//! requires the record position under the non-owner clearance meet OR the
//! public floor, with positive invariant proof as a separate lane. Tier-A,
//! world, facet and other retrieval filters remain independent conjuncts.
//!
//! Enforcement lives in `context_pack.rs` (the enforcement point IS context
//! assembly); this module owns mode/tier/scope classification, storage, and
//! the agent-visible assembly block.
//!
//! Clearances are [`ScopeCeiling`] values over the five-axis Scope lattice
//! (OF-453 One Scope, ILDF2 P1–P7/V1–V3); record exposure is the distinct
//! [`ScopePosition`] type (OF-471). The v1 entity-allowlist unit is gone:
//! unknown, revoked, missing, or undecodable roster members contribute
//! [`ScopeCeiling::bottom`], and an empty non-owner roster folds to
//! [`ScopeCeiling::top`] before any meet (P1).

mod authorization;
mod exposure_floor;
mod generation;
mod position;
mod scope;
mod tier_classification;
mod vault_context;

pub use self::authorization::DisclosureScopeAuthorization;
pub use self::generation::{DisclosureGeneration, DisclosureSession};
pub use self::scope::{
    MAX_SCOPE_AXIS_IDS, MAX_SCOPE_KINDS, SCOPE_BODY_KEYS, SCOPE_BODY_SCHEMA_VERSION,
    SENSITIVITY_MAX_RUNG, SENSITIVITY_PRIVATE, SENSITIVITY_PUBLIC, SENSITIVITY_RESTRICTED,
    SENSITIVITY_SENSITIVE, ScopeCeiling, ScopeIdAxis, ScopeKindAxis, ScopePosition,
    decode_scope_ceiling_body, decode_scope_position_body, encode_scope_ceiling_body,
    encode_scope_position_body, is_at_or_under, meet_all,
};
pub use self::tier_classification::{
    DISCLOSURE_CLAIM_PREDICATES, DISCLOSURE_TIER_A_ENTITY_TYPES,
    DISCLOSURE_TIER_A_PREDICATE_PREFIXES, DisclosureMode, DisclosureTier,
    PREDICATE_DISCLOSURE_SCOPE, PREDICATE_DISCLOSURE_TIER, PREDICATE_DISCLOSURE_TOPIC,
    is_disclosure_claim_predicate,
};
pub use self::vault_context::{DisclosureAssembly, DisclosureContext, presence_discretion_notice};

pub(crate) use self::exposure_floor::stage_record_exposure;
pub(crate) use self::position::inherited_claim_scope;
pub use self::position::{
    CLAIM_SCOPE_INVARIANT_KEY, CLAIM_SCOPE_PROJECT_ID_KEY, RECORD_SCOPE_POSITION_KEY,
};
pub(crate) use self::tier_classification::{disclosure_tier, validate_disclosure_claim_structure};
use self::vault_context::disclosure_tier_a_marked_in;

#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
mod tests;

// The flat disclosure.rs module used to provide these names to the sibling test
// module through `use super::*`: its own private crate/std import header, the
// cross-child `pub(super)` helpers, and every disclosure-internal item the
// tests name bare. After the directory split the seam re-imports them so
// `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use self::{position::*, scope::*, tier_classification::*, vault_context::*};
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, encode_claim_body,
    validate_claim_body_bytes,
};
#[cfg(test)]
use crate::edge::EdgeKind;
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::Result;
#[cfg(test)]
use crate::interlocutor::InterlocutorSet;
#[cfg(test)]
use crate::registry::ENTITY_TYPE_CLAIM;
#[cfg(test)]
use crate::temporal::TimeRange;
#[cfg(test)]
use rmpv::Value;
