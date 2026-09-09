//! Interlocutor-scoped disclosure clamp substrate (OF-365 ILD-2).
//!
//! Two-mode law: owner ABSENT means out-of-scope memories are ABSENT from
//! model context (absence is the boundary — prompt-side withholding is not a
//! security boundary); owner PRESENT with third parties keeps Tier A
//! absence-clamped while Tier B surfaces under a named-presence discretion
//! notice. Mode is stateless — recomputed from the presented interlocutor
//! set on every assembly.
//!
//! Enforcement lives in `context_pack.rs` (the enforcement point IS context
//! assembly); this module owns mode/tier/scope classification, storage, and
//! the agent-visible assembly block.

mod scope_codec;
mod tier_classification;
mod vault_context;

pub use self::scope_codec::{
    DISCLOSURE_SCOPE_BODY_KEYS, DISCLOSURE_SCOPE_SCHEMA_VERSION, DisclosureScope,
    DisclosureScopeStatus, MAX_DISCLOSURE_SCOPE_ENTITIES, MAX_DISCLOSURE_SCOPE_TOPICS,
    decode_disclosure_scope_body, encode_disclosure_scope_body,
};
pub use self::tier_classification::{
    DISCLOSURE_CLAIM_PREDICATES, DISCLOSURE_TIER_A_ENTITY_TYPES,
    DISCLOSURE_TIER_A_PREDICATE_PREFIXES, DisclosureMode, DisclosureTier,
    PREDICATE_DISCLOSURE_SCOPE, PREDICATE_DISCLOSURE_TIER, PREDICATE_DISCLOSURE_TOPIC,
    is_disclosure_claim_predicate,
};
pub use self::vault_context::{DisclosureAssembly, DisclosureContext, presence_discretion_notice};

pub(crate) use self::tier_classification::{disclosure_tier, validate_disclosure_claim_structure};
use self::vault_context::disclosure_tier_a_marked_in;

#[cfg(test)]
mod tests;

// The flat disclosure.rs module used to provide these names to the sibling test
// module through `use super::*`: its own private crate/std import header, the
// cross-child `pub(super)` helpers, and every disclosure-internal item the
// tests name bare. After the directory split the seam re-imports them so
// `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use self::{scope_codec::*, tier_classification::*, vault_context::*};
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
