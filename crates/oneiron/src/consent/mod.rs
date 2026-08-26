//! DEC-0006 unified consent-mode — bounded standing grants.
//!
//! One consent primitive spans BOTH surfaces the owner experiences:
//! **disclosure** (what the companion reveals about them, data → audience)
//! and **action** (what an agent runs from the sandbox, actor → verb →
//! target). The nine DEC-0006 invariants are the acceptance authority and
//! are implemented here exactly, not illustratively.
//!
//! # Axes
//!
//! Two axes stay orthogonal and are never collapsed:
//!
//! * **Lifetime** — [`ConsentGrant`] is either [`ConsentGrant::ApproveOnce`]
//!   (this op, now, keyed by the exact [`EffectDigest`]) or
//!   [`ConsentGrant::Standing`] (a remembered bound).
//! * **Domain** — [`StandingConsentGrant`] is the DISJOINT
//!   [`StandingConsentGrant::Disclosure`] or [`StandingConsentGrant::Action`].
//!   A mixed operation (a `channel_send` of private content) carries TWO
//!   requirements and the evaluator applies logical AND — invariant 4.
//!
//! # What this module owns and does not own
//!
//! * It owns the canonical standing-grant rows, persisted as strict versioned
//!   MessagePack under the `CONSENT_GRANT_KEY_PREFIX` `vault_meta` prefix,
//!   written atomically with the Gate receipt. **No entity type and no type
//!   byte are allocated** — existing entity codecs are left intact.
//! * It owns the [`CATASTROPHE_FLOOR_V1`] closed set and its version pin.
//! * It owns host-side reversibility classification over an engine-built
//!   [`EffectFacts`]. No caller-supplied `reversible` verdict exists anywhere
//!   in this module's public surface — invariant 6.
//! * It does NOT mint a second receipt ledger: [`ConsentReceipt`] projects
//!   into the existing Gate receipt family via
//!   [`crate::store::GateDecisionRecord`] (`diff_handle` carries the
//!   effect/bound digest, `grant_ref` joins standing use).
//! * It stores **no key material, bearer token, credential, or hosting
//!   posture**, and no general duration/expiry field. The one named duration
//!   exception in canon is a mint-time field on the ARCH-0071 delegation
//!   record, which lives outside this module and is neither duplicated nor
//!   turned into an ask option here.
//!
//! # Folding existing shapes
//!
//! Four grant-shaped records predate this contract. They fold through
//! ADAPTERS ([`disclosure_grant_from_access_grant`],
//! [`action_grant_from_standing_outbound_grant`],
//! `action_grant_from_policy_scoped_grant`,
//! [`disclosure_grant_from_disclosure_scope`]) — never a migration, a
//! rewrite, or a byte/status/codec change to the source record.

mod adapters;
mod bound;
mod codec;
mod doors;
mod effect;
mod grant;
mod registry;
mod support;

#[cfg(test)]
mod tests;

pub use self::adapters::{
    access_grant_projection_is_active, action_grant_from_standing_outbound_grant,
    disclosure_grant_from_access_grant, disclosure_grant_from_disclosure_scope,
};
pub use self::bound::{
    ActionClass, ActionEnvelope, ActorBound, AudienceBound, BoundClass, BoundEnvelope,
    BoundSubject, ConsentDomain, DisclosureClass, DisclosureEnvelope, GrantBound,
    MAX_AUDIENCE_MEMBERS, MAX_CONSENT_REF_LEN, MAX_ENVELOPE_SELECTORS,
};
pub use self::codec::{
    CONSENT_GRANT_BODY_KEYS, CONSENT_GRANT_SCHEMA_VERSION, decode_consent_grant_row,
    encode_consent_grant_row,
};
pub use self::doors::{
    AuthenticatedOwner, ConsentEvaluation, bound_catastrophe_class, load_active_standing_grants,
};
pub use self::effect::{
    BULK_BLAST_RADIUS_FLOOR, CATASTROPHE_FLOOR_V1, CATASTROPHE_FLOOR_VERSION, CatastropheClass,
    ComposedEffect, ConsentDecision, EffectDigest, EffectFacts, ReversibilityClass, UndoFidelity,
};
pub use self::grant::{
    ActionGrant, CONSENT_CONTENT_KIND, CONSENT_REASON_APPROVE_ONCE, CONSENT_REASON_DENIED,
    CONSENT_REASON_REVOKED, CONSENT_REASON_STANDING_CREATED, CONSENT_REASON_STANDING_USED,
    ConsentGrant, ConsentGrantRow, ConsentGrantStatus, ConsentGuard, ConsentOwnerStamp,
    ConsentProposal, ConsentReceipt, DisclosureGrant, StandingConsentGrant,
};
pub use self::registry::{
    CONSENT_REVOKE_COMMAND, ConsentRegistry, ConsentRegistryQuery, ConsentRegistryRow,
    ConsentRevokeAction,
};

pub(crate) use self::bound::bound_exceeded;
pub(crate) use self::doors::{
    approve_once_authorization_in_txn, revoke_standing_grant_in_txn, spend_approve_once_in_txn,
    standing_grant_is_active_in_txn,
};
pub(crate) use self::effect::{
    ApproveOnceAuthorization, classify_composed_effect, evaluate_consent,
};

// The flat consent.rs module used to provide these names to the test module
// through `use super::*`; after the directory split the seam re-imports them so
// the sibling `tests.rs` resolves exactly as it did inline.
#[cfg(test)]
use rmpv::Value;

#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::disclosure::{DisclosureScope, DisclosureScopeStatus};
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::gate::PolicyScopedGrant;
#[cfg(test)]
use crate::outbound_grant::StandingOutboundGrantScope;
#[cfg(test)]
use crate::store::GateDecisionId;

#[cfg(test)]
use self::adapters::{action_grant_from_policy_scoped_grant, outbound_scope_axes};
#[cfg(test)]
use self::bound::DOMAIN_ACTION;
#[cfg(test)]
use self::codec::{
    ENVELOPE_KEYS, KEY_CLASS, KEY_CREATED_AT, KEY_DOMAIN, KEY_ENVELOPE, KEY_OWNER_STAMP,
    KEY_SCHEMA_VERSION, KEY_STATUS, KEY_SUBJECT, OWNER_STAMP_KEYS, SUBJECT_KEYS,
};
#[cfg(test)]
use self::support::{CONSENT_GRANT_KEY_PREFIX, SUBJECT_KIND_AUDIENCE};
