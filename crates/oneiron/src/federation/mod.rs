//! Federation grant record substrate.
//!
//! A federation grant is a vault-resident membership record for a shared
//! vault. The body is a pinned MessagePack map with fail-closed decoding:
//! unknown keys, duplicate keys, unknown role/preset strings, unsupported
//! scope kinds, and preset/role mismatches are rejected.

mod codec;
mod coreference;
mod grant;
mod guest;
mod pact_scope;
mod peer_authority;
mod relationships;
mod stale;

pub use self::coreference::{
    COREFERENCE_LINK_WEIGHT, CoreferenceStatus, coreference_share_consent,
    coreference_shared_for_pact, put_coreference_link,
};
pub use self::grant::{
    FEDERATION_GRANT_BODY_KEYS, FEDERATION_GRANT_SCHEMA_VERSION, FederationGrant,
    FederationGrantPreset, FederationGrantRole, FederationGrantScope, MAX_DELEGATE_TTL_SECS,
    decode_federation_grant_body, encode_federation_grant_body,
};
pub use self::guest::{
    GUEST_SHARE_ENVELOPE_BODY_KEYS, GUEST_SHARE_ENVELOPE_KEYS, GUEST_SHARE_ENVELOPE_SCHEMA_VERSION,
    GuestShareEnvelope, GuestShareEnvelopeBody, encode_guest_share_envelope,
    encode_guest_share_envelope_body, sign_guest_share_envelope,
};
pub use self::pact_scope::{
    FEDERATION_PACT_SCOPE_SCHEMA_VERSION, FederationDirectionScope, FederationPactScope,
    FederationScopeBands, FederationScopeFacets, FederationScopeWorlds, SelectorRange,
    decode_federation_pact_scope, encode_federation_pact_scope, selector_range_of,
};
pub use self::peer_authority::{
    MAX_PEER_AUTHORITY_ENTRIES_PER_PEER, PEER_AUTHORITY_KEY_PREFIX, admit_peer_authority_log_entry,
    peer_authority_entry_key, peer_authority_roster, peer_consent_roots,
};
pub use self::relationships::{
    MAX_RELATIONSHIP_LABEL_BYTES, MemberRelationship, MemberRelationshipContext,
    PREDICATE_RELATIONSHIP_LABEL, PREDICATE_RELATIONSHIP_PERSON_REF, RelationshipTrustClass,
    bind_member_person, default_retrieval_bands, default_trust_tier, put_member_relationship_label,
    relationship_trust_class, resolve_member_relationship,
};
pub use self::stale::{
    FEDERATION_STALE_KEY_PREFIX, FEDERATION_WORLD_KEY_PREFIX, FederationStaleReason,
    WORLD_STALE_STAMP_LEN, WorldStaleStamp, apply_federation_stale_stamps,
    decode_world_stale_stamp, encode_world_stale_stamp, foreign_world_stale_stamp,
    world_stale_marker,
};

pub(crate) use self::grant::{
    FEDERATION_GRANT_FIELDS_FULL, FEDERATION_GRANT_FIELDS_MINIMAL,
    FEDERATION_GRANT_FIELDS_STANDARD, validate_federation_grant_body_bytes,
};
pub(crate) use self::pact_scope::{
    decode_federation_direction_scope_value, decode_federation_pact_scope_value,
    federation_direction_scope_value, federation_pact_scope_value,
};
pub(crate) use self::peer_authority::admitted_peer_consent_roots_in_txn;
pub(crate) use self::stale::stale_stamped_worlds;

// These two are test-only doors (federation, pipeline, and context-pack
// suites); the re-export is cfg(test) so the non-test build sees no unused
// import, matching the flat module's test-only use.
#[cfg(test)]
pub(crate) use self::stale::{federation_stale_key, register_foreign_world_for_pact};

#[cfg(test)]
mod tests;

// The flat federation.rs module used to provide these names to the sibling test
// module through `use super::*`: the shared codec helpers and the grant key
// tables the tests name bare. After the directory split the seam re-imports
// them so `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use self::{codec::*, grant::*};
#[cfg(test)]
use crate::authority::{
    AuthorityFold, AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthorityVaultId,
    authority_entry_hash, fold_peer_authority_log, genesis_vault_id,
};
#[cfg(test)]
use crate::claim::{
    COREFERENCE_PACT_ID_LEN, ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource,
    ClaimSubject,
};
#[cfg(test)]
use crate::edge::EdgeKind;
#[cfg(test)]
use crate::entity_id::{EntityId, ForeignWorldId, bytes_to_hex_lower, is_foreign_world_id_range};
#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(test)]
use crate::temporal::TimeRange;
#[cfg(test)]
use crate::vault::Vault;
#[cfg(test)]
use crate::write_envelope::WriteActor;
#[cfg(test)]
use rmpv::Value;
#[cfg(test)]
use std::collections::{BTreeMap, BTreeSet};
#[cfg(test)]
use std::io::Cursor;
