//! The CRM pack's claim families (CA-01).
//!
//! Six exact predicates live here — `campaign.member`, `crm.fit`, `crm.stage`,
//! `comm.do_not_contact`, `comm.bounce`, and `comm.jurisdiction`. The last three
//! carry a `comm.` prefix but are CA-owned: `comm.rs` stays SPINE-COMM's
//! projector hot zone, so the authoritative comm-residence seam puts their
//! constants, codecs, and validators here and routes them through the
//! `claim.rs` family chain by EXACT predicate match, which is more specific
//! than the `comm.` prefix family. No entity type byte, `EdgeKind`, or
//! serialization profile is minted at this layer.
//!
//! Two halves, mirroring `calendar::claims`:
//!
//! * `validate_campaign_pack_claim_structure` is the byte-level half wired
//!   into the write-only validator chain in `crate::claim`. It sees a decoded
//!   `ClaimBody` and no storage, so it enforces subject *shape* plus exact
//!   value shapes.
//! * `matching_do_not_contact_in_txn` is the store-aware half: the
//!   enforcement read the external-effect gate folds into
//!   `counterparty_opted_out`.
//!
//! Descriptor-gap posture: ARCH-0057's descriptor runtime does not exist in
//! engine Rust. Rather than block on it, every family here ships an interim
//! exact-predicate validator plus a pure-data `claim_class_descriptors` table
//! that is ready to register when the registry lands. Building that registry is
//! explicitly NOT this ticket's job.

mod codec;
mod store;
mod types;

pub use self::codec::{
    encode_campaign_member_value, encode_comm_bounce_value, encode_crm_stage_value,
    encode_do_not_contact_value, normalize_campaign_pack_token,
};
pub use self::store::{do_not_contact_applies, resolve_crm_fit, supersede_crm_stage_in_txn};
pub use self::types::{
    BounceKind, CAMPAIGN_PACK_CLAIM_PREDICATES, CampaignMemberChannel, CampaignMemberDerivation,
    CampaignMemberState, CampaignMemberValue, ClaimClassDescriptorRow, CommBounceValue,
    CommDoNotContactValue, CommJurisdictionValue, CrmFitValue, CrmFitVerdict, CrmStageValue,
    DO_NOT_CONTACT_SCOPE_ALL, EvidenceBasis, PREDICATE_CAMPAIGN_MEMBER, PREDICATE_COMM_BOUNCE,
    PREDICATE_COMM_DO_NOT_CONTACT, PREDICATE_COMM_JURISDICTION, PREDICATE_CRM_FIT,
    PREDICATE_CRM_STAGE, StageEvidenceClass, StageKey, claim_class_descriptors,
    is_campaign_pack_claim_predicate,
};

pub(crate) use self::codec::{
    decode_campaign_member_value, validate_campaign_pack_claim_structure,
};
pub(in crate::campaign) use self::codec::{decode_comm_jurisdiction_value, decode_crm_stage_value};

// These three decoders are named only by the sibling test module; the
// re-export exists in test builds so those paths keep resolving, and is
// absent otherwise so the non-test build carries no unused import.
#[cfg(test)]
use self::codec::{decode_comm_bounce_value, decode_crm_fit_value, decode_do_not_contact_value};
pub(crate) use self::store::counterparty_do_not_contact_in_txn;
pub(in crate::campaign) use self::store::{
    identical_live_head_in_txn, live_campaign_member_head_in_txn,
};

#[cfg(test)]
mod tests;

// The flat claims.rs module used to provide these names to the sibling test
// module through `use super::*`: its own private crate/std import header, and
// every claims-internal item the tests name bare. After the directory split
// the seam re-imports both so `tests.rs` resolves exactly as it did before.
// The key consts and the stage-head scanner live in private children with no
// seam re-export, so they are imported explicitly; everything else the tests
// name bare already arrives through the `pub`/`pub(crate)` seam above, and a
// glob here would double-bind those names and warn as unused.
#[cfg(test)]
use self::codec::{
    KEY_BASIS, KEY_BASIS_EVIDENCE, KEY_BOUNCE, KEY_CAMPAIGN, KEY_CAMPAIGN_REF, KEY_CHANNEL,
    KEY_CHANNELS, KEY_DERIVATION, KEY_EPOCH, KEY_EVIDENCE_CLASS, KEY_EVIDENCE_HASH,
    KEY_EVIDENCE_REFS, KEY_ICP_SCOPE, KEY_JURISDICTION, KEY_KIND, KEY_NEW_TRIGGER, KEY_OBSERVED_AT,
    KEY_OCCURRED_AT, KEY_RECORDED_AT, KEY_SCOPE, KEY_SENDER_REF, KEY_SOURCE_QUERY, KEY_STAGE,
    KEY_STATE, KEY_UNTIL, KEY_VERDICT,
};
#[cfg(test)]
use self::store::other_live_crm_stage_heads_in_txn;
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::claim::{ClaimLifecycleStatus, ClaimSubject};
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(test)]
use crate::registry::ENTITY_TYPE_PERSON;
#[cfg(test)]
use rmpv::Value;
