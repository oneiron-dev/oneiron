//! Counterparty contact record substrate (OF-347 CID-7).
//!
//! A CounterpartyContactRecord is a vault-resident per-(channel identity,
//! counterparty) consent/contact row plus a typed `counterparty_contact.*`
//! claim family. Provider adapters and multiplayer graph expansion are
//! intentionally outside this module.
//!
//! A [`TrustedContact`] (OF-527) is a person's consented contact for a
//! crisis notice, fired only by the policy gate's `RouteToHelp`.

mod codec;
mod doors;
mod lifecycle;
mod storage;
mod trusted_contact;
mod trusted_contact_notice;
mod types;

pub use self::codec::{
    decode_counterparty_contact_body, encode_counterparty_contact_body,
    is_counterparty_contact_claim_predicate,
};
pub(crate) use self::codec::{
    validate_counterparty_contact_body_bytes, validate_counterparty_contact_claim_structure,
};
#[cfg(test)]
pub(crate) use self::lifecycle::rematerialize_contact_cache_in_txn;
pub use self::lifecycle::{drop_contact_cache_row, rematerialize_contact_cache};
pub(crate) use self::lifecycle::{
    drop_contact_index_rows_in_txn, rematerialize_party_contact_cache_in_txn,
    supersede_family_owned_claim_in_txn,
};
pub use self::storage::{counterparty_contact_party_channel_index_key, normalize_channel_class};
pub(crate) use self::storage::{
    counterparty_contacts_for_send_in_claims_in_txn, party_has_contact_on_class_in_claims_in_txn,
    read_counterparty_contact_in_txn,
};
pub(crate) use self::trusted_contact::TrustedContactFire;
pub use self::trusted_contact::{
    TrustedContact, TrustedContactAcceptance, TrustedContactAnswer, TrustedContactAsk,
    TrustedContactAskOutcome, TrustedContactDial, TrustedContactParty, TrustedContactReach,
    TrustedContactRevocation, TrustedContactTier,
};
pub use self::trusted_contact_notice::{
    TRUSTED_CONTACT_NOTICE_ATTEMPT_KIND, TRUSTED_CONTACT_NOTICE_CONTENT_REF, TrustedContactNotice,
};
pub use self::types::{
    COUNTERPARTY_CONTACT_BODY_KEYS, COUNTERPARTY_CONTACT_CLAIM_PREDICATES,
    COUNTERPARTY_CONTACT_SCHEMA_VERSION, CounterpartyContactRecord, CounterpartyContactStatus,
    CounterpartyFirstTouch, CounterpartyOptOut, CounterpartyOptOutReason,
    PREDICATE_COUNTERPARTY_CONTACT_COUNTERPARTY, PREDICATE_COUNTERPARTY_CONTACT_CREATED_AT,
    PREDICATE_COUNTERPARTY_CONTACT_FIRST_TOUCH, PREDICATE_COUNTERPARTY_CONTACT_IDENTITY_REF,
    PREDICATE_COUNTERPARTY_CONTACT_NOTES, PREDICATE_COUNTERPARTY_CONTACT_OPT_OUT,
    PREDICATE_COUNTERPARTY_CONTACT_PROMO_CONSENT, PREDICATE_COUNTERPARTY_CONTACT_REVOKED_AT,
    PREDICATE_COUNTERPARTY_CONTACT_STATUS, PREDICATE_COUNTERPARTY_CONTACT_UPDATED_AT,
};
pub(crate) use self::types::{
    COUNTERPARTY_CONTACT_FIELDS_FULL, COUNTERPARTY_CONTACT_FIELDS_MINIMAL,
    COUNTERPARTY_CONTACT_FIELDS_STANDARD,
};

#[cfg(test)]
mod tests;
#[cfg(test)]
mod trusted_contact_tests;

#[cfg(test)]
use self::lifecycle::comm_fold_error;
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::claim::ClaimLifecycleStatus;
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::Result;
#[cfg(test)]
use rmpv::Value;

pub(crate) use self::storage::rebuild_checkpoint_contact_index;
