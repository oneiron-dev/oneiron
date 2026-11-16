use rmpv::Value;

use crate::error::Result;
use crate::side_table::{self, SideTable};

use super::bound::{ActionClass, BoundClass, ConsentDomain, DisclosureClass, GrantBound};
use super::grant::ConsentGrantRow;
use super::support::{invalid_row, required_value, validate_keys};

/// Standing consent-grant rows, keyed by the grant's own hex64 digest
/// reference — an arbitrary caller-supplied string at the API boundary
/// (`revoke_consent_grant`), never format-checked before this migration, so
/// the key stays generic text rather than a validating hex64 type.
pub(super) const GRANTS: SideTable<String, ConsentGrantRow, side_table::Raw> =
    SideTable::new(&side_table::CONSENT_STANDING_GRANT);

/// Writes one standing consent Grant row under `grant_ref`, and the standing
/// outbound grant indexes' keys for it, in the caller's write transaction.
/// Every Grant row write goes through here, so a complete index names every
/// outbound grant row (census L3-28A).
pub(super) fn put_grant_row_in_txn(
    store: &crate::store::Store,
    wtxn: &mut heed::RwTxn<'_>,
    grant_ref: &str,
    row: &ConsentGrantRow,
) -> Result<()> {
    GRANTS.put(store, wtxn, &grant_ref.to_owned(), row)?;
    crate::outbound_grant::index_standing_outbound_grant_row_in_txn(store, wtxn, grant_ref, row)
}

#[doc(hidden)]
pub use oneiron_consent_state::consent::codec::{
    CONSENT_GRANT_BODY_KEYS, CONSENT_GRANT_SCHEMA_VERSION, decode_consent_grant_row,
    encode_consent_grant_row,
};
#[doc(hidden)]
pub(super) use oneiron_consent_state::consent::codec::{
    KEY_CLASS, KEY_DOMAIN, KEY_ENVELOPE, KEY_SUBJECT,
};
#[doc(hidden)]
use oneiron_consent_state::consent::codec::{
    decode_envelope, decode_subject, encode_envelope, encode_subject,
};
// The consent tests read these key names through `super::codec` (consent/mod.rs, cfg(test)); the moved codec
// was their only other user.
#[cfg(test)]
#[doc(hidden)]
pub(super) use oneiron_consent_state::consent::codec::{
    ENVELOPE_KEYS, KEY_CREATED_AT, KEY_OWNER_STAMP, KEY_SCHEMA_VERSION, KEY_STATUS,
    OWNER_STAMP_KEYS, SUBJECT_KEYS,
};

/// Canonical bound-only value used by propose-only widen deltas.
pub(super) fn encode_bound_value(bound: &GrantBound) -> Result<Value> {
    Ok(Value::Map(vec![
        (
            Value::from(KEY_DOMAIN),
            Value::from(bound.domain().as_str()),
        ),
        (Value::from(KEY_SUBJECT), encode_subject(bound.subject())),
        (Value::from(KEY_CLASS), Value::from(bound.class().as_str())),
        (
            Value::from(KEY_ENVELOPE),
            encode_envelope(bound.envelope())?,
        ),
    ]))
}
pub(super) fn decode_bound_value(value: &Value) -> Result<GrantBound> {
    let Value::Map(entries) = value else {
        return Err(invalid_row());
    };
    validate_keys(entries, &[KEY_DOMAIN, KEY_SUBJECT, KEY_CLASS, KEY_ENVELOPE])?;
    let domain = required_value(entries, KEY_DOMAIN)?
        .as_str()
        .and_then(ConsentDomain::parse)
        .ok_or_else(invalid_row)?;
    let subject = decode_subject(required_value(entries, KEY_SUBJECT)?, domain)?;
    let class = required_value(entries, KEY_CLASS)?
        .as_str()
        .ok_or_else(invalid_row)?;
    let class = match domain {
        ConsentDomain::Action => BoundClass::Action(ActionClass::new(class)?),
        ConsentDomain::Disclosure => BoundClass::Disclosure(DisclosureClass::new(class)?),
    };
    GrantBound::new(
        subject,
        class,
        decode_envelope(required_value(entries, KEY_ENVELOPE)?, domain)?,
    )
}

#[cfg(test)]
impl crate::Vault {
    /// Stores `bound` as an active standing grant under `stamper`'s stamp with
    /// no door's check: a row the owner-tier mint refuses, such as one a guest
    /// stamped for themselves.
    pub(crate) fn put_standing_grant_unchecked_for_test(
        &self,
        stamper: &super::AuthenticatedOwner,
        bound: GrantBound,
    ) -> Result<String> {
        self.with_write_txn(|wtxn| {
            let row = ConsentGrantRow {
                grant: super::grant::StandingConsentGrant::from_bound(bound)?,
                status: super::grant::ConsentGrantStatus::Active,
                owner_stamp: stamper.stamp(),
                created_at: crate::ports::recorded_at_in_txn(&self.store, wtxn)?,
                bypass: None,
            };
            let grant_ref = super::grant::consent_grant_row_grant_ref(&row);
            put_grant_row_in_txn(&self.store, wtxn, &grant_ref, &row)?;
            Ok(grant_ref)
        })
    }
}
