//! Door to the decode of a stored POLICY_MANIFEST's booking anti-abuse rule
//! field (Engine RULING HOLD-CAP-STORED-MANIFEST = A, 16 Nov 00:48): a test
//! hands the field's value as a vault holds it and reads back the rows the
//! policy manifest decode keeps.

use crate::booking::anti_abuse::{
    BOOKING_ANTI_ABUSE_RULES_KEY, BookingAntiAbuseRuleRow, decode_manifest_rule_field,
};

/// Decodes `value` as a stored policy manifest's booking anti-abuse rule
/// field. `None` is the answer that makes the whole manifest undecodable.
#[must_use]
pub fn decode_stored_rule_field(value: rmpv::Value) -> Option<Vec<BookingAntiAbuseRuleRow>> {
    decode_manifest_rule_field(&[(rmpv::Value::from(BOOKING_ANTI_ABUSE_RULES_KEY), value)])
}
