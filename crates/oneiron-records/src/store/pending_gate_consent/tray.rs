//! Moved from `crates/oneiron/src/store/pending_gate_consent/tray.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::store::pending_gate_consent::records::PendingGateConsentRecord;
use crate::store::pending_gate_consent::records::decode_pending_gate_consent;
use crate::store::pending_gate_consent::records::encode_pending_gate_consent;
use oneiron_store::side_table::codec::CodecError;
use oneiron_store::side_table::codec::RawValue;

impl RawValue for PendingGateConsentRecord {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(encode_pending_gate_consent(self)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(decode_pending_gate_consent(bytes)?)
    }
}
