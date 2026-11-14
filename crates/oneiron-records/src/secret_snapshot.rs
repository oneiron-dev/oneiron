//! Moved from `crates/oneiron/src/secret_snapshot.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use heed::RoTxn;
use oneiron_base::error::CodeError;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_store::side_table::codec::CodecError;
use oneiron_store::side_table::codec::RawValue;
pub use oneiron_verb_wire::secret_snapshot::SnapshotSecretLiftProposal;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// The durable, value-free outcome of snapshot custody filtering.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotCustodyReport {
    pub excluded_secret_paths: Vec<String>,
    pub quarantined_paths: Vec<String>,
    pub proposals: Vec<SnapshotSecretLiftProposal>,
}

/// The side table's declared codec is `Raw`, not `Named`: the put/get/delete call sites in
/// `codebase/store.rs` have always written this report through `rmp_serde::to_vec_named` and read
/// it back through a plain (non-strict) `rmp_serde::from_slice`, so this impl keeps exactly that
/// pair rather than switching to the door's strict whole-row `Named` decode.
impl RawValue for SnapshotCustodyReport {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(encode_report(self)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        rmp_serde::from_slice(bytes).map_err(|_| {
            Error::Code(CodeError::InvalidCodebaseSnapshotBody(
                "decode custody report",
            ))
            .into()
        })
    }
}

pub fn encode_report(report: &SnapshotCustodyReport) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(report).map_err(|_| {
        Error::Code(CodeError::InvalidCodebaseSnapshotBody(
            "encode custody report",
        ))
    })
}
