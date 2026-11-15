//! Door to the burst ledger's read of one stored receipt row (L7-41, the
//! lead's M-1 STORED-CHANGE-RULE): a test hands it the bytes of a receipt in
//! the shape a vault stored before own devices had receipts.

use crate::Result;
use crate::sync::federation_burst::{FederationBurstPeerRef, FederationBurstReceipt};

/// The ledger's read of stored receipt `bytes` for batch `batch_ref` and the
/// peer `named`, exactly as a burst read or review list loads it.
pub fn decode_burst_receipt_row(
    bytes: &[u8],
    named: &FederationBurstPeerRef,
    batch_ref: &str,
) -> Result<FederationBurstReceipt> {
    let id = crate::deletion::parse_hex::<32>(batch_ref)
        .ok_or_else(|| crate::Error::InvalidConfig("invalid batch_ref".into()))?;
    crate::sync::federation_burst::decode_receipt_row(bytes, named, &id)
}
