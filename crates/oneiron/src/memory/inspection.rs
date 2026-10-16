//! `vault.inspection.resolve` (OF-235): the bound actor reopens an
//! inspection link through its own read lane. The handle is untrusted
//! locator data; the lane's fresh point read is the whole admission.

use super::{Memory, MemoryError, MemoryResult};
use crate::claim::{ClaimReadStatus, ScopedReadResult};
use crate::lens::{
    InspectionResolveRequest, InspectionResolved, decode_inspection_handle,
    encode_inspection_handle,
};
use crate::vault::ReadMode;

impl Memory<'_> {
    /// Resolves an inspection handle for the bound actor. A target the actor
    /// cannot read, one that does not exist and one of another kind all
    /// answer with no item, under the same receipt.
    pub fn inspection_resolve(
        &self,
        request: &InspectionResolveRequest,
    ) -> MemoryResult<InspectionResolved> {
        let state = decode_inspection_handle(&request.handle)
            .map_err(|_| MemoryError::bad_request("handle is not an inspection handle"))?;
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let ScopedReadResult { value, receipt } =
            self.vault
                .inspect_state_projected(&lane, &state, |txn, row| match row {
                    Some(row) => self.entity_view_of_in_txn(&lane, txn, row, ReadMode::Live),
                    None => Ok(None),
                })?;
        Ok(InspectionResolved {
            state,
            handle: encode_inspection_handle(&state),
            item: value,
            narrowing: receipt,
        })
    }
}
