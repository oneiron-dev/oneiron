//! A typed body's view as a reader masked from lifted keys reads it
//! (OF-067): the body read, a fork's diff and merge, a proposal and its
//! settlement, a workbook preview and a deck review all mask here, so the
//! masks cannot drift apart from one view to the next (FIX 12302).

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::batch::secret_scan::{LiftedKeys, mask_spanning_json, mask_unplaced_json};
use crate::memory::MemoryResult;

/// `view` as a reader masked from lifted keys reads it: each value `keys`
/// holds as its handle; then each string that still shows a key no mark
/// places as the door's placeholder (FIX 8996, FIX 12233); then each string
/// a key split over adjacent strings touches as the placeholder too, where
/// the view's type still decodes (FIX 12232). These views only mask: none
/// opens a write or files a proposal (FIX 12302).
pub(super) fn masked_body_view<T: Serialize + DeserializeOwned>(
    keys: &LiftedKeys,
    view: T,
) -> MemoryResult<T> {
    let mut value = serde_json::to_value(&view)
        .map_err(|_| crate::Error::InvariantViolation("a typed body view did not encode"))?;
    let lifted = keys.mask_json(&mut value);
    let unplaced = mask_unplaced_json(&mut value);
    let spanning = mask_spanning_json(&mut value, &|masked| T::deserialize(masked).is_ok())?;
    if !(lifted || unplaced || spanning) {
        return Ok(view);
    }
    Ok(serde_json::from_value(value).map_err(|_| {
        crate::Error::InvariantViolation("a masked typed body view did not decode")
    })?)
}
