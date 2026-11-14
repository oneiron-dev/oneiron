//! Edit operation vocabulary and anchor effects.

use super::address::column_to_letters;
use super::{Axis, CellRef, RangeRef};
use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub use oneiron_records::edit_roundtrip::ops::{
    AnchorEffect, CellValue, CellWrite, EditOp, StructuralShift,
};
