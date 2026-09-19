//! ARTL inspect/edit/recalculate/validate stages, independent of storage and authority.
mod address;
pub(crate) mod inspect;
mod manifest;
mod ops;
mod pipeline;
mod session_validate;
mod store;
use crate::opc;
pub use address::{Axis, CellRef, OfficeFormat, RangeRef};
pub use inspect::{CrossSheetDep, SheetSummary, StructureSummary};
pub use manifest::{
    EDIT_MANIFEST_SCHEMA_VERSION, EditManifest, EditWarning, MutationMode, WarningCode,
};
pub use ops::{AnchorEffect, CellValue, CellWrite, EditOp, StructuralShift};
pub use pipeline::{EditOutcome, EditProposal, RecalcStatus, run_edit_roundtrip};
pub use session_validate::{
    AppliedEdit, EditPlan, EditSession, OfficeDoc, ValidationCheck, ValidationReport,
};
pub use store::{DocumentHead, DocumentStore, propose_document_edit};
#[cfg(test)]
mod tests;
#[cfg(test)]
use self::{inspect::*, session_validate::*};
#[cfg(test)]
use crate::{Error, Result};
