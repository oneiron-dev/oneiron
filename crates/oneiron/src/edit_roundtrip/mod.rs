//! ARTL-3 (OF-368 D5): agent edit round-trip — code-session pipeline.
//!
//! An agent implementing a commented change on a foreign office file (xlsx
//! first) runs in a code-session (doc 11: own=Wasmtime, foreign=microVM)
//! against a **copy** of the artifact's current bytes. The output is a
//! *retained output* — `(new blob bytes + [`EditManifest`])` — that touches
//! nothing until settled. This module owns the host-side orchestration and the
//! canonical [`EditManifest`]; settlement (append the version, mint the
//! receipt) is ARTL-4 and out of scope here.
//!
//! # Fidelity law (Grok DR 2026-07-07)
//!
//! Nothing round-trips 100%. The pipeline is **minimal-mutation + passthrough**:
//! it touches only supported elements and preserves unknown XML parts
//! byte-for-byte. The passthrough and corruption gates run in the engine (the
//! `opc` submodule) against the bytes the session produced, so the gate never
//! trusts the tool that wrote them.
//!
//! # Four mandatory stages
//!
//! 1. **Inspect-first** — the `inspect` stage summarizes structure (sheets, defined
//!    names, pivots/charts/macros presence, cross-sheet dependency map) before
//!    any edit. SpreadsheetBench evidence: skipping this is the dominant agent
//!    failure mode, so it always runs.
//! 2. **Targeted edit** — the agent's [`EditPlan`] is applied through the
//!    [`EditSession`] seam via narrow verbs ([`EditOp`]). In production the
//!    session library is Python openpyxl (`keep_vba=True, data_only=False`);
//!    umya-spreadsheet (Rust) and protobi/exceljs (JS) are recorded alternates.
//! 3. **Recalc** — when inputs/formulas changed, [`EditSession::recalc`]
//!    refreshes cached formula values. In production this is LibreOffice
//!    headless (a session-image dependency); HyperFormula/`formulas` is the
//!    recorded in-process fallback.
//! 4. **Corruption-check validation** — the `validate` stage runs an automated
//!    open/verify plus a passthrough diff. A failed check yields
//!    [`EditOutcome::Rejected`] and never reaches the proposal stage.
//!
//! # External-binary seam
//!
//! openpyxl and LibreOffice are NOT available in CI and are NOT repo
//! dependencies (D10 licensing wall: repo code is Apache/MIT only; openpyxl
//! lives in session images). They sit behind the [`EditSession`] trait so the
//! architecture is present but the whole gate passes with a mock. The pipeline
//! logic, manifest, inspection, and validation are pure Rust and fully tested
//! in CI against a fixture session.
//!
//! # Reconciliation seams
//!
//! * **ARTL-2 (anchored comments, ONE-1552)** consumes [`EditManifest::anchor_effects`]
//!   to replay row/column shifts, range moves, and sheet renames against its
//!   `(sheet, A1-range)` anchors. This module keeps its manifest self-contained
//!   and does not import ARTL-2 types; whichever PR merges second reconciles.
//! * **ARTL-4 (settle/receipts)** consumes an [`EditProposal`]:
//!   [`EditProposal::agent_run_provenance`] yields the
//!   [`BlobVersionProvenance::AgentRun`] to append, and [`EditManifest::to_msgpack`]
//!   the manifest bytes to receipt.

mod address;
mod inspect;
mod manifest;
mod opc;
mod ops;
mod pipeline;
mod session_validate;

pub use self::address::{Axis, CellRef, OfficeFormat, RangeRef};
pub use self::inspect::{CrossSheetDep, SheetSummary, StructureSummary};
pub use self::manifest::{
    EDIT_MANIFEST_SCHEMA_VERSION, EditManifest, EditWarning, MutationMode, WarningCode,
};
pub use self::ops::{AnchorEffect, CellValue, CellWrite, EditOp, StructuralShift};
pub use self::pipeline::{EditOutcome, EditProposal, RecalcStatus, run_edit_roundtrip};
pub use self::session_validate::{
    AppliedEdit, EditPlan, EditSession, OfficeDoc, ValidationCheck, ValidationReport,
};

#[cfg(test)]
mod tests;

// The flat edit_roundtrip.rs module used to provide these names to the sibling
// test module through `use super::*`: its own private crate/std import header,
// every edit-roundtrip-internal item the tests name bare, and the crate imports
// the tests rely on. After the directory split the seam re-imports them so
// `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use self::{inspect::*, session_validate::*};
#[cfg(test)]
use crate::blob_artifact::BlobVersionProvenance;
#[cfg(test)]
use crate::error::{Error, Result};
