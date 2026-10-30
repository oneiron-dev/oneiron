//! Live office body records and Vault doors.
//! Entry: `Vault::import_office_body`.
//! records owns the record types; doors owns Vault methods; support owns shared helpers.
//!
//! Live office bodies (ARCH-0075; ARCH-0077, "Multiplayer: the target body
//! shape"): an imported DOCX, XLSX or PPTX as a typed model, edited together,
//! the file an export.
//!
//! People edit the live body. Machine work runs on a fork and lands as a
//! three-way diff. A DOCX or XLSX fork joins a proposal when it is opened, and
//! lands on a person's word from outside its opener's lineage or on a standing
//! grant ([`consent`]). Every commit keeps a MadeBy receipt over its exact
//! operations. An export projects the body onto
//! the imported package and lands it as a new version of the artifact, recorded
//! with the body frontier it projects.
//!
//! Every body is a Loro document on the entity-document plane's typed-body
//! door ([`crate::typed_body`], schemas `office.docx.v1`, `office.xlsx.v1` and
//! `office.pptx.v1`), which keeps its commits and receipts. A DOCX export
//! lands as one tracked revision. An XLSX body is a map keyed by sheet and
//! address; its export writes the changed cells and names and recalculates in
//! process, and [`Vault::preview_xlsx_body`] shows the recalculated values
//! without landing a version. DOCX and XLSX forks are typed-body forks.
//!
//! A PPTX body is the OF-510 live deck: one tree with a rich-text body per
//! text shape, whose concurrent edits merge and must still keep the deck's
//! tree rules. Its machine work runs on a deck fork kept in this module's
//! tables and lands through the deck preflight, and its export stays a
//! proposal artifact until the deck export gate opens. Erasing the artifact
//! erases its office rows ([`erase_in_txn`]).

mod actor_erase;
mod author_token;
pub(crate) mod checkpoint;
mod consent;
mod docx;
mod doors;
mod fork;
mod holder_ask;
mod live_units;
mod pptx;
mod records;
mod resources;
mod support;
mod verbs;
mod xlsx;

pub(crate) use actor_erase::{
    erase_export_actor_in_txn, erase_fork_actor_in_txn, erase_oracle_actor_in_txn,
    erase_proposal_actor_in_txn,
};
pub use consent::{
    AnsweringAuthority, BundleVerdict, MemberAnswer, MemberVerdict, OFFICE_BODY_EDIT_CLASS,
    OfficeBodyProposal, ProposalAsk, ProposalAskRefusal, ProposalHeader, ProposalMember,
    ProposalSettleRequest, ProposalSettlement, ReviewedFork, SettleVerdict,
};
pub(crate) use consent::{DiscardAdmission, MergeAdmission};
pub use docx::{BodyBlock, BodyBlockKind, DocxBody, DocxBodyOp};
pub use fork::{BlockChange, BodyConflict, ChangeKind, ConflictKind, OfficeBodyDiff};
pub use live_units::LivePin;
pub(crate) use live_units::{LiveChange, LiveSheet};
pub use oneiron_docedit::live::LandingReceipt;
pub use oneiron_docedit::xlsx_body::{
    XlsxArea, XlsxBook, XlsxLock, XlsxSheetVisibility, XlsxStyle, XlsxTable, XlsxValue,
};
pub use pptx::merge_deck_peers;
pub use pptx::{
    DeckBodyView, DeckExportRequest, DeckExportView, DeckForkMergeRequest, DeckGateRequest,
    DeckGateView, DeckNodeView, DeckOracleRequest, DeckPreview, DeckPreviewRequest,
    DeckPreviewSlide, DeckReviewView, PptxBody, PptxExport, PptxReview,
};
pub(crate) use pptx::{deck_json_values, deck_log_ops, live_refused};
pub use verbs::{
    DocxBlockView, DocxBodyView, DocxCellView, OfficeBodyArtifactRequest, OfficeBodyCommitGap,
    OfficeBodyCommitView, OfficeBodyCommitsRequest, OfficeBodyEditRequest,
    OfficeBodyExportVerbRequest, OfficeBodyExportView, OfficeBodyForkEditRequest,
    OfficeBodyForkMergeRequest, OfficeBodyForkOpenRequest, OfficeBodyForkRequest,
    OfficeBodyImportRequest, OfficeBodyOps, OfficeBodyPreviewRequest, OfficeBodyProposalRequest,
    OfficeBodyProposalSettleRequest, OfficeBodyReadRequest, OfficeBodyReviewedFork, OfficeBodyView,
    XlsxBodyView, XlsxSheetView,
};
pub use xlsx::{BodyCell, BodyFormat, BodyName, BodySheet, XlsxBody, XlsxBodyOp};

use crate::Vault;
use crate::batch::secret_scan::LiftedKeys;
use crate::blob_artifact::{BlobArtifactVersion, BlobVersionProvenance, CalcEngineStamp};
use crate::edge::EdgeActorClass;
use crate::edit_roundtrip::OfficeFormat;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::provenance::made_by::MadeBy;
use crate::provenance::text_commit::TextCommitReceipt;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::typed_body::{
    BodyActor, LiftedSources, TypedBodyFork, TypedBodyHead, TypedBodyWriter, TypedForkState,
    birth_typed_body_in_txn, discard_typed_body_fork_in_txn, edit_typed_body_fork_in_txn,
    edit_typed_body_in_txn, open_typed_body_fork_in_txn, typed_body_fork_in_txn, typed_body_in_txn,
};
use crate::write_envelope::WriteActor;
use heed::{RoTxn, RwTxn};
use loro::LoroDoc;
use oneiron_docedit::ArchiveLimits;
use oneiron_docedit::docx_body::{DocxRevision, project_docx, read_docx_blocks};
use oneiron_docedit::retained_opc::Limits;
use oneiron_docedit::xlsx_body::{mark_full_calc, project_xlsx, read_xlsx_cells};
use oneiron_xlsx_formula::RecalcClock;
use oneiron_xlsx_formula::engine::FormualizerEngine;
use serde::{Deserialize, Serialize};

pub use oneiron_docedit::resource::{RESERVE_STEP, ResourcePort, ResourceRefusal, Resources};
use records::{EXPORTS, FORKS, OfficeBodyRead, OfficeBodySource, SOURCES};
pub use records::{
    ForkState, OfficeBodyEdit, OfficeBodyExport, OfficeBodyExportRecord, OfficeBodyExportRequest,
    OfficeBodyFork, OfficeBodyHead, OfficeBodyKind, OfficeRecalcZone, XlsxPreview,
};
pub use resources::{
    DocumentMemory, document_resources, document_resources_until, register_document_memory,
};
pub(crate) use resources::{document_error, document_refused, docx_error};
use support::{
    apply_all, apply_xlsx, bounded_ops, check_made_by, claim_source, fork_view, loro_kind,
    open_fork, recalc_label, recalc_xlsx, source, three_way, timestamp, validate, version_key,
    writer,
};
pub(crate) use support::{erase_in_txn, fork_waits};

fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.into())
}
