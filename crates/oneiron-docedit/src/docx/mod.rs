//! Native docx editing: tracked-change part writer plus span comments.
//!
//! The step-24 native lane. Text ops emit Word's own revision marks
//! (`w:ins`/`w:del`) through a retained splicing writer that preserves
//! unknown XML in place; comment ops anchor legacy comment ranges plus rows;
//! the linker re-checks cross-part references; the pipeline binds the output
//! to a manifest and a prepared handoff over the retained OPC substrate.
//! Uses the pinned stateless stemma source fork; see `vendor/stemma/PROVENANCE.md`.
//! Word validity is judged by the Mac oracle, never claimed here.

mod anchor;
mod handoff;
pub use anchor::replay_span;
mod comments;
mod inspect;
mod join;
mod linker;
mod ops;
mod pipeline;
mod retained_run;
mod revision;
mod settings;
mod stamp;
mod writer;

pub use comments::{
    CommentWrite, apply_comment, comments_override_row, comments_rel_row, next_comment_id,
};
pub use inspect::{DocxStructure, inspect_docx};
pub use linker::{DocxLinkCheck, DocxLinkReport, check_docx_links};
pub use ops::{DocxAnchorEffect, DocxOp, DocxSpan};
pub use pipeline::{
    DOCX_MANIFEST_SCHEMA_VERSION, DocxManifest, DocxOutcome, DocxPlan, DocxPrepared, DocxProposal,
    DocxValidationCheck, DocxValidationReport, run_docx_roundtrip,
};
pub use settings::{DocxProtection, DocxSettings, inspect_docx_settings};
pub use stamp::{DOCX_ENGINE, DOCX_ENGINE_VERSION, DOCX_STEMMA_PIN, DocxEngineStamp};
pub use writer::{RevisionMark, TextWrite, apply_text_op, next_revision_id};

#[cfg(test)]
mod tests;
