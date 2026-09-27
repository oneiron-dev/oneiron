//! Read-only PDF parse plus byte-exact incremental-update writer (§7.1, §7.2).
//!
//! `lopdf` is used only to inspect objects and references. Signed-output
//! bytes are emitted by the writer here; every pre-existing input byte is
//! preserved and all changes are appended revisions.

mod incremental;
mod lex;
mod objects;
mod parse;
mod revision_chain;
mod revision_facts;
#[cfg(test)]
mod tests;

pub(crate) use self::incremental::{
    append_revision, field_name_for, hash_byte_range, patch_contents, pdf_date,
};
pub(crate) use self::objects::{DraftRevision, RevisionKind};
pub(crate) use self::parse::{
    PreparedInput, analyze_security, last_startxref, reparse_revision, validate_prepared,
};
#[cfg(test)]
pub(crate) use self::parse::{RevisionState, XrefStyle};
pub(crate) use self::revision_chain::{
    RevisionBoundary, bind_range, file_tail_covered, load_snapshot, revision_ends,
};

#[cfg(test)]
use self::parse::*;

pub(crate) use self::revision_facts::{RevisionFacts, analyze as analyze_revision_facts};
