//! Read-only PDF parse plus byte-exact incremental-update writer (§7.1, §7.2).
//!
//! `lopdf` is used only to inspect objects and references. Signed-output
//! bytes are emitted by the writer here; every pre-existing input byte is
//! preserved and all changes are appended revisions.

mod incremental;
mod objects;
mod parse;
#[cfg(test)]
mod tests;

pub(crate) use self::incremental::{
    append_revision, field_name_for, hash_byte_range, patch_contents, pdf_date,
};
pub(crate) use self::objects::{DraftRevision, RevisionKind};
pub(crate) use self::parse::{PreparedInput, last_startxref, reparse_revision, validate_prepared};
#[cfg(test)]
pub(crate) use self::parse::{RevisionState, XrefStyle};

#[cfg(test)]
use self::parse::*;
