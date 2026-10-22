//! The full sources a repo's symbol graph is derived from (FIX 7608 slice
//! 3): a file a receive mark covers is projected whole, BEFORE any
//! definition, chunk, fingerprint or line range is parsed out of it, so
//! nothing the graph keeps is derived from its stored bytes. A whole-blob
//! mark cannot be found from a chunk's hash, so masking after the parse
//! would be too late.
//!
//! The parser, the diff utility and the supplied-graph writers keep their
//! contracts; this is the stored-repo provider of their inputs. A file the
//! parser read before is read again, as its copy: an opaque file reads as
//! the sealed-file placeholder, keeping its place in the snapshot and its
//! searchable document while no definition of its stored bytes survives.

use std::borrow::Cow;

use heed::RoTxn;

use crate::Vault;
use crate::error::Result;
use crate::origin::secret_projection::index::RepoIndexMarks;

/// Each of `files`' full source as the symbol parser reads it, `(path,
/// stored bytes)` in: a marked blob's copy, any other file its stored text
/// borrowed. A file whose stored bytes are not UTF-8 is left out, as the
/// parser always left it.
///
/// # Errors
/// A store failure reading a marked blob's mask row.
pub(crate) fn masked_repo_symbol_texts_in_txn<'a, I>(
    vault: &Vault,
    txn: &RoTxn<'_>,
    marks: &RepoIndexMarks,
    files: I,
) -> Result<Vec<(&'a str, Cow<'a, str>)>>
where
    I: IntoIterator<Item = (&'a str, &'a [u8])>,
{
    let mut texts = Vec::new();
    for (path, bytes) in files {
        let Ok(text) = std::str::from_utf8(bytes) else {
            continue;
        };
        if marks.is_empty() || !marks.is_marked(blake3::hash(bytes).as_bytes()) {
            texts.push((path, Cow::Borrowed(text)));
            continue;
        }
        let copy = marks.input_in_txn(vault, txn, bytes.to_vec())?.into_text();
        texts.push((path, Cow::Owned(copy)));
    }
    Ok(texts)
}
