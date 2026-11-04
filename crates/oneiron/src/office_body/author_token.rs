//! A DOCX export's default author (FIX 4513, Engine ruling B 10-19): the
//! bytes carry an opaque token, not the actor.
//!
//! An export the caller gave no author lands its tracked revision under a
//! fresh token, [`DOCX_AUTHOR_TOKEN_MARKER`] and a new id's hex, minted per
//! export and never derived from the actor. Its export record keeps the
//! token beside the actor, and the revision group hashes the token, so the
//! stored bytes and their content hash name no one. An author the caller
//! typed is document content and lands as typed.
//!
//! A copy leaving the vault reads each token it carries through the export
//! and per-group author rows: the actor's hex while the actor stands, [`ERASED_CALL_IDENTITY`]
//! once its erase forgot it. Only `word/document.xml` is read, as XML: a
//! token is read only as the whole value of a tracked revision's `w:author`
//! (FIX 9993), and only that value's quoted source is rewritten; text,
//! comments, every other attribute and a token inside a longer value stay
//! byte for byte. Only a copy that carries a token is zipped again. A token
//! no row here names stays as it is: one opaque id in place of another. The
//! stored bytes and every reader inside the vault keep the token.
//!
//! [`ERASED_CALL_IDENTITY`]: crate::receipt::ERASED_CALL_IDENTITY

mod carrier;
pub(super) mod index;

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use heed::RoTxn;
use oneiron_docedit::ooxml::{Node, XmlTree};
use oneiron_docedit::retained_opc::Package;

use super::{OfficeBodyExportRequest, OfficeBodyKind};
use crate::Vault;
use crate::error::Result;
use crate::receipt::ERASED_CALL_IDENTITY;

/// What a default author's token starts with; a new id's 32 hex characters
/// follow. It is no actor's id and no other marker's (FIX 4513).
pub(crate) const DOCX_AUTHOR_TOKEN_MARKER: &str = "oneiron-author:";

/// The hex characters after the marker.
const TOKEN_HEX_LEN: usize = 32;

/// The package part a DOCX keeps its tracked revisions in.
const DOCUMENT_PART: &str = "word/document.xml";

/// WordprocessingML's main namespace, the one a revision's `w:author` is in.
const W_MAIN: &str = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";

/// The WordprocessingML elements whose `w:author` names a tracked
/// revision's author (ECMA-376 Part 1, 17.13.5): the only attributes a
/// default author's token is read in.
const REVISION_ELEMENTS: &[&str] = &[
    "ins",
    "del",
    "moveFrom",
    "moveTo",
    "moveFromRangeStart",
    "moveToRangeStart",
    "customXmlInsRangeStart",
    "customXmlDelRangeStart",
    "customXmlMoveFromRangeStart",
    "customXmlMoveToRangeStart",
    "rPrChange",
    "pPrChange",
    "sectPrChange",
    "tblPrChange",
    "tblPrExChange",
    "trPrChange",
    "tcPrChange",
    "tblGridChange",
    "numberingChange",
    "cellIns",
    "cellDel",
    "cellMerge",
];

/// The author an export lands in its bytes, the one its record shows, and
/// the token, when it is one.
pub(super) struct ExportAuthor {
    pub(super) landed: String,
    pub(super) shown: String,
    pub(super) token: Option<String>,
}

impl ExportAuthor {
    /// The request's author as the caller gave it, or for a DOCX with none,
    /// a fresh token the record shows as the exporting actor. Another format
    /// lands no author.
    pub(super) fn of(
        vault: &Vault,
        kind: OfficeBodyKind,
        request: &OfficeBodyExportRequest<'_>,
    ) -> Result<Self> {
        let actor = request.actor.entity_ref();
        if let Some(author) = request.author {
            return Ok(Self {
                landed: author.to_owned(),
                shown: author.to_owned(),
                token: None,
            });
        }
        let token = match kind {
            OfficeBodyKind::Docx => Some(format!(
                "{DOCX_AUTHOR_TOKEN_MARKER}{}",
                vault.new_entity_id()?.to_hex()
            )),
            OfficeBodyKind::Xlsx | OfficeBodyKind::Pptx => None,
        };
        Ok(Self {
            landed: token.clone().unwrap_or_else(|| actor.to_hex()),
            shown: actor.to_hex(),
            token,
        })
    }
}

impl Vault {
    /// `bytes`, a copy of a stored version leaving the vault, with each
    /// default-author token read through the export rows (see the module).
    /// Any other file, and a DOCX with no token or none a row names, is
    /// returned as it is.
    ///
    /// # Errors
    ///
    /// Storage errors reading the export rows.
    pub(crate) fn resolve_docx_authors(&self, bytes: Vec<u8>) -> Result<Vec<u8>> {
        if !bytes.starts_with(b"PK\x03\x04") {
            return Ok(bytes);
        }
        let txn = self.store.env.read_txn()?;
        self.resolve_docx_authors_in_txn(&txn, bytes)
    }

    /// [`Vault::resolve_docx_authors`] in the caller's snapshot.
    ///
    /// # Errors
    ///
    /// Storage errors reading the export rows; memory or a deadline that
    /// stopped reading the document's XML, as that refusal.
    pub(crate) fn resolve_docx_authors_in_txn(
        &self,
        txn: &RoTxn<'_>,
        bytes: Vec<u8>,
    ) -> Result<Vec<u8>> {
        if !bytes.starts_with(b"PK\x03\x04") {
            return Ok(bytes);
        }
        // A package this vault's limits do not read was never an export's
        // projection: it is served as it is.
        let Ok(limits) = self.docedit_package_limits_in_txn(txn) else {
            return Ok(bytes);
        };
        let Ok(mut package) =
            Package::open(&bytes, limits, &crate::office_body::document_resources())
        else {
            return Ok(bytes);
        };
        let Ok(Some(document)) = package.part(DOCUMENT_PART) else {
            return Ok(bytes);
        };
        let tree = match XmlTree::parse(&document, package.resources()) {
            Ok(tree) => tree,
            Err(error) => match error.resource() {
                Some(refusal) => return Err(super::resources::document_refused(refusal)),
                None => return Ok(bytes),
            },
        };
        let tokens: BTreeSet<Vec<u8>> = tree
            .nodes
            .iter()
            .filter_map(revision_token)
            .map(|token| token.as_bytes().to_vec())
            .collect();
        if tokens.is_empty() {
            return Ok(bytes);
        }
        // Token keys follow copies across undo, restore and forks. The index
        // holds only canonical row keys; each lookup reads the current row.
        let mut authors: BTreeMap<Vec<u8>, String> =
            index::lookup_exports(&self.store, txn, &tokens)?
                .into_iter()
                .filter_map(|(_, record)| Some((record.token?.into_bytes(), record.actor.to_hex())))
                .collect();
        for (_, record) in index::lookup_authors(&self.store, txn, &tokens)? {
            let shown = record
                .actor
                .map_or_else(|| ERASED_CALL_IDENTITY.to_owned(), |actor| actor.to_hex());
            authors.insert(record.token.into_bytes(), shown);
        }
        // With no row naming a token, the copy holds none of ours. A token is
        // matched decoded, so no raw-byte scan stands in for this one.
        if authors.is_empty() {
            return Ok(bytes);
        }
        let Some(resolved) = swap_tokens(&document, &tree, &authors) else {
            return Ok(bytes);
        };
        match package
            .replace_xml_part(DOCUMENT_PART, resolved)
            .and_then(|()| package.export())
        {
            Ok(presented) => Ok(presented),
            Err(_) => Ok(bytes),
        }
    }
}

/// `document` with each default-author token `authors` names, as the whole
/// value of a tracked revision's `w:author`, replaced by its author; `None`
/// when it holds none. Only that value's quoted source is rewritten; every
/// other byte stays.
fn swap_tokens(
    document: &[u8],
    tree: &XmlTree,
    authors: &BTreeMap<Vec<u8>, String>,
) -> Option<Vec<u8>> {
    let mut splices: Vec<(Range<usize>, &str)> = Vec::new();
    for node in &tree.nodes {
        let Some(value) = revision_token(node) else {
            continue;
        };
        let Some(author) = authors.get(value.as_bytes()) else {
            continue;
        };
        // The one prefixed `author` the source spells holding this value:
        // two that hold it leave the element as it is.
        let mut spelled = node.attr_spans.iter().filter(|(name, _)| {
            name.rsplit_once(':')
                .is_some_and(|(_, local)| local == "author")
                && node.attr(name) == Some(value)
        });
        let (Some((_, pair)), None) = (spelled.next(), spelled.next()) else {
            continue;
        };
        if let Some(inner) = quoted_value(document, pair) {
            splices.push((inner, author.as_str()));
        }
    }
    if splices.is_empty() {
        return None;
    }
    splices.sort_by_key(|(range, _)| range.start);
    let mut out = Vec::with_capacity(document.len());
    let mut at = 0;
    for (range, author) in splices {
        out.extend_from_slice(document.get(at..range.start).unwrap_or_default());
        for byte in author.bytes() {
            match byte {
                b'&' => out.extend_from_slice(b"&amp;"),
                b'<' => out.extend_from_slice(b"&lt;"),
                b'"' => out.extend_from_slice(b"&quot;"),
                b'\'' => out.extend_from_slice(b"&apos;"),
                other => out.push(other),
            }
        }
        at = range.end;
    }
    out.extend_from_slice(document.get(at..).unwrap_or_default());
    Some(out)
}

/// The whole token a tracked revision carries as its `w:author`, or none.
/// Both the resolver and the byte-bound carrier use this one XML predicate.
fn revision_token(node: &Node) -> Option<&str> {
    if node.namespace != W_MAIN || !REVISION_ELEMENTS.contains(&node.name.as_str()) {
        return None;
    }
    node.attr_ns(W_MAIN, "author")
        .filter(|value| is_token(value))
}

/// Whether `value` is a whole default author's token: the marker, then a
/// new id's hex characters and nothing else.
fn is_token(value: &str) -> bool {
    value
        .strip_prefix(DOCX_AUTHOR_TOKEN_MARKER)
        .is_some_and(|hex| hex.len() == TOKEN_HEX_LEN && hex.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// The source bytes between the quotes of one `name="value"` pair.
fn quoted_value(document: &[u8], pair: &Range<usize>) -> Option<Range<usize>> {
    let bytes = document.get(pair.clone())?;
    let equals = bytes.iter().position(|&byte| byte == b'=')?;
    let open = equals
        + 1
        + bytes
            .get(equals + 1..)?
            .iter()
            .position(|byte| !byte.is_ascii_whitespace())?;
    let quote = *bytes.get(open)?;
    (matches!(quote, b'"' | b'\'') && bytes.len() >= open + 2 && bytes.last() == Some(&quote))
        .then(|| pair.start + open + 1..pair.end - 1)
}
