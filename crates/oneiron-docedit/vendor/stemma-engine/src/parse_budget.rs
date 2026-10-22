//! What one parse's XML trees cost, across every part of a DOCX package,
//! reserved through the operation it runs in before any tree is built
//! (Rule 5; FIX 8570).
//!
//! The archive reader reserves the inflated bytes, but not the heap nodes a
//! shallow, highly compressible part expands into. Admission streams each XML
//! part once, building nothing, and measures what the tree builders would
//! keep: a node per element, attribute, namespace binding, text run, CDATA
//! section, comment and processing instruction, and the decoded bytes of
//! names, values and text, with the resolved namespace URI each element and
//! attribute stores. The counts are observations, never a reason to stop:
//! each part's cost is reserved through the operation's port before the next
//! part is measured, and the operation is asked at each part whether its
//! deadline passed. The port refuses only at the machine's floor or that
//! deadline. The decoded bytes are measured; the node overhead is the
//! estimate, so only the decoded bytes can meet the machine's floor at once.
//!
//! A part the tree builders cannot read stops measuring where they stop, with
//! what it measured so far kept. Packages read exactly as they did without
//! admission; only their memory is reserved first.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Seek};

use quick_xml::Reader;
use quick_xml::escape::unescape;
use quick_xml::events::attributes::Attributes;
use quick_xml::events::{BytesStart, Event};
use quick_xml::name::{Prefix, QName};
use zip::ZipArchive;

use crate::admission::{Hold, Operation, Refusal, bytes_of};
use crate::word_xml::{canonicalize_ooxml_namespace, canonicalize_relationship_type};

const XML_URI: &str = "http://www.w3.org/XML/1998/namespace";
const XMLNS_URI: &str = "http://www.w3.org/2000/xmlns/";

/// Reserve the trees one package already inflated in memory builds, its
/// parts in archive order. The hold lasts until the caller drops it, once the
/// trees are built.
///
/// # Errors
/// The operation's refusal.
pub(crate) fn admit_parts<'a>(
    parts: impl IntoIterator<Item = &'a [u8]>,
    operation: &Operation,
) -> Result<Hold, Refusal> {
    let mut trees = operation.hold();
    for part in parts {
        operation.checkpoint()?;
        let mut cost = Cost::default();
        admit_part(part, &mut cost);
        cost.reserve(&mut trees)?;
    }
    Ok(trees)
}

/// [`admit_parts`] for every entry of a ZIP its reader opened itself. Each
/// entry inflates as a stream, so admission keeps none of it.
///
/// # Errors
/// The operation's refusal.
pub(crate) fn admit_zip<R: Read + Seek>(
    zip: &mut ZipArchive<R>,
    operation: &Operation,
) -> Result<Hold, Refusal> {
    let mut trees = operation.hold();
    for index in 0..zip.len() {
        operation.checkpoint()?;
        // An unreadable entry is its reader's own finding.
        let Ok(entry) = zip.by_index(index) else {
            continue;
        };
        let mut cost = Cost::default();
        admit_part(BufReader::new(entry), &mut cost);
        cost.reserve(&mut trees)?;
    }
    Ok(trees)
}

/// What one part's trees keep: observations, reserved as bytes.
#[derive(Default)]
struct Cost {
    nodes: u64,
    decoded_bytes: u64,
}

impl Cost {
    fn charge(&mut self, nodes: u64, bytes: usize) {
        self.nodes = self.nodes.saturating_add(nodes);
        self.decoded_bytes = self
            .decoded_bytes
            .saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX));
    }

    /// Reserve the part's trees: each node as one tree node, and the decoded
    /// bytes they hold. Only the decoded bytes are measured.
    fn reserve(&self, trees: &mut Hold) -> Result<(), Refusal> {
        let nodes = bytes_of::<xmltree::XMLNode>(usize::try_from(self.nodes).unwrap_or(usize::MAX));
        trees.take_estimate(nodes.saturating_add(self.decoded_bytes), self.decoded_bytes)
    }
}

/// Charge one part, read with the tree builders' reader settings.
fn admit_part<R: BufRead>(mut source: R, budget: &mut Cost) {
    if !opens_as_xml(&mut source) {
        return;
    }
    let mut reader = Reader::from_reader(source);
    {
        let config = reader.config_mut();
        config.trim_text(false);
        config.expand_empty_elements = false;
        config.check_end_names = true;
    }
    let mut scope = Scope::default();
    // A text run arrives split at each reference but is one node.
    let mut in_text_run = false;
    let mut buf = Vec::new();
    loop {
        let Ok(event) = reader.read_event_into(&mut buf) else {
            return;
        };
        let continues_run = in_text_run;
        in_text_run = matches!(event, Event::Text(_) | Event::GeneralRef(_));
        match event {
            Event::Start(ref start) => {
                if !charge_tag(start, true, &mut scope, budget) {
                    return;
                }
            }
            Event::Empty(ref start) => {
                if !charge_tag(start, false, &mut scope, budget) {
                    return;
                }
            }
            Event::End(_) => scope.close(),
            Event::Text(text) => budget.charge(u64::from(!continues_run), text.len()),
            // A reference's name is never shorter than what it decodes to.
            Event::GeneralRef(reference) => {
                budget.charge(u64::from(!continues_run), reference.len());
            }
            Event::CData(text) => budget.charge(1, text.len()),
            Event::Comment(text) | Event::DocType(text) => budget.charge(1, text.len()),
            Event::PI(pi) => budget.charge(1, pi.len()),
            Event::Decl(_) => {}
            Event::Eof => return,
        }
        buf.clear();
    }
}

/// Whether a part opens as XML: `<` after an optional UTF-8 byte order mark
/// and XML whitespace. Media and other binary parts are not charged.
fn opens_as_xml<R: BufRead>(source: &mut R) -> bool {
    let Ok(head) = source.fill_buf() else {
        return false;
    };
    let head = head.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(head);
    head.iter()
        .find(|byte| !matches!(**byte, b' ' | b'\t' | b'\r' | b'\n'))
        .is_none_or(|byte| *byte == b'<')
}

/// Charge one start or empty tag: its namespace bindings, the element with
/// its resolved URI, each attribute with its own, and each binding an
/// `mc:Choice` hoists for its `Requires` prefixes. `false` is a malformed
/// attribute, where the tree builders stop reading the part.
fn charge_tag(start: &BytesStart<'_>, opens: bool, scope: &mut Scope, budget: &mut Cost) -> bool {
    // Bindings first: a binding is in scope on its own element.
    let mut declared = Vec::new();
    for attribute in attributes(start) {
        let Ok(attribute) = attribute else {
            return false;
        };
        let Some(prefix) = declared_prefix(attribute.key) else {
            continue;
        };
        let Ok(value) = unescape(&attribute.value) else {
            return false;
        };
        let uri = canonicalize_ooxml_namespace(&value).len();
        budget.charge(1, prefix.len() + uri);
        declared.push((prefix.to_owned(), uri));
    }
    scope.open(declared);

    let name = start.name();
    let (local, prefix) = name.decompose();
    let prefix = prefix.map_or("", Prefix::into_inner);
    budget.charge(1, name.as_ref().len() + scope.resolve(prefix));
    let hoists = prefix == "mc" && local.as_ref() == "Choice";

    for attribute in attributes(start) {
        let Ok(attribute) = attribute else {
            return false;
        };
        if declared_prefix(attribute.key).is_some() {
            continue;
        }
        let Ok(value) = unescape(&attribute.value) else {
            return false;
        };
        let value = canonicalize_ooxml_namespace(&value);
        let value = canonicalize_relationship_type(&value);
        let (key_local, key_prefix) = attribute.key.decompose();
        let uri = key_prefix.map_or(0, |key_prefix| scope.resolve(key_prefix.into_inner()));
        budget.charge(1, attribute.key.as_ref().len() + value.len() + uri);
        if hoists && key_prefix.is_none() && key_local.as_ref() == "Requires" {
            for token in value.split_whitespace() {
                if scope.binds_here(token) {
                    continue;
                }
                if let Some(uri) = scope.lookup(token) {
                    budget.charge(1, token.len() + uri);
                }
            }
        }
    }

    if !opens {
        scope.close();
    }
    true
}

/// A tag's attributes as the tree builders read them, without the duplicate
/// check: a duplicate is charged rather than stopping the part.
fn attributes<'a>(start: &'a BytesStart<'_>) -> Attributes<'a> {
    let mut attributes = start.attributes();
    attributes.with_checks(false);
    attributes
}

/// The prefix an `xmlns` or `xmlns:p` attribute binds ("" for the default).
fn declared_prefix(key: QName<'_>) -> Option<&str> {
    if key.as_ref() == "xmlns" {
        return Some("");
    }
    match key.decompose() {
        (local, Some(prefix)) if prefix.into_inner() == "xmlns" => Some(local.into_inner()),
        _ => None,
    }
}

/// The namespace bindings in scope while a part is read, kept as the byte
/// length of the URI each prefix resolves to ("" is the default namespace).
/// Only elements that bind a prefix keep a frame, so plain nesting costs
/// nothing here.
#[derive(Default)]
struct Scope {
    bound: HashMap<String, Vec<usize>>,
    frames: Vec<(usize, Vec<String>)>,
    depth: usize,
}

impl Scope {
    /// Enter an element with the prefixes it binds.
    fn open(&mut self, declared: Vec<(String, usize)>) {
        self.depth += 1;
        if declared.is_empty() {
            return;
        }
        let mut prefixes = Vec::with_capacity(declared.len());
        for (prefix, uri) in declared {
            self.bound.entry(prefix.clone()).or_default().push(uri);
            prefixes.push(prefix);
        }
        self.frames.push((self.depth, prefixes));
    }

    /// Leave the innermost element, dropping what it bound.
    fn close(&mut self) {
        if self
            .frames
            .last()
            .is_some_and(|(depth, _)| *depth == self.depth)
            && let Some((_, prefixes)) = self.frames.pop()
        {
            for prefix in prefixes {
                if let Some(uris) = self.bound.get_mut(&prefix) {
                    uris.pop();
                }
            }
        }
        self.depth = self.depth.saturating_sub(1);
    }

    /// Whether the innermost element binds `prefix` itself.
    fn binds_here(&self, prefix: &str) -> bool {
        self.frames.last().is_some_and(|(depth, prefixes)| {
            *depth == self.depth && prefixes.iter().any(|bound| bound == prefix)
        })
    }

    /// The URI length `prefix` resolves to, innermost binding first.
    fn lookup(&self, prefix: &str) -> Option<usize> {
        match prefix {
            "xml" => Some(XML_URI.len()),
            "xmlns" => Some(XMLNS_URI.len()),
            _ => self.bound.get(prefix).and_then(|uris| uris.last()).copied(),
        }
    }

    /// [`Self::lookup`], with an unbound prefix storing no URI.
    fn resolve(&self, prefix: &str) -> usize {
        self.lookup(prefix).unwrap_or(0)
    }
}
