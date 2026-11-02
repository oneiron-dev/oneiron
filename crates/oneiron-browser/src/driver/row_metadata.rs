//! Where a link row goes, a heading row's level and a row's datetimes, from
//! the outline's own candidates and one DOM read per capture (FIX 6851:
//! [`row_href_policy`], [`row_level_policy`], [`row_datetime_policy`]).
//!
//! The capture reads `DOM.getDocument` at `depth: -1` between its outline
//! read and its after-sample (`handles`), so a navigation between the two
//! reads both again. Chromium adds `pierce`, for its same-process frames
//! and shadow trees; Lightpanda reads its main document's tree. The read
//! is indexed by backend node, with each node's DOM parent and the end of
//! its subtree, and a row joins it by its own backend node only, never by
//! its name or its place. A frame's document is indexed apart, so no
//! row's ancestors or subtree cross into another document.
//!
//! The read never fails a verb: one that fails (past the message bound, an
//! engine error, its time) leaves the rows as the outline made them, with a
//! `read_failed` gap on each field it would have filled, as a row it cannot
//! join has one naming why. Its texts live only in the rows it fills; the
//! read is dropped once they are, and nothing of it is logged.
//!
//! The same read gives the secret classifier (FIX 8028) each field's input
//! type and autocomplete tokens, joined the same way, before any row is
//! built (`driver::secrets`).
//!
//! The read binds every node it returns to Chromium's frontend, so a page
//! that changes sends DOM events (attribute, child and text changes) until
//! the capture's after-sample reads the document again, which drops those
//! bindings; the pipe drops the events.

use super::CdpDriver;
use crate::cdp::Held;
use crate::outline::{self, Line};
use crate::{BrowserEngine, RowFieldGap, RowGapField, RowGapReason};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use url::Url;

/// Chromium cuts each accessibility string, a link's `url` among them, at
/// 10,000 UTF-8 bytes and marks no cut: a destination this long may be cut.
const AX_TEXT_CUT: usize = 10_000;

/// What one capture's DOM read gave: the read, with the charge for what
/// of a past-threshold reply it keeps, given back as it drops (FIX
/// 11578); or a read that failed, which keeps nothing.
pub(super) enum DomRead {
    Read(Dom, #[allow(dead_code)] Option<Held>),
    Failed,
}

/// One DOM read, indexed by backend node.
pub(super) struct Dom {
    /// Every node read, in document order, each document's apart: a
    /// node's subtree follows it, its shadow trees and pseudo-elements
    /// first.
    nodes: Vec<DomNode>,
    by_backend: HashMap<u64, usize>,
    /// Each document's base for its links, in the read's order: the main
    /// document's first.
    bases: Vec<Base>,
    /// The frames whose documents the read holds, as their own elements
    /// name them.
    frames: HashSet<String>,
    /// The front tab's out-of-process frames, whose documents no read of
    /// the tab's holds (FIX 8336): their rows join none of its nodes.
    oopifs: HashSet<String>,
    /// Whether the read holds shadow trees: Chromium's `pierce` does;
    /// Lightpanda's writes light-DOM children only, so a node it does not
    /// hold may be in a shadow tree, never proved stale (FIX 6964).
    shadows_read: bool,
}

/// What one node of the read gives its rows.
struct DomNode {
    parent: Option<usize>,
    /// Where its subtree ends among the read's nodes.
    end: usize,
    /// Its document, among the read's.
    document: usize,
    href: Option<String>,
    datetime: Option<String>,
    aria_level: Option<u32>,
    /// Its h1 to h6 tag's level.
    tag_level: Option<u32>,
    /// An input's `type` attribute, as written.
    input_type: Option<String>,
    /// Its `autocomplete` attribute's tokens, as written.
    autocomplete: Option<String>,
}

/// A document's base, for the hrefs it holds.
enum Base {
    Url(Url),
    /// It names none that parses.
    Absent,
    /// Its read apart failed.
    Failed,
}

/// One step of a document's walk: a node to read under its parent, or a
/// node whose subtree was read.
enum Step<'v> {
    Open(&'v Value, Option<usize>),
    Close(usize),
}

impl CdpDriver {
    /// The front tab's DOM, read once for `lines`. Never an error: a read
    /// that fails is kept as failed, for the rows' gaps.
    pub(super) fn read_dom(&self, lines: &[Line]) -> DomRead {
        let params = match self.engine {
            BrowserEngine::Chromium => json!({"depth": -1, "pierce": true}),
            BrowserEngine::Lightpanda => json!({"depth": -1}),
        };
        let mut dom = {
            let Ok(read) = self.page("DOM.getDocument", params) else {
                return DomRead::Failed;
            };
            let Some(root) = read.get("root") else {
                return DomRead::Failed;
            };
            let dom = Dom::index(root);
            // A deep read is taken apart without nesting (FIX 6963).
            crate::cdp::deep::dismantle(read);
            dom
        };
        dom.shadows_read = self.engine == BrowserEngine::Chromium;
        dom.oopifs = self
            .pipe
            .oopifs(&self.session)
            .into_iter()
            .map(|(frame, _, _)| frame)
            .collect();
        if dom.needs_main_base(lines) {
            dom.bases[0] = self.main_base();
        }
        // The read's charge rides it until it drops (FIX 11578): its
        // reply's went back as its call took it, and the charge is taken
        // on the read as it is kept, its base settled.
        let held = self.pipe.charge_retained(dom.footprint());
        DomRead::Read(dom, held)
    }

    /// The front tab's document base, where its DOM read names none
    /// (Lightpanda's): one fixed `document.baseURI` read, which runs no
    /// script of the page's or the program's.
    fn main_base(&self) -> Base {
        let read = self.page(
            "Runtime.evaluate",
            json!({"expression": "document.baseURI", "returnByValue": true}),
        );
        match read {
            Ok(reply) if reply.get("exceptionDetails").is_none() => reply
                .pointer("/result/value")
                .and_then(Value::as_str)
                .and_then(|base| Url::parse(base).ok())
                .map_or(Base::Absent, Base::Url),
            _ => Base::Failed,
        }
    }
}

impl Dom {
    /// Indexes the read whose document node is `root`.
    fn index(root: &Value) -> Self {
        let mut dom = Self {
            nodes: Vec::new(),
            by_backend: HashMap::new(),
            bases: Vec::new(),
            frames: HashSet::new(),
            oopifs: HashSet::new(),
            shadows_read: true,
        };
        let mut documents = vec![root];
        while let Some(document) = documents.pop() {
            dom.walk(document, &mut documents);
        }
        dom
    }

    /// Indexes `document`'s tree, its shadow trees in it; the documents its
    /// frames show go on `documents`, each to be read apart.
    fn walk<'v>(&mut self, document: &'v Value, documents: &mut Vec<&'v Value>) {
        let at_document = self.bases.len();
        self.bases.push(
            document
                .get("baseURL")
                .and_then(Value::as_str)
                .and_then(|base| Url::parse(base).ok())
                .map_or(Base::Absent, Base::Url),
        );
        let first = self.nodes.len();
        let mut steps = vec![Step::Open(document, None)];
        while let Some(step) = steps.pop() {
            let (node, parent) = match step {
                Step::Open(node, parent) => (node, parent),
                Step::Close(at) => {
                    self.nodes[at].end = self.nodes.len();
                    continue;
                }
            };
            let at = self.nodes.len();
            self.nodes.push(DomNode::of(node, parent, at_document));
            if let Some(backend) = node.get("backendNodeId").and_then(Value::as_u64) {
                self.by_backend.entry(backend).or_insert(at);
            }
            // A document's own element names the frame that shows it.
            if parent == Some(first)
                && let Some(frame) = node.get("frameId").and_then(Value::as_str)
            {
                self.frames.insert(frame.to_owned());
            }
            if let Some(content) = node.get("contentDocument") {
                documents.push(content);
            }
            // Its shadow trees and pseudo-elements (a text row may be a
            // pseudo-element's) under it, then its children; never a
            // template's inert content.
            steps.push(Step::Close(at));
            for child in list(node, "shadowRoots")
                .iter()
                .chain(list(node, "pseudoElements"))
                .chain(list(node, "children"))
                .rev()
            {
                steps.push(Step::Open(child, Some(at)));
            }
        }
    }

    /// The bytes the read keeps: its nodes' room and the strings they
    /// keep, and its indexes' room, each map's table by its slot.
    fn footprint(&self) -> usize {
        let text = |text: &Option<String>| text.as_ref().map_or(0, String::capacity);
        let kept = self
            .nodes
            .iter()
            .map(|node| {
                text(&node.href)
                    .saturating_add(text(&node.datetime))
                    .saturating_add(text(&node.input_type))
                    .saturating_add(text(&node.autocomplete))
            })
            .fold(0, usize::saturating_add);
        let frames = self
            .frames
            .iter()
            .map(|frame| frame.capacity())
            .fold(0, usize::saturating_add);
        let bases = self
            .bases
            .iter()
            .map(|base| match base {
                Base::Url(url) => url.as_str().len(),
                Base::Absent | Base::Failed => 0,
            })
            .fold(0, usize::saturating_add);
        let entry = std::mem::size_of::<String>() + 1;
        self.nodes
            .len()
            .saturating_mul(std::mem::size_of::<DomNode>())
            .saturating_add(kept)
            .saturating_add(
                self.by_backend
                    .len()
                    .saturating_mul(std::mem::size_of::<(u64, usize)>() + 1),
            )
            .saturating_add(self.bases.len().saturating_mul(std::mem::size_of::<Base>()))
            .saturating_add(bases)
            .saturating_add(self.frames.len().saturating_mul(entry))
            .saturating_add(frames)
    }

    /// The node `line` joins by its own backend node, or why it joins none.
    fn join(&self, line: &Line) -> Result<usize, RowGapReason> {
        let node = line.backend_node.ok_or(RowGapReason::NoDomNode)?;
        // An out-of-process frame's node ids are its own process's: one
        // never names a node of this read.
        if line
            .frame
            .as_deref()
            .is_some_and(|frame| self.oopifs.contains(frame))
        {
            return Err(RowGapReason::OutsideDomRead);
        }
        self.by_backend
            .get(&node)
            .copied()
            .ok_or_else(|| match line.frame.as_deref() {
                Some(frame) if !self.frames.is_empty() && !self.frames.contains(frame) => {
                    RowGapReason::OutsideDomRead
                }
                _ if !self.shadows_read => RowGapReason::OutsideDomRead,
                _ => RowGapReason::StaleNode,
            })
    }

    /// Whether a link row of the main document takes its destination from
    /// an href attribute that is no whole URL alone, while the read names
    /// that document no base.
    fn needs_main_base(&self, lines: &[Line]) -> bool {
        matches!(self.bases.first(), Some(Base::Absent))
            && lines.iter().any(|line| {
                line.row.role == "link"
                    && !line.ax_url.as_deref().is_some_and(whole_destination)
                    && self.join(line).is_ok_and(|at| {
                        let node = &self.nodes[at];
                        node.document == 0
                            && node
                                .href
                                .as_deref()
                                .is_some_and(|raw| Url::parse(raw).is_err())
                    })
            })
    }
}

impl DomNode {
    /// What `node`, read under `parent` in `document`, gives its rows.
    fn of(node: &Value, parent: Option<usize>, document: usize) -> Self {
        let mut read = Self {
            parent,
            end: 0,
            document,
            href: None,
            datetime: None,
            aria_level: None,
            tag_level: None,
            input_type: None,
            autocomplete: None,
        };
        let input = node.get("localName").and_then(Value::as_str) == Some("input");
        let mut xlink = None;
        for pair in list(node, "attributes").chunks(2) {
            let [name, value] = pair else {
                continue;
            };
            let (Some(name), Some(value)) = (name.as_str(), value.as_str()) else {
                continue;
            };
            if name.eq_ignore_ascii_case("href") {
                read.href = Some(value.to_owned());
            } else if name.eq_ignore_ascii_case("xlink:href") {
                xlink = Some(value.to_owned());
            } else if name.eq_ignore_ascii_case("datetime") {
                read.datetime = Some(value.to_owned());
            } else if name.eq_ignore_ascii_case("aria-level") {
                read.aria_level = value.trim().parse().ok().filter(|level| *level > 0);
            } else if input && name.eq_ignore_ascii_case("type") {
                read.input_type = Some(value.to_owned());
            } else if name.eq_ignore_ascii_case("autocomplete") {
                read.autocomplete = Some(value.to_owned());
            }
        }
        // An SVG link may name its destination the older way.
        read.href = read.href.or(xlink);
        read.tag_level = match node.get("localName").and_then(Value::as_str) {
            Some("h1") => Some(1),
            Some("h2") => Some(2),
            Some("h3") => Some(3),
            Some("h4") => Some(4),
            Some("h5") => Some(5),
            Some("h6") => Some(6),
            _ => None,
        };
        read
    }
}

impl DomRead {
    /// The input type and autocomplete tokens of the element `line` joins
    /// by its own backend node: none where the read failed or joins none.
    pub(super) fn field_attributes(&self, line: &Line) -> (Option<&str>, Option<&str>) {
        let Self::Read(dom, _) = self else {
            return (None, None);
        };
        match dom.join(line) {
            Ok(at) => {
                let node = &dom.nodes[at];
                (node.input_type.as_deref(), node.autocomplete.as_deref())
            }
            Err(_) => (None, None),
        }
    }
}

/// The nodes `node` lists under `key`; none when it lists none.
fn list<'v>(node: &'v Value, key: &str) -> &'v [Value] {
    match node.get(key).and_then(Value::as_array) {
        Some(nodes) => nodes,
        None => &[],
    }
}

/// Whether the tree's own destination for a link is whole: shorter than
/// Chromium's cut, and a URL that parses (Lightpanda names an href it
/// could not resolve as it was written).
fn whole_destination(url: &str) -> bool {
    url.len() < AX_TEXT_CUT && Url::parse(url).is_ok()
}

/// Fills each line's row from its tree candidates and the capture's DOM
/// `read`: its link destination, its heading level and its datetimes, and
/// a gap on each one the read could not give.
pub(super) fn fill(lines: &mut [Line], read: &DomRead) {
    for line in lines {
        let joined = match read {
            DomRead::Read(dom, _) => dom.join(line).map(|at| (dom, at)),
            DomRead::Failed => Err(RowGapReason::ReadFailed),
        };
        let (ax_url, ax_level) = (line.ax_url.take(), line.ax_level.take());
        let row = &mut line.row;
        let mut gaps = Vec::new();
        if row.role == "link" {
            let element = joined.map(|(dom, at)| {
                let node = &dom.nodes[at];
                (node, &dom.bases[node.document])
            });
            match row_href_policy(ax_url, element) {
                Ok(href) => row.href = href,
                Err(reason) => gaps.push(gap(RowGapField::Href, reason)),
            }
        }
        if row.role == "heading" {
            match row_level_policy(ax_level, joined.map(|(dom, at)| &dom.nodes[at])) {
                Ok(level) => row.level = level,
                Err(reason) => gaps.push(gap(RowGapField::Level, reason)),
            }
        }
        match joined {
            Ok((dom, at)) => {
                row.datetimes = row_datetime_policy(dom, at, outline::is_control(&row.role));
            }
            Err(reason) => gaps.push(gap(RowGapField::Datetime, reason)),
        }
        row.unavailable = gaps;
    }
}

fn gap(field: RowGapField, reason: RowGapReason) -> RowFieldGap {
    RowFieldGap { field, reason }
}

/// A link row's destination: the tree's own when it is whole (Chromium's
/// native one, Lightpanda's resolved one); else the href attribute its
/// element carries (a long link Chromium cut, Lightpanda's empty href, a
/// non-native or SVG link), resolved against its document's base with the
/// url crate, in UTF-8, so a legacy-charset page may spell a query apart
/// from its engine. Every scheme is carried as written. A link with no
/// destination either way carries none; one whose destination has no
/// whole form, or whose element the read cannot give, is a gap.
fn row_href_policy(
    ax_url: Option<String>,
    element: Result<(&DomNode, &Base), RowGapReason>,
) -> Result<Option<String>, RowGapReason> {
    let named = ax_url.is_some();
    if let Some(url) = ax_url.filter(|url| whole_destination(url)) {
        return Ok(Some(url));
    }
    let (node, base) = element?;
    let resolved = match (&node.href, base) {
        (Some(raw), Base::Url(base)) => base.join(raw).map_err(|_| RowGapReason::Unresolvable),
        (Some(raw), Base::Absent) => Url::parse(raw).map_err(|_| RowGapReason::Unresolvable),
        (Some(raw), Base::Failed) => Url::parse(raw).map_err(|_| RowGapReason::ReadFailed),
        (None, _) if named => Err(RowGapReason::Unresolvable),
        (None, _) => return Ok(None),
    };
    resolved.map(|url| Some(String::from(url)))
}

/// A heading row's level: the tree's semantic one (Chromium's counts
/// aria-level and heading offsets); else, where the tree names none (a
/// Lightpanda heading by role), its element's own aria-level, a positive
/// integer, else its h1 to h6 tag. A heading with neither has none.
fn row_level_policy(
    ax_level: Option<u32>,
    element: Result<&DomNode, RowGapReason>,
) -> Result<Option<u32>, RowGapReason> {
    if ax_level.is_some() {
        return Ok(ax_level);
    }
    let node = element?;
    Ok(node.aria_level.or(node.tag_level))
}

/// A row's datetimes: the `datetime` attribute its element carries, else
/// the one its nearest DOM ancestor carries (DOM parents within its
/// document, never a sibling's); on a control row, a link among them, whose
/// text the outline folds into its name, every one inside its element too.
/// Each is its attribute's raw text, in document order, every one.
fn row_datetime_policy(dom: &Dom, at: usize, control: bool) -> Vec<String> {
    let mut datetimes = Vec::new();
    let mut up = Some(at);
    while let Some(node) = up {
        if let Some(datetime) = &dom.nodes[node].datetime {
            datetimes.push(datetime.clone());
            break;
        }
        up = dom.nodes[node].parent;
    }
    if control {
        let inside = &dom.nodes[at + 1..dom.nodes[at].end];
        datetimes.extend(inside.iter().filter_map(|node| node.datetime.clone()));
    }
    datetimes
}
