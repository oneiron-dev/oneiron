//! Live handles (AB-001): every row the driver reads is minted here, once,
//! as the outline becomes rows.
//!
//! A handle is opaque, `h<token>:<n>`: `token` is the session's, and `n`
//! comes from one counter for the whole session, never reset or reused (not
//! when an observation ages out, the page navigates, a person hands the
//! browser back, or the front tab moves). It is bound to one DOM node of one
//! document: the tab, the frame, the frame's loader and, for the main frame,
//! its document root, as CDP reports them when the outline is read (polled,
//! no event stream). A read that cannot pin its documents (the page moved
//! between the samples around it) mints handles bound to that read alone. A
//! row with no DOM node (generated text) keeps its handle by its locator
//! within its document. The session keeps every handle's locator, so a
//! handle whose node is gone still resolves by its locator, as a rebound.
//!
//! The node and locator bindings no lookup can reach again go as reads
//! come (C013): a document's once a read shows its frame holding another
//! (another loader or root), an earlier unsettled read's, and a node's once
//! the page answers that it no longer has it. Handle records stay, so an old
//! handle still rebinds by its locator. What the registry holds is charged
//! to the host's memory floor before it grows ([`HandleRetention`]): a read
//! whose new handles the floor will not admit mints none and fails
//! `MemoryFloor`, and the session stays.

use super::CdpDriver;
use super::row_metadata;
use crate::observation::HandleInfo;
use crate::outline::{self, Line, Masks};
use crate::retention::HandleRetention;
use crate::{BrowserError, Row};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::hash::Hash;
use std::time::Instant;

/// Samples of the page's documents one read takes before it stops waiting
/// for the page to hold still between them.
const SAMPLE_TRIES: u32 = 3;

/// One slot of each map's table: its entry and its control byte.
const NODE_SLOT: usize = std::mem::size_of::<((String, u64), String)>() + 1;
const LOCATOR_SLOT: usize = std::mem::size_of::<((String, String), String)>() + 1;
const RECORD_SLOT: usize = std::mem::size_of::<(String, HandleInfo)>() + 1;

/// The session's live handles: by the node, or the row with no node, each
/// names, and each one's locator and last scope.
pub(super) struct Handles {
    token: String,
    /// The last handle's number.
    next: u64,
    by_node: HashMap<(String, u64), String>,
    by_locator: HashMap<(String, String), String>,
    records: HashMap<String, HandleInfo>,
    /// Reads whose documents could not be pinned.
    unsettled: u64,
    /// Bytes the strings the three maps hold take, kept as they come and go.
    strings: usize,
    /// The host's charge for what the registry holds, and its bytes now.
    retention: Box<dyn HandleRetention>,
    charged: usize,
}

/// What one row binds its handle by: its DOM node, or its locator when it
/// has none, within its document.
#[derive(PartialEq, Eq, Hash)]
enum Key {
    Node((String, u64)),
    Locator((String, String)),
}

/// One read of the front tab, minted: its rows with their live handles, the
/// DOM node of each, the accessibility nodes they were read from, and the
/// scope they belong to; and, for each row that shows a secret in place,
/// what its page holds there, for the read's own checks only.
pub(super) struct Capture {
    pub(super) rows: Vec<Row>,
    pub(super) nodes: Vec<Option<u64>>,
    pub(super) ax: Vec<Value>,
    pub(super) scope: String,
    pub(super) originals: Vec<Option<String>>,
}

/// The front tab's documents as CDP reports them: each frame's loader by
/// the frame's id, the main frame, and the main document's root node.
#[derive(PartialEq, Eq)]
struct Documents {
    main: String,
    loaders: BTreeMap<String, String>,
    root: Option<u64>,
}

impl Documents {
    /// The identity of the document `frame` shows: the main frame's when
    /// none is named.
    fn of(&self, target: &str, frame: Option<&str>) -> String {
        let frame = frame.unwrap_or(self.main.as_str());
        let loader = self.loaders.get(frame).map_or("", String::as_str);
        if frame == self.main {
            let root = self.root.map_or_else(String::new, |root| root.to_string());
            format!("{target}/{frame}/{loader}/{root}")
        } else {
            format!("{target}/{frame}/{loader}")
        }
    }

    /// Every document the tab shows, as one name: the main one's, then each
    /// frame's loader.
    fn shown(&self, target: &str) -> String {
        let main = self.of(target, None);
        let frames: Vec<String> = self
            .loaders
            .iter()
            .map(|(frame, loader)| format!("{frame}/{loader}"))
            .collect();
        let frames = frames.join("|");
        format!("{main}|{frames}")
    }
}

impl Handles {
    /// Drops every binding of tab `target`, closed (FIX 6158): no lookup
    /// reaches its nodes again. Each handle's record stays, its locator
    /// with it, for a stale handle to rebind by on another tab.
    pub(super) fn forget_tab(&mut self, target: &str) {
        let prefix = format!("{target}/");
        let mut freed = 0usize;
        self.by_node.retain(|(document, _), handle| {
            let closed = document.starts_with(prefix.as_str());
            if closed {
                freed = freed.saturating_add(document.capacity() + handle.capacity());
            }
            !closed
        });
        self.by_locator.retain(|(document, locator), handle| {
            let closed = document.starts_with(prefix.as_str());
            if closed {
                freed = freed
                    .saturating_add(document.capacity() + locator.capacity() + handle.capacity());
            }
            !closed
        });
        if freed > 0 {
            self.strings = self.strings.saturating_sub(freed);
            shrink(&mut self.by_node);
            shrink(&mut self.by_locator);
            self.settle();
        }
    }

    pub(super) fn new(token: String, retention: Box<dyn HandleRetention>) -> Self {
        Self {
            token,
            next: 0,
            by_node: HashMap::new(),
            by_locator: HashMap::new(),
            records: HashMap::new(),
            unsettled: 0,
            strings: 0,
            retention,
            charged: 0,
        }
    }

    /// What the session knows of `handle`, when it minted it.
    pub(super) fn info(&self, handle: &str) -> Option<HandleInfo> {
        self.records.get(handle).cloned()
    }

    fn bound(&self, key: &Key) -> Option<&String> {
        match key {
            Key::Node(key) => self.by_node.get(key),
            Key::Locator(key) => self.by_locator.get(key),
        }
    }

    /// The bytes the registry holds now: each map's room by its slot, and
    /// the strings in them.
    fn footprint(&self) -> usize {
        slots(self.by_node.capacity(), NODE_SLOT)
            .saturating_add(slots(self.by_locator.capacity(), LOCATOR_SLOT))
            .saturating_add(slots(self.records.capacity(), RECORD_SLOT))
            .saturating_add(self.strings)
    }

    /// Charges `bytes` before the registry grows to them. When the host's
    /// floor will not admit them, nothing is charged and the read mints
    /// nothing.
    fn reserve(&mut self, bytes: usize) -> Result<(), BrowserError> {
        if bytes > self.charged {
            if !self.retention.resize(bytes) {
                return Err(BrowserError::MemoryFloor);
            }
            self.charged = bytes;
        }
        Ok(())
    }

    /// Moves the charge to what the registry holds now, once it has pruned
    /// or grown within what it reserved.
    fn settle(&mut self) {
        let bytes = self.footprint();
        if bytes != self.charged && self.retention.resize(bytes) {
            self.charged = bytes;
        }
    }

    /// The nodes bound in a document this read shows that the read did not
    /// find: hidden, or gone from the page. Only a settled read can tell.
    fn missing(&self, target: &str, documents: Option<&Documents>, lines: &[Line]) -> Vec<u64> {
        let Some(documents) = documents else {
            return Vec::new();
        };
        let read: BTreeSet<String> = lines
            .iter()
            .map(|line| documents.of(target, line.frame.as_deref()))
            .chain([documents.of(target, None)])
            .collect();
        let found: HashSet<u64> = lines.iter().filter_map(|line| line.backend_node).collect();
        let missing: BTreeSet<u64> = self
            .by_node
            .keys()
            .filter(|(document, node)| !found.contains(node) && read.contains(document))
            .map(|(_, node)| *node)
            .collect();
        missing.into_iter().collect()
    }

    /// Drops the bindings no lookup can reach again: those of a document a
    /// frame in this read (`read`, of tab `target`) no longer shows, those
    /// of a frame that left the tab (one of `shown`, the frames the tab
    /// shows now, no longer; FIX 6158), those of this tab's earlier
    /// unsettled reads, and those of the nodes of a document in this read
    /// the page no longer has (`gone`). Another tab's bindings stay, and so
    /// does every handle's record, its locator with it, for a stale handle
    /// to rebind by.
    fn retire(
        &mut self,
        target: &str,
        read: &BTreeSet<&str>,
        gone: &BTreeSet<u64>,
        shown: Option<&HashSet<&str>>,
    ) {
        let frames: Vec<String> = read
            .iter()
            .filter_map(|document| frame_of(target, document))
            .collect();
        let unsettled = format!("{target}/unsettled.");
        let departed = |document: &str| {
            shown.is_some_and(|shown| {
                document
                    .strip_prefix(target)
                    .and_then(|rest| rest.strip_prefix('/'))
                    .and_then(|rest| rest.split_once('/'))
                    .is_some_and(|(frame, _)| frame != "unsettled" && !shown.contains(frame))
            })
        };
        let superseded = |document: &str| {
            !read.contains(document)
                && (document.starts_with(unsettled.as_str())
                    || departed(document)
                    || frames
                        .iter()
                        .any(|frame| document.starts_with(frame.as_str())))
        };
        let mut freed = 0usize;
        self.by_node.retain(|(document, node), handle| {
            let stale = superseded(document.as_str())
                || (gone.contains(node) && read.contains(document.as_str()));
            if stale {
                freed = freed.saturating_add(document.capacity() + handle.capacity());
            }
            !stale
        });
        self.by_locator.retain(|(document, locator), handle| {
            let stale = superseded(document.as_str());
            if stale {
                freed = freed
                    .saturating_add(document.capacity() + locator.capacity() + handle.capacity());
            }
            !stale
        });
        if freed > 0 {
            self.strings = self.strings.saturating_sub(freed);
            shrink(&mut self.by_node);
            shrink(&mut self.by_locator);
            self.settle();
        }
    }

    /// `lines` of tab `target` as rows with their handles, each row's DOM
    /// node, and the read's scope: the session, the tab and every document
    /// the rows came from, with the main one. The bindings this read shows
    /// superseded go first (`gone`: nodes the page no longer has); the new
    /// handles are charged before any is kept, and a refused charge mints
    /// none.
    fn mint(
        &mut self,
        target: &str,
        documents: Option<&Documents>,
        lines: Vec<Line>,
        gone: &BTreeSet<u64>,
    ) -> Result<(Vec<Row>, Vec<Option<u64>>, String), BrowserError> {
        let unsettled = documents
            .is_none()
            .then(|| format!("{target}/unsettled.{}", self.unsettled.saturating_add(1)));
        let home = |frame: Option<&str>| {
            let mut home = match (documents, &unsettled) {
                (Some(documents), _) => documents.of(target, frame),
                (None, Some(unsettled)) => unsettled.clone(),
                (None, None) => String::new(),
            };
            home.shrink_to_fit();
            home
        };
        let homes: Vec<String> = lines
            .iter()
            .map(|line| home(line.frame.as_deref()))
            .collect();
        let main = home(None);
        let read: BTreeSet<&str> = homes
            .iter()
            .map(String::as_str)
            .chain([main.as_str()])
            .collect();
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.token.as_bytes());
        for document in &read {
            hasher.update(b"\n");
            hasher.update(document.as_bytes());
        }
        let scope = format!("page:{}", &hasher.finalize().to_hex()[..16]);
        let frames: Option<HashSet<&str>> = documents.map(|documents| {
            std::iter::once(documents.main.as_str())
                .chain(documents.loaders.keys().map(String::as_str))
                .collect()
        });
        self.retire(target, &read, gone, frames.as_ref());

        // Each row's handle: the one its node or locator is bound to, else a
        // new one, numbered in row order, that its key's later rows share.
        let keys: Vec<Key> = lines
            .iter()
            .zip(homes)
            .map(|(line, home)| match line.backend_node {
                Some(node) => Key::Node((home, node)),
                None => Key::Locator((home, line.row.locator.clone())),
            })
            .collect();
        let mut next = self.next;
        let mut handles: Vec<String> = Vec::with_capacity(keys.len());
        let mut new = Vec::with_capacity(keys.len());
        let mut fresh: HashMap<&Key, usize> = HashMap::new();
        for key in &keys {
            let (handle, first) = match (self.bound(key), fresh.get(key)) {
                (Some(handle), _) => (handle.clone(), false),
                (None, Some(&at)) => (handles[at].clone(), false),
                (None, None) => {
                    next = next.saturating_add(1);
                    fresh.insert(key, handles.len());
                    (format!("h{}:{}", self.token, next), true)
                }
            };
            handles.push(handle);
            new.push(first);
        }

        // What keeping them adds: the new bindings and records, each record
        // as its last row in this read leaves it.
        let (mut nodes_added, mut locators_added) = (0usize, 0usize);
        let (mut added, mut freed) = (0usize, 0usize);
        for (key, &at) in &fresh {
            let handle = handles[at].len();
            added = added.saturating_add(match key {
                Key::Node((document, _)) => {
                    nodes_added += 1;
                    document.capacity() + handle
                }
                Key::Locator((document, locator)) => {
                    locators_added += 1;
                    document.capacity() + locator.capacity() + handle
                }
            });
            // The record's own key.
            added = added.saturating_add(handle);
        }
        let last: HashMap<&str, usize> = handles
            .iter()
            .enumerate()
            .map(|(at, handle)| (handle.as_str(), at))
            .collect();
        for (handle, at) in &last {
            added = added.saturating_add(lines[*at].row.locator.len() + scope.len());
            if let Some(old) = self.records.get(*handle) {
                freed = freed.saturating_add(old.locator.capacity() + old.scope.capacity());
            }
        }
        drop(last);
        let strings = self.strings.saturating_add(added).saturating_sub(freed);
        let projected = slots(
            grown(self.by_node.len(), self.by_node.capacity(), nodes_added),
            NODE_SLOT,
        )
        .saturating_add(slots(
            grown(
                self.by_locator.len(),
                self.by_locator.capacity(),
                locators_added,
            ),
            LOCATOR_SLOT,
        ))
        .saturating_add(slots(
            grown(self.records.len(), self.records.capacity(), fresh.len()),
            RECORD_SLOT,
        ))
        .saturating_add(strings);
        drop(fresh);
        self.reserve(projected)?;

        if documents.is_none() {
            self.unsettled = self.unsettled.saturating_add(1);
        }
        self.next = next;
        let mut rows = Vec::with_capacity(lines.len());
        let mut nodes = Vec::with_capacity(lines.len());
        for (((line, key), handle), first) in lines.into_iter().zip(keys).zip(handles).zip(new) {
            if first {
                match key {
                    Key::Node(key) => {
                        self.strings = self.strings.saturating_add(key.0.capacity() + handle.len());
                        self.by_node.insert(key, handle.clone());
                    }
                    Key::Locator(key) => {
                        self.strings = self
                            .strings
                            .saturating_add(key.0.capacity() + key.1.capacity() + handle.len());
                        self.by_locator.insert(key, handle.clone());
                    }
                }
            }
            let info = HandleInfo {
                locator: line.row.locator.clone(),
                scope: scope.clone(),
                secret: line.row.secret.as_ref().map(|secret| secret.kind),
            };
            self.strings = self
                .strings
                .saturating_add(info.locator.capacity() + info.scope.capacity());
            match self.records.insert(handle.clone(), info) {
                Some(old) => {
                    self.strings = self
                        .strings
                        .saturating_sub(old.locator.capacity() + old.scope.capacity());
                }
                None => self.strings = self.strings.saturating_add(handle.len()),
            }
            let mut row = line.row;
            row.target = handle;
            rows.push(row);
            nodes.push(line.backend_node);
        }
        self.settle();
        Ok((rows, nodes, scope))
    }
}

/// `{target}/{frame}/`: what a settled document's identity shares with the
/// later documents of its frame. An unsettled read's has none.
fn frame_of(target: &str, document: &str) -> Option<String> {
    let rest = document.strip_prefix(target)?.strip_prefix('/')?;
    let (frame, _) = rest.split_once('/')?;
    Some(format!("{target}/{frame}/"))
}

fn slots(capacity: usize, slot: usize) -> usize {
    capacity.saturating_mul(slot)
}

/// A map's room once `added` more entries join its `len`, from its
/// `capacity` now: the same room while they fit, else at most twice what
/// it then holds (its table doubles as it fills).
fn grown(len: usize, capacity: usize, added: usize) -> usize {
    let len = len.saturating_add(added);
    if len <= capacity {
        capacity
    } else {
        len.saturating_mul(2).max(7)
    }
}

/// Gives back a map's room once it holds under a quarter of it.
fn shrink<K: Eq + Hash, V>(map: &mut HashMap<K, V>) {
    if map.len() < map.capacity() / 4 {
        map.shrink_to_fit();
    }
}

impl CdpDriver {
    /// Every document the front tab shows now, as one name, for a
    /// screenshot's scope (AB-004).
    pub(super) fn shown_documents(&self) -> Result<String, BrowserError> {
        Ok(self.documents()?.shown(&self.target))
    }

    /// Every document the front tab shows now, as one name, both reads
    /// answered by `deadline`: the change check's sample (FIX 6680).
    pub(super) fn shown_documents_by(&self, deadline: Instant) -> Result<String, BrowserError> {
        Ok(self.documents_by(Some(deadline))?.shown(&self.target))
    }

    /// The front tab's documents as they stand.
    fn documents(&self) -> Result<Documents, BrowserError> {
        self.documents_by(None)
    }

    /// The front tab's documents as they stand: both reads answered by
    /// `deadline` when one is named, else each within its own call bound.
    fn documents_by(&self, deadline: Option<Instant>) -> Result<Documents, BrowserError> {
        let read = |method: &str, params: Value| match deadline {
            Some(deadline) => self
                .pipe
                .call(Some(&self.session), method, params, deadline),
            None => self.page(method, params),
        };
        let tree = read("Page.getFrameTree", json!({}))?;
        let text = |frame: &Value, name: &str| {
            frame
                .get(name)
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned()
        };
        let main = tree
            .pointer("/frameTree/frame/id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let mut loaders = BTreeMap::new();
        let mut stack: Vec<&Value> = tree.get("frameTree").into_iter().collect();
        while let Some(node) = stack.pop() {
            if let Some(frame) = node.get("frame") {
                loaders.insert(text(frame, "id"), text(frame, "loaderId"));
            }
            stack.extend(
                node.get("childFrames")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten(),
            );
        }
        let root = read("DOM.getDocument", json!({"depth": 0}))?
            .pointer("/root/backendNodeId")
            .and_then(Value::as_u64);
        Ok(Documents {
            main,
            loaders,
            root,
        })
    }

    /// Of `nodes`, those the page no longer has: one
    /// `DOM.pushNodesByBackendIdsToFrontend` call answers 0 for a node it
    /// cannot find in the tab's frames. A hidden node, or a detached one the
    /// page still holds, answers an id and keeps its binding; a failed call
    /// proves nothing, as a guest that serves no such call (Lightpanda's)
    /// proves nothing without one.
    fn gone_nodes(&self, nodes: &[u64]) -> BTreeSet<u64> {
        if nodes.is_empty() || !self.probes_gone_nodes() {
            return BTreeSet::new();
        }
        let Ok(reply) = self.page(
            "DOM.pushNodesByBackendIdsToFrontend",
            json!({ "backendNodeIds": nodes }),
        ) else {
            return BTreeSet::new();
        };
        match reply.get("nodeIds").and_then(Value::as_array) {
            Some(ids) if ids.len() == nodes.len() => nodes
                .iter()
                .zip(ids)
                .filter(|(_, id)| id.as_u64() == Some(0))
                .map(|(node, _)| *node)
                .collect(),
            _ => BTreeSet::new(),
        }
    }

    /// Reads the front tab and mints its rows: the one place a row gets its
    /// live handle. The documents are sampled before and after the outline
    /// and the rows' DOM read (`row_metadata`, FIX 6851); a page that moved
    /// between them is read again, both reads together, and one that never
    /// held still mints handles bound to this read alone. The read's
    /// secrets are found on the tree's own candidates and held before any
    /// row is built (`secrets`, FIX 8028); its rows are built through them.
    pub(super) fn capture(&mut self) -> Result<Capture, BrowserError> {
        self.capture_read(true)
    }

    /// [`Self::capture`], its DOM read only `with_dom` (`capture_dom_policy`,
    /// FIX 6965): a wait's poll whose rows no answer returns reads the tree
    /// alone, and the capture whose rows it returns reads the DOM, as every
    /// other capture does. Without the DOM read, the rows' DOM fields are
    /// gaps and its secrets are those the tree and the session's custody
    /// show.
    pub(super) fn capture_read(&mut self, with_dom: bool) -> Result<Capture, BrowserError> {
        let mut tries = 0;
        let (documents, ax, candidates, dom) = loop {
            let before = self.documents()?;
            let ax = self.ax_nodes()?;
            let candidates = outline::lines(&ax, &Masks::default());
            let dom = if with_dom {
                self.read_dom(&candidates)
            } else {
                row_metadata::DomRead::Failed
            };
            let after = self.documents()?;
            tries += 1;
            if before == after {
                break (Some(after), ax, candidates, dom);
            }
            if tries >= SAMPLE_TRIES {
                break (None, ax, candidates, dom);
            }
        };
        let masks = self.secret_masks(&ax, &candidates, &dom);
        let mut lines = if masks.is_empty() {
            candidates
        } else {
            drop(candidates);
            outline::lines(&ax, &masks)
        };
        drop(masks);
        row_metadata::fill(&mut lines, &dom);
        drop(dom);
        self.secret_nodes = lines
            .iter()
            .filter(|line| line.masked)
            .filter_map(|line| Some((line.frame.clone(), line.backend_node?)))
            .collect();
        let originals = lines.iter_mut().map(|line| line.original.take()).collect();
        let target = self.target.clone();
        let missing = self.handles.missing(&target, documents.as_ref(), &lines);
        let gone = self.gone_nodes(&missing);
        let (rows, nodes, scope) = self
            .handles
            .mint(&target, documents.as_ref(), lines, &gone)?;
        Ok(Capture {
            rows,
            nodes,
            ax,
            scope,
            originals,
        })
    }
}
