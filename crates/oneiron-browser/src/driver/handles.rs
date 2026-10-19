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

use super::CdpDriver;
use crate::observation::HandleInfo;
use crate::outline::{self, Line};
use crate::{BrowserError, Row};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Samples of the page's documents one read takes before it stops waiting
/// for the page to hold still between them.
const SAMPLE_TRIES: u32 = 3;

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
}

/// One read of the front tab, minted: its rows with their live handles, the
/// DOM node of each, the accessibility nodes they were read from, and the
/// scope they belong to.
pub(super) struct Capture {
    pub(super) rows: Vec<Row>,
    pub(super) nodes: Vec<Option<u64>>,
    pub(super) ax: Vec<Value>,
    pub(super) scope: String,
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
    pub(super) fn new(token: String) -> Self {
        Self {
            token,
            next: 0,
            by_node: HashMap::new(),
            by_locator: HashMap::new(),
            records: HashMap::new(),
            unsettled: 0,
        }
    }

    /// What the session knows of `handle`, when it minted it.
    pub(super) fn info(&self, handle: &str) -> Option<HandleInfo> {
        self.records.get(handle).cloned()
    }

    fn fresh(&mut self) -> String {
        self.next = self.next.saturating_add(1);
        format!("h{}:{}", self.token, self.next)
    }

    fn of_node(&mut self, document: String, node: u64) -> String {
        let key = (document, node);
        if let Some(handle) = self.by_node.get(&key) {
            return handle.clone();
        }
        let handle = self.fresh();
        self.by_node.insert(key, handle.clone());
        handle
    }

    fn of_locator(&mut self, document: String, locator: String) -> String {
        let key = (document, locator);
        if let Some(handle) = self.by_locator.get(&key) {
            return handle.clone();
        }
        let handle = self.fresh();
        self.by_locator.insert(key, handle.clone());
        handle
    }

    /// `lines` of tab `target` as rows with their handles, each row's DOM
    /// node, and the read's scope: the session, the tab and every document
    /// the rows came from, with the main one.
    fn mint(
        &mut self,
        target: &str,
        documents: Option<&Documents>,
        lines: Vec<Line>,
    ) -> (Vec<Row>, Vec<Option<u64>>, String) {
        let unsettled = documents.is_none().then(|| {
            self.unsettled += 1;
            format!("{target}/unsettled.{}", self.unsettled)
        });
        let home = |frame: Option<&str>| match (documents, &unsettled) {
            (Some(documents), _) => documents.of(target, frame),
            (None, Some(unsettled)) => unsettled.clone(),
            (None, None) => String::new(),
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
        let mut rows = Vec::with_capacity(lines.len());
        let mut nodes = Vec::with_capacity(lines.len());
        for (line, home) in lines.into_iter().zip(homes) {
            let mut row = line.row;
            let handle = match line.backend_node {
                Some(node) => self.of_node(home, node),
                None => self.of_locator(home, row.locator.clone()),
            };
            self.records.insert(
                handle.clone(),
                HandleInfo {
                    locator: row.locator.clone(),
                    scope: scope.clone(),
                },
            );
            row.target = handle;
            rows.push(row);
            nodes.push(line.backend_node);
        }
        (rows, nodes, scope)
    }
}

impl CdpDriver {
    /// Every document the front tab shows now, as one name, for a
    /// screenshot's scope (AB-004).
    pub(super) fn shown_documents(&self) -> Result<String, BrowserError> {
        Ok(self.documents()?.shown(&self.target))
    }

    /// The front tab's documents as they stand.
    fn documents(&self) -> Result<Documents, BrowserError> {
        let tree = self.page("Page.getFrameTree", json!({}))?;
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
        let root = self
            .page("DOM.getDocument", json!({"depth": 0}))?
            .pointer("/root/backendNodeId")
            .and_then(Value::as_u64);
        Ok(Documents {
            main,
            loaders,
            root,
        })
    }

    /// Reads the front tab and mints its rows: the one place a row gets its
    /// live handle. The documents are sampled before and after the outline
    /// is read; a page that moved between them is read again, and one that
    /// never held still mints handles bound to this read alone.
    pub(super) fn capture(&mut self) -> Result<Capture, BrowserError> {
        let mut tries = 0;
        let (documents, ax) = loop {
            let before = self.documents()?;
            let ax = self.ax_nodes()?;
            let after = self.documents()?;
            tries += 1;
            if before == after {
                break (Some(after), ax);
            }
            if tries >= SAMPLE_TRIES {
                break (None, ax);
            }
        };
        let lines = outline::lines(&ax);
        let target = self.target.clone();
        let (rows, nodes, scope) = self.handles.mint(&target, documents.as_ref(), lines);
        Ok(Capture {
            rows,
            nodes,
            ax,
            scope,
        })
    }
}
