//! The accessibility tree as rows a program reads: a closed set of roles,
//! closed menus collapsed, layout and text-run noise left out, and each row
//! named by a locator built from its role, its name and its named
//! ancestors. Its live handle is minted once the rows are read
//! (`driver::handles`); here the row's `ref` stays empty.
//!
//! A link row's destination (`url`) and a heading row's level (`level`),
//! as the tree names them, ride beside the row, never in it or its locator:
//! the capture joins them to its DOM read (`driver::row_metadata`, FIX
//! 6851), and a settle poll's fingerprint hashes the row's fields as before.

use crate::Row;
use serde_json::Value;
use std::collections::{HashMap, HashSet};

/// Roles a program acts on.
const CONTROLS: &[&str] = &[
    "button",
    "link",
    "textbox",
    "searchbox",
    "combobox",
    "listbox",
    "option",
    "checkbox",
    "radio",
    "switch",
    "slider",
    "spinbutton",
    "menuitem",
    "menuitemcheckbox",
    "menuitemradio",
    "tab",
    "treeitem",
];

/// Roles a program reads but does not act on.
const READS: &[&str] = &[
    "heading",
    "dialog",
    "alertdialog",
    "alert",
    "status",
    "img",
    "StaticText",
];

/// Roles whose name, when they have one, joins the ref of every row inside.
const SCOPES: &[&str] = &[
    "dialog",
    "alertdialog",
    "form",
    "region",
    "navigation",
    "main",
    "banner",
    "contentinfo",
    "complementary",
    "search",
    "list",
    "listitem",
    "row",
    "table",
    "grid",
    "group",
    "radiogroup",
    "menu",
    "menubar",
    "tablist",
    "toolbar",
    "article",
    "tree",
];

const STATES: &[&str] = &[
    "focused", "disabled", "checked", "expanded", "selected", "required", "invalid", "pressed",
];

/// The longest name or text a row carries.
const NAME_CHARS: usize = 200;

/// A row, the DOM node it was read from, and the frame whose document
/// holds it, when the tree names one; with a link row's destination and a
/// heading row's level as the tree names them.
pub(crate) struct Line {
    pub(crate) row: Row,
    pub(crate) backend_node: Option<u64>,
    pub(crate) frame: Option<String>,
    pub(crate) ax_url: Option<String>,
    pub(crate) ax_level: Option<u32>,
}

/// Whether a row of `role` is a control, whose text the outline folds into
/// its name.
pub(crate) fn is_control(role: &str) -> bool {
    CONTROLS.contains(&role)
}

struct Node<'a> {
    raw: &'a Value,
    role: &'a str,
    name: String,
}

/// Reads `Accessibility.getFullAXTree`'s `nodes` into rows, in page order.
pub(crate) fn lines(nodes: &[Value]) -> Vec<Line> {
    let by_id: HashMap<&str, &Value> = nodes
        .iter()
        .filter_map(|n| Some((n.get("nodeId")?.as_str()?, n)))
        .collect();
    let Some(root) = nodes.iter().find(|n| n.get("parentId").is_none()) else {
        return Vec::new();
    };
    let mut walk = Walk {
        by_id: &by_id,
        scope: Vec::new(),
        seen: HashMap::new(),
        out: Vec::new(),
        visited: HashSet::new(),
    };
    walk.visit(root, false, None);
    walk.out
}

struct Walk<'a> {
    by_id: &'a HashMap<&'a str, &'a Value>,
    scope: Vec<String>,
    seen: HashMap<String, u32>,
    out: Vec<Line>,
    visited: HashSet<&'a str>,
}

impl<'a> Walk<'a> {
    /// Visits `raw` and the rows under it. `frame` is the frame of the
    /// nearest node above that named one: a document's nodes are its frame's.
    fn visit(&mut self, raw: &'a Value, in_control: bool, frame: Option<&'a str>) {
        if let Some(id) = raw.get("nodeId").and_then(Value::as_str)
            && !self.visited.insert(id)
        {
            return;
        }
        let frame = raw.get("frameId").and_then(Value::as_str).or(frame);
        let ignored = raw.get("ignored").and_then(Value::as_bool).unwrap_or(false);
        let node = Node {
            raw,
            role: field(raw, "role").unwrap_or(""),
            name: clip(field(raw, "name").unwrap_or("")),
        };
        let control = CONTROLS.contains(&node.role);
        let mut scoped = false;
        if !ignored {
            // A control's own text is already its name.
            let read = READS.contains(&node.role)
                && !node.name.is_empty()
                && !(node.role == "StaticText" && in_control);
            if control || read {
                self.emit(&node, frame);
            }
            if SCOPES.contains(&node.role) && !node.name.is_empty() {
                self.scope.push(format!("{} \"{}\"", node.role, node.name));
                scoped = true;
            }
        }
        // A closed menu, list or tree shows its own row and none of its items.
        if state(raw, "expanded").as_deref() != Some("false") {
            for child in raw
                .get("childIds")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let Some(child) = child.as_str().and_then(|id| self.by_id.get(id)) {
                    self.visit(child, in_control || control, frame);
                }
            }
        }
        if scoped {
            self.scope.pop();
        }
    }

    fn emit(&mut self, node: &Node<'_>, frame: Option<&str>) {
        let mut key = self.scope.join(" > ");
        key.push_str(&format!(" > {} \"{}\"", node.role, node.name));
        // Identical twins (same role, name and named ancestors) are told apart
        // by their order among themselves alone.
        let twin = self.seen.entry(key.clone()).or_insert(0);
        *twin += 1;
        if *twin > 1 {
            key.push_str(&format!(" ~{twin}"));
        }
        let hash = blake3::hash(key.as_bytes()).to_hex();
        let states = STATES
            .iter()
            .filter_map(|&name| match state(node.raw, name).as_deref() {
                None | Some("false") => None,
                Some("true") => Some(name.to_owned()),
                Some(other) => Some(format!("{name}={other}")),
            })
            .collect();
        let value = field(node.raw, "value").filter(|v| !v.is_empty()).map(clip);
        let row = Row {
            target: String::new(),
            locator: format!("e{}", &hash[..12]),
            role: node.role.to_owned(),
            name: node.name.clone(),
            value,
            states,
            depth: u16::try_from(self.scope.len()).unwrap_or(u16::MAX),
            href: None,
            level: None,
            datetimes: Vec::new(),
            unavailable: Vec::new(),
        };
        let backend_node = node.raw.get("backendDOMNodeId").and_then(Value::as_u64);
        // Only a link's `url` is its destination and only a heading's
        // `level` its rank: a document, an image or a list item names
        // its own. Chromium writes the level as a number, Lightpanda as a
        // decimal string.
        let ax_url = (node.role == "link")
            .then(|| state(node.raw, "url"))
            .flatten()
            .filter(|url| !url.is_empty());
        let ax_level = (node.role == "heading")
            .then(|| state(node.raw, "level"))
            .flatten()
            .and_then(|level| level.trim().parse::<u32>().ok())
            .filter(|level| *level > 0);
        self.out.push(Line {
            row,
            backend_node,
            frame: frame.map(str::to_owned),
            ax_url,
            ax_level,
        });
    }
}

fn field<'v>(node: &'v Value, name: &str) -> Option<&'v str> {
    node.get(name)?.get("value")?.as_str()
}

fn state(node: &Value, name: &str) -> Option<String> {
    let property = node
        .get("properties")?
        .as_array()?
        .iter()
        .find(|p| p.get("name").and_then(Value::as_str) == Some(name))?;
    match property.get("value")?.get("value")? {
        Value::String(text) => Some(text.clone()),
        other => Some(other.to_string()),
    }
}

fn clip(text: &str) -> String {
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    match text.char_indices().nth(NAME_CHARS) {
        Some((end, _)) => format!("{}…", &text[..end]),
        None => text,
    }
}
